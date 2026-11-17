package ipa

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	// MainSize is the locked thin arm64 device executable length.
	MainSize int64 = 40969408
	// MainSHA256 is the locked thin arm64 device executable digest.
	MainSHA256 = "e4029164cb6cbf80dee7b17250ca706bfbab9f218436f007bbbbcbc8baf20141"
	// LoaderPath is the single LC_LOAD_DYLIB path inserted into the main image.
	LoaderPath = "@executable_path/Frameworks/libraspberry.dylib"

	lcSegment         = 0x1
	lcSegment64       = 0x19
	lcLoadDylib       = 0xc
	lcIdDylib         = 0xd
	lcLoadWeakDylib   = 0x80000018
	lcReexportDylib   = 0x8000001f
	lcLoadUpwardDylib = 0x80000023

	segment64HeaderSize = 72
	section64Size       = 80
	dylibCmdHeaderSize  = 24
)

// AddLoader returns a copy of the locked main executable with one LC_LOAD_DYLIB
// for LoaderPath placed in verified zero slack after the load commands. Every
// other byte is unchanged. The result is not signed; it must be re-signed
// before any install. data is not modified.
func AddLoader(data []byte) ([]byte, error) {
	if int64(len(data)) != MainSize {
		return nil, fmt.Errorf("%w: size %d", ErrBaseline, len(data))
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != MainSHA256 {
		return nil, fmt.Errorf("%w: sha256 %s", ErrBaseline, hex.EncodeToString(sum[:]))
	}
	return addLoader(data)
}

func addLoader(data []byte) ([]byte, error) {
	plan, err := planLoader(data)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	copy(out, data)
	binary.LittleEndian.PutUint32(out[16:], plan.ncmd+1)
	binary.LittleEndian.PutUint32(out[20:], plan.cmdsz+uint32(len(plan.cmd)))
	copy(out[plan.insertAt:], plan.cmd)
	return out, nil
}

type loaderPlan struct {
	ncmd      uint32
	cmdsz     uint32
	insertAt  int
	firstFile int
	slack     int
	cmd       []byte
}

func planLoader(data []byte) (loaderPlan, error) {
	m, err := parseMachO(data)
	if err != nil {
		return loaderPlan{}, err
	}
	if m.Magic != "64-bit little-endian" || m.CPU != "arm64" || m.FileType != "executable" {
		return loaderPlan{}, fmt.Errorf("ipa: loader: need thin arm64 MH_EXECUTE, got %s %s %s", m.Magic, m.CPU, m.FileType)
	}
	if m.CryptID == nil || *m.CryptID != 0 {
		id := "missing"
		if m.CryptID != nil {
			id = fmt.Sprintf("%d", *m.CryptID)
		}
		return loaderPlan{}, fmt.Errorf("ipa: loader: cryptid must be 0, got %s", id)
	}

	bo := binary.LittleEndian
	ncmd := bo.Uint32(data[16:])
	cmdsz := bo.Uint32(data[20:])
	if cmdsz%8 != 0 {
		return loaderPlan{}, errors.New("ipa: loader: sizeofcmds is not 8-byte aligned")
	}
	headerSize := 32
	cmdEnd := headerSize + int(cmdsz)
	cmd := loaderCommand()
	if cmdEnd+len(cmd) > len(data) {
		return loaderPlan{}, errors.New("ipa: loader: insufficient slack")
	}

	firstFile, err := firstFileBacked(data, bo, headerSize, ncmd, cmdEnd, len(data))
	if err != nil {
		return loaderPlan{}, err
	}
	if firstFile <= cmdEnd {
		return loaderPlan{}, errors.New("ipa: loader: load commands collide with the first file-backed section")
	}
	slack := firstFile - cmdEnd
	if slack < len(cmd) {
		return loaderPlan{}, fmt.Errorf("ipa: loader: insufficient slack %d, need %d", slack, len(cmd))
	}
	pad := data[cmdEnd:firstFile]
	if !allZero(pad) {
		return loaderPlan{}, errors.New("ipa: loader: header padding is not zero")
	}
	if err := rejectDuplicateLoader(data, bo, headerSize, ncmd, cmdEnd); err != nil {
		return loaderPlan{}, err
	}

	return loaderPlan{
		ncmd:      ncmd,
		cmdsz:     cmdsz,
		insertAt:  cmdEnd,
		firstFile: firstFile,
		slack:     slack,
		cmd:       cmd,
	}, nil
}

func loaderCommand() []byte {
	name := LoaderPath + "\x00"
	n := dylibCmdHeaderSize + len(name)
	padded := (n + 7) &^ 7
	buf := make([]byte, padded)
	binary.LittleEndian.PutUint32(buf[0:], lcLoadDylib)
	binary.LittleEndian.PutUint32(buf[4:], uint32(padded))
	binary.LittleEndian.PutUint32(buf[8:], dylibCmdHeaderSize)
	binary.LittleEndian.PutUint32(buf[16:], 0x10000)
	binary.LittleEndian.PutUint32(buf[20:], 0x10000)
	copy(buf[dylibCmdHeaderSize:], name)
	return buf
}

func firstFileBacked(data []byte, bo binary.ByteOrder, headerSize int, ncmd uint32, cmdEnd, imageLen int) (int, error) {
	first := imageLen + 1
	found := false
	off := headerSize
	for i := uint32(0); i < ncmd; i++ {
		cmd := bo.Uint32(data[off:])
		sz := bo.Uint32(data[off+4:])
		body := data[off : off+int(sz)]
		if cmd == lcSegment {
			return 0, errors.New("ipa: loader: 32-bit segment in a 64-bit image")
		}
		if cmd == lcSegment64 {
			start, err := segment64FileBounds(body, imageLen)
			if err != nil {
				return 0, err
			}
			for _, v := range start {
				if v > 0 && v < first {
					first = v
					found = true
				}
			}
		}
		off += int(sz)
	}
	if off != cmdEnd {
		return 0, errors.New("ipa: loader: load command sizes do not add up")
	}
	if !found {
		return 0, errors.New("ipa: loader: no file-backed section")
	}
	if first > imageLen {
		return 0, errors.New("ipa: loader: first file-backed offset is past the image")
	}
	return first, nil
}

func segment64FileBounds(body []byte, imageLen int) ([]int, error) {
	if len(body) < segment64HeaderSize {
		return nil, errors.New("ipa: loader: truncated LC_SEGMENT_64")
	}
	nsect := binary.LittleEndian.Uint32(body[64:])
	want := segment64HeaderSize + int(nsect)*section64Size
	if want != len(body) {
		return nil, errors.New("ipa: loader: LC_SEGMENT_64 size does not match nsects")
	}
	var out []int
	// LC_SEGMENT_64: vmaddr 24, vmsize 32, fileoff 40, filesize 48.
	fileoff := binary.LittleEndian.Uint64(body[40:])
	filesize := binary.LittleEndian.Uint64(body[48:])
	if filesize > 0 {
		if err := fileRangeInImage(fileoff, filesize, imageLen); err != nil {
			return nil, err
		}
		if fileoff > 0 {
			out = append(out, int(fileoff))
		}
	}
	for i := uint32(0); i < nsect; i++ {
		sec := body[segment64HeaderSize+int(i)*section64Size:]
		sec = sec[:section64Size]
		secOff := binary.LittleEndian.Uint32(sec[48:])
		secSize := binary.LittleEndian.Uint64(sec[40:])
		flags := binary.LittleEndian.Uint32(sec[64:])
		if sectionZerofill(flags) || secSize == 0 || secOff == 0 {
			continue
		}
		if err := fileRangeInImage(uint64(secOff), secSize, imageLen); err != nil {
			return nil, err
		}
		out = append(out, int(secOff))
	}
	return out, nil
}

func fileRangeInImage(off, size uint64, imageLen int) error {
	if imageLen < 0 {
		return errors.New("ipa: loader: invalid image length")
	}
	end, ok := add64(off, size)
	if !ok || off > uint64(^uint(0)>>1) || end > uint64(^uint(0)>>1) {
		return errors.New("ipa: loader: file range overflows")
	}
	if end > uint64(imageLen) {
		return errors.New("ipa: loader: file range is outside the image")
	}
	return nil
}

func add64(a, b uint64) (uint64, bool) {
	c := a + b
	if c < a {
		return 0, false
	}
	return c, true
}

func sectionZerofill(flags uint32) bool {
	switch flags & 0xff {
	case 0x1, 0xc, 0x12: // S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL
		return true
	default:
		return false
	}
}

func rejectDuplicateLoader(data []byte, bo binary.ByteOrder, headerSize int, ncmd uint32, cmdEnd int) error {
	off := headerSize
	for i := uint32(0); i < ncmd; i++ {
		cmd := bo.Uint32(data[off:])
		sz := bo.Uint32(data[off+4:])
		body := data[off : off+int(sz)]
		if isLoadDylibCmd(cmd) {
			name, err := dylibName(body, bo)
			if err != nil {
				return err
			}
			if name == LoaderPath {
				return fmt.Errorf("ipa: loader: duplicate dependency %q", LoaderPath)
			}
		}
		off += int(sz)
	}
	if off != cmdEnd {
		return errors.New("ipa: loader: load command sizes do not add up")
	}
	return nil
}

func isLoadDylibCmd(cmd uint32) bool {
	switch cmd {
	case lcLoadDylib, lcIdDylib, lcLoadWeakDylib, lcReexportDylib, lcLoadUpwardDylib:
		return true
	default:
		return false
	}
}

func dylibName(body []byte, bo binary.ByteOrder) (string, error) {
	if len(body) < dylibCmdHeaderSize {
		return "", errors.New("ipa: loader: truncated dylib command")
	}
	off := bo.Uint32(body[8:])
	if off < dylibCmdHeaderSize || int(off) >= len(body) {
		return "", errors.New("ipa: loader: invalid dylib name offset")
	}
	name := body[off:]
	n := bytes.IndexByte(name, 0)
	if n < 0 {
		return "", errors.New("ipa: loader: unterminated dylib name")
	}
	s := string(name[:n])
	if strings.ContainsRune(s, 0) {
		return "", errors.New("ipa: loader: invalid dylib name")
	}
	return s, nil
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
