package ipa

import (
	"bytes"
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAddLoaderWrongBaseline(t *testing.T) {
	if _, err := AddLoader([]byte("short")); !errors.Is(err, ErrBaseline) {
		t.Fatalf("short: %v", err)
	}
	zeros := make([]byte, MainSize)
	_, err := AddLoader(zeros)
	if !errors.Is(err, ErrBaseline) {
		t.Fatalf("wrong hash: %v", err)
	}
	if strings.Contains(err.Error(), "loader:") && !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("parsed before hash: %v", err)
	}
}

func TestAddLoaderSynthetic(t *testing.T) {
	src := synthExec(t, synthOpt{firstFile: 0x400})
	before := sha256.Sum256(src)
	plan, err := planLoader(src)
	if err != nil {
		t.Fatal(err)
	}
	if plan.slack != 0x400-32-int(plan.cmdsz) || plan.slack < len(plan.cmd) {
		t.Fatalf("slack %+v", plan)
	}
	out, err := addLoader(src)
	if err != nil {
		t.Fatal(err)
	}
	after := sha256.Sum256(src)
	if after != before {
		t.Fatal("input mutated")
	}
	if len(out) != len(src) {
		t.Fatalf("length %d -> %d", len(src), len(out))
	}
	wantNcmd := binary.LittleEndian.Uint32(src[16:]) + 1
	wantCmdsz := binary.LittleEndian.Uint32(src[20:]) + uint32(len(plan.cmd))
	if binary.LittleEndian.Uint32(out[16:]) != wantNcmd || binary.LittleEndian.Uint32(out[20:]) != wantCmdsz {
		t.Fatalf("header ncmd/cmdsz")
	}
	got := out[plan.insertAt : plan.insertAt+len(plan.cmd)]
	if !bytes.Equal(got, plan.cmd) {
		t.Fatal("inserted command mismatch")
	}
	if !bytes.Contains(got, []byte(LoaderPath+"\x00")) {
		t.Fatal("missing loader path")
	}
	if err := collateralWrites(src, out, [2]int{16, 24}, [2]int{plan.insertAt, plan.insertAt + len(plan.cmd)}); err != nil {
		t.Fatal(err)
	}

	again, err := addLoader(out)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate: %v", err)
	}
	_ = again
}

func TestAddLoaderRejects(t *testing.T) {
	t.Run("insufficient", func(t *testing.T) {
		src := synthExec(t, synthOpt{firstFile: 0x100})
		if _, err := addLoader(src); err == nil || !strings.Contains(err.Error(), "insufficient") && !strings.Contains(err.Error(), "collide") {
			t.Fatalf("insufficient: %v", err)
		}
	})
	t.Run("nonzero", func(t *testing.T) {
		src := synthExec(t, synthOpt{firstFile: 0x400, dirty: 0x20})
		if _, err := addLoader(src); err == nil || !strings.Contains(err.Error(), "not zero") {
			t.Fatalf("nonzero: %v", err)
		}
	})
	t.Run("duplicate", func(t *testing.T) {
		src := synthExec(t, synthOpt{firstFile: 0x400, extraDylib: LoaderPath})
		if _, err := addLoader(src); err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("duplicate: %v", err)
		}
	})
	t.Run("cryptid", func(t *testing.T) {
		src := synthExec(t, synthOpt{firstFile: 0x400, cryptID: 1})
		if _, err := addLoader(src); err == nil || !strings.Contains(err.Error(), "cryptid") {
			t.Fatalf("cryptid: %v", err)
		}
	})
	t.Run("cpu", func(t *testing.T) {
		src := synthExec(t, synthOpt{firstFile: 0x400, cpu: macho.CpuAmd64})
		if _, err := addLoader(src); err == nil || !strings.Contains(err.Error(), "arm64") {
			t.Fatalf("cpu: %v", err)
		}
	})
	t.Run("gap-segment", func(t *testing.T) {
		src := synthExec(t, synthOpt{firstFile: 0x400, gapOff: 0x200, gapSize: 16, gapVM: 0x1000})
		plan, err := planLoader(src)
		if err != nil {
			t.Fatal(err)
		}
		if plan.firstFile != 0x200 {
			t.Fatalf("first file-backed %d, used vmsize or skipped nsects=0 segment", plan.firstFile)
		}
		out, err := addLoader(src)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(src[0x200:0x200+16], out[0x200:0x200+16]) {
			t.Fatal("overwrote reserved gap segment")
		}
		if err := collateralWrites(src, out, [2]int{16, 24}, [2]int{plan.insertAt, plan.insertAt + len(plan.cmd)}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("segment-past-eof", func(t *testing.T) {
		src := synthExec(t, synthOpt{firstFile: 0x400, gapOff: 0x200, gapSize: 0x100000, gapVM: 0x1000})
		if _, err := addLoader(src); err == nil || !strings.Contains(err.Error(), "outside") {
			t.Fatalf("past eof: %v", err)
		}
	})
}

func TestAddLoaderRealBaseline(t *testing.T) {
	path := os.Getenv("RASPBERRY_IOS_MAIN")
	if path == "" {
		t.Skip("set RASPBERRY_IOS_MAIN to the locked main executable")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	orig := append([]byte(nil), data...)
	plan, err := planLoader(data)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("first file-backed offset=%d cmdsz=%d insert=%d slack=%d cmd=%d", plan.firstFile, plan.cmdsz, plan.insertAt, plan.slack, len(plan.cmd))
	out, err := AddLoader(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, orig) {
		t.Fatal("input mutated")
	}
	if err := collateralWrites(orig, out, [2]int{16, 24}, [2]int{plan.insertAt, plan.insertAt + len(plan.cmd)}); err != nil {
		t.Fatal(err)
	}
}

func collateralWrites(orig, out []byte, windows ...[2]int) error {
	if len(orig) != len(out) {
		return fmt.Errorf("length %d -> %d", len(orig), len(out))
	}
	for i := range orig {
		if orig[i] == out[i] {
			continue
		}
		ok := false
		for _, w := range windows {
			if i >= w[0] && i < w[1] {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("collateral write at offset %d", i)
		}
	}
	return nil
}

type synthOpt struct {
	firstFile  int
	extraDylib string
	cryptID    uint32
	cpu        macho.Cpu
	dirty      int
	gapOff     int
	gapSize    int
	gapVM      uint64
}

func synthExec(t *testing.T, opt synthOpt) []byte {
	t.Helper()
	cpu := opt.cpu
	if cpu == 0 {
		cpu = macho.CpuArm64
	}
	bo := binary.LittleEndian

	var cmds []byte
	enc := make([]byte, 24)
	bo.PutUint32(enc[0:], lcEncryptionInfo64)
	bo.PutUint32(enc[4:], 24)
	bo.PutUint32(enc[16:], opt.cryptID)
	cmds = append(cmds, enc...)

	if opt.extraDylib != "" {
		name := opt.extraDylib + "\x00"
		n := dylibCmdHeaderSize + len(name)
		padded := (n + 7) &^ 7
		d := make([]byte, padded)
		bo.PutUint32(d[0:], lcLoadDylib)
		bo.PutUint32(d[4:], uint32(padded))
		bo.PutUint32(d[8:], dylibCmdHeaderSize)
		copy(d[dylibCmdHeaderSize:], name)
		cmds = append(cmds, d...)
	}
	if opt.gapSize != 0 {
		gap := make([]byte, segment64HeaderSize)
		bo.PutUint32(gap[0:], lcSegment64)
		bo.PutUint32(gap[4:], segment64HeaderSize)
		copy(gap[8:], "__GAP")
		vm := opt.gapVM
		if vm == 0 {
			vm = 0x1000
		}
		bo.PutUint64(gap[24:], 0x200000000)
		bo.PutUint64(gap[32:], vm)
		bo.PutUint64(gap[40:], uint64(opt.gapOff))
		bo.PutUint64(gap[48:], uint64(opt.gapSize))
		cmds = append(cmds, gap...)
	}

	segSize := segment64HeaderSize + section64Size
	ncmd := uint32(2)
	if opt.extraDylib != "" {
		ncmd++
	}
	if opt.gapSize != 0 {
		ncmd++
	}
	cmdszWithoutSeg := uint32(len(cmds))
	cmdsz := uint32(segSize) + cmdszWithoutSeg
	headerSize := 32
	cmdEnd := headerSize + int(cmdsz)
	first := opt.firstFile
	if first < cmdEnd {
		// still emit; addLoader must reject
	}
	fileLen := first + 16
	if fileLen < cmdEnd+16 {
		fileLen = cmdEnd + 16
	}

	seg := make([]byte, segSize)
	bo.PutUint32(seg[0:], lcSegment64)
	bo.PutUint32(seg[4:], uint32(segSize))
	copy(seg[8:], "__TEXT")
	bo.PutUint64(seg[24:], 0x100000000)
	bo.PutUint64(seg[32:], 0x4000)
	bo.PutUint64(seg[40:], 0)
	bo.PutUint64(seg[48:], uint64(fileLen))
	bo.PutUint32(seg[56:], 7)
	bo.PutUint32(seg[60:], 5)
	bo.PutUint32(seg[64:], 1)
	sec := seg[segment64HeaderSize:]
	copy(sec[0:], "__text")
	copy(sec[16:], "__TEXT")
	bo.PutUint64(sec[32:], 0x100000000+uint64(first))
	bo.PutUint64(sec[40:], 16)
	bo.PutUint32(sec[48:], uint32(first))
	bo.PutUint32(sec[52:], 4)

	hdr := make([]byte, 32)
	bo.PutUint32(hdr[0:], macho.Magic64)
	bo.PutUint32(hdr[4:], uint32(cpu))
	bo.PutUint32(hdr[12:], uint32(macho.TypeExec))
	bo.PutUint32(hdr[16:], ncmd)
	bo.PutUint32(hdr[20:], cmdsz)

	out := make([]byte, fileLen)
	copy(out, hdr)
	copy(out[32:], seg)
	copy(out[32+segSize:], cmds)
	if opt.dirty > 0 {
		pos := cmdEnd + opt.dirty
		if pos < first && pos < len(out) {
			out[pos] = 0xff
		}
	}
	copy(out[first:], []byte("SECTDATA________")[:16])
	return out
}

func TestLoaderCommandSize(t *testing.T) {
	cmd := loaderCommand()
	const (
		wantLC     = uint32(0xc) // LC_LOAD_DYLIB
		wantSize   = 72
		wantNameAt = 24
		wantVer    = uint32(0x10000) // 1.0.0
	)
	if len(cmd) != wantSize {
		t.Fatalf("len %d, want %d", len(cmd), wantSize)
	}
	if binary.LittleEndian.Uint32(cmd[0:]) != wantLC {
		t.Fatalf("cmd 0x%x, want LC_LOAD_DYLIB 0xc", binary.LittleEndian.Uint32(cmd[0:]))
	}
	if binary.LittleEndian.Uint32(cmd[4:]) != wantSize {
		t.Fatalf("cmdsize %d, want %d", binary.LittleEndian.Uint32(cmd[4:]), wantSize)
	}
	if binary.LittleEndian.Uint32(cmd[8:]) != wantNameAt {
		t.Fatalf("name offset %d, want %d", binary.LittleEndian.Uint32(cmd[8:]), wantNameAt)
	}
	if binary.LittleEndian.Uint32(cmd[12:]) != 0 {
		t.Fatalf("timestamp %d, want 0", binary.LittleEndian.Uint32(cmd[12:]))
	}
	if binary.LittleEndian.Uint32(cmd[16:]) != wantVer || binary.LittleEndian.Uint32(cmd[20:]) != wantVer {
		t.Fatalf("versions current=0x%x compat=0x%x, want 0x10000", binary.LittleEndian.Uint32(cmd[16:]), binary.LittleEndian.Uint32(cmd[20:]))
	}
	wantName := []byte(LoaderPath + "\x00")
	if 24+len(wantName) > wantSize {
		t.Fatalf("path %q does not fit in %d", LoaderPath, wantSize)
	}
	if !bytes.Equal(cmd[24:24+len(wantName)], wantName) {
		t.Fatalf("name bytes %q", cmd[24:24+len(wantName)])
	}
	for i, b := range cmd[24+len(wantName):] {
		if b != 0 {
			t.Fatalf("padding at %d = %d", 24+len(wantName)+i, b)
		}
	}
}

func TestBuiltLoaderID(t *testing.T) {
	path := os.Getenv("RASPBERRY_IOS_DYLIB")
	if path == "" {
		path = filepath.Join("..", "..", "build", "ios", "libraspberry.dylib")
	}
	f, err := macho.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skip("dylib not built")
		}
		t.Fatal(err)
	}
	defer f.Close()
	var found bool
	for _, l := range f.Loads {
		raw := l.Raw()
		if len(raw) < dylibCmdHeaderSize || binary.LittleEndian.Uint32(raw) != lcIdDylib {
			continue
		}
		found = true
		name, err := dylibName(raw, binary.LittleEndian)
		if err != nil {
			t.Fatal(err)
		}
		if name != "@rpath/libraspberry.dylib" {
			t.Fatalf("id name %q", name)
		}
		cur := binary.LittleEndian.Uint32(raw[16:])
		compat := binary.LittleEndian.Uint32(raw[20:])
		if cur != 0x10000 || compat != 0x10000 {
			t.Fatalf("id versions current=0x%x compat=0x%x", cur, compat)
		}
	}
	if !found {
		t.Fatal("missing LC_ID_DYLIB")
	}
}
