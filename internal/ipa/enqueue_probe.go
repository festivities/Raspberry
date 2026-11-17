package ipa

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

const (
	enqueueProbeTargetRVA     = uint64(0x17aa618)
	enqueueProbeThunkRVA      = uint64(0x3000)
	enqueueProbeTrampolineRVA = uint64(0x3100)
	enqueueProbeLiteralRVA    = uint64(0x30c0)
	enqueueProbeMetadataRVA   = uint64(0x3200)
	enqueueProbeDlsymStubRVA  = uint64(0x1ac1748)

	enqueueProbeHeaderEnd     = uint64(0x20a0)
	enqueueProbeFirstSection  = uint64(0x555c)
	enqueueProbeTextVMAddr    = uint64(0x100000000)
	enqueueProbeTextVMSize    = uint64(0x1d38000)
	enqueueProbeDataVMAddr    = uint64(0x101d38000)
	enqueueProbeDataVMSize    = uint64(0xc94000)
	enqueueProbeDataFileOff   = uint64(0x1d38000)
	enqueueProbeDataFileSize  = uint64(0x4e8000)
	enqueueProbeLinkVMAddr    = uint64(0x1029cc000)
	enqueueProbeLinkVMSize    = uint64(0x4f4000)
	enqueueProbeLinkFileOff   = uint64(0x2220000)
	enqueueProbeLinkFileSize  = uint64(0x4f24c0)
	enqueueProbeSignatureOff  = uint64(0x2615c60)
	enqueueProbeSignatureSize = uint64(0xfc860)

	enqueueProbeOriginalEntryWord = uint32(0xa9bd57f6)
	enqueueProbeMetadataSize      = 64
	enqueueProbeVersion           = 1

	lcCodeSignature = 0x1d

	sectionSymbolStubs = 0x8
)

const enqueueProbeHookName = "raspberry_ios_enqueue_probe_v1"

var enqueueProbeMetadataMagic = [8]byte{'R', 'B', 'E', 'N', 'Q', 'P', 'V', '1'}

type enqueueProbeRange struct {
	name       string
	start, end uint64
}

type enqueueProbeSegment struct {
	name                              string
	vmaddr, vmsize, fileoff, filesize uint64
	maxprot, initprot, nsects         uint32
}

type enqueueProbeSection struct {
	name, segment               string
	addr, size, fileoff         uint64
	flags, reserved1, reserved2 uint32
}

// AddEnqueueProbe returns a copy of the locked executable with the existing
// loader dependency and a fixed, diagnostic-only enqueue passthrough probe.
// The returned bytes are unsigned and are not an installable artifact.
func AddEnqueueProbe(data []byte) ([]byte, error) {
	withLoader, err := AddLoader(data)
	if err != nil {
		return nil, err
	}
	return addEnqueueProbe(withLoader)
}

// addEnqueueProbe is the fixed-layout transform after AddLoader. It is kept
// unexported so there is no caller-controlled RVA/version surface.
func addEnqueueProbe(data []byte) ([]byte, error) {
	layout, err := validateEnqueueProbeLayout(data)
	if err != nil {
		return nil, err
	}
	words, entryBranch, trampolineBranch, err := enqueueProbeWords()
	if err != nil {
		return nil, err
	}
	literal := append([]byte(enqueueProbeHookName), 0)
	metadata := enqueueProbeMetadata(entryBranch, trampolineBranch, words)
	ranges := []enqueueProbeRange{
		{name: "resolver thunk", start: enqueueProbeThunkRVA, end: enqueueProbeThunkRVA + uint64(len(words))*4},
		{name: "trampoline", start: enqueueProbeTrampolineRVA, end: enqueueProbeTrampolineRVA + 8},
		{name: "hook literal", start: enqueueProbeLiteralRVA, end: enqueueProbeLiteralRVA + uint64(len(literal))},
		{name: "metadata", start: enqueueProbeMetadataRVA, end: enqueueProbeMetadataRVA + uint64(len(metadata))},
	}
	if err := validateEnqueueProbeRanges(ranges, layout.headerEnd, layout.firstSection, uint64(len(data))); err != nil {
		return nil, err
	}
	for _, r := range ranges {
		if !allZero(data[r.start:r.end]) {
			return nil, fmt.Errorf("ipa: enqueue probe: reserved %s bytes are not zero", r.name)
		}
	}
	if layout.targetWord != enqueueProbeOriginalEntryWord {
		return nil, fmt.Errorf("ipa: enqueue probe: target first word mismatch")
	}

	out := append([]byte(nil), data...)
	for i, word := range words {
		binary.LittleEndian.PutUint32(out[enqueueProbeThunkRVA+uint64(i*4):], word)
	}
	binary.LittleEndian.PutUint32(out[enqueueProbeTrampolineRVA:], enqueueProbeOriginalEntryWord)
	binary.LittleEndian.PutUint32(out[enqueueProbeTrampolineRVA+4:], trampolineBranch)
	copy(out[enqueueProbeLiteralRVA:], literal)
	copy(out[enqueueProbeMetadataRVA:], metadata)
	binary.LittleEndian.PutUint32(out[enqueueProbeTargetRVA:], entryBranch)
	return out, nil
}

type enqueueProbeLayout struct {
	headerEnd, firstSection uint64
	targetWord              uint32
}

func validateEnqueueProbeLayout(data []byte) (enqueueProbeLayout, error) {
	if int64(len(data)) != MainSize {
		return enqueueProbeLayout{}, fmt.Errorf("ipa: enqueue probe: unexpected main size %d", len(data))
	}
	m, err := parseMachO(data)
	if err != nil {
		return enqueueProbeLayout{}, err
	}
	if m.Magic != "64-bit little-endian" || m.CPU != "arm64" || m.FileType != "executable" {
		return enqueueProbeLayout{}, errors.New("ipa: enqueue probe: need locked thin arm64 MH_EXECUTE")
	}
	if m.CryptID == nil || *m.CryptID != 0 {
		return enqueueProbeLayout{}, errors.New("ipa: enqueue probe: main executable is not decrypted")
	}

	bo := binary.LittleEndian
	ncmd := bo.Uint32(data[16:])
	cmdsz := bo.Uint32(data[20:])
	if ncmd != 77 || cmdsz != 8320 {
		return enqueueProbeLayout{}, fmt.Errorf("ipa: enqueue probe: loader header mismatch ncmds=%d sizeofcmds=%d", ncmd, cmdsz)
	}
	cmdEnd := uint64(32) + uint64(cmdsz)
	if cmdEnd != enqueueProbeHeaderEnd {
		return enqueueProbeLayout{}, errors.New("ipa: enqueue probe: load-command end mismatch")
	}
	firstFile, err := firstFileBacked(data, bo, 32, ncmd, int(cmdEnd), len(data))
	if err != nil {
		return enqueueProbeLayout{}, err
	}
	if uint64(firstFile) != enqueueProbeFirstSection {
		return enqueueProbeLayout{}, fmt.Errorf("ipa: enqueue probe: first file-backed section mismatch 0x%x", firstFile)
	}
	if firstFile <= int(cmdEnd) || !allZero(data[cmdEnd:uint64(firstFile)]) {
		return enqueueProbeLayout{}, errors.New("ipa: enqueue probe: post-loader header padding is not zero")
	}

	segments, sections, loaderCount, sigCount, sigOff, sigSize, cryptCount, err := readEnqueueProbeCommands(data, ncmd, cmdsz)
	if err != nil {
		return enqueueProbeLayout{}, err
	}
	if loaderCount != 1 {
		return enqueueProbeLayout{}, errors.New("ipa: enqueue probe: expected exactly one loader dependency")
	}
	if sigCount != 1 || sigOff != enqueueProbeSignatureOff || sigSize != enqueueProbeSignatureSize ||
		sigOff+sigSize != uint64(len(data)) {
		return enqueueProbeLayout{}, errors.New("ipa: enqueue probe: code-signature layout mismatch")
	}
	if cryptCount != 1 {
		return enqueueProbeLayout{}, errors.New("ipa: enqueue probe: expected one encryption command")
	}
	if err := validateEnqueueProbeSegments(segments, sections, len(data)); err != nil {
		return enqueueProbeLayout{}, err
	}
	if err := validateEnqueueProbeDlsym(data); err != nil {
		return enqueueProbeLayout{}, err
	}
	if enqueueProbeTargetRVA+4 > uint64(len(data)) {
		return enqueueProbeLayout{}, errors.New("ipa: enqueue probe: target window is outside the file")
	}
	if enqueueProbeTargetRVA+4 > enqueueProbeTextVMSize {
		return enqueueProbeLayout{}, errors.New("ipa: enqueue probe: target is outside __TEXT")
	}
	return enqueueProbeLayout{
		headerEnd:    cmdEnd,
		firstSection: uint64(firstFile),
		targetWord:   bo.Uint32(data[enqueueProbeTargetRVA:]),
	}, nil
}

func readEnqueueProbeCommands(data []byte, ncmd, cmdsz uint32) ([]enqueueProbeSegment, []enqueueProbeSection, int, int, uint64, uint64, int, error) {
	bo := binary.LittleEndian
	off := uint64(32)
	end := off + uint64(cmdsz)
	var segments []enqueueProbeSegment
	var sections []enqueueProbeSection
	loaderCount, sigCount, cryptCount := 0, 0, 0
	var sigOff, sigSize uint64
	for i := uint32(0); i < ncmd; i++ {
		if off+8 > end {
			return nil, nil, 0, 0, 0, 0, 0, errors.New("ipa: enqueue probe: truncated load command")
		}
		cmd := bo.Uint32(data[off:])
		sz := bo.Uint32(data[off+4:])
		if sz < 8 || uint64(sz) > end-off {
			return nil, nil, 0, 0, 0, 0, 0, errors.New("ipa: enqueue probe: invalid load-command size")
		}
		raw := data[off : off+uint64(sz)]
		switch cmd {
		case lcSegment64:
			if len(raw) < segment64HeaderSize {
				return nil, nil, 0, 0, 0, 0, 0, errors.New("ipa: enqueue probe: truncated segment")
			}
			nsect := bo.Uint32(raw[64:])
			if uint64(segment64HeaderSize)+uint64(nsect)*section64Size != uint64(len(raw)) {
				return nil, nil, 0, 0, 0, 0, 0, errors.New("ipa: enqueue probe: segment section count mismatch")
			}
			seg := enqueueProbeSegment{
				name:     fixedMachCString(raw[8:24]),
				vmaddr:   bo.Uint64(raw[24:]),
				vmsize:   bo.Uint64(raw[32:]),
				fileoff:  bo.Uint64(raw[40:]),
				filesize: bo.Uint64(raw[48:]),
				maxprot:  bo.Uint32(raw[56:]),
				initprot: bo.Uint32(raw[60:]),
				nsects:   nsect,
			}
			segments = append(segments, seg)
			for j := uint32(0); j < nsect; j++ {
				p := segment64HeaderSize + int(j)*section64Size
				sec := raw[p : p+section64Size]
				sections = append(sections, enqueueProbeSection{
					name:      fixedMachCString(sec[:16]),
					segment:   fixedMachCString(sec[16:32]),
					addr:      bo.Uint64(sec[32:]),
					size:      bo.Uint64(sec[40:]),
					fileoff:   uint64(bo.Uint32(sec[48:])),
					flags:     bo.Uint32(sec[64:]),
					reserved1: bo.Uint32(sec[68:]),
					reserved2: bo.Uint32(sec[72:]),
				})
			}
		case lcSegment:
			return nil, nil, 0, 0, 0, 0, 0, errors.New("ipa: enqueue probe: 32-bit segment in arm64 image")
		case lcLoadDylib:
			name, err := dylibName(raw, bo)
			if err != nil {
				return nil, nil, 0, 0, 0, 0, 0, err
			}
			if name == LoaderPath {
				loaderCount++
			}
		case lcCodeSignature:
			if len(raw) < 16 {
				return nil, nil, 0, 0, 0, 0, 0, errors.New("ipa: enqueue probe: truncated code-signature command")
			}
			sigCount++
			sigOff = uint64(bo.Uint32(raw[8:]))
			sigSize = uint64(bo.Uint32(raw[12:]))
		case lcEncryptionInfo64:
			if len(raw) < 24 || bo.Uint32(raw[16:]) != 0 {
				return nil, nil, 0, 0, 0, 0, 0, errors.New("ipa: enqueue probe: invalid encryption command")
			}
			cryptCount++
		}
		off += uint64(sz)
	}
	if off != end {
		return nil, nil, 0, 0, 0, 0, 0, errors.New("ipa: enqueue probe: load-command sizes do not add up")
	}
	return segments, sections, loaderCount, sigCount, sigOff, sigSize, cryptCount, nil
}

func validateEnqueueProbeSegments(segments []enqueueProbeSegment, sections []enqueueProbeSection, imageSize int) error {
	want := map[string]enqueueProbeSegment{
		"__PAGEZERO": {name: "__PAGEZERO", vmaddr: 0, vmsize: 0x100000000, fileoff: 0, filesize: 0, maxprot: 0, initprot: 0, nsects: 0},
		"__TEXT":     {name: "__TEXT", vmaddr: enqueueProbeTextVMAddr, vmsize: enqueueProbeTextVMSize, fileoff: 0, filesize: enqueueProbeTextVMSize, maxprot: 5, initprot: 5, nsects: 13},
		"__DATA":     {name: "__DATA", vmaddr: enqueueProbeDataVMAddr, vmsize: enqueueProbeDataVMSize, fileoff: enqueueProbeDataFileOff, filesize: enqueueProbeDataFileSize, maxprot: 3, initprot: 3, nsects: 21},
		"__LINKEDIT": {name: "__LINKEDIT", vmaddr: enqueueProbeLinkVMAddr, vmsize: enqueueProbeLinkVMSize, fileoff: enqueueProbeLinkFileOff, filesize: enqueueProbeLinkFileSize, maxprot: 1, initprot: 1, nsects: 0},
	}
	if len(segments) != len(want) {
		return fmt.Errorf("ipa: enqueue probe: segment count mismatch: %d", len(segments))
	}
	seen := make(map[string]bool, len(segments))
	for _, seg := range segments {
		expected, ok := want[seg.name]
		if !ok || seen[seg.name] {
			return fmt.Errorf("ipa: enqueue probe: unexpected or duplicate segment %q", seg.name)
		}
		seen[seg.name] = true
		if seg.vmaddr%0x4000 != 0 || seg.vmsize%0x4000 != 0 {
			return fmt.Errorf("ipa: enqueue probe: segment %s is not 16-KiB VM aligned", seg.name)
		}
		if seg != expected {
			return fmt.Errorf("ipa: enqueue probe: segment %s layout mismatch", seg.name)
		}
		if seg.initprot&3 == 3 && seg.initprot&4 != 0 {
			return fmt.Errorf("ipa: enqueue probe: writable-executable segment %s", seg.name)
		}
		if seg.filesize > 0 {
			end, ok := add64(seg.fileoff, seg.filesize)
			if !ok || end > uint64(imageSize) {
				return fmt.Errorf("ipa: enqueue probe: segment %s file bounds invalid", seg.name)
			}
		}
	}
	for name := range want {
		if !seen[name] {
			return fmt.Errorf("ipa: enqueue probe: missing segment %s", name)
		}
	}

	var textFound, stubsFound bool
	for _, sec := range sections {
		if sec.segment != "__TEXT" {
			continue
		}
		switch sec.name {
		case "__text":
			textFound = sec.addr == enqueueProbeTextVMAddr+enqueueProbeFirstSection &&
				sec.fileoff == enqueueProbeFirstSection && sec.size > 0
		case "__stubs":
			stubsFound = sec.addr == enqueueProbeTextVMAddr+0x1abee50 &&
				sec.fileoff == 0x1abee50 && sec.size == 0x3ba0 &&
				sec.flags&0xff == sectionSymbolStubs && sec.reserved2 == 12
		}
	}
	if !textFound {
		return errors.New("ipa: enqueue probe: __TEXT,__text layout mismatch")
	}
	if !stubsFound {
		return errors.New("ipa: enqueue probe: __TEXT,__stubs layout mismatch")
	}
	return nil
}

func validateEnqueueProbeDlsym(data []byte) error {
	file, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("ipa: enqueue probe: parse imports: %w", err)
	}
	imports, err := file.ImportedSymbols()
	if err != nil {
		return fmt.Errorf("ipa: enqueue probe: read imports: %w", err)
	}
	hasDlsym := false
	for _, name := range imports {
		if name == "_dlsym" {
			hasDlsym = true
			break
		}
	}
	if !hasDlsym || file.Symtab == nil || file.Dysymtab == nil {
		return errors.New("ipa: enqueue probe: _dlsym import metadata missing")
	}

	bo := binary.LittleEndian
	off := uint64(32)
	end := off + uint64(file.Cmdsz)
	matches := 0
	for i := uint32(0); i < file.Ncmd; i++ {
		rawHeader := data[off : off+8]
		cmd := bo.Uint32(rawHeader)
		sz := bo.Uint32(rawHeader[4:])
		raw := data[off : off+uint64(sz)]
		if cmd == lcSegment64 {
			nsect := bo.Uint32(raw[64:])
			for j := uint32(0); j < nsect; j++ {
				p := segment64HeaderSize + int(j)*section64Size
				sec := raw[p : p+section64Size]
				if fixedMachCString(sec[:16]) != "__stubs" || fixedMachCString(sec[16:32]) != "__TEXT" {
					continue
				}
				secAddr := bo.Uint64(sec[32:])
				secSize := bo.Uint64(sec[40:])
				secOff := uint64(bo.Uint32(sec[48:]))
				flags := bo.Uint32(sec[64:])
				firstIndirect := bo.Uint32(sec[68:])
				stubSize := bo.Uint32(sec[72:])
				if flags&0xff != sectionSymbolStubs || stubSize == 0 || secSize%uint64(stubSize) != 0 {
					return errors.New("ipa: enqueue probe: malformed __stubs indirect table")
				}
				for stub := uint64(0); stub < secSize/uint64(stubSize); stub++ {
					indirectIndex := uint64(firstIndirect) + stub
					if indirectIndex >= uint64(len(file.Dysymtab.IndirectSyms)) {
						return errors.New("ipa: enqueue probe: __stubs indirect index out of bounds")
					}
					symbolIndex := file.Dysymtab.IndirectSyms[indirectIndex]
					if symbolIndex&0xc0000000 != 0 {
						continue
					}
					if symbolIndex >= uint32(len(file.Symtab.Syms)) {
						return errors.New("ipa: enqueue probe: __stubs symbol index out of bounds")
					}
					if file.Symtab.Syms[symbolIndex].Name != "_dlsym" {
						continue
					}
					rva := secAddr + stub*uint64(stubSize) - enqueueProbeTextVMAddr
					fileoff := secOff + stub*uint64(stubSize)
					if rva != enqueueProbeDlsymStubRVA || fileoff != enqueueProbeDlsymStubRVA || stubSize != 12 {
						return errors.New("ipa: enqueue probe: _dlsym stub location mismatch")
					}
					matches++
				}
			}
		}
		off += uint64(sz)
	}
	if off != end || matches != 1 {
		return errors.New("ipa: enqueue probe: expected one verified _dlsym stub")
	}
	return nil
}

func fixedMachCString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func enqueueProbeWords() ([]uint32, uint32, uint32, error) {
	entryBranch, err := encodeArm64Branch(enqueueProbeTargetRVA, enqueueProbeThunkRVA, false)
	if err != nil {
		return nil, 0, 0, err
	}
	trampolineBranch, err := encodeArm64Branch(enqueueProbeTrampolineRVA+4, enqueueProbeTargetRVA+4, false)
	if err != nil {
		return nil, 0, 0, err
	}
	callDlsym, err := encodeArm64Branch(enqueueProbeThunkRVA+9*4, enqueueProbeDlsymStubRVA, true)
	if err != nil {
		return nil, 0, 0, err
	}
	hookLiteral, err := encodeArm64ADR(enqueueProbeThunkRVA+8*4, enqueueProbeLiteralRVA, 1)
	if err != nil {
		return nil, 0, 0, err
	}
	cbnzResolve, err := encodeArm64CBNZ(enqueueProbeThunkRVA+11*4, enqueueProbeThunkRVA+13*4, 16)
	if err != nil {
		return nil, 0, 0, err
	}
	words := []uint32{
		0xd10183ff,  // sub sp, sp, #96
		0xa90007e0,  // stp x0, x1, [sp]
		0xa9010fe2,  // stp x2, x3, [sp, #16]
		0xa90217e4,  // stp x4, x5, [sp, #32]
		0xa9031fe6,  // stp x6, x7, [sp, #48]
		0xa90477e8,  // stp x8, x29, [sp, #64]
		0xf9002bfe,  // str x30, [sp, #80]
		0x92800020,  // movn x0, #1 (RTLD_DEFAULT == (void *)-2)
		hookLiteral, // adr x1, hook-name literal
		callDlsym,   // bl main-image _dlsym stub
		0xaa0003f0,  // mov x16, x0
		cbnzResolve, // cbnz x16, restore
		0xd4200000,  // brk #0 (fail closed if dlsym returned NULL)
		0xa94007e0,  // ldp x0, x1, [sp]
		0xa9410fe2,  // ldp x2, x3, [sp, #16]
		0xa94217e4,  // ldp x4, x5, [sp, #32]
		0xa9431fe6,  // ldp x6, x7, [sp, #48]
		0xa94477e8,  // ldp x8, x29, [sp, #64]
		0xf9402bfe,  // ldr x30, [sp, #80]
		0x910183ff,  // add sp, sp, #96
		0xd61f0200,  // br x16 (tail branch; no wrapper return frame)
	}
	return words, entryBranch, trampolineBranch, nil
}

func enqueueProbeMetadata(entryBranch, trampolineBranch uint32, words []uint32) []byte {
	buf := make([]byte, enqueueProbeMetadataSize)
	copy(buf, enqueueProbeMetadataMagic[:])
	fields := []uint32{
		enqueueProbeVersion,
		enqueueProbeMetadataSize,
		uint32(enqueueProbeTargetRVA),
		enqueueProbeOriginalEntryWord,
		entryBranch,
		uint32(enqueueProbeThunkRVA),
		uint32(len(words) * 4),
		uint32(enqueueProbeTrampolineRVA),
		8,
		uint32(enqueueProbeLiteralRVA),
		uint32(len(enqueueProbeHookName) + 1),
		uint32(enqueueProbeDlsymStubRVA),
		words[9],
		trampolineBranch,
	}
	for i, field := range fields {
		binary.LittleEndian.PutUint32(buf[8+i*4:], field)
	}
	return buf
}

func validateEnqueueProbeRanges(ranges []enqueueProbeRange, gapStart, gapEnd, fileSize uint64) error {
	for i, r := range ranges {
		if r.start%4 != 0 && r.name != "hook literal" {
			return fmt.Errorf("ipa: enqueue probe: %s is not instruction-aligned", r.name)
		}
		if r.start < gapStart || r.end <= r.start || r.end > gapEnd || r.end > fileSize {
			return fmt.Errorf("ipa: enqueue probe: %s is outside verified RX header padding", r.name)
		}
		for _, other := range ranges[:i] {
			if r.start < other.end && other.start < r.end {
				return fmt.Errorf("ipa: enqueue probe: %s overlaps %s", r.name, other.name)
			}
		}
	}
	return nil
}

func encodeArm64Branch(pc, target uint64, link bool) (uint32, error) {
	if pc&3 != 0 || target&3 != 0 {
		return 0, errors.New("ipa: enqueue probe: ARM64 branch address is not 4-byte aligned")
	}
	if pc > math.MaxInt64 || target > math.MaxInt64 {
		return 0, errors.New("ipa: enqueue probe: ARM64 branch address overflows")
	}
	delta := int64(target) - int64(pc)
	if delta < -(1<<27) || delta > (1<<27)-4 {
		return 0, errors.New("ipa: enqueue probe: ARM64 branch target is out of signed range")
	}
	imm26 := uint32(delta>>2) & 0x03ffffff
	op := uint32(0x14000000)
	if link {
		op = 0x94000000
	}
	return op | imm26, nil
}

func encodeArm64ADR(pc, target uint64, rd uint32) (uint32, error) {
	if pc > math.MaxInt64 || target > math.MaxInt64 || rd > 31 {
		return 0, errors.New("ipa: enqueue probe: invalid ARM64 ADR operands")
	}
	delta := int64(target) - int64(pc)
	if delta < -(1<<20) || delta > (1<<20)-1 {
		return 0, errors.New("ipa: enqueue probe: ARM64 ADR target is out of signed range")
	}
	imm := uint32(delta) & 0x1fffff
	immlo := (imm & 0x3) << 29
	immhi := ((imm >> 2) & 0x7ffff) << 5
	return 0x10000000 | immlo | immhi | rd, nil
}

func encodeArm64CBNZ(pc, target uint64, rt uint32) (uint32, error) {
	if pc&3 != 0 || target&3 != 0 || rt > 31 || pc > math.MaxInt64 || target > math.MaxInt64 {
		return 0, errors.New("ipa: enqueue probe: invalid ARM64 CBNZ operands")
	}
	delta := int64(target) - int64(pc)
	if delta < -(1<<20) || delta > (1<<20)-4 {
		return 0, errors.New("ipa: enqueue probe: ARM64 CBNZ target is out of signed range")
	}
	imm19 := uint32(delta>>2) & 0x7ffff
	return 0xb5000000 | (imm19 << 5) | rt, nil
}
