package ipa

import (
	"bytes"
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

const (
	testLCSymtab       = 0x2
	testLCDysymtab     = 0xb
	testLCRPath        = 0x8000001c
	testLCCodeSign     = 0x1d
	testLCEncryption64 = 0x2c

	testIndirectLocal = 0x80000000
	testDlsymIndex    = 874
	testStubCount     = 1272
)

func TestAddEnqueueProbeWrongBaseline(t *testing.T) {
	if _, err := AddEnqueueProbe([]byte("short")); !errors.Is(err, ErrBaseline) {
		t.Fatalf("short input: %v", err)
	}
}

func TestAddEnqueueProbeSynthetic(t *testing.T) {
	src := syntheticEnqueueImage(t, syntheticEnqueueOptions{})
	before := sha256.Sum256(src)
	words, entryBranch, trampolineBranch, err := enqueueProbeWords()
	if err != nil {
		t.Fatal(err)
	}
	out, err := addEnqueueProbe(src)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(src) != before {
		t.Fatal("input mutated")
	}
	if len(out) != len(src) {
		t.Fatalf("length %d -> %d", len(src), len(out))
	}
	if got := binary.LittleEndian.Uint32(out[enqueueProbeTargetRVA:]); got != entryBranch {
		t.Fatalf("entry branch %#08x, want %#08x", got, entryBranch)
	}
	for i, want := range words {
		if got := binary.LittleEndian.Uint32(out[enqueueProbeThunkRVA+uint64(i*4):]); got != want {
			t.Fatalf("thunk word %d = %#08x, want %#08x", i, got, want)
		}
	}
	if got := binary.LittleEndian.Uint32(out[enqueueProbeTrampolineRVA:]); got != enqueueProbeOriginalEntryWord {
		t.Fatalf("trampoline first word %#08x", got)
	}
	if got := binary.LittleEndian.Uint32(out[enqueueProbeTrampolineRVA+4:]); got != trampolineBranch {
		t.Fatalf("trampoline branch %#08x, want %#08x", got, trampolineBranch)
	}
	if got := out[enqueueProbeLiteralRVA : enqueueProbeLiteralRVA+uint64(len(enqueueProbeHookName)+1)]; !bytes.Equal(got, []byte(enqueueProbeHookName+"\x00")) {
		t.Fatalf("hook literal %q", got)
	}
	wantMetadata := enqueueProbeMetadata(entryBranch, trampolineBranch, words)
	if got := out[enqueueProbeMetadataRVA : enqueueProbeMetadataRVA+enqueueProbeMetadataSize]; !bytes.Equal(got, wantMetadata) {
		t.Fatal("metadata mismatch")
	}

	if err := collateralWrites(src, out,
		[2]int{int(enqueueProbeTargetRVA), int(enqueueProbeTargetRVA + 4)},
		[2]int{int(enqueueProbeThunkRVA), int(enqueueProbeThunkRVA + uint64(len(words))*4)},
		[2]int{int(enqueueProbeTrampolineRVA), int(enqueueProbeTrampolineRVA + 8)},
		[2]int{int(enqueueProbeLiteralRVA), int(enqueueProbeLiteralRVA + uint64(len(enqueueProbeHookName)+1))},
		[2]int{int(enqueueProbeMetadataRVA), int(enqueueProbeMetadataRVA + enqueueProbeMetadataSize)},
	); err != nil {
		t.Fatal(err)
	}
	if err := validateEnqueueProbeSegmentsForTest(out); err != nil {
		t.Fatalf("patched segment layout: %v", err)
	}
	if _, err := addEnqueueProbe(out); err == nil || !strings.Contains(err.Error(), "not zero") {
		t.Fatalf("repeated patch: %v", err)
	}
	again, err := addEnqueueProbe(src)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, again) {
		t.Fatal("transform is not deterministic")
	}
}

func TestAddEnqueueProbeSyntheticRejectsBadLayout(t *testing.T) {
	src := syntheticEnqueueImage(t, syntheticEnqueueOptions{})
	t.Run("target-word", func(t *testing.T) {
		old := binary.LittleEndian.Uint32(src[enqueueProbeTargetRVA:])
		binary.LittleEndian.PutUint32(src[enqueueProbeTargetRVA:], old^1)
		defer binary.LittleEndian.PutUint32(src[enqueueProbeTargetRVA:], old)
		if _, err := addEnqueueProbe(src); err == nil || !strings.Contains(err.Error(), "target first word") {
			t.Fatalf("target mismatch: %v", err)
		}
	})
	t.Run("dirty-reserved-range", func(t *testing.T) {
		old := src[enqueueProbeThunkRVA]
		src[enqueueProbeThunkRVA] = 1
		defer func() { src[enqueueProbeThunkRVA] = old }()
		if _, err := addEnqueueProbe(src); err == nil || !strings.Contains(err.Error(), "padding is not zero") {
			t.Fatalf("dirty header padding: %v", err)
		}
	})
	t.Run("bad-dlsym-mapping", func(t *testing.T) {
		old := binary.LittleEndian.Uint32(src[syntheticIndirectOffset()+testDlsymIndex*4:])
		binary.LittleEndian.PutUint32(src[syntheticIndirectOffset()+testDlsymIndex*4:], testIndirectLocal)
		defer binary.LittleEndian.PutUint32(src[syntheticIndirectOffset()+testDlsymIndex*4:], old)
		if _, err := addEnqueueProbe(src); err == nil || !strings.Contains(err.Error(), "_dlsym stub") {
			t.Fatalf("bad _dlsym mapping: %v", err)
		}
	})
	t.Run("writable-executable-text", func(t *testing.T) {
		off := syntheticTextSegmentProtectionOffset()
		old := binary.LittleEndian.Uint32(src[off:])
		binary.LittleEndian.PutUint32(src[off:], 7)
		defer binary.LittleEndian.PutUint32(src[off:], old)
		if _, err := addEnqueueProbe(src); err == nil || !strings.Contains(err.Error(), "segment __TEXT layout") {
			t.Fatalf("RWX segment: %v", err)
		}
	})
	t.Run("wrong-first-section", func(t *testing.T) {
		off := syntheticTextSectionOffset()
		old := binary.LittleEndian.Uint32(src[off+48:])
		binary.LittleEndian.PutUint32(src[off+48:], uint32(enqueueProbeFirstSection+4))
		defer binary.LittleEndian.PutUint32(src[off+48:], old)
		if _, err := addEnqueueProbe(src); err == nil || !strings.Contains(err.Error(), "first file-backed section") {
			t.Fatalf("first section changed: %v", err)
		}
	})
}

func TestEnqueueProbeFixedRanges(t *testing.T) {
	valid := []enqueueProbeRange{
		{name: "thunk", start: 0x3000, end: 0x3054},
		{name: "literal", start: 0x30c0, end: enqueueProbeLiteralRVA + uint64(len(enqueueProbeHookName)+1)},
		{name: "trampoline", start: 0x3100, end: 0x3108},
		{name: "metadata", start: 0x3200, end: 0x3240},
	}
	if err := validateEnqueueProbeRanges(valid, 0x20a0, 0x555c, uint64(MainSize)); err != nil {
		t.Fatalf("valid ranges: %v", err)
	}
	cases := []struct {
		name   string
		ranges []enqueueProbeRange
	}{
		{
			name: "before-gap",
			ranges: []enqueueProbeRange{
				{name: "thunk", start: 0x209c, end: 0x20a4},
			},
		},
		{
			name: "past-gap",
			ranges: []enqueueProbeRange{
				{name: "metadata", start: 0x5550, end: 0x5560},
			},
		},
		{
			name: "instruction-unaligned",
			ranges: []enqueueProbeRange{
				{name: "thunk", start: 0x3002, end: 0x3010},
			},
		},
		{
			name: "overlap",
			ranges: []enqueueProbeRange{
				{name: "thunk", start: 0x3000, end: 0x3010},
				{name: "metadata", start: 0x300c, end: 0x3020},
			},
		},
		{
			name: "beyond-file",
			ranges: []enqueueProbeRange{
				{name: "metadata", start: uint64(MainSize - 4), end: uint64(MainSize + 4)},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateEnqueueProbeRanges(tc.ranges, 0x20a0, 0x555c, uint64(MainSize)); err == nil {
				t.Fatal("invalid range accepted")
			}
		})
	}
}

func TestEnqueueProbeARM64Encodings(t *testing.T) {
	tests := []struct {
		name     string
		pc       uint64
		target   uint64
		link     bool
		want     uint32
		wantFail bool
	}{
		{name: "forward B", pc: 0x1000, target: 0x1004, want: 0x14000001},
		{name: "backward B", pc: 0x1004, target: 0x1000, want: 0x17ffffff},
		{name: "forward BL", pc: 0x1000, target: 0x1008, link: true, want: 0x94000002},
		{name: "maximum positive", pc: 0x1000, target: 0x1000 + (1 << 27) - 4, want: 0x15ffffff},
		{name: "minimum negative", pc: 1 << 27, target: 0, want: 0x16000000},
		{name: "positive overflow", pc: 0x1000, target: 0x1000 + (1 << 27), wantFail: true},
		{name: "negative overflow", pc: (1 << 27) + 4, target: 0, wantFail: true},
		{name: "unaligned pc", pc: 0x1001, target: 0x1004, wantFail: true},
		{name: "unaligned target", pc: 0x1000, target: 0x1002, wantFail: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := encodeArm64Branch(tc.pc, tc.target, tc.link)
			if tc.wantFail {
				if err == nil {
					t.Fatalf("accepted branch word %#08x", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("branch = %#08x, %v; want %#08x", got, err, tc.want)
			}
		})
	}

	adr, err := encodeArm64ADR(0x3020, 0x30c0, 1)
	if err != nil || adr != 0x10000501 {
		t.Fatalf("ADR = %#08x, %v; want 0x10000501", adr, err)
	}
	if _, err := encodeArm64ADR(0, (1<<20)-1, 0); err != nil {
		t.Fatalf("ADR max positive: %v", err)
	}
	if _, err := encodeArm64ADR(0, (1<<20)+1, 0); err == nil {
		t.Fatal("ADR positive overflow accepted")
	}
	cbnz, err := encodeArm64CBNZ(0x302c, 0x3034, 16)
	if err != nil || cbnz != 0xb5000050 {
		t.Fatalf("CBNZ = %#08x, %v; want 0xb5000050", cbnz, err)
	}
	if _, err := encodeArm64CBNZ(0x3001, 0x3034, 16); err == nil {
		t.Fatal("unaligned CBNZ accepted")
	}

	// These exact words were independently emitted by Apple's arm64 iOS
	// assembler from a temporary fixture with the same fixed RVAs.
	words, entry, trampoline, err := enqueueProbeWords()
	if err != nil {
		t.Fatal(err)
	}
	if entry != 0x17a1627a || trampoline != 0x145e9d46 {
		t.Fatalf("fixed branches = %#08x / %#08x", entry, trampoline)
	}
	wantWords := []uint32{
		0xd10183ff, 0xa90007e0, 0xa9010fe2, 0xa90217e4, 0xa9031fe6,
		0xa90477e8, 0xf9002bfe, 0x92800020, 0x10000501, 0x946af9c9,
		0xaa0003f0, 0xb5000050, 0xd4200000, 0xa94007e0, 0xa9410fe2,
		0xa94217e4, 0xa9431fe6, 0xa94477e8, 0xf9402bfe, 0x910183ff,
		0xd61f0200,
	}
	if len(words) != len(wantWords) {
		t.Fatalf("thunk word count %d, want %d", len(words), len(wantWords))
	}
	for i := range words {
		if words[i] != wantWords[i] {
			t.Fatalf("thunk word %d = %#08x, want %#08x", i, words[i], wantWords[i])
		}
	}
}

func TestAddEnqueueProbeRealBaseline(t *testing.T) {
	path := os.Getenv("RASPBERRY_IOS_MAIN")
	if path == "" {
		t.Skip("set RASPBERRY_IOS_MAIN to the locked main executable")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), data...)
	out, err := AddEnqueueProbe(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, original) {
		t.Fatal("input mutated")
	}
	words, entryBranch, trampolineBranch, err := enqueueProbeWords()
	if err != nil {
		t.Fatal(err)
	}
	metadata := enqueueProbeMetadata(entryBranch, trampolineBranch, words)
	if err := collateralWrites(original, out,
		[2]int{16, 24},
		[2]int{int(enqueueProbeHeaderEnd) - 72, int(enqueueProbeHeaderEnd)},
		[2]int{int(enqueueProbeTargetRVA), int(enqueueProbeTargetRVA + 4)},
		[2]int{int(enqueueProbeThunkRVA), int(enqueueProbeThunkRVA + uint64(len(words))*4)},
		[2]int{int(enqueueProbeLiteralRVA), int(enqueueProbeLiteralRVA + uint64(len(enqueueProbeHookName)+1))},
		[2]int{int(enqueueProbeTrampolineRVA), int(enqueueProbeTrampolineRVA + 8)},
		[2]int{int(enqueueProbeMetadataRVA), int(enqueueProbeMetadataRVA + uint64(len(metadata)))},
	); err != nil {
		t.Fatal(err)
	}
	if len(out) != len(original) {
		t.Fatalf("length %d -> %d", len(original), len(out))
	}
	if err := validateEnqueueProbeSegmentsForTest(out); err != nil {
		t.Fatal(err)
	}
}

func validateEnqueueProbeSegmentsForTest(data []byte) error {
	ncmd := binary.LittleEndian.Uint32(data[16:])
	cmdsz := binary.LittleEndian.Uint32(data[20:])
	segments, sections, _, _, _, _, _, err := readEnqueueProbeCommands(data, ncmd, cmdsz)
	if err != nil {
		return err
	}
	return validateEnqueueProbeSegments(segments, sections, len(data))
}

type syntheticEnqueueOptions struct {
	textProtection uint32
}

func syntheticEnqueueImage(t *testing.T, options syntheticEnqueueOptions) []byte {
	t.Helper()
	textProt := options.textProtection
	if textProt == 0 {
		textProt = 5
	}
	image := make([]byte, MainSize)
	bo := binary.LittleEndian
	bo.PutUint32(image[0:], macho.Magic64)
	bo.PutUint32(image[4:], uint32(macho.CpuArm64))
	bo.PutUint32(image[8:], 0)
	bo.PutUint32(image[12:], uint32(macho.TypeExec))
	bo.PutUint32(image[16:], 77)
	bo.PutUint32(image[20:], 8320)

	var commands []byte
	commands = append(commands, syntheticSegment("__PAGEZERO", 0, 0x100000000, 0, 0, 0, 0, nil)...)
	commands = append(commands, syntheticTextSegment(textProt)...)
	commands = append(commands, syntheticDataSegment()...)
	commands = append(commands, syntheticSegment("__LINKEDIT", 0x1029cc000, 0x4f4000,
		0x2220000, 0x4f24c0, 1, 1, nil)...)
	commands = append(commands, syntheticEncryptionCommand()...)
	commands = append(commands, syntheticCodeSignatureCommand()...)
	commands = append(commands, syntheticSymtabCommand()...)
	commands = append(commands, syntheticDysymtabCommand()...)
	commands = append(commands, syntheticRPathCommands(t)...)
	if len(commands) != 8248 {
		t.Fatalf("synthetic original sizeofcmds = %d", len(commands))
	}
	commands = append(commands, loaderCommand()...)
	if len(commands) != 8320 {
		t.Fatalf("synthetic loader sizeofcmds = %d", len(commands))
	}
	copy(image[32:], commands)
	bo.PutUint32(image[enqueueProbeTargetRVA:], enqueueProbeOriginalEntryWord)

	stubCount := testStubCount
	indirect := image[syntheticIndirectOffset() : syntheticIndirectOffset()+stubCount*4]
	for i := 0; i < stubCount; i++ {
		bo.PutUint32(indirect[i*4:], testIndirectLocal)
	}
	bo.PutUint32(indirect[testDlsymIndex*4:], 0)

	symoff := 0x24f0000
	bo.PutUint32(image[symoff:], 1)
	image[symoff+4] = 0x01 // N_EXT | N_UNDF
	bo.PutUint32(image[0x25f0000:], 0)
	copy(image[0x25f0001:], "_dlsym\x00")
	return image
}

func syntheticSegment(name string, vmaddr, vmsize, fileoff, filesize uint64,
	maxprot, initprot uint32, sections []byte) []byte {
	bo := binary.LittleEndian
	command := make([]byte, segment64HeaderSize+len(sections))
	bo.PutUint32(command[0:], lcSegment64)
	bo.PutUint32(command[4:], uint32(len(command)))
	copy(command[8:24], name)
	bo.PutUint64(command[24:], vmaddr)
	bo.PutUint64(command[32:], vmsize)
	bo.PutUint64(command[40:], fileoff)
	bo.PutUint64(command[48:], filesize)
	bo.PutUint32(command[56:], maxprot)
	bo.PutUint32(command[60:], initprot)
	bo.PutUint32(command[64:], uint32(len(sections)/section64Size))
	copy(command[segment64HeaderSize:], sections)
	return command
}

func syntheticTextSegment(protection uint32) []byte {
	var sections []byte
	sections = append(sections, syntheticSection("__text", "__TEXT",
		0x10000555c, 0x1ab98f4, 0x555c, 2, 0x80000400, 0, 0)...)
	sections = append(sections, syntheticSection("__stubs", "__TEXT",
		0x101abee50, 0x3ba0, 0x1abee50, 2, 0x80000408, 0, 12)...)
	for i := 2; i < 13; i++ {
		offset := uint32(0x1ac29f0 + (i-2)*0x100)
		sections = append(sections, syntheticSection(fmt.Sprintf("__t%02d", i), "__TEXT",
			0x100000000+uint64(offset), 0x100, offset, 2, 0, 0, 0)...)
	}
	return syntheticSegment("__TEXT", enqueueProbeTextVMAddr, enqueueProbeTextVMSize,
		0, enqueueProbeTextVMSize, protection, protection, sections)
}

func syntheticDataSegment() []byte {
	var sections []byte
	for i := 0; i < 21; i++ {
		offset := uint32(0x1d38000 + i*0x100)
		name := fmt.Sprintf("__d%02d", i)
		sections = append(sections, syntheticSection(name, "__DATA",
			enqueueProbeDataVMAddr+uint64(offset-0x1d38000), 0x100,
			offset, 2, 0, 0, 0)...)
	}
	return syntheticSegment("__DATA", enqueueProbeDataVMAddr, enqueueProbeDataVMSize,
		enqueueProbeDataFileOff, enqueueProbeDataFileSize, 3, 3, sections)
}

func syntheticSection(name, segment string, addr, size uint64, fileoff, align,
	flags, reserved1, reserved2 uint32) []byte {
	bo := binary.LittleEndian
	section := make([]byte, section64Size)
	copy(section[0:16], name)
	copy(section[16:32], segment)
	bo.PutUint64(section[32:], addr)
	bo.PutUint64(section[40:], size)
	bo.PutUint32(section[48:], fileoff)
	bo.PutUint32(section[52:], align)
	bo.PutUint32(section[64:], flags)
	bo.PutUint32(section[68:], reserved1)
	bo.PutUint32(section[72:], reserved2)
	return section
}

func syntheticEncryptionCommand() []byte {
	command := make([]byte, 24)
	binary.LittleEndian.PutUint32(command[0:], lcEncryptionInfo64)
	binary.LittleEndian.PutUint32(command[4:], uint32(len(command)))
	return command
}

func syntheticCodeSignatureCommand() []byte {
	command := make([]byte, 16)
	binary.LittleEndian.PutUint32(command[0:], testLCCodeSign)
	binary.LittleEndian.PutUint32(command[4:], uint32(len(command)))
	binary.LittleEndian.PutUint32(command[8:], uint32(enqueueProbeSignatureOff))
	binary.LittleEndian.PutUint32(command[12:], uint32(enqueueProbeSignatureSize))
	return command
}

func syntheticSymtabCommand() []byte {
	command := make([]byte, 24)
	binary.LittleEndian.PutUint32(command[0:], testLCSymtab)
	binary.LittleEndian.PutUint32(command[4:], uint32(len(command)))
	binary.LittleEndian.PutUint32(command[8:], 0x24f0000)
	binary.LittleEndian.PutUint32(command[12:], 1)
	binary.LittleEndian.PutUint32(command[16:], 0x25f0000)
	binary.LittleEndian.PutUint32(command[20:], 7)
	return command
}

func syntheticDysymtabCommand() []byte {
	command := make([]byte, 80)
	bo := binary.LittleEndian
	bo.PutUint32(command[0:], testLCDysymtab)
	bo.PutUint32(command[4:], uint32(len(command)))
	bo.PutUint32(command[24:], 0)
	bo.PutUint32(command[28:], 1)
	bo.PutUint32(command[56:], uint32(syntheticIndirectOffset()))
	bo.PutUint32(command[60:], testStubCount)
	return command
}

func syntheticRPathCommands(t *testing.T) []byte {
	t.Helper()
	var commands []byte
	for i := 0; i < 67; i++ {
		commands = append(commands, syntheticRPath(72)...)
	}
	commands = append(commands, syntheticRPath(272)...)
	return commands
}

func syntheticRPath(size int) []byte {
	command := make([]byte, size)
	binary.LittleEndian.PutUint32(command[0:], testLCRPath)
	binary.LittleEndian.PutUint32(command[4:], uint32(size))
	binary.LittleEndian.PutUint32(command[8:], 12)
	copy(command[12:], "/Raspberry-fixture\x00")
	return command
}

func syntheticIndirectOffset() int {
	return 0x2500000
}

func syntheticTextSegmentProtectionOffset() int {
	return 32 + segment64HeaderSize + 60
}

func syntheticTextSectionOffset() int {
	return 32 + segment64HeaderSize + segment64HeaderSize
}
