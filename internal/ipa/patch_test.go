package ipa

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestExportConstants(t *testing.T) {
	if ExportNotice404DiagnosticEntry != "rb_ios_notice_404_diagnostic_entry" ||
		ExportGetaddrinfo != "rb_ios_getaddrinfo" ||
		ExportFreeaddrinfo != "rb_ios_freeaddrinfo" ||
		ExportGethostbyname != "rb_ios_gethostbyname" ||
		ExportConnect != "rb_ios_connect" ||
		ExportGuestUniqueCode != "rb_ios_guest_unique_code" {
		t.Fatal("unexpected exported symbol constant value")
	}
}

func TestArm64EncodersAndDecoders(t *testing.T) {
	branchTests := []struct {
		name   string
		pc     uint64
		target uint64
		link   bool
	}{
		{"positive BL", 0x1000, 0x2340, true},
		{"negative B", 0x2340, 0x1000, false},
		{"minimum BL", 0x10000000, 0x10000000 - (1 << 27), true},
		{"maximum B", 0x10000000, 0x10000000 + (1 << 27) - 4, false},
	}
	for _, tt := range branchTests {
		t.Run(tt.name, func(t *testing.T) {
			word, err := encodeArm64Branch(tt.pc, tt.target, tt.link)
			if err != nil {
				t.Fatal(err)
			}
			got, gotLink, ok := decodeArm64Branch(word, tt.pc)
			if !ok || got != tt.target || gotLink != tt.link {
				t.Fatalf("decode=(0x%x, link=%t, ok=%t), want (0x%x, link=%t)", got, gotLink, ok, tt.target, tt.link)
			}
		})
	}
	for _, tt := range []struct {
		name   string
		pc     uint64
		target uint64
	}{
		{"unaligned pc", 0x1001, 0x2000},
		{"unaligned target", 0x1000, 0x2002},
		{"too far negative", 0x10000000, 0x10000000 - (1 << 27) - 4},
		{"too far positive", 0x10000000, 0x10000000 + (1 << 27)},
	} {
		t.Run("reject branch "+tt.name, func(t *testing.T) {
			if _, err := encodeArm64Branch(tt.pc, tt.target, true); err == nil {
				t.Fatal("expected branch range/alignment rejection")
			}
		})
	}

	adrWord, err := encodeArm64ADR(0x3114, 0x3180, 1)
	if err != nil {
		t.Fatal(err)
	}
	adrTarget, adrRd, ok := decodeArm64ADR(adrWord, 0x3114)
	if !ok || adrRd != 1 || adrTarget != 0x3180 {
		t.Fatalf("ADR decode=(0x%x, rd=%d, ok=%t)", adrTarget, adrRd, ok)
	}
	if _, err := encodeArm64ADR(0x1000000, 0x1000000+(1<<20), 1); err == nil {
		t.Fatal("expected ADR out-of-range error")
	}

	cbnzWord, err := encodeArm64CBNZ(0x3120, 0x3128, 16)
	if err != nil {
		t.Fatal(err)
	}
	cbnzTarget, cbnzRt, ok := decodeArm64CBNZ(cbnzWord, 0x3120)
	if !ok || cbnzRt != 16 || cbnzTarget != 0x3128 {
		t.Fatalf("CBNZ decode=(0x%x, rt=%d, ok=%t)", cbnzTarget, cbnzRt, ok)
	}

	cbzWord, err := encodeArm64CBZ(0x353c, 0x3544, 1)
	if err != nil {
		t.Fatal(err)
	}
	if cbzWord != 0xb4000041 {
		t.Fatalf("CBZ word = 0x%08x, want 0xb4000041", cbzWord)
	}
	cbzTarget, cbzRt, ok := decodeArm64CBZ(cbzWord, 0x353c)
	if !ok || cbzRt != 1 || cbzTarget != 0x3544 {
		t.Fatalf("CBZ decode=(0x%x, rt=%d, ok=%t)", cbzTarget, cbzRt, ok)
	}
	if _, _, ok := decodeArm64CBZ(cbnzWord, 0x3120); ok {
		t.Fatal("decodeArm64CBZ accepted CBNZ")
	}
	if _, _, ok := decodeArm64CBNZ(cbzWord, 0x353c); ok {
		t.Fatal("decodeArm64CBNZ accepted CBZ")
	}
}

func TestAutoGuestEntryBranchEncodingAndDecode(t *testing.T) {
	origWord, err := encodeArm64Branch(autoGuestEntryRVA, autoGuestEntryOrigTarget, false)
	if err != nil {
		t.Fatal(err)
	}
	if origWord != autoGuestEntryOrigWord {
		t.Fatalf("encoded original word = 0x%08x, want 0x%08x", origWord, autoGuestEntryOrigWord)
	}
	origTarget, origLink, ok := decodeArm64Branch(origWord, autoGuestEntryRVA)
	if !ok || origLink || origTarget != autoGuestEntryOrigTarget {
		t.Fatalf("decoded original = (0x%x, link=%t, ok=%t), want (0x%x, link=false, ok=true)",
			origTarget, origLink, ok, autoGuestEntryOrigTarget)
	}

	patchedWord, err := autoGuestEntryBranchWord()
	if err != nil {
		t.Fatal(err)
	}
	if patchedWord != 0x141b0d08 {
		t.Fatalf("patched word = 0x%08x, want 0x141b0d08", patchedWord)
	}
	patchedTarget, patchedLink, ok := decodeArm64Branch(patchedWord, autoGuestEntryRVA)
	if !ok || patchedLink || patchedTarget != createGuestAccountRVA {
		t.Fatalf("decoded patched = (0x%x, link=%t, ok=%t), want (0x%x, link=false, ok=true)",
			patchedTarget, patchedLink, ok, createGuestAccountRVA)
	}
}

func TestResolverEncodingsAndABIShape(t *testing.T) {
	noticeWords, err := noticeResolverWords()
	if err != nil {
		t.Fatal(err)
	}
	if len(noticeWords) != noticeResolverWordCount || len(encodeWords(noticeWords)) != 64 {
		t.Fatalf("notice resolver size = %d words", len(noticeWords))
	}
	if noticeWords[0] != 0xd100c3ff || noticeWords[1] != 0xa90007e0 ||
		noticeWords[2] != 0xa9010fe2 || noticeWords[3] != 0xf90013fe ||
		noticeWords[4] != 0x92800020 || noticeWords[7] != 0xaa0003f0 ||
		noticeWords[9] != 0xd4200000 || noticeWords[10] != 0xa94007e0 ||
		noticeWords[11] != 0xa9410fe2 || noticeWords[12] != 0xf94013e4 ||
		noticeWords[13] != 0xf94013fe || noticeWords[14] != 0x9100c3ff ||
		noticeWords[15] != 0xd61f0200 {
		t.Fatalf("unexpected notice resolver words: %#v", noticeWords)
	}
	if target, rd, ok := decodeArm64ADR(noticeWords[5], noticeResolverRVA+5*4); !ok || rd != 1 || target != noticeExportRVA {
		t.Fatalf("notice ADR=(0x%x, rd=%d, ok=%t)", target, rd, ok)
	}
	if target, link, ok := decodeArm64Branch(noticeWords[6], noticeResolverRVA+6*4); !ok || !link || target != patchDlsymStubRVA {
		t.Fatalf("notice BL=(0x%x, link=%t, ok=%t)", target, link, ok)
	}
	if target, rt, ok := decodeArm64CBNZ(noticeWords[8], noticeResolverRVA+8*4); !ok || rt != 16 || target != noticeResolverRVA+10*4 {
		t.Fatalf("notice CBNZ=(0x%x, rt=%d, ok=%t)", target, rt, ok)
	}

	for _, spec := range socketStubSpecs {
		t.Run(spec.name, func(t *testing.T) {
			words, err := stubResolverWords(spec.resolverRVA, spec.exportRVA)
			if err != nil {
				t.Fatal(err)
			}
			if len(words) != stubResolverWordCount || len(encodeWords(words)) != 60 {
				t.Fatalf("stub resolver size = %d words", len(words))
			}
			wantFixed := []struct {
				idx  int
				word uint32
			}{
				{0, 0xd100c3ff},
				{1, 0xa90007e0},
				{2, 0xa9010fe2},
				{3, 0xf90013fe},
				{4, 0x92800020},
				{7, 0xaa0003f0},
				{9, 0xd4200000},
				{10, 0xa94007e0},
				{11, 0xa9410fe2},
				{12, 0xf94013fe},
				{13, 0x9100c3ff},
				{14, 0xd61f0200},
			}
			for _, f := range wantFixed {
				if words[f.idx] != f.word {
					t.Fatalf("word[%d] = 0x%08x, want 0x%08x", f.idx, words[f.idx], f.word)
				}
			}
			if target, rd, ok := decodeArm64ADR(words[5], spec.resolverRVA+5*4); !ok || rd != 1 || target != spec.exportRVA {
				t.Fatalf("ADR=(0x%x, rd=%d, ok=%t)", target, rd, ok)
			}
			if target, link, ok := decodeArm64Branch(words[6], spec.resolverRVA+6*4); !ok || !link || target != patchDlsymStubRVA {
				t.Fatalf("BL=(0x%x, link=%t, ok=%t)", target, link, ok)
			}
			if target, rt, ok := decodeArm64CBNZ(words[8], spec.resolverRVA+8*4); !ok || rt != 16 || target != spec.resolverRVA+10*4 {
				t.Fatalf("CBNZ=(0x%x, rt=%d, ok=%t)", target, rt, ok)
			}
		})
	}

	t.Run("guest_auth_resolver", func(t *testing.T) {
		words, err := guestResolverWords()
		if err != nil {
			t.Fatal(err)
		}
		if len(words) != guestResolverWordCount || len(encodeWords(words)) != 72 {
			t.Fatalf("guest resolver size = %d words", len(words))
		}
		wantFixed := []struct {
			idx  int
			word uint32
		}{
			{0, 0xd10083ff},  // sub sp, sp, #32
			{1, 0xa90007e0},  // stp x0, x1, [sp]
			{2, 0xf9000bfe},  // str x30, [sp, #16]
			{3, 0x92800020},  // movn x0, #1
			{6, 0xb5000040},  // cbnz x0, +8
			{7, 0xd4200000},  // brk #0
			{8, 0xaa0003f0},  // mov x16, x0
			{9, 0xa94007e0},  // ldp x0, x1, [sp]
			{10, 0xd63f0200}, // blr x16
			{11, 0xaa0003e1}, // mov x1, x0
			{12, 0xf94003e0}, // ldr x0, [sp]
			{13, 0xf9400bfe}, // ldr x30, [sp, #16]
			{14, 0x910083ff}, // add sp, sp, #32
			{15, 0xb4000041}, // cbz x1, +8
			{17, 0xd65f03c0}, // ret
		}
		for _, f := range wantFixed {
			if words[f.idx] != f.word {
				t.Fatalf("guest word[%d] = 0x%08x, want 0x%08x", f.idx, words[f.idx], f.word)
			}
		}
		if target, rd, ok := decodeArm64ADR(words[4], guestResolverRVA+4*4); !ok || rd != 1 || target != guestExportRVA {
			t.Fatalf("guest ADR=(0x%x, rd=%d, ok=%t)", target, rd, ok)
		}
		if target, link, ok := decodeArm64Branch(words[5], guestResolverRVA+5*4); !ok || !link || target != patchDlsymStubRVA {
			t.Fatalf("guest BL=(0x%x, link=%t, ok=%t)", target, link, ok)
		}
		if target, rt, ok := decodeArm64CBNZ(words[6], guestResolverRVA+6*4); !ok || rt != 0 || target != guestResolverRVA+8*4 {
			t.Fatalf("guest CBNZ=(0x%x, rt=%d, ok=%t)", target, rt, ok)
		}
		if target, rt, ok := decodeArm64CBZ(words[15], guestResolverRVA+15*4); !ok || rt != 1 || target != guestResolverRVA+17*4 {
			t.Fatalf("guest CBZ=(0x%x, rt=%d, ok=%t)", target, rt, ok)
		}
		if target, link, ok := decodeArm64Branch(words[16], guestResolverRVA+16*4); !ok || link || target != guestGenerateRVA {
			t.Fatalf("guest tail B=(0x%x, link=%t, ok=%t)", target, link, ok)
		}
	})
}

func TestReservedRangeValidation(t *testing.T) {
	ranges, err := reservedRanges()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateReservedRanges(ranges); err != nil {
		t.Fatalf("valid reserved ranges rejected: %v", err)
	}

	tests := []struct {
		name   string
		ranges []byteRange
	}{
		{
			name: "overlap",
			ranges: []byteRange{
				{0x3000, 0x3040, "a"},
				{0x303c, 0x3048, "b"},
			},
		},
		{
			name:   "unaligned",
			ranges: []byteRange{{0x3002, 0x3010, "unaligned"}},
		},
		{
			name:   "before 0x3000",
			ranges: []byteRange{{0x2ff0, 0x3000, "early"}},
		},
		{
			name:   "past 0x3fff",
			ranges: []byteRange{{0x3ff0, 0x4004, "late"}},
		},
		{
			name:   "empty",
			ranges: []byteRange{{0x3000, 0x3000, "empty"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateReservedRanges(tt.ranges); err == nil {
				t.Fatal("expected range rejection")
			}
		})
	}
}

func TestEmitAllPatchesSynthetic(t *testing.T) {
	prepared := syntheticPreparedImage()
	beforeHash := sha256.Sum256(prepared)

	out1, err := emitAllPatches(prepared)
	if err != nil {
		t.Fatal(err)
	}
	out2, err := emitAllPatches(prepared)
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256.Sum256(prepared); got != beforeHash {
		t.Fatal("emitter mutated input")
	}
	if !bytes.Equal(out1, out2) {
		t.Fatal("emitter output is not deterministic")
	}
	if err := verifyPatchOnlyDelta(prepared, out1); err != nil {
		t.Fatal(err)
	}
	if err := verifyDecodedInstructions(prepared, out1); err != nil {
		t.Fatal(err)
	}

	// Verify exact [0x53af68, 0x53af6c) write window and decoded auto-guest-entry branch.
	foundAutoGuestRange := false
	for _, r := range patchCallsiteRanges() {
		if r.start == 0x53af68 && r.end == 0x53af6c {
			foundAutoGuestRange = true
			break
		}
	}
	if !foundAutoGuestRange {
		t.Fatal("patchCallsiteRanges missing [0x53af68, 0x53af6c)")
	}
	gotAutoWord := binary.LittleEndian.Uint32(out1[0x53af68:])
	if gotAutoWord != 0x141b0d08 {
		t.Fatalf("patched auto-guest-entry word = 0x%08x, want 0x141b0d08", gotAutoWord)
	}
	if target, link, ok := decodeArm64Branch(gotAutoWord, 0x53af68); !ok || link || target != 0xbfe388 {
		t.Fatalf("decoded patched auto-guest-entry = (0x%x, link=%t, ok=%t), want (0xbfe388, link=false, ok=true)",
			target, link, ok)
	}
	for _, adj := range []uint64{0x53af67, 0x53af6c} {
		badAdj := append([]byte(nil), out1...)
		badAdj[adj] ^= 1
		if err := verifyPatchOnlyDelta(prepared, badAdj); err == nil {
			t.Fatalf("verifyPatchOnlyDelta accepted adjacent mutation at 0x%x", adj)
		}
		if err := verifyFullWriteSet(prepared, badAdj); err == nil {
			t.Fatalf("verifyFullWriteSet accepted adjacent mutation at 0x%x", adj)
		}
	}

	// Cookie-present CheckAutoLogin tail and US COPPA check must remain byte-identical.
	if !bytes.Equal(prepared[0x53ae3c:0x53ae4c], out1[0x53ae3c:0x53ae4c]) {
		t.Fatal("cookie-present CheckAutoLogin tail 0x53ae3c..0x53ae4c mutated")
	}
	if !bytes.Equal(prepared[0x53aee0:0x53aef8], out1[0x53aee0:0x53aef8]) {
		t.Fatal("US COPPA check 0x53aee0..0x53aef8 mutated")
	}
	for _, w := range autoGuestGuardWindows {
		if !bytes.Equal(prepared[w.start:w.unchanged], out1[w.start:w.unchanged]) {
			t.Fatalf("auto-guest-entry guard window %s [0x%x..0x%x) mutated", w.name, w.start, w.unchanged)
		}
	}

	// Mutated notice callsite guard rejected.
	badCallsite := append([]byte(nil), prepared...)
	badCallsite[noticeCallsiteRVA] ^= 1
	if _, err := emitAllPatches(badCallsite); err == nil {
		t.Fatal("accepted mutated notice callsite")
	}

	// Mutated ARC continuation rejected.
	badCont := append([]byte(nil), prepared...)
	badCont[noticeContinuationRVA+1] ^= 1
	if _, err := emitAllPatches(badCont); err == nil {
		t.Fatal("accepted mutated ARC continuation")
	}

	// Mutated sub_1006BDD4C prologue rejected.
	badPrologue := append([]byte(nil), prepared...)
	badPrologue[guestGenerateRVA+8] ^= 1
	if _, err := emitAllPatches(badPrologue); err == nil {
		t.Fatal("accepted mutated sub_1006BDD4C prologue")
	}

	// Mutated guest callsites and surrounding guards rejected.
	for _, spec := range guestCallsiteSpecs {
		badBranch := append([]byte(nil), prepared...)
		badBranch[spec.callsiteRVA] ^= 1
		if _, err := emitAllPatches(badBranch); err == nil {
			t.Fatalf("accepted mutated %s branch word", spec.name)
		}

		badPrefix := append([]byte(nil), prepared...)
		badPrefix[spec.prefixStart] ^= 1
		if _, err := emitAllPatches(badPrefix); err == nil {
			t.Fatalf("accepted mutated %s prefix guard", spec.name)
		}

		if len(spec.suffixWords) > 0 {
			badSuffix := append([]byte(nil), prepared...)
			badSuffix[spec.suffixStart] ^= 1
			if _, err := emitAllPatches(badSuffix); err == nil {
				t.Fatalf("accepted mutated %s suffix guard", spec.name)
			}
		}
	}

	// Mutated auto-guest-entry guard windows and original branch word rejected.
	for _, w := range autoGuestGuardWindows {
		winLen := uint64(len(w.words)) * 4
		for _, offset := range []uint64{0, winLen / 2, winLen - 1} {
			badGuard := append([]byte(nil), prepared...)
			badGuard[w.start+offset] ^= 1
			if err := validateAutoGuestEntry(badGuard); err == nil {
				t.Fatalf("validateAutoGuestEntry accepted mutated %s at +0x%x", w.name, offset)
			}
			if _, err := emitAllPatches(badGuard); err == nil {
				t.Fatalf("emitAllPatches accepted mutated %s at +0x%x", w.name, offset)
			}
		}
	}
	badAutoWord := append([]byte(nil), prepared...)
	badAutoWord[autoGuestEntryRVA] ^= 1
	if err := validateAutoGuestEntry(badAutoWord); err == nil {
		t.Fatal("validateAutoGuestEntry accepted mutated 0x53af68 word")
	}
	if _, err := emitAllPatches(badAutoWord); err == nil {
		t.Fatal("emitAllPatches accepted mutated 0x53af68 word")
	}

	// Non-zero RX header slack rejected (including guest resolver/export slots).
	for _, off := range []uint64{0x3250, guestResolverRVA + 12, guestExportRVA + 4} {
		badSlack := append([]byte(nil), prepared...)
		badSlack[off] = 0xff
		if _, err := emitAllPatches(badSlack); err == nil {
			t.Fatalf("accepted non-zero RX header slack at 0x%x", off)
		}
	}
}

func TestValidateStubEntryRejections(t *testing.T) {
	data := syntheticPreparedImage()
	stubsSec := &patchImageSection{
		name:     "__stubs",
		segment:  "__TEXT",
		addr:     patchTextVMAddr + patchStubsFileOff,
		size:     patchStubsSize,
		fileoff:  patchStubsFileOff,
		flags:    0x80000408,
		indirect: 0,
		stubLen:  patchStubsLen,
	}
	laSymPtrSec := &patchImageSection{
		name:    "__la_symbol_ptr",
		segment: "__DATA",
		addr:    patchLaSymPtrAddr,
		size:    patchLaSymPtrSize,
		fileoff: patchLaSymPtrFileOff,
		flags:   sectionLazyPtr,
	}
	gotSec := &patchImageSection{
		name:    "__got",
		segment: "__DATA",
		addr:    patchGotSectionAddr,
		size:    patchGotSectionSize,
		fileoff: patchGotSectionOff,
		flags:   sectionNonLazyPtr,
	}

	nstubs := patchStubsSize / uint64(patchStubsLen)
	indirectSyms := make([]uint32, nstubs)
	for i := range indirectSyms {
		indirectSyms[i] = 0x80000000
	}
	syms := []macho.Symbol{
		{Name: "_getaddrinfo"},
		{Name: "_freeaddrinfo"},
		{Name: "_gethostbyname"},
		{Name: "_connect"},
		{Name: "_other"},
	}
	for idx, spec := range socketStubSpecs {
		stubIndex := (spec.stubRVA - patchStubsFileOff) / uint64(patchStubsLen)
		indirectSyms[stubIndex] = uint32(idx)
	}

	if err := validateStubEntry(data, stubsSec, laSymPtrSec, gotSec, indirectSyms, syms, socketStubSpecs[0]); err != nil {
		t.Fatalf("valid stub fixture failed: %v", err)
	}

	// Wrong symbol name at indirect slot.
	badIndirect := append([]uint32(nil), indirectSyms...)
	stubIdx0 := (socketStubSpecs[0].stubRVA - patchStubsFileOff) / uint64(patchStubsLen)
	badIndirect[stubIdx0] = 4
	if err := validateStubEntry(data, stubsSec, laSymPtrSec, gotSec, badIndirect, syms, socketStubSpecs[0]); err == nil {
		t.Fatal("accepted wrong indirect symbol")
	}

	// Corrupted ADRP / LDR / BR word in stub.
	for _, offset := range []uint64{0, 4, 8} {
		mutated := append([]byte(nil), data...)
		mutated[socketStubSpecs[0].stubRVA+offset] ^= 0x01
		if err := validateStubEntry(mutated, stubsSec, laSymPtrSec, gotSec, indirectSyms, syms, socketStubSpecs[0]); err == nil {
			t.Fatalf("accepted corrupted stub word at +%d", offset)
		}
	}

	// Stub outside __TEXT,__stubs.
	badSpec := socketStubSpecs[0]
	badSpec.stubRVA = patchStubsFileOff - 12
	if err := validateStubEntry(data, stubsSec, laSymPtrSec, gotSec, indirectSyms, syms, badSpec); err == nil {
		t.Fatal("accepted stub outside __TEXT,__stubs")
	}
}

func TestPatchMainExecutableRejectsBadInputs(t *testing.T) {
	if _, err := PatchMainExecutable([]byte("short")); err == nil {
		t.Fatal("accepted short input")
	} else if !errors.Is(err, ErrBaseline) {
		t.Fatalf("short input error = %v, want ErrBaseline", err)
	}
	wrongHash := make([]byte, MainSize)
	if _, err := PatchMainExecutable(wrongHash); err == nil {
		t.Fatal("accepted wrong-SHA256 input")
	} else if !errors.Is(err, ErrBaseline) {
		t.Fatalf("wrong hash error = %v, want ErrBaseline", err)
	}
}

func findBaselineIPAPath() string {
	for _, candidate := range []string{
		filepath.Join("..", "..", ".opencode", "line-play-artifacts", "jp.naver.lineplay_10.1.0_decrypted.ipa"),
		filepath.Join(".opencode", "line-play-artifacts", "jp.naver.lineplay_10.1.0_decrypted.ipa"),
	} {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate
		}
	}
	return ""
}

func loadBaselineMainForTest(t *testing.T) []byte {
	t.Helper()
	var original []byte
	if envMain := os.Getenv("RASPBERRY_IOS_MAIN"); envMain != "" {
		b, err := os.ReadFile(envMain)
		if err != nil {
			t.Fatal(err)
		}
		original = b
	} else {
		ipaPath := findBaselineIPAPath()
		if ipaPath == "" {
			t.Skip("locked baseline IPA not present")
		}
		ipaBytes, err := os.ReadFile(ipaPath)
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(ipaBytes)) != BaselineSize {
			t.Fatalf("IPA size=%d, want %d", len(ipaBytes), BaselineSize)
		}
		ipaSum := sha256.Sum256(ipaBytes)
		if got := hex.EncodeToString(ipaSum[:]); got != BaselineSHA256 {
			t.Fatalf("IPA SHA-256=%s, want %s", got, BaselineSHA256)
		}
		zr, err := zip.NewReader(bytes.NewReader(ipaBytes), int64(len(ipaBytes)))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range zr.File {
			if f.Name == ExecutablePath {
				rc, err := f.Open()
				if err != nil {
					t.Fatal(err)
				}
				original, err = io.ReadAll(rc)
				rc.Close()
				if err != nil {
					t.Fatal(err)
				}
				break
			}
		}
		if len(original) == 0 {
			t.Fatalf("missing %s inside IPA", ExecutablePath)
		}
	}

	origHash := sha256.Sum256(original)
	if int64(len(original)) != MainSize || hex.EncodeToString(origHash[:]) != MainSHA256 {
		t.Fatalf("baseline main mismatch: size=%d sha256=%x", len(original), origHash)
	}
	return original
}

func TestPatchMainExecutableAutoGuestEntryFailClosed(t *testing.T) {
	original := loadBaselineMainForTest(t)

	for _, w := range autoGuestGuardWindows {
		mutated := append([]byte(nil), original...)
		mutated[w.start] ^= 0x01
		if _, err := PatchMainExecutable(mutated); err == nil {
			t.Fatalf("PatchMainExecutable accepted mutated %s", w.name)
		}
		if err := validateBaselineImage(mutated); err == nil {
			t.Fatalf("validateBaselineImage accepted mutated %s", w.name)
		}
	}

	mutatedSite := append([]byte(nil), original...)
	mutatedSite[autoGuestEntryRVA] ^= 0x01
	if _, err := PatchMainExecutable(mutatedSite); err == nil {
		t.Fatal("PatchMainExecutable accepted mutated 0x53af68 word")
	}
	if err := validateBaselineImage(mutatedSite); err == nil {
		t.Fatal("validateBaselineImage accepted mutated 0x53af68 word")
	}
}

func TestPatchMainExecutableRealBaselineIPAInMemory(t *testing.T) {
	original := loadBaselineMainForTest(t)
	origHash := sha256.Sum256(original)

	out1, err := PatchMainExecutable(original)
	if err != nil {
		t.Fatal(err)
	}
	out2, err := PatchMainExecutable(original)
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256.Sum256(original); got != origHash {
		t.Fatal("PatchMainExecutable mutated input slice")
	}
	if !bytes.Equal(out1, out2) {
		t.Fatal("PatchMainExecutable is not deterministic")
	}
	if len(out1) != len(original) {
		t.Fatalf("output size changed: %d -> %d", len(original), len(out1))
	}

	// Re-parse patched Mach-O and check exact delta + loader + decoded instructions.
	mf, err := macho.NewFile(bytes.NewReader(out1))
	if err != nil {
		t.Fatalf("macho.NewFile(patched): %v", err)
	}
	libs, err := mf.ImportedLibraries()
	if err != nil {
		t.Fatal(err)
	}
	foundLoader := false
	for _, lib := range libs {
		if lib == LoaderPath {
			foundLoader = true
			break
		}
	}
	if !foundLoader {
		t.Fatalf("patched Mach-O missing loader %q", LoaderPath)
	}

	if err := verifyFullWriteSet(original, out1); err != nil {
		t.Fatal(err)
	}
	if err := verifyDecodedInstructions(original, out1); err != nil {
		t.Fatal(err)
	}

	// Explicitly confirm sub_1006BDD4C prologue and callsite guard windows remain byte-identical.
	prologueEnd := guestGenerateRVA + uint64(len(guestGeneratePrologueWords))*4
	if !bytes.Equal(original[guestGenerateRVA:prologueEnd], out1[guestGenerateRVA:prologueEnd]) {
		t.Fatal("sub_1006BDD4C prologue modified")
	}
	for _, spec := range guestCallsiteSpecs {
		prefixEnd := spec.prefixStart + uint64(len(spec.prefixWords))*4
		if !bytes.Equal(original[spec.prefixStart:prefixEnd], out1[spec.prefixStart:prefixEnd]) {
			t.Fatalf("%s prefix guard modified", spec.name)
		}
		if len(spec.suffixWords) > 0 {
			suffixEnd := spec.suffixStart + uint64(len(spec.suffixWords))*4
			if !bytes.Equal(original[spec.suffixStart:suffixEnd], out1[spec.suffixStart:suffixEnd]) {
				t.Fatalf("%s suffix guard modified", spec.name)
			}
		}
	}

	// Explicitly confirm auto-guest-entry branch + intact non-patched guard windows.
	if got := binary.LittleEndian.Uint32(original[0x53af68:]); got != 0x17fff794 {
		t.Fatalf("baseline word at 0x53af68 = 0x%08x, want 0x17fff794", got)
	} else if target, link, ok := decodeArm64Branch(got, 0x53af68); !ok || link || target != 0x538db8 {
		t.Fatalf("baseline branch at 0x53af68 = (0x%x, link=%t, ok=%t)", target, link, ok)
	}
	if got := binary.LittleEndian.Uint32(out1[0x53af68:]); got != 0x141b0d08 {
		t.Fatalf("patched word at 0x53af68 = 0x%08x, want 0x141b0d08", got)
	} else if target, link, ok := decodeArm64Branch(got, 0x53af68); !ok || link || target != 0xbfe388 {
		t.Fatalf("patched branch at 0x53af68 = (0x%x, link=%t, ok=%t)", target, link, ok)
	}
	for i := uint64(0x53af68); i < 0x53af6c; i++ {
		if original[i] == out1[i] {
			t.Fatalf("expected byte at 0x%x inside [0x53af68, 0x53af6c) to change", i)
		}
	}
	if !bytes.Equal(original[0x53af6c:0x53af70], out1[0x53af6c:0x53af70]) {
		t.Fatal("SetEndLoading post-patch boundary 0x53af6c..0x53af70 modified")
	}
	for _, w := range autoGuestGuardWindows {
		if !bytes.Equal(original[w.start:w.unchanged], out1[w.start:w.unchanged]) {
			t.Fatalf("auto-guest-entry guard window %s [0x%x..0x%x) modified", w.name, w.start, w.unchanged)
		}
	}

	outHash := sha256.Sum256(out1)
	t.Logf("verified in memory: baseline=%x patched=%x size=%d (6 resolvers + 6 exports + notice BL + 4 stub B + 3 guest callsites + auto-guest B + loader)",
		origHash, outHash, len(out1))
}

func syntheticPreparedImage() []byte {
	buf := make([]byte, MainSize)
	binary.LittleEndian.PutUint32(buf[noticeCallsiteRVA:], originalNoticeCallWord)
	copy(buf[noticeContinuationRVA:], stockContinuation[:])
	for _, spec := range socketStubSpecs {
		writeWords(buf[spec.stubRVA:], spec.expectedWords[:])
	}
	writeWords(buf[guestGenerateRVA:], guestGeneratePrologueWords[:])
	for _, spec := range guestCallsiteSpecs {
		writeWords(buf[spec.prefixStart:], spec.prefixWords)
		binary.LittleEndian.PutUint32(buf[spec.callsiteRVA:], spec.origWord)
		if len(spec.suffixWords) > 0 {
			writeWords(buf[spec.suffixStart:], spec.suffixWords)
		}
	}
	for _, w := range autoGuestGuardWindows {
		writeWords(buf[w.start:], w.words)
	}
	return buf
}
