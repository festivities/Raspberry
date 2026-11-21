package ipa

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
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
		ExportGuestUniqueCode != "rb_ios_guest_unique_code" ||
		ExportLoginReady != "rb_ios_on_login_ready" ||
		ExportSessionReset != "rb_ios_on_session_reset" ||
		ExportCheckSessionError != "rb_ios_on_check_session_error" ||
		ExportGuestGenerateError != "rb_ios_on_guest_generate_error" {
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
	if patchedWord != autoGuestEntryPatchedWord {
		t.Fatalf("patched word = 0x%08x, want 0x%08x", patchedWord, autoGuestEntryPatchedWord)
	}
	patchedTarget, patchedLink, ok := decodeArm64Branch(patchedWord, autoGuestEntryRVA)
	if !ok || patchedLink || patchedTarget != loginReadyResolverRVA {
		t.Fatalf("decoded patched = (0x%x, link=%t, ok=%t), want (0x%x, link=false, ok=true)",
			patchedTarget, patchedLink, ok, loginReadyResolverRVA)
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

func TestCheckSessionErrorResolverLoadsSavedX3(t *testing.T) {
	out, err := emitAllPatches(syntheticPreparedImage())
	if err != nil {
		t.Fatal(err)
	}

	// The resolver saves X3 in the second slot of STP X2,X3,[SP,#16].
	if got := binary.LittleEndian.Uint32(out[checkSessionResolverRVA+2*4:]); got != 0xa9010fe2 {
		t.Fatalf("checkSession resolver save instruction = 0x%08x, want STP X2,X3,[SP,#16]", got)
	}
	// Decode the actual emitted argument-load instruction, independently of the
	// resolver-word generator/comparison, so a caller-saved X3 cannot regress.
	got := binary.LittleEndian.Uint32(out[checkSessionResolverRVA+12*4:])
	rt, rn, offset, ok := decodeArm64LDR64Unsigned(got)
	if !ok || rt != 0 || rn != 31 || offset != 24 {
		t.Fatalf("checkSession callback argument instruction 0x%08x decodes (rt=%d rn=%d offset=%d ok=%t), want LDR X0,[SP,#24]",
			got, rt, rn, offset, ok)
	}
	if got == 0xaa0303e0 {
		t.Fatal("checkSession resolver passes caller-saved X3 directly after dlsym")
	}
}

type lrResolverCase struct {
	name            string
	base            uint64
	wordCount       int
	restoreStart    int
	stackAddIndex   int
	tailBranchIndex int
	tailTarget      uint64
}

func TestReauthResolversPreserveLRAcrossCallbacks(t *testing.T) {
	out, err := emitAllPatches(syntheticPreparedImage())
	if err != nil {
		t.Fatal(err)
	}
	resolvers := []lrResolverCase{
		{"Logout reset", sessionOutResolverRVA, sessionResetResolverWordCount, 14, 19, 20, 0x89ad04},
		{"direct delete reset", deleteDirectResolverRVA, sessionResetResolverWordCount, 14, 19, 20, 0x89ad04},
		{"SNS delete reset", deleteSNSResolverRVA, sessionResetResolverWordCount, 14, 19, 20, 0x89b23c},
		{"checkSession error", checkSessionResolverRVA, checkSessionResolverWordCount, 14, 19, 21, checkSessionErrorEntryRVA + 4},
		{"guest refusal", guestGenerateResolverRVA, guestGenerateResolverWordCount, 15, 20, 23, guestGenerateDialogTailRVA},
	}

	for _, resolver := range resolvers {
		t.Run(resolver.name, func(t *testing.T) {
			if err := assertLRPairSemantics(out, resolver); err != nil {
				t.Fatal(err)
			}
			if err := runEmittedResolverModel(out, resolver); err != nil {
				t.Fatalf("emitted resolver model failed: %v", err)
			}

			// Recreate the old bad X8,XZR encodings in this emitted resolver.
			// The field assertions and bounded model must both reject them.
			oldPair := append([]byte(nil), out...)
			putResolverWord(oldPair, resolver, 5, 0xa9047fe8)
			putResolverWord(oldPair, resolver, resolver.restoreStart+4, 0xa9447fe8)
			if err := assertLRPairSemantics(oldPair, resolver); err == nil {
				t.Fatal("accepted old pair encodings with Rt2=XZR")
			}
			if err := runEmittedResolverModel(oldPair, resolver); err == nil {
				t.Fatal("old pair encodings did not expose the corrupted incoming LR")
			}
		})
	}
}

func TestLogoutOldLRPairCanPlausiblyReplayCleanupWithNullX0(t *testing.T) {
	out, err := emitAllPatches(syntheticPreparedImage())
	if err != nil {
		t.Fatal(err)
	}
	logout := lrResolverCase{
		name: "Logout reset", base: sessionOutResolverRVA, wordCount: sessionResetResolverWordCount,
		restoreStart: 14, stackAddIndex: 19, tailBranchIndex: 20, tailTarget: 0x89ad04,
	}
	fixed, err := simulateLogoutCleanupReturn(out, logout)
	if err != nil {
		t.Fatalf("fixed emitted resolver model failed: %v", err)
	}
	if fixed.cleanupCalls != 1 || fixed.firstStockX0 == 0 || fixed.firstStockSP != fixed.callerSP ||
		fixed.firstReturnPC != fixed.originalLR {
		t.Fatalf("fixed pair did not produce one normal cleanup return: %+v", fixed)
	}

	// A synthetic caller frame with a zero first word is only a plausible
	// reproduction of the hypothesized stack shape, not evidence of production
	// Logout's first-pass SP contents.
	oldPair := append([]byte(nil), out...)
	putResolverWord(oldPair, logout, 5, 0xa9047fe8)
	putResolverWord(oldPair, logout, logout.restoreStart+4, 0xa9447fe8)
	replayed, err := simulateLogoutCleanupReturn(oldPair, logout)
	if err != nil {
		t.Fatalf("old-pair replay model failed: %v", err)
	}
	if replayed.cleanupCalls != 2 ||
		replayed.firstStockX0 == 0 || replayed.firstStockSP != replayed.callerSP ||
		replayed.firstReturnPC != logout.base+14*4 ||
		!replayed.reentryWasLDPX0X1 || replayed.reentryX0 != 0 ||
		replayed.secondStockSP != replayed.callerSP+80 ||
		replayed.secondStockX0 != 0 || replayed.secondStockTarget != logout.tailTarget {
		t.Fatalf("old pair did not exhibit bounded null-x0 replay path: %+v", replayed)
	}
}

type logoutReplayResult struct {
	callerSP, originalLR uint64
	cleanupCalls         int
	firstStockX0         uint64
	firstStockSP         uint64
	firstReturnPC        uint64
	reentryWasLDPX0X1    bool
	reentryX0            uint64
	secondStockSP        uint64
	secondStockX0        uint64
	secondStockTarget    uint64
}

// simulateLogoutCleanupReturn consumes the emitted resolver bytes, models one
// stock cleanup return, and follows a possible return into the resolver's
// restore tail using a synthetic caller frame. The modeled frame is not a
// claim about the real callback's first-pass stack contents.
func simulateLogoutCleanupReturn(data []byte, resolver lrResolverCase) (logoutReplayResult, error) {
	const (
		callerSP   = uint64(0x200000)
		originalLR = uint64(0xabcdef0000001234)
		initialX0  = uint64(0x123456789abcdef0)
	)
	result := logoutReplayResult{callerSP: callerSP, originalLR: originalLR}
	stack := map[uint64]uint64{
		callerSP:      0, // the hypothesized caller-frame word used on re-entry
		callerSP + 8:  0x8888,
		callerSP + 16: 0x1616,
		callerSP + 24: 0x2424,
		callerSP + 32: 0x3232,
		callerSP + 40: 0x4040,
		callerSP + 48: 0x4848,
		callerSP + 56: 0x5656,
		callerSP + 64: 0x6464,
		callerSP + 72: 0x7272,
	}
	regs := [31]uint64{}
	for i := range regs {
		regs[i] = 0x1000000000000000 + uint64(i)*0x100
	}
	regs[0], regs[30] = initialX0, originalLR
	sp := callerSP
	word := func(index int) uint32 { return resolverWord(data, resolver, index) }

	frameBytes, ok := decodeSubSPImmediateForTest(word(0))
	if !ok || frameBytes != 80 {
		return result, fmt.Errorf("Logout resolver frame allocation=%d ok=%t", frameBytes, ok)
	}
	sp -= frameBytes
	for idx := 1; idx <= 5; idx++ {
		fields, ok := decodePair64OffsetForTest(word(idx))
		if !ok || fields.load || fields.rn != 31 || fields.offset < 0 {
			return result, fmt.Errorf("Logout save word[%d] is not STP on SP: %+v", idx, fields)
		}
		address := sp + uint64(fields.offset)
		stack[address] = pairRegisterValue(regs, fields.rt)
		stack[address+8] = pairRegisterValue(regs, fields.rt2)
	}

	dlsymPC := resolver.base + 8*4
	if target, link, ok := decodeArm64Branch(word(8), dlsymPC); !ok || !link || target != patchDlsymStubRVA {
		return result, fmt.Errorf("Logout dlsym target=0x%x link=%t ok=%t", target, link, ok)
	}
	for i := 0; i <= 18; i++ {
		regs[i] = 0xd15a000000000000 + uint64(i)
	}
	regs[0], regs[30] = 0xd15f000000000001, dlsymPC+4
	if rd, rm, ok := decodeMOVRegForTest(word(9)); !ok || rd != 16 || rm != 0 {
		return result, fmt.Errorf("Logout dlsym result move rd=%d rm=%d ok=%t", rd, rm, ok)
	}
	regs[16] = regs[0]
	if target, rt, ok := decodeArm64CBNZ(word(10), resolver.base+10*4); !ok ||
		rt != 16 || target != resolver.base+12*4 || regs[16] == 0 {
		return result, fmt.Errorf("Logout callback-ready branch target=0x%x rt=%d ok=%t", target, rt, ok)
	}
	if word(13)&0xfffffc1f != 0xd63f0000 || (word(13)>>5)&0x1f != 16 {
		return result, fmt.Errorf("Logout callback instruction is not BLR X16: 0x%08x", word(13))
	}
	for i := 0; i <= 18; i++ {
		regs[i] = 0xcbac000000000000 + uint64(i)
	}
	regs[0], regs[30] = 0, resolver.base+14*4

	for idx := resolver.restoreStart; idx < resolver.restoreStart+5; idx++ {
		fields, ok := decodePair64OffsetForTest(word(idx))
		if !ok || !fields.load || fields.rn != 31 || fields.offset < 0 {
			return result, fmt.Errorf("Logout restore word[%d] is not LDP on SP: %+v", idx, fields)
		}
		address := sp + uint64(fields.offset)
		restorePairRegister(&regs, fields.rt, stack[address])
		restorePairRegister(&regs, fields.rt2, stack[address+8])
	}
	stackBytes, ok := decodeAddSPImmediateForTest(word(resolver.stackAddIndex))
	if !ok || stackBytes != frameBytes {
		return result, fmt.Errorf("Logout resolver stack restore=%d ok=%t", stackBytes, ok)
	}
	sp += stackBytes
	if sp != callerSP {
		return result, fmt.Errorf("first resolver restore SP=0x%x, want 0x%x", sp, callerSP)
	}

	stockPC := resolver.base + uint64(resolver.tailBranchIndex*4)
	target, link, ok := decodeArm64Branch(word(resolver.tailBranchIndex), stockPC)
	if !ok || link || target != resolver.tailTarget {
		return result, fmt.Errorf("first stock cleanup target=0x%x link=%t ok=%t", target, link, ok)
	}
	result.cleanupCalls = 1
	result.firstStockX0, result.firstStockSP = regs[0], sp

	// Model stock cleanup's balanced frame and RET through the LR left by the
	// resolver. Its ordinary caller-saved X0 result is not relied upon.
	regs[0] = 0xcccccccc
	sp = callerSP
	result.firstReturnPC = regs[30]
	if result.firstReturnPC == originalLR {
		return result, nil
	}
	if result.firstReturnPC != resolver.base+14*4 {
		return result, fmt.Errorf("first cleanup returned to 0x%x, unexpected", result.firstReturnPC)
	}

	// The callback-return PC is the emitted LDP X0,X1,[SP] at index 14,
	// with no intervening SUB. Re-entering it on the synthetic caller stack
	// loads the zero first word into X0 and then restores/advances from that
	// unrelated frame as the emitted tail dictates.
	firstReload, ok := decodePair64OffsetForTest(word(14))
	result.reentryWasLDPX0X1 = ok && firstReload.load && firstReload.rt == 0 &&
		firstReload.rt2 == 1 && firstReload.rn == 31 && firstReload.offset == 0 &&
		!isSubSPImmediateForTest(word(14))
	if !result.reentryWasLDPX0X1 {
		return result, fmt.Errorf("callback-return PC 0x%x is not LDP X0,X1,[SP]", result.firstReturnPC)
	}
	for idx := 14; idx <= 18; idx++ {
		fields, ok := decodePair64OffsetForTest(word(idx))
		if !ok || !fields.load || fields.rn != 31 || fields.offset < 0 {
			return result, fmt.Errorf("re-entry restore word[%d] is not LDP on caller SP: %+v", idx, fields)
		}
		address := sp + uint64(fields.offset)
		restorePairRegister(&regs, fields.rt, stack[address])
		restorePairRegister(&regs, fields.rt2, stack[address+8])
	}
	result.reentryX0 = regs[0]
	stackBytes, ok = decodeAddSPImmediateForTest(word(19))
	if !ok || stackBytes != 80 {
		return result, fmt.Errorf("re-entry stack advance=%d ok=%t, want 80", stackBytes, ok)
	}
	sp += stackBytes
	secondPC := resolver.base + 20*4
	target, link, ok = decodeArm64Branch(word(20), secondPC)
	if !ok || link || target != resolver.tailTarget {
		return result, fmt.Errorf("second stock cleanup target=0x%x link=%t ok=%t", target, link, ok)
	}
	result.cleanupCalls++
	result.secondStockSP, result.secondStockX0, result.secondStockTarget = sp, regs[0], target
	return result, nil
}

type pair64OffsetFields struct {
	load        bool
	rt, rt2, rn uint32
	offset      int64
}

// This test-only decoder inspects the emitted A64 pair fields directly; it
// deliberately does not compare against any resolver word-generator output.
func decodePair64OffsetForTest(word uint32) (pair64OffsetFields, bool) {
	op := word & 0xffc00000
	if op != 0xa9000000 && op != 0xa9400000 {
		return pair64OffsetFields{}, false
	}
	imm7 := int64((word >> 15) & 0x7f)
	if imm7&0x40 != 0 {
		imm7 -= 0x80
	}
	return pair64OffsetFields{
		load:   op == 0xa9400000,
		rt:     word & 0x1f,
		rn:     (word >> 5) & 0x1f,
		rt2:    (word >> 10) & 0x1f,
		offset: imm7 * 8,
	}, true
}

func assertLRPairSemantics(data []byte, resolver lrResolverCase) error {
	store, ok := decodePair64OffsetForTest(resolverWord(data, resolver, 5))
	if !ok || store.load || store.rt != 8 || store.rt2 != 30 || store.rn != 31 || store.offset != 64 {
		return fmt.Errorf("%s LR save fields=%+v (decoded=%t), want STP Rt=8 Rt2=30 Rn=SP offset=64",
			resolver.name, store, ok)
	}
	load, ok := decodePair64OffsetForTest(resolverWord(data, resolver, resolver.restoreStart+4))
	if !ok || !load.load || load.rt != 8 || load.rt2 != 30 || load.rn != 31 || load.offset != 64 {
		return fmt.Errorf("%s LR restore fields=%+v (decoded=%t), want LDP Rt=8 Rt2=30 Rn=SP offset=64",
			resolver.name, load, ok)
	}
	return nil
}

// runEmittedResolverModel interprets only the bounded bridge path: its stack
// allocation and STP/LDP pairs come from emitted bytes, dlsym/callback calls
// clobber caller-saved registers, and the emitted stock B is followed by RET.
func runEmittedResolverModel(data []byte, resolver lrResolverCase) error {
	if resolver.base+uint64(resolver.wordCount*4) > uint64(len(data)) {
		return fmt.Errorf("%s resolver exceeds image", resolver.name)
	}
	word := func(index int) uint32 { return resolverWord(data, resolver, index) }

	regs := [31]uint64{}
	for i := range regs {
		regs[i] = 0x1000000000000000 + uint64(i)*0x101
	}
	const (
		initialSP = uint64(0x100000)
		initialLR = uint64(0xabcdef0012345678)
		initialX0 = uint64(0x1122334455667788)
	)
	sp := initialSP
	regs[0], regs[19], regs[30] = initialX0, 0x19191919, initialLR
	stack := map[uint64]uint64{}

	frameBytes, ok := decodeSubSPImmediateForTest(word(0))
	if !ok || frameBytes != 80 {
		return fmt.Errorf("%s frame allocation decodes to %d (ok=%t), want 80", resolver.name, frameBytes, ok)
	}
	sp -= frameBytes
	for idx := 1; idx <= 5; idx++ {
		fields, ok := decodePair64OffsetForTest(word(idx))
		if !ok || fields.load || fields.rn != 31 || fields.offset < 0 {
			return fmt.Errorf("%s save word[%d] is not STP [SP,#offset]: %+v", resolver.name, idx, fields)
		}
		address := sp + uint64(fields.offset)
		stack[address] = pairRegisterValue(regs, fields.rt)
		stack[address+8] = pairRegisterValue(regs, fields.rt2)
	}

	dlsymPC := resolver.base + 8*4
	if target, link, ok := decodeArm64Branch(word(8), dlsymPC); !ok || !link || target != patchDlsymStubRVA {
		return fmt.Errorf("%s emitted dlsym call target=0x%x link=%t ok=%t", resolver.name, target, link, ok)
	}
	// Simulate dlsym's caller-saved clobbers and its function-pointer result.
	for i := 0; i <= 18; i++ {
		regs[i] = 0xd15a000000000000 + uint64(i)
	}
	dlsymReturn := dlsymPC + 4
	regs[0], regs[30] = 0xd15f000000000001, dlsymReturn
	if rd, rm, ok := decodeMOVRegForTest(word(9)); !ok || rd != 16 || rm != 0 {
		return fmt.Errorf("%s dlsym result move decodes rd=%d rm=%d ok=%t", resolver.name, rd, rm, ok)
	}
	regs[16] = regs[0]
	cbnzTarget, cbnzReg, ok := decodeArm64CBNZ(word(10), resolver.base+10*4)
	if !ok || cbnzReg != 16 || cbnzTarget != resolver.base+12*4 || regs[16] == 0 {
		return fmt.Errorf("%s dlsym-ready branch target=0x%x rt=%d ok=%t", resolver.name, cbnzTarget, cbnzReg, ok)
	}

	if word(13)&0xfffffc1f != 0xd63f0000 || (word(13)>>5)&0x1f != 16 {
		return fmt.Errorf("%s callback instruction is not BLR X16 (0x%08x)", resolver.name, word(13))
	}
	// BLR returns from a callback that clobbers caller-saved X0-X18 and LR.
	callbackReturn := resolver.base + 14*4
	for i := 0; i <= 18; i++ {
		regs[i] = 0xcbac000000000000 + uint64(i)
	}
	regs[0], regs[30] = 0, callbackReturn

	for idx := resolver.restoreStart; idx < resolver.restoreStart+5; idx++ {
		fields, ok := decodePair64OffsetForTest(word(idx))
		if !ok || !fields.load || fields.rn != 31 || fields.offset < 0 {
			return fmt.Errorf("%s restore word[%d] is not LDP [SP,#offset]: %+v", resolver.name, idx, fields)
		}
		address := sp + uint64(fields.offset)
		restorePairRegister(&regs, fields.rt, stack[address])
		restorePairRegister(&regs, fields.rt2, stack[address+8])
	}
	stackBytes, ok := decodeAddSPImmediateForTest(word(resolver.stackAddIndex))
	if !ok || stackBytes != frameBytes {
		return fmt.Errorf("%s frame restore decodes to %d (ok=%t), want %d", resolver.name, stackBytes, ok, frameBytes)
	}
	sp += stackBytes
	if sp != initialSP || regs[30] != initialLR || regs[0] != initialX0 {
		return fmt.Errorf("%s bridge state SP=0x%x LR=0x%x X0=0x%x; want SP=0x%x LR=0x%x X0=0x%x",
			resolver.name, sp, regs[30], regs[0], initialSP, initialLR, initialX0)
	}

	pc := resolver.base + uint64(resolver.tailBranchIndex*4)
	target, link, ok := decodeArm64Branch(word(resolver.tailBranchIndex), pc)
	if !ok || link || target != resolver.tailTarget {
		return fmt.Errorf("%s stock continuation target=0x%x link=%t ok=%t", resolver.name, target, link, ok)
	}
	pc = target // execute the emitted direct B without changing LR
	// The direct stock B preserves LR; after the stock continuation eventually
	// returns, its RET must therefore select the original caller.
	pc = regs[30] // bounded model of the stock continuation's RET
	if pc != initialLR {
		return fmt.Errorf("%s stock RET target=0x%x, want original LR 0x%x", resolver.name, pc, initialLR)
	}
	return nil
}

func resolverWord(data []byte, resolver lrResolverCase, index int) uint32 {
	return binary.LittleEndian.Uint32(data[resolver.base+uint64(index*4):])
}

func putResolverWord(data []byte, resolver lrResolverCase, index int, word uint32) {
	binary.LittleEndian.PutUint32(data[resolver.base+uint64(index*4):], word)
}

func pairRegisterValue(regs [31]uint64, reg uint32) uint64 {
	if reg == 31 {
		return 0
	}
	return regs[reg]
}

func restorePairRegister(regs *[31]uint64, reg uint32, value uint64) {
	if reg != 31 {
		regs[reg] = value
	}
}

func decodeSubSPImmediateForTest(word uint32) (uint64, bool) {
	if word&0xffc003ff != 0xd10003ff {
		return 0, false
	}
	return uint64((word >> 10) & 0xfff), true
}

func decodeAddSPImmediateForTest(word uint32) (uint64, bool) {
	if word&0xffc003ff != 0x910003ff {
		return 0, false
	}
	return uint64((word >> 10) & 0xfff), true
}

func isSubSPImmediateForTest(word uint32) bool {
	_, ok := decodeSubSPImmediateForTest(word)
	return ok
}

func decodeMOVRegForTest(word uint32) (rd, rm uint32, ok bool) {
	if word&0xffe0ffe0 != 0xaa0003e0 {
		return 0, 0, false
	}
	return word & 0x1f, (word >> 16) & 0x1f, true
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
	if err := verifyReauthInstructions(prepared, out1); err != nil {
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
	if gotAutoWord != autoGuestEntryPatchedWord {
		t.Fatalf("patched auto-guest-entry word = 0x%08x, want 0x%08x", gotAutoWord, autoGuestEntryPatchedWord)
	}
	if target, link, ok := decodeArm64Branch(gotAutoWord, autoGuestEntryRVA); !ok || link || target != loginReadyResolverRVA {
		t.Fatalf("decoded patched auto-guest-entry = (0x%x, link=%t, ok=%t), want (%#x, link=false, ok=true)",
			target, link, ok, loginReadyResolverRVA)
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

	for _, guard := range reauthGuardWindows {
		end := guard.start + uint64(len(guard.words))*4
		mutation := guard.start
		if mutation >= guard.patchRVA && mutation < guard.patchRVA+4 {
			mutation = guard.patchRVA + 4
		}
		if mutation >= end {
			mutation = guard.patchRVA
		}
		badGuard := append([]byte(nil), prepared...)
		badGuard[mutation] ^= 1
		if _, err := emitAllPatches(badGuard); err == nil {
			t.Fatalf("accepted mutated %s guard at 0x%x", guard.name, mutation)
		}
	}

	for _, tc := range []struct {
		name   string
		site   uint64
		target uint64
		link   bool
	}{
		{"legacy login visibility", legacyLoginVisibilityRVA, legacyLoginResolverRVA, false},
		{"login-ready", autoGuestEntryRVA, loginReadyResolverRVA, false},
		{"Logout reset", sessionOutSuccessRVA, sessionOutResolverRVA, false},
		{"direct Delete Avatar reset", deleteDirectSuccessRVA, deleteDirectResolverRVA, false},
		{"SNS Delete Avatar reset", deleteSNSuccessRVA, deleteSNSResolverRVA, false},
		{"checkSession error", checkSessionErrorEntryRVA, checkSessionResolverRVA, false},
		{"guest-generate error", guestGenerateErrorTailRVA, guestGenerateResolverRVA, false},
		{"case 10043 GDPR-ready", gdprLoginReadyCallsiteRVA, gdprLoginReadyResolverRVA, true},
	} {
		t.Run("reauth branch "+tc.name, func(t *testing.T) {
			word := binary.LittleEndian.Uint32(out1[tc.site:])
			target, link, ok := decodeArm64Branch(word, tc.site)
			if !ok || link != tc.link || target != tc.target {
				t.Fatalf("branch=(0x%x, link=%t, ok=%t), want branch 0x%x (link=%t)", target, link, ok, tc.target, tc.link)
			}
			found := false
			for _, r := range patchCallsiteRanges() {
				if r.start == tc.site && r.end == tc.site+4 {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("patchCallsiteRanges missing exact [%#x,%#x) branch window", tc.site, tc.site+4)
			}
		})
	}
	for _, site := range []uint64{
		legacyLoginVisibilityRVA,
		sessionOutSuccessRVA,
		deleteDirectSuccessRVA,
		deleteSNSuccessRVA,
		checkSessionErrorEntryRVA,
		guestGenerateErrorTailRVA,
		gdprLoginReadyCallsiteRVA,
	} {
		for _, adj := range []uint64{site - 1, site + 4} {
			badAdj := append([]byte(nil), out1...)
			badAdj[adj] ^= 1
			if err := verifyPatchOnlyDelta(prepared, badAdj); err == nil {
				t.Fatalf("verifyPatchOnlyDelta accepted adjacent re-auth mutation at 0x%x", adj)
			}
			if err := verifyFullWriteSet(prepared, badAdj); err == nil {
				t.Fatalf("verifyFullWriteSet accepted adjacent re-auth mutation at 0x%x", adj)
			}
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
	case10043Guard := []uint32{0x52800021, gdprLoginReadyOrigWord, 0xf940ce60, 0xf9400008}
	for i, want := range case10043Guard {
		off := uint64(0x53c430 + i*4)
		if got := binary.LittleEndian.Uint32(original[off:]); got != want {
			t.Fatalf("locked source case-10043 word at 0x%x = 0x%08x, want 0x%08x", off, got, want)
		}
	}
	if target, link, ok := decodeArm64Branch(case10043Guard[1], gdprLoginReadyCallsiteRVA); !ok || !link || target != 0x538db8 {
		t.Fatalf("locked source case-10043 instruction decodes to 0x%x (link=%t ok=%t), want BL 0x538db8",
			target, link, ok)
	}
	case10043Hook := binary.LittleEndian.Uint32(out1[gdprLoginReadyCallsiteRVA:])
	if target, link, ok := decodeArm64Branch(case10043Hook, gdprLoginReadyCallsiteRVA); !ok || !link || target != gdprLoginReadyResolverRVA {
		t.Fatalf("patched case-10043 instruction decodes to 0x%x (link=%t ok=%t), want BL 0x%x",
			target, link, ok, gdprLoginReadyResolverRVA)
	}
	if !bytes.Equal(original[0x53c438:0x53c440], out1[0x53c438:0x53c440]) {
		t.Fatal("case-10043 BL continuation at 0x53c438..0x53c440 was modified")
	}
	gdprResolver := out1[gdprLoginReadyResolverRVA:]
	for idx, want := range map[int]uint32{
		0:  0xd10043ff, // save stack frame
		1:  0xf90003fe, // save BL return address
		8:  0x52800020, // uint32 source mode = 1
		10: 0xf94003fe, // restore BL return address
		11: 0x910043ff, // restore stack pointer
		12: 0xd65f03c0, // return to 0x53c438
	} {
		if got := binary.LittleEndian.Uint32(gdprResolver[uint64(idx*4):]); got != want {
			t.Fatalf("GDPR-ready resolver word[%d] = 0x%08x, want 0x%08x", idx, got, want)
		}
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
	if got := binary.LittleEndian.Uint32(out1[0x53af68:]); got != autoGuestEntryPatchedWord {
		t.Fatalf("patched word at 0x53af68 = 0x%08x, want 0x%08x", got, autoGuestEntryPatchedWord)
	} else if target, link, ok := decodeArm64Branch(got, 0x53af68); !ok || link || target != loginReadyResolverRVA {
		t.Fatalf("patched branch at 0x53af68 = (0x%x, link=%t, ok=%t)", target, link, ok)
	}
	if bytes.Equal(original[0x53af68:0x53af6c], out1[0x53af68:0x53af6c]) {
		t.Fatal("expected login-ready branch word at [0x53af68,0x53af6c) to change")
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
	t.Logf("verified in memory: baseline=%x patched=%x size=%d (10 exports + re-auth resolvers/callsites + existing runtime patches + loader)",
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
	for _, w := range reauthGuardWindows {
		writeWords(buf[w.start:], w.words)
	}
	return buf
}
