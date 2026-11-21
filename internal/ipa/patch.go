package ipa

import (
	"bytes"
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
)

// Exported dylib symbol names resolved via RTLD_DEFAULT dlsym at runtime.
const (
	ExportNotice404DiagnosticEntry = "rb_ios_notice_404_diagnostic_entry"
	ExportGetaddrinfo              = "rb_ios_getaddrinfo"
	ExportFreeaddrinfo             = "rb_ios_freeaddrinfo"
	ExportGethostbyname            = "rb_ios_gethostbyname"
	ExportConnect                  = "rb_ios_connect"
	ExportGuestUniqueCode          = "rb_ios_guest_unique_code"
	ExportLoginReady               = "rb_ios_on_login_ready"
	ExportSessionReset             = "rb_ios_on_session_reset"
	ExportCheckSessionError        = "rb_ios_on_check_session_error"
	ExportGuestGenerateError       = "rb_ios_on_guest_generate_error"
)

const (
	patchBaselineNcmds    = uint32(76)
	patchBaselineCmdSize  = uint32(8248)
	patchLoaderNcmds      = uint32(77)
	patchLoaderCmdSize    = uint32(8320)
	patchLoaderCommandOff = uint64(0x2058)
	patchLoaderHeaderEnd  = uint64(0x20a0)
	patchFirstTextSection = uint64(0x555c)

	patchSlackWindowStart = uint64(0x3000)
	patchSlackWindowEnd   = uint64(0x4000)

	noticeCallsiteRVA      = uint64(0x12d8be4)
	noticeContinuationRVA  = noticeCallsiteRVA + 4
	originalObjcMsgSendRVA = uint64(0x1ac21f8)
	originalNoticeCallWord = uint32(0x941fa585)

	autoGuestEntryRVA         = uint64(0x53af68)
	autoGuestEntryOrigTarget  = uint64(0x538db8)
	autoGuestEntryOrigWord    = uint32(0x17fff794) // b 0x100538db8
	autoGuestEntryPatchedWord = uint32(0x17eb21b6) // b loginReadyResolverRVA

	legacyLoginVisibilityRVA      = uint64(0x538de4)
	legacyLoginVisibilityOrigWord = uint32(0xaa0103f4) // mov x20, x1

	gdprLoginReadyCallsiteRVA = uint64(0x53c434)
	gdprLoginReadyOrigWord    = uint32(0x97fff261) // bl sub_100538DB8

	sessionOutSuccessRVA       = uint64(0x6af020)
	deleteDirectSuccessRVA     = uint64(0x6b39bc)
	deleteSNSuccessRVA         = uint64(0xbdf494)
	checkSessionErrorEntryRVA  = uint64(0x6ae0c8)
	guestGenerateErrorTailRVA  = uint64(0x6b2a54)
	guestGenerateDialogTailRVA = uint64(0x6b2a58)

	guestGenerateRVA = uint64(0x6bdd4c)

	patchDlsymStubRVA = uint64(0x1ac1748)
	dlsymImportName   = "_dlsym"
	dlsymPtrVA        = uint64(0x101d40208)

	// Verified RX zero-slack layout inside 0x3000..0x3FFF (all 4-byte aligned).
	noticeResolverRVA        = uint64(0x3000)
	noticeExportRVA          = uint64(0x3080)
	getaddrinfoResolverRVA   = uint64(0x3100)
	getaddrinfoExportRVA     = uint64(0x3180)
	freeaddrinfoResolverRVA  = uint64(0x3200)
	freeaddrinfoExportRVA    = uint64(0x3280)
	gethostbynameResolverRVA = uint64(0x3300)
	gethostbynameExportRVA   = uint64(0x3380)
	connectResolverRVA       = uint64(0x3400)
	connectExportRVA         = uint64(0x3480)
	guestResolverRVA         = uint64(0x3500)
	guestExportRVA           = uint64(0x3580)

	legacyLoginResolverRVA    = uint64(0x3600)
	loginReadyResolverRVA     = uint64(0x3640)
	loginReadyExportRVA       = uint64(0x3680)
	gdprLoginReadyResolverRVA = uint64(0x3b40)
	sessionOutResolverRVA     = uint64(0x3700)
	sessionResetExportRVA     = uint64(0x3780)
	deleteDirectResolverRVA   = uint64(0x3800)
	deleteSNSResolverRVA      = uint64(0x38c0)
	checkSessionResolverRVA   = uint64(0x3980)
	checkSessionExportRVA     = uint64(0x3a00)
	guestGenerateResolverRVA  = uint64(0x3a40)
	guestGenerateExportRVA    = uint64(0x3b00)

	noticeResolverWordCount         = 16
	stubResolverWordCount           = 15
	guestResolverWordCount          = 18
	loginReadyResolverWordCount     = 13
	gdprLoginReadyResolverWordCount = 13
	sessionResetResolverWordCount   = 21
	checkSessionResolverWordCount   = 22
	guestGenerateResolverWordCount  = 26

	// Verified __TEXT,__stubs entries for socket/DNS interposition.
	stubConnectRVA       = uint64(0x1ac149c)
	stubFreeaddrinfoRVA  = uint64(0x1ac1874)
	stubGetaddrinfoRVA   = uint64(0x1ac1904)
	stubGethostbynameRVA = uint64(0x1ac1928)

	patchTextVMAddr   = uint64(0x100000000)
	patchTextVMSize   = uint64(0x1d38000)
	patchStubsFileOff = uint64(0x1abee50)
	patchStubsSize    = uint64(0x3ba0)
	patchStubsLen     = uint32(12)

	patchDataVMAddr      = uint64(0x101d38000)
	patchDataVMSize      = uint64(0xc94000)
	patchDataFileOff     = uint64(0x1d38000)
	patchDataFileLen     = uint64(0x4e8000)
	patchGotSectionAddr  = uint64(0x101d38000)
	patchGotSectionOff   = uint64(0x1d38000)
	patchGotSectionSize  = uint64(0x66b8)
	patchLaSymPtrAddr    = uint64(0x101d3e6b8)
	patchLaSymPtrFileOff = uint64(0x1d3e6b8)
	patchLaSymPtrSize    = uint64(0x27c0)
	patchLinkVMAddr      = uint64(0x1029cc000)
	patchLinkVMSize      = uint64(0x4f4000)
	patchLinkFileOff     = uint64(0x2220000)
	patchLinkFileLen     = uint64(0x4f24c0)
	patchSignatureOff    = uint64(0x2615c60)
	patchSignatureSize   = uint64(0xfc860)

	sectionNonLazyPtr = uint32(0x6)
	sectionLazyPtr    = uint32(0x7)
)

// stockContinuation is MOV X29,X29; BL _objc_retainAutoreleasedReturnValue; MOV X20,X0.
var stockContinuation = [...]byte{
	0xfd, 0x03, 0x1d, 0xaa,
	0x9b, 0xa5, 0x1f, 0x94,
	0xf4, 0x03, 0x00, 0xaa,
}

// guestGeneratePrologueWords is the verified 7-word prologue of sub_1006BDD4C.
var guestGeneratePrologueWords = [7]uint32{
	0xd102c3ff,
	0xa90857f6,
	0xa9094ff4,
	0xa90a7bfd,
	0x910283fd,
	0xaa0103f4,
	0xaa0003f3,
}

type guardWindowSpec struct {
	name      string
	start     uint64
	unchanged uint64
	words     []uint32
}

var autoGuestGuardWindows = []guardWindowSpec{
	{
		name:      "SetEndLoading entry prologue",
		start:     0x53ad08,
		unchanged: 0x53ad28,
		words: []uint32{
			0xa9be4ff4, 0xa9017bfd, 0x910043fd, 0xaa0003f3,
			0x944d50ad, 0x944d5b64, 0xf940c668, 0xb40010c8,
		},
	},
	{
		name:      "avcookie.na check",
		start:     0x53ade0,
		unchanged: 0x53adf0,
		words: []uint32{
			0x97f43f7c, 0x940c0b08, 0x34000320, 0x940d7951,
		},
	},
	{
		name:      "cookie-present CheckAutoLogin tail",
		start:     0x53ae3c,
		unchanged: 0x53ae4c,
		words: []uint32{
			0xaa1303e0, 0xa9417bfd, 0xa8c24ff4, 0x17fffac2,
		},
	},
	{
		name:      "US COPPA check",
		start:     0x53aee0,
		unchanged: 0x53aef8,
		words: []uint32{
			0x940d7914, 0x940d7d12, 0x34000300,
			0x940d7911, 0x940d7d06, 0x340002a0,
		},
	},
	{
		name:      "SetEndLoading eligible tail",
		start:     0x53af48,
		unchanged: 0x53af68,
		words: []uint32{
			0x941c21b0, 0x941c2bbf, 0x944d501f, 0x944d5816,
			0xaa1303e0, 0x52800021, 0xa9417bfd, 0xa8c24ff4,
			0x17fff794,
		},
	},
	{
		name:      "createGuestAccount body",
		start:     0xbfe388,
		unchanged: 0xbfe3b8,
		words: []uint32{
			0xa9be4ff4, 0xa9017bfd, 0x910043fd, 0xd00089c8,
			0xf9453108, 0xf9400113, 0x9432430b, 0x9432495f,
			0xaa0003e1, 0xaa1303e0, 0xa9417bfd, 0xa8c24ff4,
			0x17eafe65,
		},
	},
}

type reauthGuardSpec struct {
	name     string
	start    uint64
	patchRVA uint64
	link     bool
	words    []uint32
}

// These source words are from the hash-locked LINEPlay_Store image. Each
// re-auth trampoline replaces only patchRVA; all other words remain stock.
var reauthGuardWindows = []reauthGuardSpec{
	{
		name:     "legacy login visibility helper",
		start:    0x538db8,
		patchRVA: legacyLoginVisibilityRVA,
		words: []uint32{
			0xd10143ff, 0x6d0123e9, 0xa90257f6, 0xa9034ff4,
			0xa9047bfd, 0x910103fd, 0xaa0003f3, 0xf940c400,
			0xb40009e0, 0xf940ca68, 0xb40009a8, 0xaa0103f4,
			0x7100003f, 0x1e2703e0, 0x1e2e1001, 0x1e201c28,
		},
	},
	{
		name:     "Logout sessionout success",
		start:    0x6aeff8,
		patchRVA: sessionOutSuccessRVA,
		words: []uint32{
			0xa9bf7bfd, 0x910003fd, 0xaa0303e0, 0x9000a6a1,
			0x9105c421, 0x9448b69f, 0x9448b562, 0x34000080,
			0x9407a8c6, 0xa8c17bfd, 0x1407af39, 0xa8c17bfd,
			0xd65f03c0,
		},
	},
	{
		name:     "SNS Delete Avatar success",
		start:    0xbdf478,
		patchRVA: deleteSNSuccessRVA,
		words: []uint32{
			0xaa1303e0, 0x9433f583, 0x9433f446, 0x340000a0,
			0x97f2e7aa, 0xa9417bfd, 0xa8c24ff4, 0x17f2ef6a,
			0xa9417bfd, 0xa8c24ff4, 0xd65f03c0,
		},
	},
	{
		name:     "direct Delete Avatar success",
		start:    0x6b398c,
		patchRVA: deleteDirectSuccessRVA,
		words: []uint32{
			0xa9bf7bfd, 0x910003fd, 0xaa0303e0, 0x9000a681,
			0x9105c421, 0x9448a43a, 0x9448a2fd, 0x340000c0,
			0x940a2f61, 0x940a313d, 0x9407965f, 0xa8c17bfd,
			0x14079cd2, 0xa8c17bfd, 0xd65f03c0,
		},
	},
	{
		name:     "checkSession failure entry",
		start:    checkSessionErrorEntryRVA,
		patchRVA: checkSessionErrorEntryRVA,
		words: []uint32{
			0xa9bd57f6, 0xa9014ff4, 0xa9027bfd, 0x910083fd,
			0xaa0303f3, 0xaa0003f4, 0xd000b448, 0xf9438108,
			0xf9400100, 0xb9402281, 0x94254876,
		},
	},
	{
		name:     "guest/generate failure handler",
		start:    0x6b29e0,
		patchRVA: guestGenerateErrorTailRVA,
		words: []uint32{
			0xa9be4ff4, 0xa9017bfd, 0x910043fd, 0xaa0303f3,
			0xd000b428, 0xf9438108, 0xf9400108, 0xb9402001,
			0xaa0803e0, 0x94253631, 0x52800028, 0x39030268,
			0xaa1303e0, 0x97e7a1ed, 0xb9407268, 0x711f751f,
			0x5284eba8, 0x52840da9, 0x1a880128, 0x7100001f,
			0x5284f249, 0x1a881120, 0x52800021, 0xd2800002,
			0x52800003, 0x12800004, 0x52800005, 0x52800006,
			0x52800007, 0xa9417bfd, 0xa8c24ff4, 0x140f44bd,
		},
	},
	{
		name:     "case 10043 GDPR-ready branch",
		start:    0x53c430,
		patchRVA: gdprLoginReadyCallsiteRVA,
		link:     true,
		words: []uint32{
			0x52800021, gdprLoginReadyOrigWord, 0xf940ce60, 0xf9400008,
		},
	},
}

type guestCallsiteSpec struct {
	name        string
	callsiteRVA uint64
	origWord    uint32
	link        bool
	prefixStart uint64
	prefixWords []uint32
	suffixStart uint64
	suffixWords []uint32
}

var guestCallsiteSpecs = []guestCallsiteSpec{
	{
		name:        "callsite1",
		callsiteRVA: 0x53bc98,
		origWord:    0x9406082d, // bl 0x1006bdd4c
		link:        true,
		prefixStart: 0x53bc8c,
		prefixWords: []uint32{
			0x944d5325, // bl 0x101890920
			0xaa0003e1, // mov x1, x0
			0xaa1403e0, // mov x0, x20
		},
		suffixStart: 0x53bc9c,
		suffixWords: []uint32{
			0x140001db, // b 0x10053c408
		},
	},
	{
		name:        "callsite2",
		callsiteRVA: 0xbfe3b8,
		origWord:    0x17eafe65, // b 0x1006bdd4c
		link:        false,
		prefixStart: 0xbfe3a4,
		prefixWords: []uint32{
			0x9432495f, // bl 0x101890920
			0xaa0003e1, // mov x1, x0
			0xaa1303e0, // mov x0, x19
			0xa9417bfd, // ldp x29, x30, [sp, #0x10]
			0xa8c24ff4, // ldp x20, x19, [sp], #0x20
		},
	},
	{
		name:        "callsite3",
		callsiteRVA: 0xd1ba00,
		origWord:    0x17e688d3, // b 0x1006bdd4c
		link:        false,
		prefixStart: 0xd1b9ec,
		prefixWords: []uint32{
			0x942dd3cd, // bl 0x101890920
			0xaa0003e1, // mov x1, x0
			0xaa1303e0, // mov x0, x19
			0xa9417bfd, // ldp x29, x30, [sp, #0x10]
			0xa8c24ff4, // ldp x20, x19, [sp], #0x20
		},
	},
}

type stubRouteSpec struct {
	name          string
	importSym     string
	exportSym     string
	stubRVA       uint64
	resolverRVA   uint64
	exportRVA     uint64
	expectedPtrVA uint64
	expectedWords [3]uint32
}

var socketStubSpecs = []stubRouteSpec{
	{
		name:          "getaddrinfo",
		importSym:     "_getaddrinfo",
		exportSym:     ExportGetaddrinfo,
		stubRVA:       stubGetaddrinfoRVA,
		resolverRVA:   getaddrinfoResolverRVA,
		exportRVA:     getaddrinfoExportRVA,
		expectedPtrVA: 0x101d40330,
		expectedWords: [3]uint32{0xf00013f0, 0xf9419a10, 0xd61f0200},
	},
	{
		name:          "freeaddrinfo",
		importSym:     "_freeaddrinfo",
		exportSym:     ExportFreeaddrinfo,
		stubRVA:       stubFreeaddrinfoRVA,
		resolverRVA:   freeaddrinfoResolverRVA,
		exportRVA:     freeaddrinfoExportRVA,
		expectedPtrVA: 0x101d402d0,
		expectedWords: [3]uint32{0xf00013f0, 0xf9416a10, 0xd61f0200},
	},
	{
		name:          "gethostbyname",
		importSym:     "_gethostbyname",
		exportSym:     ExportGethostbyname,
		stubRVA:       stubGethostbynameRVA,
		resolverRVA:   gethostbynameResolverRVA,
		exportRVA:     gethostbynameExportRVA,
		expectedPtrVA: 0x101d40348,
		expectedWords: [3]uint32{0xf00013f0, 0xf941a610, 0xd61f0200},
	},
	{
		name:          "connect",
		importSym:     "_connect",
		exportSym:     ExportConnect,
		stubRVA:       stubConnectRVA,
		resolverRVA:   connectResolverRVA,
		exportRVA:     connectExportRVA,
		expectedPtrVA: 0x101d40040,
		expectedWords: [3]uint32{0xf00013f0, 0xf9402210, 0xd61f0200},
	},
}

type byteRange struct {
	start uint64
	end   uint64
	name  string
}

type patchLoadCommand struct {
	cmd  uint32
	off  uint64
	size uint64
	raw  []byte
}

type patchImageSection struct {
	name, segment            string
	addr, size, fileoff      uint64
	flags, indirect, stubLen uint32
}

type patchImageSegment struct {
	name                              string
	vmaddr, vmsize, fileoff, filesize uint64
	maxprot, initprot, nsects         uint32
	sections                          []patchImageSection
}

// PatchMainExecutable verifies the locked LINEPlay_Store baseline in memory and
// returns a new patched executable byte slice with the dylib loader, notice
// resolver, socket/DNS and guest-auth routes, and session re-auth callsites.
// It does not touch disk.
func PatchMainExecutable(original []byte) ([]byte, error) {
	if int64(len(original)) != MainSize {
		return nil, fmt.Errorf("%w: size %d", ErrBaseline, len(original))
	}
	sum := sha256.Sum256(original)
	if got := hex.EncodeToString(sum[:]); got != MainSHA256 {
		return nil, fmt.Errorf("%w: sha256 %s", ErrBaseline, got)
	}
	if err := validateBaselineImage(original); err != nil {
		return nil, err
	}

	withLoader, err := AddLoader(original)
	if err != nil {
		return nil, fmt.Errorf("ipa: patch: AddLoader: %w", err)
	}
	if err := verifyLoaderOnlyDelta(original, withLoader); err != nil {
		return nil, err
	}
	if err := validateMachOLayout(withLoader, patchLoaderNcmds, patchLoaderCmdSize, true); err != nil {
		return nil, err
	}

	out, err := emitAllPatches(withLoader)
	if err != nil {
		return nil, err
	}
	if err := verifyPatchedMachO(original, withLoader, out); err != nil {
		return nil, err
	}
	return out, nil
}

func validateBaselineImage(data []byte) error {
	if err := validateMachOLayout(data, patchBaselineNcmds, patchBaselineCmdSize, false); err != nil {
		return err
	}
	if err := validateNoticeCallsite(data); err != nil {
		return err
	}
	if err := validateGuestAuthTargets(data); err != nil {
		return err
	}
	if err := validateAutoGuestEntry(data); err != nil {
		return err
	}
	if err := validateReauthTargets(data); err != nil {
		return err
	}
	if !allZero(data[patchLoaderCommandOff:patchFirstTextSection]) {
		return errors.New("ipa: patch: baseline RX header slack is not zero")
	}
	return nil
}

func validateNoticeCallsite(data []byte) error {
	if noticeCallsiteRVA+4+uint64(len(stockContinuation)) > uint64(len(data)) {
		return errors.New("ipa: patch: notice callsite guard window is outside the image")
	}
	if got := binary.LittleEndian.Uint32(data[noticeCallsiteRVA:]); got != originalNoticeCallWord {
		return fmt.Errorf("ipa: patch: original notice call word mismatch: 0x%08x", got)
	}
	target, link, ok := decodeArm64Branch(originalNoticeCallWord, noticeCallsiteRVA)
	if !ok || !link || target != originalObjcMsgSendRVA {
		return fmt.Errorf("ipa: patch: notice callsite is not BL _objc_msgSend (target 0x%x)", target)
	}
	if !bytes.Equal(data[noticeContinuationRVA:noticeContinuationRVA+uint64(len(stockContinuation))], stockContinuation[:]) {
		return errors.New("ipa: patch: stock ARC continuation guard mismatch")
	}
	return nil
}

func validateGuestAuthTargets(data []byte) error {
	if err := validateGuestPrologue(data); err != nil {
		return err
	}
	for _, spec := range guestCallsiteSpecs {
		if err := validateGuestCallsiteGuards(data, spec); err != nil {
			return err
		}
		gotWord := binary.LittleEndian.Uint32(data[spec.callsiteRVA:])
		if gotWord != spec.origWord {
			return fmt.Errorf("ipa: patch: %s baseline word 0x%08x != expected 0x%08x", spec.name, gotWord, spec.origWord)
		}
		target, link, ok := decodeArm64Branch(gotWord, spec.callsiteRVA)
		if !ok || link != spec.link || target != guestGenerateRVA {
			return fmt.Errorf("ipa: patch: %s baseline branch target 0x%x (link=%t, ok=%t)", spec.name, target, link, ok)
		}
	}
	return nil
}

func validateGuestPrologue(data []byte) error {
	prologueBytes := uint64(len(guestGeneratePrologueWords)) * 4
	if guestGenerateRVA+prologueBytes > uint64(len(data)) {
		return errors.New("ipa: patch: sub_1006BDD4C prologue exceeds image bounds")
	}
	if !bytes.Equal(data[guestGenerateRVA:guestGenerateRVA+prologueBytes], encodeWords(guestGeneratePrologueWords[:])) {
		return errors.New("ipa: patch: sub_1006BDD4C prologue mismatch")
	}
	return nil
}

func validateGuestCallsiteGuards(data []byte, spec guestCallsiteSpec) error {
	prefixEnd := spec.prefixStart + uint64(len(spec.prefixWords))*4
	if spec.callsiteRVA+4 > uint64(len(data)) || prefixEnd != spec.callsiteRVA {
		return fmt.Errorf("ipa: patch: %s prefix window mismatch", spec.name)
	}
	if !bytes.Equal(data[spec.prefixStart:prefixEnd], encodeWords(spec.prefixWords)) {
		return fmt.Errorf("ipa: patch: %s prefix guard mismatch", spec.name)
	}
	if len(spec.suffixWords) > 0 {
		suffixEnd := spec.suffixStart + uint64(len(spec.suffixWords))*4
		if spec.suffixStart != spec.callsiteRVA+4 || suffixEnd > uint64(len(data)) {
			return fmt.Errorf("ipa: patch: %s suffix window mismatch", spec.name)
		}
		if !bytes.Equal(data[spec.suffixStart:suffixEnd], encodeWords(spec.suffixWords)) {
			return fmt.Errorf("ipa: patch: %s suffix guard mismatch", spec.name)
		}
	}
	return nil
}

func validateAutoGuestEntry(data []byte) error {
	for _, w := range autoGuestGuardWindows {
		end := w.start + uint64(len(w.words))*4
		if end > uint64(len(data)) {
			return fmt.Errorf("ipa: patch: auto-guest-entry %s window exceeds image bounds", w.name)
		}
		if !bytes.Equal(data[w.start:end], encodeWords(w.words)) {
			return fmt.Errorf("ipa: patch: auto-guest-entry %s guard mismatch", w.name)
		}
	}
	if autoGuestEntryRVA+4 > uint64(len(data)) {
		return errors.New("ipa: patch: auto-guest-entry patch site exceeds image bounds")
	}
	gotWord := binary.LittleEndian.Uint32(data[autoGuestEntryRVA:])
	if gotWord != autoGuestEntryOrigWord {
		return fmt.Errorf("ipa: patch: auto-guest-entry baseline word 0x%08x != expected 0x%08x", gotWord, autoGuestEntryOrigWord)
	}
	target, link, ok := decodeArm64Branch(gotWord, autoGuestEntryRVA)
	if !ok || link || target != autoGuestEntryOrigTarget {
		return fmt.Errorf("ipa: patch: auto-guest-entry baseline branch target 0x%x (link=%t, ok=%t)", target, link, ok)
	}
	return nil
}

func validateReauthTargets(data []byte) error {
	for _, guard := range reauthGuardWindows {
		end := guard.start + uint64(len(guard.words))*4
		if end < guard.start || end > uint64(len(data)) {
			return fmt.Errorf("ipa: patch: %s guard window exceeds image bounds", guard.name)
		}
		if !bytes.Equal(data[guard.start:end], encodeWords(guard.words)) {
			return fmt.Errorf("ipa: patch: %s guard mismatch", guard.name)
		}
		if guard.patchRVA < guard.start || guard.patchRVA+4 > end {
			return fmt.Errorf("ipa: patch: %s patch target is outside its guard window", guard.name)
		}
	}
	if got := binary.LittleEndian.Uint32(data[legacyLoginVisibilityRVA:]); got != legacyLoginVisibilityOrigWord {
		return fmt.Errorf("ipa: patch: legacy login visibility word 0x%08x != expected 0x%08x",
			got, legacyLoginVisibilityOrigWord)
	}

	type originalBranch struct {
		name   string
		rva    uint64
		word   uint32
		target uint64
		link   bool
	}
	for _, branch := range []originalBranch{
		{"Logout sessionout success", sessionOutSuccessRVA, 0x1407af39, 0x89ad04, false},
		{"direct Delete Avatar success", deleteDirectSuccessRVA, 0x14079cd2, 0x89ad04, false},
		{"SNS Delete Avatar success", deleteSNSuccessRVA, 0x17f2ef6a, 0x89b23c, false},
		{"case 10043 GDPR-ready", gdprLoginReadyCallsiteRVA, gdprLoginReadyOrigWord, 0x538db8, true},
	} {
		got := binary.LittleEndian.Uint32(data[branch.rva:])
		target, link, ok := decodeArm64Branch(got, branch.rva)
		if got != branch.word || !ok || link != branch.link || target != branch.target {
			return fmt.Errorf("ipa: patch: %s branch mismatch (word=0x%08x target=0x%x link=%t)",
				branch.name, got, target, link)
		}
	}
	return nil
}

func autoGuestEntryBranchWord() (uint32, error) {
	word, err := encodeArm64Branch(autoGuestEntryRVA, loginReadyResolverRVA, false)
	if err != nil {
		return 0, fmt.Errorf("ipa: patch: auto-guest-entry branch: %w", err)
	}
	if word != autoGuestEntryPatchedWord {
		return 0, fmt.Errorf("ipa: patch: login-ready branch word 0x%08x != expected 0x%08x", word, autoGuestEntryPatchedWord)
	}
	return word, nil
}

func validateMachOLayout(data []byte, wantNcmds, wantCmdSize uint32, expectLoader bool) error {
	if int64(len(data)) != MainSize {
		return fmt.Errorf("ipa: patch: image size mismatch: %d", len(data))
	}
	if err := validateMachHeader(data, wantNcmds, wantCmdSize); err != nil {
		return fmt.Errorf("ipa: patch: Mach-O header: %w", err)
	}
	cmds, err := parseLoadCommands(data)
	if err != nil {
		return err
	}
	if expectLoader {
		if len(cmds) != int(patchLoaderNcmds) || cmds[len(cmds)-1].off != patchLoaderCommandOff ||
			cmds[len(cmds)-1].size != 72 || !bytes.Equal(cmds[len(cmds)-1].raw, loaderCommand()) {
			return errors.New("ipa: patch: exact post-AddLoader command layout mismatch")
		}
	}

	var (
		loaderCount, signatureCount, encryptionCount int
		gotSignatureOff, gotSignatureSize            uint64
		segments                                     []patchImageSegment
	)
	for _, c := range cmds {
		switch c.cmd {
		case lcSegment64:
			seg, err := parseSegment64(c.raw)
			if err != nil {
				return err
			}
			segments = append(segments, seg)
		case lcLoadDylib, lcLoadWeakDylib, lcReexportDylib, lcLoadUpwardDylib:
			name, err := dylibName(c.raw, binary.LittleEndian)
			if err != nil {
				return err
			}
			if name == LoaderPath {
				loaderCount++
			}
		case lcCodeSignature:
			if len(c.raw) < 16 {
				return errors.New("ipa: patch: truncated LC_CODE_SIGNATURE")
			}
			signatureCount++
			gotSignatureOff = uint64(binary.LittleEndian.Uint32(c.raw[8:]))
			gotSignatureSize = uint64(binary.LittleEndian.Uint32(c.raw[12:]))
		case lcEncryptionInfo64:
			if len(c.raw) < 24 || binary.LittleEndian.Uint32(c.raw[16:]) != 0 {
				return errors.New("ipa: patch: invalid or encrypted LC_ENCRYPTION_INFO_64")
			}
			encryptionCount++
		}
	}
	wantLoaderCount := 0
	if expectLoader {
		wantLoaderCount = 1
	}
	if loaderCount != wantLoaderCount {
		return fmt.Errorf("ipa: patch: expected %d loader dependencies, got %d", wantLoaderCount, loaderCount)
	}
	if signatureCount != 1 || gotSignatureOff != patchSignatureOff || gotSignatureSize != patchSignatureSize ||
		gotSignatureOff+gotSignatureSize != uint64(len(data)) {
		return errors.New("ipa: patch: code-signature layout mismatch")
	}
	if encryptionCount != 1 {
		return errors.New("ipa: patch: expected one unencrypted encryption command")
	}
	stubsSec, laSymPtrSec, gotSec, err := validateExactSegments(segments, len(data))
	if err != nil {
		return err
	}
	if !expectLoader {
		if err := validateBaselineStubs(data, stubsSec, laSymPtrSec, gotSec); err != nil {
			return err
		}
	}
	slackStart := patchLoaderCommandOff
	if expectLoader {
		slackStart = patchLoaderHeaderEnd
	}
	if !allZero(data[slackStart:patchFirstTextSection]) {
		return errors.New("ipa: patch: RX header slack is not zero")
	}
	return nil
}

func validateBaselineStubs(data []byte, stubsSec, laSymPtrSec, gotSec *patchImageSection) error {
	mf, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("ipa: patch: parse Mach-O imports: %w", err)
	}
	if mf.Symtab == nil || mf.Dysymtab == nil {
		return errors.New("ipa: patch: missing symtab or dysymtab")
	}

	if err := validateStubEntry(data, stubsSec, laSymPtrSec, gotSec, mf.Dysymtab.IndirectSyms, mf.Symtab.Syms, stubRouteSpec{
		name:          "dlsym",
		importSym:     dlsymImportName,
		stubRVA:       patchDlsymStubRVA,
		expectedPtrVA: dlsymPtrVA,
		expectedWords: [3]uint32{0xf00013f0, 0xf9410610, 0xd61f0200},
	}); err != nil {
		return err
	}
	for _, spec := range socketStubSpecs {
		if err := validateStubEntry(data, stubsSec, laSymPtrSec, gotSec, mf.Dysymtab.IndirectSyms, mf.Symtab.Syms, spec); err != nil {
			return err
		}
	}
	return nil
}

func validateStubEntry(
	data []byte,
	stubsSec, laSymPtrSec, gotSec *patchImageSection,
	indirectSyms []uint32,
	syms []macho.Symbol,
	spec stubRouteSpec,
) error {
	if stubsSec == nil || stubsSec.stubLen != patchStubsLen || stubsSec.size%uint64(stubsSec.stubLen) != 0 {
		return errors.New("ipa: patch: invalid __TEXT,__stubs section")
	}
	if spec.stubRVA < stubsSec.fileoff || spec.stubRVA+uint64(stubsSec.stubLen) > stubsSec.fileoff+stubsSec.size {
		return fmt.Errorf("ipa: patch: %s stub 0x%x is outside __TEXT,__stubs", spec.name, spec.stubRVA)
	}
	relOff := spec.stubRVA - stubsSec.fileoff
	if relOff%uint64(stubsSec.stubLen) != 0 {
		return fmt.Errorf("ipa: patch: %s stub 0x%x is not aligned to %d-byte stub stride", spec.name, spec.stubRVA, stubsSec.stubLen)
	}
	stubIdx := relOff / uint64(stubsSec.stubLen)

	// Verify unique indirect symbol mapping across __TEXT,__stubs.
	nstubs := stubsSec.size / uint64(stubsSec.stubLen)
	var symMatches int
	for idx := uint64(0); idx < nstubs; idx++ {
		indirectPos := uint64(stubsSec.indirect) + idx
		if indirectPos >= uint64(len(indirectSyms)) {
			return errors.New("ipa: patch: __stubs indirect index out of bounds")
		}
		symIdx := indirectSyms[indirectPos]
		if symIdx&0xc0000000 != 0 {
			continue
		}
		if symIdx >= uint32(len(syms)) {
			return errors.New("ipa: patch: __stubs symbol index out of bounds")
		}
		if syms[symIdx].Name == spec.importSym {
			if idx != stubIdx {
				return fmt.Errorf("ipa: patch: %s symbol found at unexpected stub index %d (want %d)", spec.name, idx, stubIdx)
			}
			symMatches++
		}
	}
	if symMatches != 1 {
		return fmt.Errorf("ipa: patch: expected 1 %s stub in __TEXT,__stubs, got %d", spec.importSym, symMatches)
	}

	if spec.stubRVA+12 > uint64(len(data)) {
		return fmt.Errorf("ipa: patch: %s stub exceeds image bounds", spec.name)
	}
	bo := binary.LittleEndian
	w0 := bo.Uint32(data[spec.stubRVA:])
	w1 := bo.Uint32(data[spec.stubRVA+4:])
	w2 := bo.Uint32(data[spec.stubRVA+8:])
	if [3]uint32{w0, w1, w2} != spec.expectedWords {
		return fmt.Errorf("ipa: patch: %s stub words [0x%08x 0x%08x 0x%08x] mismatch", spec.name, w0, w1, w2)
	}

	stubPC := stubsSec.addr + relOff
	pageVA, adrpRd, ok := decodeArm64ADRP(w0, stubPC)
	if !ok || adrpRd != 16 {
		return fmt.Errorf("ipa: patch: %s stub word 0 is not ADRP X16", spec.name)
	}
	ldrRt, ldrRn, ldrOff, ok := decodeArm64LDR64Unsigned(w1)
	if !ok || ldrRt != 16 || ldrRn != 16 {
		return fmt.Errorf("ipa: patch: %s stub word 1 is not LDR X16, [X16, #off]", spec.name)
	}
	if w2 != 0xd61f0200 {
		return fmt.Errorf("ipa: patch: %s stub word 2 is not BR X16", spec.name)
	}
	ptrVA := pageVA + ldrOff
	if ptrVA != spec.expectedPtrVA {
		return fmt.Errorf("ipa: patch: %s stub pointer 0x%x != expected 0x%x", spec.name, ptrVA, spec.expectedPtrVA)
	}
	inGOT := gotSec != nil && ptrVA >= gotSec.addr && ptrVA+8 <= gotSec.addr+gotSec.size
	inLazy := laSymPtrSec != nil && ptrVA >= laSymPtrSec.addr && ptrVA+8 <= laSymPtrSec.addr+laSymPtrSec.size
	if !inGOT && !inLazy {
		return fmt.Errorf("ipa: patch: %s pointer 0x%x is outside __got and __la_symbol_ptr", spec.name, ptrVA)
	}
	if inLazy && (ptrVA-laSymPtrSec.addr)/8 != stubIdx {
		return fmt.Errorf("ipa: patch: %s lazy pointer slot mismatch at 0x%x", spec.name, ptrVA)
	}
	return nil
}

func emitAllPatches(prepared []byte) ([]byte, error) {
	if int64(len(prepared)) != MainSize {
		return nil, errors.New("ipa: patch: prepared input size mismatch")
	}
	if err := validateNoticeCallsite(prepared); err != nil {
		return nil, err
	}
	if err := validateGuestAuthTargets(prepared); err != nil {
		return nil, err
	}
	if err := validateAutoGuestEntry(prepared); err != nil {
		return nil, err
	}
	if err := validateReauthTargets(prepared); err != nil {
		return nil, err
	}
	if !allZero(prepared[patchLoaderHeaderEnd:patchFirstTextSection]) {
		return nil, errors.New("ipa: patch: post-AddLoader RX gap is not zero")
	}

	ranges, err := reservedRanges()
	if err != nil {
		return nil, err
	}
	if err := validateReservedRanges(ranges); err != nil {
		return nil, err
	}
	for _, r := range ranges {
		if !allZero(prepared[r.start:r.end]) {
			return nil, fmt.Errorf("ipa: patch: reserved %s bytes are not zero", r.name)
		}
	}

	noticeWords, err := noticeResolverWords()
	if err != nil {
		return nil, err
	}
	noticeBL, err := encodeArm64Branch(noticeCallsiteRVA, noticeResolverRVA, true)
	if err != nil {
		return nil, fmt.Errorf("ipa: patch: notice callsite BL: %w", err)
	}

	type emittedStub struct {
		spec        stubRouteSpec
		words       []uint32
		stubBranch  uint32
		exportBytes []byte
	}
	stubs := make([]emittedStub, 0, len(socketStubSpecs))
	for _, spec := range socketStubSpecs {
		words, err := stubResolverWords(spec.resolverRVA, spec.exportRVA)
		if err != nil {
			return nil, fmt.Errorf("ipa: patch: %s resolver: %w", spec.name, err)
		}
		stubBranch, err := encodeArm64Branch(spec.stubRVA, spec.resolverRVA, false)
		if err != nil {
			return nil, fmt.Errorf("ipa: patch: %s stub B: %w", spec.name, err)
		}
		stubs = append(stubs, emittedStub{
			spec:        spec,
			words:       words,
			stubBranch:  stubBranch,
			exportBytes: append([]byte(spec.exportSym), 0),
		})
	}

	guestWords, err := guestResolverWords()
	if err != nil {
		return nil, fmt.Errorf("ipa: patch: guest resolver: %w", err)
	}
	guestBranches := make([]uint32, len(guestCallsiteSpecs))
	for i, spec := range guestCallsiteSpecs {
		branchWord, err := encodeArm64Branch(spec.callsiteRVA, guestResolverRVA, spec.link)
		if err != nil {
			return nil, fmt.Errorf("ipa: patch: %s branch: %w", spec.name, err)
		}
		guestBranches[i] = branchWord
	}
	autoGuestBranch, err := autoGuestEntryBranchWord()
	if err != nil {
		return nil, err
	}

	legacyWords, err := legacyLoginResolverWords()
	if err != nil {
		return nil, err
	}
	loginReadyWords, err := loginReadyResolverWords()
	if err != nil {
		return nil, err
	}
	gdprLoginReadyWords, err := gdprLoginReadyResolverWords()
	if err != nil {
		return nil, err
	}
	sessionOutWords, err := sessionResetResolverWords(sessionOutResolverRVA, sessionResetExportRVA, 0x89ad04)
	if err != nil {
		return nil, err
	}
	deleteDirectWords, err := sessionResetResolverWords(deleteDirectResolverRVA, sessionResetExportRVA, 0x89ad04)
	if err != nil {
		return nil, err
	}
	deleteSNSWords, err := sessionResetResolverWords(deleteSNSResolverRVA, sessionResetExportRVA, 0x89b23c)
	if err != nil {
		return nil, err
	}
	checkSessionWords, err := checkSessionErrorResolverWords()
	if err != nil {
		return nil, err
	}
	guestGenerateWords, err := guestGenerateErrorResolverWords()
	if err != nil {
		return nil, err
	}

	type resolverBranch struct {
		rva    uint64
		target uint64
		name   string
		link   bool
	}
	reauthBranches := []resolverBranch{
		{legacyLoginVisibilityRVA, legacyLoginResolverRVA, "legacy login visibility", false},
		{sessionOutSuccessRVA, sessionOutResolverRVA, "Logout session-reset", false},
		{deleteDirectSuccessRVA, deleteDirectResolverRVA, "direct-delete session-reset", false},
		{deleteSNSuccessRVA, deleteSNSResolverRVA, "SNS-delete session-reset", false},
		{checkSessionErrorEntryRVA, checkSessionResolverRVA, "checkSession-error", false},
		{guestGenerateErrorTailRVA, guestGenerateResolverRVA, "guest-generate-error", false},
		{gdprLoginReadyCallsiteRVA, gdprLoginReadyResolverRVA, "case 10043 GDPR-ready login overlay", true},
	}
	reauthBranchWords := make([]uint32, len(reauthBranches))
	for i, branch := range reauthBranches {
		reauthBranchWords[i], err = encodeArm64Branch(branch.rva, branch.target, branch.link)
		if err != nil {
			return nil, fmt.Errorf("ipa: patch: %s branch: %w", branch.name, err)
		}
	}

	out := append([]byte(nil), prepared...)
	writeWords(out[noticeResolverRVA:], noticeWords)
	copy(out[noticeExportRVA:], append([]byte(ExportNotice404DiagnosticEntry), 0))
	binary.LittleEndian.PutUint32(out[noticeCallsiteRVA:], noticeBL)

	for _, s := range stubs {
		writeWords(out[s.spec.resolverRVA:], s.words)
		copy(out[s.spec.exportRVA:], s.exportBytes)
		binary.LittleEndian.PutUint32(out[s.spec.stubRVA:], s.stubBranch)
	}

	writeWords(out[guestResolverRVA:], guestWords)
	copy(out[guestExportRVA:], append([]byte(ExportGuestUniqueCode), 0))
	for i, spec := range guestCallsiteSpecs {
		binary.LittleEndian.PutUint32(out[spec.callsiteRVA:], guestBranches[i])
	}
	binary.LittleEndian.PutUint32(out[autoGuestEntryRVA:], autoGuestBranch)

	writeWords(out[legacyLoginResolverRVA:], legacyWords)
	writeWords(out[loginReadyResolverRVA:], loginReadyWords)
	writeWords(out[gdprLoginReadyResolverRVA:], gdprLoginReadyWords)
	copy(out[loginReadyExportRVA:], append([]byte(ExportLoginReady), 0))
	writeWords(out[sessionOutResolverRVA:], sessionOutWords)
	copy(out[sessionResetExportRVA:], append([]byte(ExportSessionReset), 0))
	writeWords(out[deleteDirectResolverRVA:], deleteDirectWords)
	writeWords(out[deleteSNSResolverRVA:], deleteSNSWords)
	writeWords(out[checkSessionResolverRVA:], checkSessionWords)
	copy(out[checkSessionExportRVA:], append([]byte(ExportCheckSessionError), 0))
	writeWords(out[guestGenerateResolverRVA:], guestGenerateWords)
	copy(out[guestGenerateExportRVA:], append([]byte(ExportGuestGenerateError), 0))
	for i, branch := range reauthBranches {
		binary.LittleEndian.PutUint32(out[branch.rva:], reauthBranchWords[i])
	}

	if err := verifyPatchOnlyDelta(prepared, out); err != nil {
		return nil, err
	}
	if err := verifyDecodedInstructions(prepared, out); err != nil {
		return nil, err
	}
	return out, nil
}

func verifyPatchedMachO(original, withLoader, out []byte) error {
	if err := validateMachHeader(out, patchLoaderNcmds, patchLoaderCmdSize); err != nil {
		return fmt.Errorf("ipa: patch: post-patch header check: %w", err)
	}
	cmds, err := parseLoadCommands(out)
	if err != nil {
		return fmt.Errorf("ipa: patch: post-patch load commands: %w", err)
	}
	if len(cmds) != int(patchLoaderNcmds) || cmds[len(cmds)-1].off != patchLoaderCommandOff ||
		!bytes.Equal(cmds[len(cmds)-1].raw, loaderCommand()) {
		return errors.New("ipa: patch: post-patch LC_LOAD_DYLIB mismatch")
	}
	if _, err := macho.NewFile(bytes.NewReader(out)); err != nil {
		return fmt.Errorf("ipa: patch: post-patch debug/macho parse: %w", err)
	}
	if err := verifyPatchOnlyDelta(withLoader, out); err != nil {
		return err
	}
	if err := verifyFullWriteSet(original, out); err != nil {
		return err
	}
	return verifyDecodedInstructions(original, out)
}

func verifyDecodedInstructions(before, after []byte) error {
	bo := binary.LittleEndian

	// 1. Unified notice callsite BL + unchanged ARC continuation + 16-word resolver.
	gotNoticeBL := bo.Uint32(after[noticeCallsiteRVA:])
	target, link, ok := decodeArm64Branch(gotNoticeBL, noticeCallsiteRVA)
	if !ok || !link || target != noticeResolverRVA {
		return fmt.Errorf("ipa: patch: post-patch notice callsite is not BL 0x%x", noticeResolverRVA)
	}
	if !bytes.Equal(after[noticeContinuationRVA:noticeContinuationRVA+uint64(len(stockContinuation))], stockContinuation[:]) {
		return errors.New("ipa: patch: post-patch ARC continuation mutated")
	}
	if err := verifyNoticeResolverAt(after); err != nil {
		return err
	}

	// 2. Four socket/DNS stubs: first word is B <resolver>, words 1..2 untouched, 15-word resolver verified.
	for _, spec := range socketStubSpecs {
		gotB := bo.Uint32(after[spec.stubRVA:])
		target, link, ok := decodeArm64Branch(gotB, spec.stubRVA)
		if !ok || link || target != spec.resolverRVA {
			return fmt.Errorf("ipa: patch: post-patch %s stub is not B 0x%x", spec.name, spec.resolverRVA)
		}
		if !bytes.Equal(before[spec.stubRVA+4:spec.stubRVA+12], after[spec.stubRVA+4:spec.stubRVA+12]) {
			return fmt.Errorf("ipa: patch: %s stub trailing instructions modified", spec.name)
		}
		if err := verifyStubResolverAt(after, spec); err != nil {
			return err
		}
	}

	// 3. Three /v4/account/guest/generate callsites, intact sub_1006BDD4C prologue, and 18-word resolver.
	if err := validateGuestPrologue(after); err != nil {
		return fmt.Errorf("ipa: patch: post-patch prologue check: %w", err)
	}
	for _, spec := range guestCallsiteSpecs {
		gotBranch := bo.Uint32(after[spec.callsiteRVA:])
		target, link, ok := decodeArm64Branch(gotBranch, spec.callsiteRVA)
		if !ok || link != spec.link || target != guestResolverRVA {
			return fmt.Errorf("ipa: patch: post-patch %s branch target 0x%x (link=%t, ok=%t)", spec.name, target, link, ok)
		}
		if err := validateGuestCallsiteGuards(after, spec); err != nil {
			return fmt.Errorf("ipa: patch: post-patch %s guard mutated: %w", spec.name, err)
		}
	}
	if err := verifyGuestResolverAt(after); err != nil {
		return err
	}

	// 4. NaLoginLayer::SetEndLoading auto-guest-entry branch + intact non-patched guard windows.
	gotAutoGuest := bo.Uint32(after[autoGuestEntryRVA:])
	if gotAutoGuest != autoGuestEntryPatchedWord {
		return fmt.Errorf("ipa: patch: post-patch auto-guest-entry word 0x%08x != expected 0x%08x", gotAutoGuest, autoGuestEntryPatchedWord)
	}
	target, link, ok = decodeArm64Branch(gotAutoGuest, autoGuestEntryRVA)
	if !ok || link || target != loginReadyResolverRVA {
		return fmt.Errorf("ipa: patch: post-patch auto-guest-entry branch target 0x%x (link=%t, ok=%t)", target, link, ok)
	}
	for _, w := range autoGuestGuardWindows {
		if w.unchanged < w.start || w.unchanged > w.start+uint64(len(w.words))*4 {
			return fmt.Errorf("ipa: patch: invalid unchanged span for %s", w.name)
		}
		if w.unchanged > uint64(len(before)) || w.unchanged > uint64(len(after)) {
			return fmt.Errorf("ipa: patch: %s post-patch guard exceeds image bounds", w.name)
		}
		unchangedBytes := encodeWords(w.words)[:w.unchanged-w.start]
		if !bytes.Equal(after[w.start:w.unchanged], unchangedBytes) ||
			!bytes.Equal(before[w.start:w.unchanged], after[w.start:w.unchanged]) {
			return fmt.Errorf("ipa: patch: post-patch %s guard mutated", w.name)
		}
	}
	if err := verifyReauthInstructions(before, after); err != nil {
		return err
	}
	return nil
}

func verifyReauthInstructions(before, after []byte) error {
	if err := validateReauthTargets(before); err != nil {
		return fmt.Errorf("ipa: patch: original re-auth guard: %w", err)
	}

	branchTargets := map[uint64]uint64{
		legacyLoginVisibilityRVA:  legacyLoginResolverRVA,
		sessionOutSuccessRVA:      sessionOutResolverRVA,
		deleteDirectSuccessRVA:    deleteDirectResolverRVA,
		deleteSNSuccessRVA:        deleteSNSResolverRVA,
		checkSessionErrorEntryRVA: checkSessionResolverRVA,
		guestGenerateErrorTailRVA: guestGenerateResolverRVA,
		gdprLoginReadyCallsiteRVA: gdprLoginReadyResolverRVA,
	}
	for _, guard := range reauthGuardWindows {
		end := guard.start + uint64(len(guard.words))*4
		for off := guard.start; off < end; off++ {
			if off >= guard.patchRVA && off < guard.patchRVA+4 {
				continue
			}
			if before[off] != after[off] {
				return fmt.Errorf("ipa: patch: %s non-target byte at 0x%x changed", guard.name, off)
			}
		}
		target := branchTargets[guard.patchRVA]
		got := binary.LittleEndian.Uint32(after[guard.patchRVA:])
		decoded, link, ok := decodeArm64Branch(got, guard.patchRVA)
		if !ok || link != guard.link || decoded != target {
			return fmt.Errorf("ipa: patch: %s branch target 0x%x (link=%t), want 0x%x (link=%t)",
				guard.name, decoded, link, target, guard.link)
		}
	}

	legacyWords, err := legacyLoginResolverWords()
	if err != nil {
		return err
	}
	if !bytes.Equal(after[legacyLoginResolverRVA:legacyLoginResolverRVA+uint64(len(legacyWords))*4], encodeWords(legacyWords)) {
		return errors.New("ipa: patch: legacy login visibility resolver bytes mismatch")
	}
	if target, link, ok := decodeArm64Branch(legacyWords[2], legacyLoginResolverRVA+8); !ok || link || target != legacyLoginVisibilityRVA+4 {
		return fmt.Errorf("ipa: patch: legacy login visibility continuation target 0x%x", target)
	}

	loginWords, err := loginReadyResolverWords()
	if err != nil {
		return err
	}
	if !bytes.Equal(after[loginReadyResolverRVA:loginReadyResolverRVA+uint64(len(loginWords))*4], encodeWords(loginWords)) {
		return errors.New("ipa: patch: login-ready resolver bytes mismatch")
	}
	if err := verifyResolverDlsymPrefix(after, "login-ready", loginReadyResolverRVA,
		loginReadyExportRVA, ExportLoginReady, 3, 4, 6, 16, loginReadyResolverRVA+8*4); err != nil {
		return err
	}
	if got := binary.LittleEndian.Uint32(after[loginReadyResolverRVA+8*4:]); got != 0xd2800000 {
		return fmt.Errorf("ipa: patch: SetEndLoading login-ready source mode instruction 0x%08x != mov x0, #0", got)
	}
	gdprLoginWords, err := gdprLoginReadyResolverWords()
	if err != nil {
		return err
	}
	if !bytes.Equal(after[gdprLoginReadyResolverRVA:gdprLoginReadyResolverRVA+uint64(len(gdprLoginWords))*4], encodeWords(gdprLoginWords)) {
		return errors.New("ipa: patch: case 10043 GDPR-ready resolver bytes mismatch")
	}
	if err := verifyResolverDlsymPrefix(after, "case 10043 GDPR-ready login-ready", gdprLoginReadyResolverRVA,
		loginReadyExportRVA, ExportLoginReady, 3, 4, 6, 16, gdprLoginReadyResolverRVA+8*4); err != nil {
		return err
	}
	gdprCallbackModeWord := binary.LittleEndian.Uint32(after[gdprLoginReadyResolverRVA+8*4:])
	if gdprCallbackModeWord != 0x52800020 {
		return fmt.Errorf("ipa: patch: case 10043 login-ready source mode instruction 0x%08x != mov w0, #1", gdprCallbackModeWord)
	}

	for _, tc := range []struct {
		name       string
		resolver   uint64
		target     uint64
		exportName string
	}{
		{"Logout session-reset", sessionOutResolverRVA, 0x89ad04, ExportSessionReset},
		{"direct-delete session-reset", deleteDirectResolverRVA, 0x89ad04, ExportSessionReset},
		{"SNS-delete session-reset", deleteSNSResolverRVA, 0x89b23c, ExportSessionReset},
	} {
		words, err := sessionResetResolverWords(tc.resolver, sessionResetExportRVA, tc.target)
		if err != nil {
			return err
		}
		if !bytes.Equal(after[tc.resolver:tc.resolver+uint64(len(words))*4], encodeWords(words)) {
			return fmt.Errorf("ipa: patch: %s resolver bytes mismatch", tc.name)
		}
		if err := verifyResolverDlsymPrefix(after, tc.name, tc.resolver,
			sessionResetExportRVA, tc.exportName, 7, 8, 10, 16, tc.resolver+12*4); err != nil {
			return err
		}
		stockPC := tc.resolver + 20*4
		if got, link, ok := decodeArm64Branch(binary.LittleEndian.Uint32(after[stockPC:]), stockPC); !ok || link || got != tc.target {
			return fmt.Errorf("ipa: patch: %s stock continuation target 0x%x", tc.name, got)
		}
	}

	checkWords, err := checkSessionErrorResolverWords()
	if err != nil {
		return err
	}
	if !bytes.Equal(after[checkSessionResolverRVA:checkSessionResolverRVA+uint64(len(checkWords))*4], encodeWords(checkWords)) {
		return errors.New("ipa: patch: checkSession-error resolver bytes mismatch")
	}
	checkErrorArgWord := binary.LittleEndian.Uint32(after[checkSessionResolverRVA+12*4:])
	checkErrorRT, checkErrorRN, checkErrorOffset, checkErrorArgOK := decodeArm64LDR64Unsigned(checkErrorArgWord)
	if !checkErrorArgOK || checkErrorRT != 0 || checkErrorRN != 31 || checkErrorOffset != 24 {
		return fmt.Errorf("ipa: patch: checkSession-error argument instruction 0x%08x decodes (rt=%d rn=%d offset=%d ok=%t), want LDR X0, [SP,#24]",
			checkErrorArgWord, checkErrorRT, checkErrorRN, checkErrorOffset, checkErrorArgOK)
	}
	if err := verifyResolverDlsymPrefix(after, "checkSession-error", checkSessionResolverRVA,
		checkSessionExportRVA, ExportCheckSessionError, 7, 8, 10, 16, checkSessionResolverRVA+12*4); err != nil {
		return err
	}
	checkContinuePC := checkSessionResolverRVA + 21*4
	if got, link, ok := decodeArm64Branch(binary.LittleEndian.Uint32(after[checkContinuePC:]), checkContinuePC); !ok || link || got != checkSessionErrorEntryRVA+4 {
		return fmt.Errorf("ipa: patch: checkSession-error original continuation target 0x%x", got)
	}

	guestWords, err := guestGenerateErrorResolverWords()
	if err != nil {
		return err
	}
	if !bytes.Equal(after[guestGenerateResolverRVA:guestGenerateResolverRVA+uint64(len(guestWords))*4], encodeWords(guestWords)) {
		return errors.New("ipa: patch: guest-generate-error resolver bytes mismatch")
	}
	if err := verifyResolverDlsymPrefix(after, "guest-generate-error", guestGenerateResolverRVA,
		guestGenerateExportRVA, ExportGuestGenerateError, 7, 8, 10, 16, guestGenerateResolverRVA+12*4); err != nil {
		return err
	}
	handledPC := guestGenerateResolverRVA + 22*4
	handledTarget, handledReg, ok := decodeArm64ZeroBranch(
		binary.LittleEndian.Uint32(after[handledPC:]), handledPC, 0x35000000)
	if !ok || handledReg != 9 || handledTarget != guestGenerateResolverRVA+24*4 {
		return fmt.Errorf("ipa: patch: guest-generate handled CBNZ target 0x%x rt=%d", handledTarget, handledReg)
	}
	stockPC := guestGenerateResolverRVA + 23*4
	if got, link, ok := decodeArm64Branch(binary.LittleEndian.Uint32(after[stockPC:]), stockPC); !ok || link || got != guestGenerateDialogTailRVA {
		return fmt.Errorf("ipa: patch: guest-generate stock dialog continuation target 0x%x", got)
	}
	if got := binary.LittleEndian.Uint32(after[guestGenerateResolverRVA+24*4:]); got != 0xa8c24ff4 ||
		binary.LittleEndian.Uint32(after[guestGenerateResolverRVA+25*4:]) != 0xd65f03c0 {
		return fmt.Errorf("ipa: patch: guest-generate handled-return epilogue mismatch (0x%08x)", got)
	}
	for _, tc := range []struct {
		name         string
		resolverRVA  uint64
		restoreIndex int
	}{
		{"Logout session-reset", sessionOutResolverRVA, 18},
		{"direct-delete session-reset", deleteDirectResolverRVA, 18},
		{"SNS-delete session-reset", deleteSNSResolverRVA, 18},
		{"checkSession-error", checkSessionResolverRVA, 18},
		{"guest-generate-error", guestGenerateResolverRVA, 19},
	} {
		if err := verifyResolverSavedLRPair(after, tc.name, tc.resolverRVA, 5, tc.restoreIndex); err != nil {
			return err
		}
	}
	return nil
}

func verifyResolverSavedLRPair(data []byte, name string, resolverRVA uint64, saveIndex, restoreIndex int) error {
	store := binary.LittleEndian.Uint32(data[resolverRVA+uint64(saveIndex*4):])
	storeLoad, storeRT, storeRT2, storeRN, storeOffset, storeOK := decodeArm64Pair64Offset(store)
	if !storeOK || storeLoad || storeRT != 8 || storeRT2 != 30 || storeRN != 31 || storeOffset != 64 {
		return fmt.Errorf("ipa: patch: %s LR save fields=(load=%t Rt=%d Rt2=%d Rn=%d offset=%d ok=%t), want STP X8,X30,[SP,#64]",
			name, storeLoad, storeRT, storeRT2, storeRN, storeOffset, storeOK)
	}
	load := binary.LittleEndian.Uint32(data[resolverRVA+uint64(restoreIndex*4):])
	loadLoad, loadRT, loadRT2, loadRN, loadOffset, loadOK := decodeArm64Pair64Offset(load)
	if !loadOK || !loadLoad || loadRT != 8 || loadRT2 != 30 || loadRN != 31 || loadOffset != 64 {
		return fmt.Errorf("ipa: patch: %s LR restore fields=(load=%t Rt=%d Rt2=%d Rn=%d offset=%d ok=%t), want LDP X8,X30,[SP,#64]",
			name, loadLoad, loadRT, loadRT2, loadRN, loadOffset, loadOK)
	}
	return nil
}

func verifyResolverDlsymPrefix(data []byte, name string, resolverRVA, exportRVA uint64, exportSym string, adrIdx, blIdx, cbnzIdx int, cbnzRt uint32, cbnzTarget uint64) error {
	bo := binary.LittleEndian
	adrPC := resolverRVA + uint64(adrIdx)*4
	adrWord := bo.Uint32(data[adrPC:])
	adrTarget, adrRd, ok := decodeArm64ADR(adrWord, adrPC)
	if !ok || adrRd != 1 || adrTarget != exportRVA {
		return fmt.Errorf("ipa: patch: %s resolver ADR target 0x%x rd=%d", name, adrTarget, adrRd)
	}
	blPC := resolverRVA + uint64(blIdx)*4
	blWord := bo.Uint32(data[blPC:])
	blTarget, link, ok := decodeArm64Branch(blWord, blPC)
	if !ok || !link || blTarget != patchDlsymStubRVA {
		return fmt.Errorf("ipa: patch: %s resolver BL _dlsym target 0x%x", name, blTarget)
	}
	cbnzPC := resolverRVA + uint64(cbnzIdx)*4
	cbnzWord := bo.Uint32(data[cbnzPC:])
	gotTarget, gotRt, ok := decodeArm64CBNZ(cbnzWord, cbnzPC)
	if !ok || gotRt != cbnzRt || gotTarget != cbnzTarget {
		return fmt.Errorf("ipa: patch: %s resolver CBNZ target 0x%x rt=%d", name, gotTarget, gotRt)
	}
	wantLit := append([]byte(exportSym), 0)
	if !bytes.Equal(data[exportRVA:exportRVA+uint64(len(wantLit))], wantLit) {
		return fmt.Errorf("ipa: patch: %s export string mismatch", name)
	}
	return nil
}

func verifyNoticeResolverAt(data []byte) error {
	wantWords, err := noticeResolverWords()
	if err != nil {
		return err
	}
	if !bytes.Equal(data[noticeResolverRVA:noticeResolverRVA+uint64(len(wantWords))*4], encodeWords(wantWords)) {
		return errors.New("ipa: patch: notice resolver bytes mismatch")
	}
	return verifyResolverDlsymPrefix(
		data, "notice", noticeResolverRVA, noticeExportRVA, ExportNotice404DiagnosticEntry,
		5, 6, 8, 16, noticeResolverRVA+10*4,
	)
}

func verifyStubResolverAt(data []byte, spec stubRouteSpec) error {
	wantWords, err := stubResolverWords(spec.resolverRVA, spec.exportRVA)
	if err != nil {
		return err
	}
	if !bytes.Equal(data[spec.resolverRVA:spec.resolverRVA+uint64(len(wantWords))*4], encodeWords(wantWords)) {
		return fmt.Errorf("ipa: patch: %s resolver bytes mismatch", spec.name)
	}
	return verifyResolverDlsymPrefix(
		data, spec.name, spec.resolverRVA, spec.exportRVA, spec.exportSym,
		5, 6, 8, 16, spec.resolverRVA+10*4,
	)
}

func verifyGuestResolverAt(data []byte) error {
	wantWords, err := guestResolverWords()
	if err != nil {
		return err
	}
	if !bytes.Equal(data[guestResolverRVA:guestResolverRVA+uint64(len(wantWords))*4], encodeWords(wantWords)) {
		return errors.New("ipa: patch: guest resolver bytes mismatch")
	}
	if err := verifyResolverDlsymPrefix(
		data, "guest auth", guestResolverRVA, guestExportRVA, ExportGuestUniqueCode,
		4, 5, 6, 0, guestResolverRVA+8*4,
	); err != nil {
		return err
	}
	bo := binary.LittleEndian
	cbzPC := guestResolverRVA + 15*4
	cbzTarget, cbzRt, ok := decodeArm64CBZ(bo.Uint32(data[cbzPC:]), cbzPC)
	if !ok || cbzRt != 1 || cbzTarget != guestResolverRVA+17*4 {
		return fmt.Errorf("ipa: patch: guest resolver CBZ target 0x%x rt=%d", cbzTarget, cbzRt)
	}
	tailPC := guestResolverRVA + 16*4
	tailTarget, tailLink, ok := decodeArm64Branch(bo.Uint32(data[tailPC:]), tailPC)
	if !ok || tailLink || tailTarget != guestGenerateRVA {
		return fmt.Errorf("ipa: patch: guest resolver tail B target 0x%x link=%t", tailTarget, tailLink)
	}
	if gotRet := bo.Uint32(data[guestResolverRVA+17*4:]); gotRet != 0xd65f03c0 {
		return fmt.Errorf("ipa: patch: guest resolver final word 0x%08x != ret", gotRet)
	}
	return nil
}

func noticeResolverWords() ([]uint32, error) {
	adrName, err := encodeArm64ADR(noticeResolverRVA+5*4, noticeExportRVA, 1)
	if err != nil {
		return nil, err
	}
	callDlsym, err := encodeArm64Branch(noticeResolverRVA+6*4, patchDlsymStubRVA, true)
	if err != nil {
		return nil, err
	}
	cbnzReady, err := encodeArm64CBNZ(noticeResolverRVA+8*4, noticeResolverRVA+10*4, 16)
	if err != nil {
		return nil, err
	}
	words := []uint32{
		0xd100c3ff, // sub sp, sp, #48
		0xa90007e0, // stp x0, x1, [sp]
		0xa9010fe2, // stp x2, x3, [sp, #16]
		0xf90013fe, // str x30, [sp, #32]
		0x92800020, // movn x0, #1 (RTLD_DEFAULT = (void *)-2)
		adrName,    // adr x1, export literal
		callDlsym,  // bl _dlsym
		0xaa0003f0, // mov x16, x0
		cbnzReady,  // cbnz x16, restore
		0xd4200000, // brk #0
		0xa94007e0, // ldp x0, x1, [sp]
		0xa9410fe2, // ldp x2, x3, [sp, #16]
		0xf94013e4, // ldr x4, [sp, #32] (supply original callsite LR)
		0xf94013fe, // ldr x30, [sp, #32]
		0x9100c3ff, // add sp, sp, #48
		0xd61f0200, // br x16
	}
	if len(words) != noticeResolverWordCount {
		return nil, errors.New("ipa: patch: internal notice resolver count mismatch")
	}
	return words, nil
}

func stubResolverWords(resolverRVA, exportRVA uint64) ([]uint32, error) {
	adrName, err := encodeArm64ADR(resolverRVA+5*4, exportRVA, 1)
	if err != nil {
		return nil, err
	}
	callDlsym, err := encodeArm64Branch(resolverRVA+6*4, patchDlsymStubRVA, true)
	if err != nil {
		return nil, err
	}
	cbnzReady, err := encodeArm64CBNZ(resolverRVA+8*4, resolverRVA+10*4, 16)
	if err != nil {
		return nil, err
	}
	words := []uint32{
		0xd100c3ff, // sub sp, sp, #48
		0xa90007e0, // stp x0, x1, [sp]
		0xa9010fe2, // stp x2, x3, [sp, #16]
		0xf90013fe, // str x30, [sp, #32]
		0x92800020, // movn x0, #1 (RTLD_DEFAULT = (void *)-2)
		adrName,    // adr x1, export literal
		callDlsym,  // bl _dlsym
		0xaa0003f0, // mov x16, x0
		cbnzReady,  // cbnz x16, +8
		0xd4200000, // brk #0
		0xa94007e0, // ldp x0, x1, [sp]
		0xa9410fe2, // ldp x2, x3, [sp, #16]
		0xf94013fe, // ldr x30, [sp, #32]
		0x9100c3ff, // add sp, sp, #48
		0xd61f0200, // br x16
	}
	if len(words) != stubResolverWordCount {
		return nil, errors.New("ipa: patch: internal stub resolver count mismatch")
	}
	return words, nil
}

func guestResolverWords() ([]uint32, error) {
	adrName, err := encodeArm64ADR(guestResolverRVA+4*4, guestExportRVA, 1)
	if err != nil {
		return nil, err
	}
	callDlsym, err := encodeArm64Branch(guestResolverRVA+5*4, patchDlsymStubRVA, true)
	if err != nil {
		return nil, err
	}
	cbnzFound, err := encodeArm64CBNZ(guestResolverRVA+6*4, guestResolverRVA+8*4, 0)
	if err != nil {
		return nil, err
	}
	cbzDenied, err := encodeArm64CBZ(guestResolverRVA+15*4, guestResolverRVA+17*4, 1)
	if err != nil {
		return nil, err
	}
	tailGenerate, err := encodeArm64Branch(guestResolverRVA+16*4, guestGenerateRVA, false)
	if err != nil {
		return nil, err
	}
	words := []uint32{
		0xd10083ff,   // sub sp, sp, #32
		0xa90007e0,   // stp x0, x1, [sp]
		0xf9000bfe,   // str x30, [sp, #16]
		0x92800020,   // movn x0, #1 (RTLD_DEFAULT = (void *)-2)
		adrName,      // adr x1, export literal
		callDlsym,    // bl _dlsym
		cbnzFound,    // cbnz x0, +8
		0xd4200000,   // brk #0
		0xaa0003f0,   // mov x16, x0
		0xa94007e0,   // ldp x0, x1, [sp]
		0xd63f0200,   // blr x16 (rb_ios_guest_unique_code(invoker, stockCode))
		0xaa0003e1,   // mov x1, x0
		0xf94003e0,   // ldr x0, [sp]
		0xf9400bfe,   // ldr x30, [sp, #16]
		0x910083ff,   // add sp, sp, #32
		cbzDenied,    // cbz x1, +8
		tailGenerate, // b sub_1006BDD4C
		0xd65f03c0,   // ret
	}
	if len(words) != guestResolverWordCount {
		return nil, errors.New("ipa: patch: internal guest resolver count mismatch")
	}
	return words, nil
}

func legacyLoginResolverWords() ([]uint32, error) {
	continueBranch, err := encodeArm64Branch(legacyLoginResolverRVA+8, legacyLoginVisibilityRVA+4, false)
	if err != nil {
		return nil, fmt.Errorf("ipa: patch: legacy-login continuation branch: %w", err)
	}
	return []uint32{
		0xaa1f03f4, // mov x20, xzr (saved visibility state remains hidden)
		0x2a1f03e1, // mov w1, wzr (alpha/state input remains hidden)
		continueBranch,
	}, nil
}

func loginReadyResolverWords() ([]uint32, error) {
	return loginReadyResolverWordsForSource(loginReadyResolverRVA, 0, false)
}

func gdprLoginReadyResolverWords() ([]uint32, error) {
	return loginReadyResolverWordsForSource(gdprLoginReadyResolverRVA, 1, true)
}

func loginReadyResolverWordsForSource(resolverRVA uint64, source uint32, use32BitArgument bool) ([]uint32, error) {
	if source > 0xffff {
		return nil, errors.New("ipa: patch: login-ready source does not fit MOVZ")
	}
	adrName, err := encodeArm64ADR(resolverRVA+3*4, loginReadyExportRVA, 1)
	if err != nil {
		return nil, err
	}
	callDlsym, err := encodeArm64Branch(resolverRVA+4*4, patchDlsymStubRVA, true)
	if err != nil {
		return nil, err
	}
	cbnzReady, err := encodeArm64CBNZ(resolverRVA+6*4, resolverRVA+8*4, 16)
	if err != nil {
		return nil, err
	}
	sourceMode := uint32(0xd2800000)
	if use32BitArgument {
		sourceMode = 0x52800000
	}
	sourceMode |= source << 5
	words := []uint32{
		0xd10043ff, // sub sp, sp, #16
		0xf90003fe, // str x30, [sp]
		0x92800020, // movn x0, #1 (RTLD_DEFAULT = (void *)-2)
		adrName,    // adr x1, rb_ios_on_login_ready
		callDlsym,  // bl _dlsym
		0xaa0003f0, // mov x16, x0
		cbnzReady,  // cbnz x16, call
		0xd4200000, // brk #0
		sourceMode, // mov x0/w0, #source
		0xd63f0200, // blr x16
		0xf94003fe, // ldr x30, [sp]
		0x910043ff, // add sp, sp, #16
		0xd65f03c0, // ret
	}
	if len(words) != loginReadyResolverWordCount || resolverRVA == gdprLoginReadyResolverRVA && len(words) != gdprLoginReadyResolverWordCount {
		return nil, errors.New("ipa: patch: internal login-ready resolver count mismatch")
	}
	return words, nil
}

func sessionResetResolverWords(resolverRVA, exportRVA, stockTarget uint64) ([]uint32, error) {
	adrName, err := encodeArm64ADR(resolverRVA+7*4, exportRVA, 1)
	if err != nil {
		return nil, err
	}
	callDlsym, err := encodeArm64Branch(resolverRVA+8*4, patchDlsymStubRVA, true)
	if err != nil {
		return nil, err
	}
	cbnzReady, err := encodeArm64CBNZ(resolverRVA+10*4, resolverRVA+12*4, 16)
	if err != nil {
		return nil, err
	}
	tailBranch, err := encodeArm64Branch(resolverRVA+20*4, stockTarget, false)
	if err != nil {
		return nil, err
	}
	words := []uint32{
		0xd10143ff, // sub sp, sp, #80
		0xa90007e0, // stp x0, x1, [sp]
		0xa9010fe2, // stp x2, x3, [sp, #16]
		0xa90217e4, // stp x4, x5, [sp, #32]
		0xa9031fe6, // stp x6, x7, [sp, #48]
		0xa9047be8, // stp x8, x30, [sp, #64]
		0x92800020, // movn x0, #1 (RTLD_DEFAULT = (void *)-2)
		adrName,    // adr x1, rb_ios_on_session_reset
		callDlsym,  // bl _dlsym
		0xaa0003f0, // mov x16, x0
		cbnzReady,  // cbnz x16, call
		0xd4200000, // brk #0
		0xd2800000, // mov x0, #0
		0xd63f0200, // blr x16
		0xa94007e0, // ldp x0, x1, [sp]
		0xa9410fe2, // ldp x2, x3, [sp, #16]
		0xa94217e4, // ldp x4, x5, [sp, #32]
		0xa9431fe6, // ldp x6, x7, [sp, #48]
		0xa9447be8, // ldp x8, x30, [sp, #64]
		0x910143ff, // add sp, sp, #80
		tailBranch, // b stock success continuation
	}
	if len(words) != sessionResetResolverWordCount {
		return nil, errors.New("ipa: patch: internal session-reset resolver count mismatch")
	}
	return words, nil
}

func checkSessionErrorResolverWords() ([]uint32, error) {
	adrName, err := encodeArm64ADR(checkSessionResolverRVA+7*4, checkSessionExportRVA, 1)
	if err != nil {
		return nil, err
	}
	callDlsym, err := encodeArm64Branch(checkSessionResolverRVA+8*4, patchDlsymStubRVA, true)
	if err != nil {
		return nil, err
	}
	cbnzReady, err := encodeArm64CBNZ(checkSessionResolverRVA+10*4, checkSessionResolverRVA+12*4, 16)
	if err != nil {
		return nil, err
	}
	continueBranch, err := encodeArm64Branch(checkSessionResolverRVA+21*4, checkSessionErrorEntryRVA+4, false)
	if err != nil {
		return nil, err
	}
	words := []uint32{
		0xd10143ff, // sub sp, sp, #80
		0xa90007e0, // stp x0, x1, [sp]
		0xa9010fe2, // stp x2, x3, [sp, #16]
		0xa90217e4, // stp x4, x5, [sp, #32]
		0xa9031fe6, // stp x6, x7, [sp, #48]
		0xa9047be8, // stp x8, x30, [sp, #64]
		0x92800020, // movn x0, #1 (RTLD_DEFAULT = (void *)-2)
		adrName,    // adr x1, rb_ios_on_check_session_error
		callDlsym,  // bl _dlsym
		0xaa0003f0, // mov x16, x0
		cbnzReady,  // cbnz x16, call
		0xd4200000, // brk #0
		0xf9400fe0, // ldr x0, [sp, #24] (saved ParsedHttpError* from entry x3)
		0xd63f0200, // blr x16
		0xa94007e0, // ldp x0, x1, [sp]
		0xa9410fe2, // ldp x2, x3, [sp, #16]
		0xa94217e4, // ldp x4, x5, [sp, #32]
		0xa9431fe6, // ldp x6, x7, [sp, #48]
		0xa9447be8, // ldp x8, x30, [sp, #64]
		0x910143ff, // add sp, sp, #80
		0xa9bd57f6, // original STP x22, x21, [sp, #-0x30]!
		continueBranch,
	}
	if len(words) != checkSessionResolverWordCount {
		return nil, errors.New("ipa: patch: internal checkSession resolver count mismatch")
	}
	return words, nil
}

func guestGenerateErrorResolverWords() ([]uint32, error) {
	adrName, err := encodeArm64ADR(guestGenerateResolverRVA+7*4, guestGenerateExportRVA, 1)
	if err != nil {
		return nil, err
	}
	callDlsym, err := encodeArm64Branch(guestGenerateResolverRVA+8*4, patchDlsymStubRVA, true)
	if err != nil {
		return nil, err
	}
	cbnzReady, err := encodeArm64CBNZ(guestGenerateResolverRVA+10*4, guestGenerateResolverRVA+12*4, 16)
	if err != nil {
		return nil, err
	}
	cbnzHandled, err := encodeArm64ZeroBranch(
		guestGenerateResolverRVA+22*4, guestGenerateResolverRVA+24*4, 9, 0x35000000)
	if err != nil {
		return nil, err
	}
	stockContinue, err := encodeArm64Branch(
		guestGenerateResolverRVA+23*4, guestGenerateDialogTailRVA, false)
	if err != nil {
		return nil, err
	}
	words := []uint32{
		0xd10143ff,    // sub sp, sp, #80
		0xa90007e0,    // stp x0, x1, [sp]
		0xa9010fe2,    // stp x2, x3, [sp, #16]
		0xa90217e4,    // stp x4, x5, [sp, #32]
		0xa9031fe6,    // stp x6, x7, [sp, #48]
		0xa9047be8,    // stp x8, x30, [sp, #64]
		0x92800020,    // movn x0, #1 (RTLD_DEFAULT = (void *)-2)
		adrName,       // adr x1, rb_ios_on_guest_generate_error
		callDlsym,     // bl _dlsym
		0xaa0003f0,    // mov x16, x0
		cbnzReady,     // cbnz x16, call
		0xd4200000,    // brk #0
		0xaa1303e0,    // mov x0, x19 (ParsedHttpError *)
		0xd63f0200,    // blr x16
		0x2a0003e9,    // mov w9, w0 (handled result)
		0xa94007e0,    // ldp x0, x1, [sp]
		0xa9410fe2,    // ldp x2, x3, [sp, #16]
		0xa94217e4,    // ldp x4, x5, [sp, #32]
		0xa9431fe6,    // ldp x6, x7, [sp, #48]
		0xa9447be8,    // ldp x8, x30, [sp, #64]
		0x910143ff,    // add sp, sp, #80
		0xa9417bfd,    // original LDP x29, x30, [sp, #16]
		cbnzHandled,   // cbnz w9, handled return
		stockContinue, // b to original remaining epilogue/dialog tail
		0xa8c24ff4,    // original LDP x20, x19, [sp], #0x20
		0xd65f03c0,    // ret: stock spinner/handled byte are already preserved
	}
	if len(words) != guestGenerateResolverWordCount {
		return nil, errors.New("ipa: patch: internal guest-generate-error resolver count mismatch")
	}
	return words, nil
}

func reservedRanges() ([]byteRange, error) {
	ranges := []byteRange{
		{noticeResolverRVA, noticeResolverRVA + noticeResolverWordCount*4, "notice resolver"},
		{noticeExportRVA, noticeExportRVA + uint64(len(ExportNotice404DiagnosticEntry)) + 1, "notice export"},
	}
	for _, spec := range socketStubSpecs {
		ranges = append(ranges,
			byteRange{spec.resolverRVA, spec.resolverRVA + stubResolverWordCount*4, spec.name + " resolver"},
			byteRange{spec.exportRVA, spec.exportRVA + uint64(len(spec.exportSym)) + 1, spec.name + " export"},
		)
	}
	ranges = append(ranges,
		byteRange{guestResolverRVA, guestResolverRVA + guestResolverWordCount*4, "guest auth resolver"},
		byteRange{guestExportRVA, guestExportRVA + uint64(len(ExportGuestUniqueCode)) + 1, "guest auth export"},
		byteRange{legacyLoginResolverRVA, legacyLoginResolverRVA + 3*4, "legacy login visibility resolver"},
		byteRange{loginReadyResolverRVA, loginReadyResolverRVA + loginReadyResolverWordCount*4, "login-ready resolver"},
		byteRange{loginReadyExportRVA, loginReadyExportRVA + uint64(len(ExportLoginReady)) + 1, "login-ready export"},
		byteRange{gdprLoginReadyResolverRVA, gdprLoginReadyResolverRVA + gdprLoginReadyResolverWordCount*4, "case 10043 GDPR-ready login-ready resolver"},
		byteRange{sessionOutResolverRVA, sessionOutResolverRVA + sessionResetResolverWordCount*4, "Logout session-reset resolver"},
		byteRange{sessionResetExportRVA, sessionResetExportRVA + uint64(len(ExportSessionReset)) + 1, "session-reset export"},
		byteRange{deleteDirectResolverRVA, deleteDirectResolverRVA + sessionResetResolverWordCount*4, "direct-delete session-reset resolver"},
		byteRange{deleteSNSResolverRVA, deleteSNSResolverRVA + sessionResetResolverWordCount*4, "SNS-delete session-reset resolver"},
		byteRange{checkSessionResolverRVA, checkSessionResolverRVA + checkSessionResolverWordCount*4, "checkSession-error resolver"},
		byteRange{checkSessionExportRVA, checkSessionExportRVA + uint64(len(ExportCheckSessionError)) + 1, "checkSession-error export"},
		byteRange{guestGenerateResolverRVA, guestGenerateResolverRVA + guestGenerateResolverWordCount*4, "guest-generate-error resolver"},
		byteRange{guestGenerateExportRVA, guestGenerateExportRVA + uint64(len(ExportGuestGenerateError)) + 1, "guest-generate-error export"},
	)
	return ranges, nil
}

func validateReservedRanges(ranges []byteRange) error {
	for i, r := range ranges {
		if r.start%4 != 0 {
			return fmt.Errorf("ipa: patch: %s start 0x%x is not 4-byte aligned", r.name, r.start)
		}
		if r.start < patchSlackWindowStart || r.end <= r.start || r.end > patchSlackWindowEnd ||
			r.start < patchLoaderHeaderEnd || r.end > patchFirstTextSection || r.end > uint64(MainSize) {
			return fmt.Errorf("ipa: patch: %s [0x%x..0x%x) is outside verified RX slack", r.name, r.start, r.end)
		}
		for _, prior := range ranges[:i] {
			if r.start < prior.end && prior.start < r.end {
				return fmt.Errorf("ipa: patch: %s overlaps %s", r.name, prior.name)
			}
		}
	}
	return nil
}

func patchCallsiteRanges() []byteRange {
	ranges := []byteRange{
		{noticeCallsiteRVA, noticeCallsiteRVA + 4, "notice callsite BL"},
		{autoGuestEntryRVA, autoGuestEntryRVA + 4, "auto-guest-entry SetEndLoading tail B"},
		{legacyLoginVisibilityRVA, legacyLoginVisibilityRVA + 4, "legacy login visibility helper"},
		{sessionOutSuccessRVA, sessionOutSuccessRVA + 4, "Logout sessionout success tail"},
		{deleteDirectSuccessRVA, deleteDirectSuccessRVA + 4, "direct Delete Avatar success tail"},
		{deleteSNSuccessRVA, deleteSNSuccessRVA + 4, "SNS Delete Avatar success tail"},
		{checkSessionErrorEntryRVA, checkSessionErrorEntryRVA + 4, "checkSession error entry"},
		{guestGenerateErrorTailRVA, guestGenerateErrorTailRVA + 4, "guest/generate error dialog tail"},
		{gdprLoginReadyCallsiteRVA, gdprLoginReadyCallsiteRVA + 4, "case 10043 GDPR-ready login-ready BL"},
	}
	for _, spec := range socketStubSpecs {
		ranges = append(ranges, byteRange{spec.stubRVA, spec.stubRVA + 4, spec.name + " stub B"})
	}
	for _, spec := range guestCallsiteSpecs {
		ranges = append(ranges, byteRange{spec.callsiteRVA, spec.callsiteRVA + 4, "guest " + spec.name})
	}
	return ranges
}

func verifyPatchOnlyDelta(before, after []byte) error {
	permitted, err := reservedRanges()
	if err != nil {
		return err
	}
	permitted = append(permitted, patchCallsiteRanges()...)
	return ensureDiffsWithin(before, after, permitted...)
}

func verifyFullWriteSet(original, out []byte) error {
	permitted, err := reservedRanges()
	if err != nil {
		return err
	}
	permitted = append(permitted,
		byteRange{16, 24, "Mach-O command counts"},
		byteRange{patchLoaderCommandOff, patchLoaderHeaderEnd, "LC_LOAD_DYLIB"},
	)
	permitted = append(permitted, patchCallsiteRanges()...)
	return ensureDiffsWithin(original, out, permitted...)
}

func ensureDiffsWithin(before, after []byte, permitted ...byteRange) error {
	if len(before) != len(after) {
		return fmt.Errorf("image length changed from %d to %d", len(before), len(after))
	}
	for i := range before {
		if before[i] == after[i] {
			continue
		}
		allowed := false
		for _, r := range permitted {
			if uint64(i) >= r.start && uint64(i) < r.end {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("unexpected changed byte at file offset 0x%x", i)
		}
	}
	return nil
}

func validateMachHeader(data []byte, wantNcmds, wantCmdSize uint32) error {
	if len(data) < 32 {
		return errors.New("truncated Mach-O header")
	}
	bo := binary.LittleEndian
	if bo.Uint32(data[0:]) != 0xfeedfacf {
		return errors.New("expected little-endian 64-bit Mach-O")
	}
	if bo.Uint32(data[4:]) != 0x0100000c {
		return errors.New("expected arm64 Mach-O")
	}
	if bo.Uint32(data[12:]) != 2 {
		return errors.New("expected MH_EXECUTE")
	}
	if bo.Uint32(data[16:]) != wantNcmds || bo.Uint32(data[20:]) != wantCmdSize {
		return fmt.Errorf("load-command header mismatch: ncmds=%d sizeofcmds=%d", bo.Uint32(data[16:]), bo.Uint32(data[20:]))
	}
	return nil
}

func parseLoadCommands(data []byte) ([]patchLoadCommand, error) {
	if len(data) < 32 {
		return nil, errors.New("ipa: patch: truncated Mach-O header")
	}
	bo := binary.LittleEndian
	ncmds := bo.Uint32(data[16:])
	cmdSize := uint64(bo.Uint32(data[20:]))
	end := uint64(32) + cmdSize
	if end > uint64(len(data)) {
		return nil, errors.New("ipa: patch: load commands exceed image")
	}
	out := make([]patchLoadCommand, 0, ncmds)
	off := uint64(32)
	for i := uint32(0); i < ncmds; i++ {
		if off+8 > end {
			return nil, errors.New("ipa: patch: truncated load command")
		}
		cmd := bo.Uint32(data[off:])
		sz := uint64(bo.Uint32(data[off+4:]))
		if sz < 8 || sz > end-off {
			return nil, errors.New("ipa: patch: malformed load-command size")
		}
		out = append(out, patchLoadCommand{
			cmd:  cmd,
			off:  off,
			size: sz,
			raw:  data[off : off+sz],
		})
		off += sz
	}
	if off != end {
		return nil, errors.New("ipa: patch: load-command sizes do not add up")
	}
	return out, nil
}

func verifyLoaderOnlyDelta(before, after []byte) error {
	if len(before) != len(after) {
		return errors.New("ipa: patch: AddLoader changed image length")
	}
	if err := ensureDiffsWithin(before, after,
		byteRange{16, 24, "Mach-O command counts"},
		byteRange{patchLoaderCommandOff, patchLoaderHeaderEnd, "LC_LOAD_DYLIB"},
	); err != nil {
		return fmt.Errorf("ipa: patch: unexpected AddLoader write: %w", err)
	}
	if got := binary.LittleEndian.Uint32(after[patchLoaderCommandOff:]); got != lcLoadDylib {
		return errors.New("ipa: patch: AddLoader dependency command is not at the verified offset")
	}
	if !bytes.Equal(after[patchLoaderCommandOff:patchLoaderHeaderEnd], loaderCommand()) {
		return errors.New("ipa: patch: AddLoader dependency command differs from the vetted form")
	}
	return nil
}

func parseSegment64(raw []byte) (patchImageSegment, error) {
	if len(raw) < segment64HeaderSize {
		return patchImageSegment{}, errors.New("ipa: patch: truncated LC_SEGMENT_64")
	}
	bo := binary.LittleEndian
	nsects := bo.Uint32(raw[64:])
	if uint64(segment64HeaderSize)+uint64(nsects)*section64Size != uint64(len(raw)) {
		return patchImageSegment{}, errors.New("ipa: patch: segment section count mismatch")
	}
	seg := patchImageSegment{
		name:     fixedMachCString(raw[8:24]),
		vmaddr:   bo.Uint64(raw[24:]),
		vmsize:   bo.Uint64(raw[32:]),
		fileoff:  bo.Uint64(raw[40:]),
		filesize: bo.Uint64(raw[48:]),
		maxprot:  bo.Uint32(raw[56:]),
		initprot: bo.Uint32(raw[60:]),
		nsects:   nsects,
	}
	for i := uint32(0); i < nsects; i++ {
		off := segment64HeaderSize + int(i)*section64Size
		sec := raw[off : off+section64Size]
		seg.sections = append(seg.sections, patchImageSection{
			name:     fixedMachCString(sec[0:16]),
			segment:  fixedMachCString(sec[16:32]),
			addr:     bo.Uint64(sec[32:]),
			size:     bo.Uint64(sec[40:]),
			fileoff:  uint64(bo.Uint32(sec[48:])),
			flags:    bo.Uint32(sec[64:]),
			indirect: bo.Uint32(sec[68:]),
			stubLen:  bo.Uint32(sec[72:]),
		})
	}
	return seg, nil
}

func validateExactSegments(segments []patchImageSegment, imageSize int) (stubsSec, laSymPtrSec, gotSec *patchImageSection, err error) {
	want := map[string]patchImageSegment{
		"__PAGEZERO": {name: "__PAGEZERO", vmaddr: 0, vmsize: 0x100000000},
		"__TEXT": {
			name: "__TEXT", vmaddr: patchTextVMAddr, vmsize: patchTextVMSize,
			fileoff: 0, filesize: patchTextVMSize, maxprot: 5, initprot: 5, nsects: 13,
		},
		"__DATA": {
			name: "__DATA", vmaddr: patchDataVMAddr, vmsize: patchDataVMSize,
			fileoff: patchDataFileOff, filesize: patchDataFileLen, maxprot: 3, initprot: 3, nsects: 21,
		},
		"__LINKEDIT": {
			name: "__LINKEDIT", vmaddr: patchLinkVMAddr, vmsize: patchLinkVMSize,
			fileoff: patchLinkFileOff, filesize: patchLinkFileLen, maxprot: 1, initprot: 1,
		},
	}
	if len(segments) != len(want) {
		return nil, nil, nil, fmt.Errorf("ipa: patch: segment count mismatch: %d", len(segments))
	}
	seen := make(map[string]bool, len(segments))
	var textFound bool
	for _, seg := range segments {
		expected, ok := want[seg.name]
		if !ok || seen[seg.name] {
			return nil, nil, nil, fmt.Errorf("ipa: patch: unexpected or duplicate segment %q", seg.name)
		}
		seen[seg.name] = true
		if seg.name != expected.name ||
			seg.vmaddr != expected.vmaddr || seg.vmsize != expected.vmsize ||
			seg.fileoff != expected.fileoff || seg.filesize != expected.filesize ||
			seg.maxprot != expected.maxprot || seg.initprot != expected.initprot ||
			seg.nsects != expected.nsects {
			return nil, nil, nil, fmt.Errorf("ipa: patch: %s segment bounds/protections differ from locked image", seg.name)
		}
		if seg.vmaddr%0x4000 != 0 || seg.vmsize%0x4000 != 0 {
			return nil, nil, nil, fmt.Errorf("ipa: patch: %s segment is not 16-KiB aligned", seg.name)
		}
		if seg.initprot&3 == 3 && seg.initprot&4 != 0 {
			return nil, nil, nil, fmt.Errorf("ipa: patch: writable-executable %s segment", seg.name)
		}
		if seg.filesize > 0 {
			end := seg.fileoff + seg.filesize
			if end < seg.fileoff || end > uint64(imageSize) {
				return nil, nil, nil, fmt.Errorf("ipa: patch: %s file bounds invalid", seg.name)
			}
		}
		for i := range seg.sections {
			sec := seg.sections[i]
			if sec.segment != seg.name {
				return nil, nil, nil, errors.New("ipa: patch: section segment name mismatch")
			}
			switch {
			case seg.name == "__TEXT" && sec.name == "__text":
				textFound = sec.addr == patchTextVMAddr+patchFirstTextSection &&
					sec.fileoff == patchFirstTextSection && sec.size > 0
			case seg.name == "__TEXT" && sec.name == "__stubs":
				if sec.addr == patchTextVMAddr+patchStubsFileOff && sec.fileoff == patchStubsFileOff &&
					sec.size == patchStubsSize && sec.flags&0xff == sectionSymbolStubs && sec.stubLen == patchStubsLen {
					s := sec
					stubsSec = &s
				}
			case seg.name == "__DATA" && sec.name == "__la_symbol_ptr":
				if sec.addr == patchLaSymPtrAddr && sec.fileoff == patchLaSymPtrFileOff &&
					sec.size == patchLaSymPtrSize && sec.flags&0xff == sectionLazyPtr {
					s := sec
					laSymPtrSec = &s
				}
			case seg.name == "__DATA" && sec.name == "__got":
				if sec.addr == patchGotSectionAddr && sec.fileoff == patchGotSectionOff &&
					sec.size == patchGotSectionSize && sec.flags&0xff == sectionNonLazyPtr {
					s := sec
					gotSec = &s
				}
			}
		}
	}
	for name := range want {
		if !seen[name] {
			return nil, nil, nil, fmt.Errorf("ipa: patch: missing %s segment", name)
		}
	}
	if !textFound {
		return nil, nil, nil, errors.New("ipa: patch: __TEXT,__text layout mismatch")
	}
	if stubsSec == nil {
		return nil, nil, nil, errors.New("ipa: patch: __TEXT,__stubs layout mismatch")
	}
	if laSymPtrSec == nil || gotSec == nil {
		return nil, nil, nil, errors.New("ipa: patch: __DATA pointer sections mismatch")
	}
	return stubsSec, laSymPtrSec, gotSec, nil
}

func writeWords(dst []byte, words []uint32) {
	for i, w := range words {
		binary.LittleEndian.PutUint32(dst[i*4:], w)
	}
}

func encodeWords(words []uint32) []byte {
	buf := make([]byte, len(words)*4)
	writeWords(buf, words)
	return buf
}

func decodeArm64Branch(word uint32, pc uint64) (uint64, bool, bool) {
	op := word & 0xfc000000
	if op != 0x14000000 && op != 0x94000000 {
		return 0, false, false
	}
	imm := int64(word & 0x03ffffff)
	if imm&(1<<25) != 0 {
		imm |= ^int64(0x03ffffff)
	}
	delta := imm << 2
	if pc > math.MaxInt64 {
		return 0, false, false
	}
	target := int64(pc) + delta
	if target < 0 {
		return 0, false, false
	}
	return uint64(target), op == 0x94000000, true
}

func decodeArm64ADR(word uint32, pc uint64) (uint64, uint32, bool) {
	if word&0x9f000000 != 0x10000000 || pc > math.MaxInt64 {
		return 0, 0, false
	}
	rd := word & 0x1f
	imm := int64(((word >> 5) & 0x7ffff) << 2)
	imm |= int64((word >> 29) & 3)
	if imm&(1<<20) != 0 {
		imm |= ^int64(0x1fffff)
	}
	target := int64(pc) + imm
	if target < 0 {
		return 0, 0, false
	}
	return uint64(target), rd, true
}

func decodeArm64ADRP(word uint32, pc uint64) (uint64, uint32, bool) {
	if word&0x9f000000 != 0x90000000 || pc > math.MaxInt64 {
		return 0, 0, false
	}
	rd := word & 0x1f
	imm := int64(((word >> 5) & 0x7ffff) << 2)
	imm |= int64((word >> 29) & 3)
	if imm&(1<<20) != 0 {
		imm |= ^int64(0x1fffff)
	}
	pageBase := int64(pc &^ 0xfff)
	target := pageBase + (imm << 12)
	if target < 0 {
		return 0, 0, false
	}
	return uint64(target), rd, true
}

func decodeArm64LDR64Unsigned(word uint32) (rt, rn uint32, offset uint64, ok bool) {
	if word&0xffc00000 != 0xf9400000 {
		return 0, 0, 0, false
	}
	rt = word & 0x1f
	rn = (word >> 5) & 0x1f
	imm12 := uint64((word >> 10) & 0xfff)
	return rt, rn, imm12 << 3, true
}

func decodeArm64Pair64Offset(word uint32) (load bool, rt, rt2, rn uint32, offset int64, ok bool) {
	op := word & 0xffc00000
	if op != 0xa9000000 && op != 0xa9400000 {
		return false, 0, 0, 0, 0, false
	}
	imm7 := int64((word >> 15) & 0x7f)
	if imm7&(1<<6) != 0 {
		imm7 |= ^int64(0x7f)
	}
	return op == 0xa9400000, word & 0x1f, (word >> 10) & 0x1f, (word >> 5) & 0x1f, imm7 * 8, true
}

func encodeArm64ZeroBranch(pc, target uint64, rt uint32, opcode uint32) (uint32, error) {
	if pc&3 != 0 || target&3 != 0 || rt > 31 || pc > math.MaxInt64 || target > math.MaxInt64 {
		return 0, errors.New("ipa: patch: invalid ARM64 CBZ/CBNZ operands")
	}
	delta := int64(target) - int64(pc)
	if delta < -(1<<20) || delta > (1<<20)-4 {
		return 0, errors.New("ipa: patch: ARM64 CBZ/CBNZ target is outside signed imm19 range")
	}
	return opcode | ((uint32(delta>>2) & 0x7ffff) << 5) | rt, nil
}

func decodeArm64ZeroBranch(word uint32, pc uint64, opcode uint32) (uint64, uint32, bool) {
	if word&0xff000000 != opcode || pc&3 != 0 || pc > math.MaxInt64 {
		return 0, 0, false
	}
	rt := word & 0x1f
	imm := int64((word >> 5) & 0x7ffff)
	if imm&(1<<18) != 0 {
		imm |= ^int64(0x7ffff)
	}
	target := int64(pc) + (imm << 2)
	if target < 0 {
		return 0, 0, false
	}
	return uint64(target), rt, true
}

func encodeArm64CBZ(pc, target uint64, rt uint32) (uint32, error) {
	return encodeArm64ZeroBranch(pc, target, rt, 0xb4000000)
}

func decodeArm64CBZ(word uint32, pc uint64) (uint64, uint32, bool) {
	return decodeArm64ZeroBranch(word, pc, 0xb4000000)
}

func decodeArm64CBNZ(word uint32, pc uint64) (uint64, uint32, bool) {
	return decodeArm64ZeroBranch(word, pc, 0xb5000000)
}
