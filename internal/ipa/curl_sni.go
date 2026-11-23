package ipa

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Bundled libcurl 7.61.1 (SecureTransport backend) connect step, sub_101437698.
// Stock curl calls SSLSetPeerDomainName, which is the only place SNI gets set,
// only when CURLOPT_SSL_VERIFYHOST (connection byte +0x301) is nonzero. The
// game's ADI HTTP wrapper sets VERIFYPEER=0 and VERIFYHOST=0, so iOS sends no
// SNI on any game HTTPS connection. Hosts that need SNI (for example
// Cloudflare-fronted object storage a Cherry operator redirects static assets
// to) then fail the TLS handshake. Android's OpenSSL backend sends SNI
// regardless of verification.
//
// The patch turns the VERIFYHOST gate (CBZ W8 -> skip) into a NOP so the
// original request host name is always set as the peer domain name. VERIFYHOST
// is read nowhere else in the backend; certificate trust stays off because
// VERIFYPEER (+0x300) still selects kSSLSessionOptionBreakOnServerAuth and curl
// skips trust evaluation. The two inet_pton calls that follow are diagnostics
// whose results stock code discards.
const (
	curlSNIGateRVA          = uint64(0x1438000)
	curlSNIGateOrigWord     = uint32(0x34000288) // cbz w8, 0x1438050
	curlSNIGateSkipTarget   = uint64(0x1438050)
	curlSNIGatePatchedWord  = uint32(0xd503201f) // nop
	curlSNIGuardStart       = uint64(0x1437ffc)
	curlSetPeerDomainCallPC = uint64(0x1438028)
	curlSetPeerDomainStub   = uint64(0x1abfcc0) // __stubs _SSLSetPeerDomainName
)

// curlSNIGuardWords is LDRB W8,[X21,#0x301]; CBZ W8; the context/host-name
// loads; BL _strlen; argument moves; BL _SSLSetPeerDomainName; MOV W0,#2.
var curlSNIGuardWords = []uint32{
	0x394c06a8, curlSNIGateOrigWord, 0xf94033e8, 0xf9400108,
	0xf9400119, 0xf9403ffa, 0xaa1a03e0, 0x941a29e3,
	0xaa0003e2, 0xaa1903e0, 0xaa1a03e1, 0x941a1f26,
	0x321f03e0,
}

func curlSNIGuardEnd() uint64 {
	return curlSNIGuardStart + uint64(len(curlSNIGuardWords))*4
}

// validateCurlSNIGate checks the locked stock SecureTransport SNI gate.
func validateCurlSNIGate(data []byte) error {
	end := curlSNIGuardEnd()
	if end > uint64(len(data)) {
		return fmt.Errorf("ipa: patch: curl SNI guard window exceeds image bounds")
	}
	if !bytes.Equal(data[curlSNIGuardStart:end], encodeWords(curlSNIGuardWords)) {
		return fmt.Errorf("ipa: patch: curl SNI guard mismatch")
	}
	target, rt, ok := decodeArm64ZeroBranch(curlSNIGateOrigWord, curlSNIGateRVA, 0x34000000) // 32-bit CBZ Wt
	if !ok || rt != 8 || target != curlSNIGateSkipTarget {
		return fmt.Errorf("ipa: patch: curl SNI gate is not CBZ W8, 0x%x", curlSNIGateSkipTarget)
	}
	call := binary.LittleEndian.Uint32(data[curlSetPeerDomainCallPC:])
	if target, link, ok := decodeArm64Branch(call, curlSetPeerDomainCallPC); !ok || !link || target != curlSetPeerDomainStub {
		return fmt.Errorf("ipa: patch: curl SNI call is not BL _SSLSetPeerDomainName (0x%x)", target)
	}
	return nil
}

// verifyCurlSNIPatch checks that only the gate word changed, to a NOP.
func verifyCurlSNIPatch(before, after []byte) error {
	if got := binary.LittleEndian.Uint32(after[curlSNIGateRVA:]); got != curlSNIGatePatchedWord {
		return fmt.Errorf("ipa: patch: post-patch curl SNI gate word 0x%08x != NOP", got)
	}
	end := curlSNIGuardEnd()
	if !bytes.Equal(before[curlSNIGuardStart:curlSNIGateRVA], after[curlSNIGuardStart:curlSNIGateRVA]) ||
		!bytes.Equal(before[curlSNIGateRVA+4:end], after[curlSNIGateRVA+4:end]) {
		return fmt.Errorf("ipa: patch: post-patch curl SNI guard mutated")
	}
	return nil
}
