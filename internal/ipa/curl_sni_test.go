package ipa

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestCurlSNIGateSynthetic(t *testing.T) {
	prepared := syntheticPreparedImage()
	if err := validateCurlSNIGate(prepared); err != nil {
		t.Fatal(err)
	}
	out, err := emitAllPatches(prepared)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(out[curlSNIGateRVA:]); got != curlSNIGatePatchedWord {
		t.Fatalf("gate word 0x%08x, want NOP", got)
	}
	// Only the gate word changes inside the guard window.
	end := curlSNIGuardEnd()
	for off := curlSNIGuardStart; off < end; off += 4 {
		if off == curlSNIGateRVA {
			continue
		}
		if !bytes.Equal(prepared[off:off+4], out[off:off+4]) {
			t.Fatalf("guard word at 0x%x changed", off)
		}
	}
	if err := verifyCurlSNIPatch(prepared, out); err != nil {
		t.Fatal(err)
	}

	found := false
	for _, r := range patchCallsiteRanges() {
		if r.start == curlSNIGateRVA && r.end == curlSNIGateRVA+4 {
			found = true
		}
	}
	if !found {
		t.Fatal("patchCallsiteRanges missing the curl SNI gate word")
	}
}

func TestCurlSNIGateRejectsDrift(t *testing.T) {
	for off := curlSNIGuardStart; off < curlSNIGuardEnd(); off += 4 {
		img := syntheticPreparedImage()
		img[off] ^= 0x01
		if err := validateCurlSNIGate(img); err == nil {
			t.Fatalf("accepted mutated guard word at 0x%x", off)
		}
		if _, err := emitAllPatches(img); err == nil {
			t.Fatalf("emitAllPatches accepted mutated guard word at 0x%x", off)
		}
	}
}

func TestCurlSNIVerifyRejectsWrongPatch(t *testing.T) {
	prepared := syntheticPreparedImage()
	out, err := emitAllPatches(prepared)
	if err != nil {
		t.Fatal(err)
	}
	// Gate left as stock CBZ.
	bad := append([]byte(nil), out...)
	binary.LittleEndian.PutUint32(bad[curlSNIGateRVA:], curlSNIGateOrigWord)
	if err := verifyCurlSNIPatch(prepared, bad); err == nil {
		t.Fatal("accepted unpatched gate")
	}
	// Neighbouring guard word changed (for example the VERIFYHOST load).
	bad = append([]byte(nil), out...)
	bad[curlSNIGuardStart] ^= 0x01
	if err := verifyCurlSNIPatch(prepared, bad); err == nil {
		t.Fatal("accepted mutated VERIFYHOST load")
	}
	bad = append([]byte(nil), out...)
	bad[curlSetPeerDomainCallPC] ^= 0x01
	if err := verifyCurlSNIPatch(prepared, bad); err == nil {
		t.Fatal("accepted mutated SSLSetPeerDomainName call")
	}
}

func TestCurlSNIGateDecodes(t *testing.T) {
	target, rt, ok := decodeArm64ZeroBranch(curlSNIGateOrigWord, curlSNIGateRVA, 0x34000000) // 32-bit CBZ Wt
	if !ok || rt != 8 || target != curlSNIGateSkipTarget {
		t.Fatalf("CBZ decode target=0x%x rt=%d ok=%t", target, rt, ok)
	}
	call := curlSNIGuardWords[(curlSetPeerDomainCallPC-curlSNIGuardStart)/4]
	target, link, ok := decodeArm64Branch(call, curlSetPeerDomainCallPC)
	if !ok || !link || target != curlSetPeerDomainStub {
		t.Fatalf("BL decode target=0x%x link=%t ok=%t", target, link, ok)
	}
}

func TestCurlSNIGateRealBaseline(t *testing.T) {
	original := loadBaselineMainForTest(t)
	if err := validateCurlSNIGate(original); err != nil {
		t.Fatal(err)
	}
	out, err := PatchMainExecutable(original)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCurlSNIPatch(original, out); err != nil {
		t.Fatal(err)
	}
	mutated := append([]byte(nil), original...)
	mutated[curlSNIGateRVA] ^= 0x01
	if _, err := PatchMainExecutable(mutated); err == nil {
		t.Fatal("PatchMainExecutable accepted a mutated SNI gate")
	}
}
