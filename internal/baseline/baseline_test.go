package baseline

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLockedConstants(t *testing.T) {
	if SHA256Hex != "aa6495a0430beef0c9a719a1f09fe836ff1c82a0f4f96235d47fffda070b45d1" {
		t.Fatalf("hash %s", SHA256Hex)
	}
	if Size != 63962807 {
		t.Fatalf("size %d", Size)
	}
	if expectedSum != mustDecode(SHA256Hex) {
		t.Fatal("expected sum drifted")
	}
}

func TestHashReaderKnown(t *testing.T) {
	sum, n, err := hashReader(strings.NewReader("abc"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("n %d", n)
	}
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := fmtHex(sum); got != want {
		t.Fatalf("got %s", got)
	}
}

func TestVerifyRejectsSynthetic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "synthetic.bin")
	body := []byte("synthetic-not-an-apk")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	err := Verify(path)
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), "synthetic") {
		t.Fatalf("error leaked file bytes: %v", err)
	}
}

func TestVerifyStreamMismatchHasDigestOnly(t *testing.T) {
	sum, n, err := hashReader(bytes.NewReader([]byte("abc")))
	if err != nil {
		t.Fatal(err)
	}
	if n == Size && sum == expectedSum {
		t.Fatal("synthetic hash collided with baseline")
	}
}

func fmtHex(sum [32]byte) string {
	const hexdigits = "0123456789abcdef"
	var b [64]byte
	for i, c := range sum {
		b[i*2] = hexdigits[c>>4]
		b[i*2+1] = hexdigits[c&0x0f]
	}
	return string(b[:])
}
