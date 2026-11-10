// Package baseline locks the patcher to one LINE PLAY APK by size and SHA-256.
// It streams the file and never logs file bytes.
package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	// SHA256Hex is the locked baseline digest (Cherry 2026-11-09, rechecked 2026-11-10).
	SHA256Hex = "aa6495a0430beef0c9a719a1f09fe836ff1c82a0f4f96235d47fffda070b45d1"
	// Size is the locked baseline length in bytes.
	Size int64 = 63962807
)

// ErrMismatch means the file is not the locked baseline. The error text has
// size and digest only, never file bytes.
var ErrMismatch = errors.New("baseline mismatch")

var expectedSum = mustDecode(SHA256Hex)

func mustDecode(s string) [32]byte {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		panic("baseline: locked hash is not 32 bytes")
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

// Verify reports whether path is a regular file of the locked size and digest.
func Verify(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return errors.New("baseline: not a regular file")
	}
	if st.Size() != Size {
		return fmt.Errorf("%w: size %d", ErrMismatch, st.Size())
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sum, n, err := hashReader(f)
	if err != nil {
		return err
	}
	if n != Size || sum != expectedSum {
		return fmt.Errorf("%w: size %d hash %x", ErrMismatch, n, sum[:])
	}
	return nil
}

func hashReader(r io.Reader) (sum [32]byte, n int64, err error) {
	h := sha256.New()
	n, err = io.Copy(h, r)
	if err != nil {
		return sum, n, err
	}
	copy(sum[:], h.Sum(nil))
	return sum, n, nil
}
