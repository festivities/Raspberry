package patch

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode"
)

const (
	// LibgameArm64SHA is the locked uncompressed arm64 libgame.so digest.
	LibgameArm64SHA = "d824c3ef72ac1948f3c5a31619879384f4659c9306e6f5a1b04793334e795b04"
	// LibgameArmv7SHA is the locked uncompressed armeabi-v7a libgame.so digest.
	LibgameArmv7SHA = "8eadba34f30f971188f54010b9dcb5217f1000d2073911fed421edc646473ca7"
	// Classes3SHA is the locked classes3.dex digest.
	Classes3SHA = "a2f4a9551f0671f87c22c09f0a9e27e30b6ffe972359511520515cda2c5603f1"
	// Classes3Size is the locked classes3.dex length.
	Classes3Size int64 = 10365648
)

var (
	// ErrHash means the input digest is not the table's locked digest.
	ErrHash = errors.New("patch: hash mismatch")
	// ErrBounds means an edit or window does not fit in the input.
	ErrBounds = errors.New("patch: out of bounds")
	// ErrExpected means the bytes at an offset are not the expected bytes.
	ErrExpected = errors.New("patch: expected bytes mismatch")
	// ErrTable means the table text is invalid.
	ErrTable = errors.New("patch: bad table")
)

// Edit is one expected-bytes replacement. Offset is a file offset.
type Edit struct {
	Offset      int64
	Expected    []byte
	Replacement []byte
	Comment     string
}

// Window is an expected byte run that is not itself a write. It catches a
// shifted offset before any byte is changed.
type Window struct {
	Offset   int64
	Expected []byte
}

// Table is a hash-locked set of byte edits.
type Table struct {
	ID      string
	SHA256  string
	Edits   []Edit
	Windows []Window
}

// LoadTable reads a patch table. Lines are "id", "sha256", "edit" or "window".
// A '#' starts a comment. edit is: offset expected replacement comment...
func LoadTable(path string) (Table, error) {
	f, err := os.Open(path)
	if err != nil {
		return Table{}, err
	}
	defer f.Close()
	return ParseTable(f)
}

// ParseTable parses a table from r.
func ParseTable(r io.Reader) (Table, error) {
	var t Table
	sc := bufio.NewScanner(r)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return Table{}, fmt.Errorf("%w: line %d", ErrTable, lineNo)
		}
		switch fields[0] {
		case "id":
			if len(fields) != 2 || t.ID != "" {
				return Table{}, fmt.Errorf("%w: line %d", ErrTable, lineNo)
			}
			t.ID = fields[1]
		case "sha256":
			if len(fields) != 2 || t.SHA256 != "" || !isSHA(fields[1]) {
				return Table{}, fmt.Errorf("%w: line %d", ErrTable, lineNo)
			}
			t.SHA256 = fields[1]
		case "edit":
			if len(fields) < 4 {
				return Table{}, fmt.Errorf("%w: line %d", ErrTable, lineNo)
			}
			ed, err := parseEdit(fields[1], fields[2], fields[3], strings.Join(fields[4:], " "))
			if err != nil {
				return Table{}, fmt.Errorf("%w: line %d", err, lineNo)
			}
			t.Edits = append(t.Edits, ed)
		case "window":
			if len(fields) != 3 {
				return Table{}, fmt.Errorf("%w: line %d", ErrTable, lineNo)
			}
			off, err := parseOff(fields[1])
			if err != nil {
				return Table{}, fmt.Errorf("%w: line %d", err, lineNo)
			}
			exp, err := hex.DecodeString(fields[2])
			if err != nil || len(exp) == 0 {
				return Table{}, fmt.Errorf("%w: line %d", ErrTable, lineNo)
			}
			t.Windows = append(t.Windows, Window{Offset: off, Expected: exp})
		default:
			return Table{}, fmt.Errorf("%w: line %d", ErrTable, lineNo)
		}
	}
	if err := sc.Err(); err != nil {
		return Table{}, err
	}
	if t.ID == "" || t.SHA256 == "" || len(t.Edits) == 0 {
		return Table{}, fmt.Errorf("%w: incomplete", ErrTable)
	}
	return t, nil
}

func parseEdit(offS, expS, repS, comment string) (Edit, error) {
	off, err := parseOff(offS)
	if err != nil {
		return Edit{}, err
	}
	exp, err := hex.DecodeString(expS)
	if err != nil || len(exp) == 0 {
		return Edit{}, ErrTable
	}
	rep, err := hex.DecodeString(repS)
	if err != nil || len(rep) != len(exp) {
		return Edit{}, ErrTable
	}
	if bytes.Equal(exp, rep) {
		return Edit{}, ErrTable
	}
	return Edit{Offset: off, Expected: exp, Replacement: rep, Comment: comment}, nil
}

func parseOff(s string) (int64, error) {
	n, err := strconv.ParseInt(s, 0, 64)
	if err != nil || n < 0 {
		return 0, ErrTable
	}
	return n, nil
}

func isSHA(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !unicode.Is(unicode.ASCII_Hex_Digit, r) || unicode.IsUpper(r) {
			return false
		}
	}
	return true
}

// Apply checks the locked digest, every window and every expected byte, then
// returns a copy with the edits applied. It does not mutate buf. Errors name
// the offset only; they never include input bytes.
func Apply(buf []byte, t Table) ([]byte, error) {
	sum := sha256.Sum256(buf)
	got := hex.EncodeToString(sum[:])
	if got != t.SHA256 {
		return nil, fmt.Errorf("%w: got %s", ErrHash, got)
	}
	for _, w := range t.Windows {
		if err := expect(buf, w.Offset, w.Expected); err != nil {
			return nil, err
		}
	}
	for _, ed := range t.Edits {
		if err := expect(buf, ed.Offset, ed.Expected); err != nil {
			return nil, err
		}
	}
	out := bytes.Clone(buf)
	for _, ed := range t.Edits {
		copy(out[ed.Offset:], ed.Replacement)
	}
	return out, nil
}

func expect(buf []byte, off int64, want []byte) error {
	end := off + int64(len(want))
	if off < 0 || end < off || end > int64(len(buf)) {
		return fmt.Errorf("%w: offset %d len %d", ErrBounds, off, len(want))
	}
	if !bytes.Equal(buf[off:end], want) {
		return fmt.Errorf("%w: offset %d", ErrExpected, off)
	}
	return nil
}

// ApplyFile reads inPath, applies t and writes outPath. outPath must not exist.
func ApplyFile(inPath, outPath string, t Table) error {
	buf, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}
	out, err := Apply(buf, t)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(outPath); err == nil {
		return errors.New("patch: destination exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.WriteFile(outPath, out, 0o644)
}
