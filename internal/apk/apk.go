// Package apk repacks a ZIP/APK entry by entry.
// Compressed payloads are copied raw. Timestamps are fixed. Order is the
// source central-directory order.
//
// shortcut: this drops the APK Signing Block (it is not a ZIP entry) and does
// not zipalign. v1 META-INF signatures stay unless Options.StripSignatures.
// Upgrade when the signer lands.
package apk

import (
	"archive/zip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	dataDescriptorFlag = 0x8
	extTimeExtraID     = 0x5455
	ntfsExtraID        = 0x000a
	unixExtraID        = 0x000d
)

// fixedTime is the ZIP DOS epoch. Every repack uses it.
var fixedTime = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

var (
	ErrExists    = errors.New("apk: destination exists")
	ErrDuplicate = errors.New("apk: duplicate entry")
	ErrName      = errors.New("apk: invalid entry name")
	ErrMissing   = errors.New("apk: replacement target missing")
	ErrPresent   = errors.New("apk: addition target exists")
	ErrOverlap   = errors.New("apk: conflicting upsert")
)

// Options controls a repack. The zero value copies every entry and keeps signatures.
type Options struct {
	// StripSignatures drops JAR signature entries. Set it only when the
	// caller will sign the output; a stale v1 signature would not match.
	StripSignatures bool
	// Replacements are uncompressed payloads for entries that already exist.
	// The entry stays in place and keeps its compression method.
	Replacements map[string][]byte
	// Additions are uncompressed payloads for entries that must not already exist.
	// They are written after the source entries, sorted by name, deflated.
	Additions map[string][]byte
}

// Repack reads src and writes dst. dst must not exist. The write is a temp
// file in the destination directory, linked into place without replacement.
func Repack(src, dst string, opt Options) error {
	same, err := samePath(src, dst)
	if err != nil {
		return err
	}
	if same {
		return errors.New("apk: source and destination are the same")
	}
	return writeAtomic(dst, func(w io.Writer) error {
		zr, err := zip.OpenReader(src)
		if err != nil {
			return err
		}
		defer zr.Close()
		zw := zip.NewWriter(w)
		if err := copyEntries(&zr.Reader, zw, opt); err != nil {
			zw.Close()
			return err
		}
		return zw.Close()
	})
}

func copyEntries(r *zip.Reader, w *zip.Writer, opt Options) error {
	keep, err := plan(r, opt)
	if err != nil {
		return err
	}
	for _, f := range keep {
		if body, ok := opt.Replacements[f.Name]; ok {
			if err := writePayload(w, f.Name, f.Method, body, f.Extra); err != nil {
				return err
			}
			continue
		}
		if err := copyRaw(w, f); err != nil {
			return err
		}
	}
	names := make([]string, 0, len(opt.Additions))
	for name := range opt.Additions {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := writePayload(w, name, zip.Deflate, opt.Additions[name], nil); err != nil {
			return err
		}
	}
	return nil
}

func plan(r *zip.Reader, opt Options) ([]*zip.File, error) {
	if err := checkUpsertNames(opt.Replacements); err != nil {
		return nil, err
	}
	if err := checkUpsertNames(opt.Additions); err != nil {
		return nil, err
	}
	for name := range opt.Replacements {
		if _, ok := opt.Additions[name]; ok {
			return nil, fmt.Errorf("%w: %s", ErrOverlap, name)
		}
	}
	seen := make(map[string]struct{}, len(r.File))
	keep := make([]*zip.File, 0, len(r.File))
	for _, f := range r.File {
		if err := checkName(f.Name); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrName, f.Name)
		}
		if _, ok := seen[f.Name]; ok {
			return nil, fmt.Errorf("%w: %s", ErrDuplicate, f.Name)
		}
		seen[f.Name] = struct{}{}
		if opt.StripSignatures && isSignature(f.Name) {
			if _, repl := opt.Replacements[f.Name]; repl {
				return nil, fmt.Errorf("%w: %s", ErrOverlap, f.Name)
			}
			continue
		}
		keep = append(keep, f)
	}
	for name := range opt.Replacements {
		if _, ok := seen[name]; !ok {
			return nil, fmt.Errorf("%w: %s", ErrMissing, name)
		}
	}
	for name := range opt.Additions {
		if _, ok := seen[name]; ok {
			return nil, fmt.Errorf("%w: %s", ErrPresent, name)
		}
		if opt.StripSignatures && isSignature(name) {
			return nil, fmt.Errorf("%w: %s", ErrOverlap, name)
		}
	}
	return keep, nil
}

func checkUpsertNames(m map[string][]byte) error {
	for name := range m {
		if strings.HasSuffix(name, "/") || checkName(name) != nil {
			return fmt.Errorf("%w: %s", ErrName, name)
		}
	}
	return nil
}

func writePayload(w *zip.Writer, name string, method uint16, body, extra []byte) error {
	switch method {
	case zip.Store, zip.Deflate:
	default:
		return fmt.Errorf("apk: unsupported compression method %d", method)
	}
	fh := &zip.FileHeader{Name: name, Method: method}
	fh.SetModTime(fixedTime)
	fh.Extra = stripTimeExtra(extra)
	dst, err := w.CreateHeader(fh)
	if err != nil {
		return err
	}
	_, err = dst.Write(body)
	return err
}

func copyRaw(w *zip.Writer, f *zip.File) error {
	fh := f.FileHeader
	fh.SetModTime(fixedTime)
	fh.Extra = stripTimeExtra(fh.Extra)
	fh.Flags &^= dataDescriptorFlag
	dst, err := w.CreateRaw(&fh)
	if err != nil {
		return err
	}
	r, err := f.OpenRaw()
	if err != nil {
		return err
	}
	n, err := io.Copy(dst, r)
	if err != nil {
		return err
	}
	if uint64(n) != f.CompressedSize64 {
		return fmt.Errorf("apk: short raw copy")
	}
	return nil
}

func isSignature(name string) bool {
	u := strings.ToUpper(name)
	const prefix = "META-INF/"
	if !strings.HasPrefix(u, prefix) {
		return false
	}
	base := u[len(prefix):]
	if base == "" || strings.Contains(base, "/") {
		return false
	}
	if base == "MANIFEST.MF" || strings.HasPrefix(base, "SIG-") {
		return true
	}
	switch filepath.Ext(base) {
	case ".SF", ".RSA", ".DSA", ".EC":
		return true
	default:
		return false
	}
}

func checkName(name string) error {
	if name == "" || strings.Contains(name, `\`) || strings.ContainsAny(name, ":") {
		return ErrName
	}
	if strings.HasPrefix(name, "/") {
		return ErrName
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return ErrName
		}
	}
	parts := strings.Split(name, "/")
	for i, p := range parts {
		if p == "" {
			if i == len(parts)-1 {
				continue
			}
			return ErrName
		}
		if p == "." || p == ".." {
			return ErrName
		}
	}
	return nil
}

func stripTimeExtra(extra []byte) []byte {
	var out []byte
	for len(extra) >= 4 {
		id := binary.LittleEndian.Uint16(extra[0:2])
		sz := int(binary.LittleEndian.Uint16(extra[2:4]))
		if sz < 0 || 4+sz > len(extra) {
			break
		}
		field := extra[:4+sz]
		extra = extra[4+sz:]
		switch id {
		case extTimeExtraID, ntfsExtraID, unixExtraID:
			continue
		default:
			out = append(out, field...)
		}
	}
	return out
}

func writeAtomic(dst string, write func(io.Writer) error) error {
	if _, err := os.Lstat(dst); err == nil {
		return ErrExists
	} else if !os.IsNotExist(err) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(dst), ".raspberry-*.partial")
	if err != nil {
		return err
	}
	tmp := f.Name()
	remove := true
	defer func() {
		if remove {
			os.Remove(tmp)
		}
	}()
	if err := write(f); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// Link does not replace. A filesystem that cannot hard-link fails closed.
	if err := os.Link(tmp, dst); err != nil {
		if os.IsExist(err) {
			return ErrExists
		}
		return err
	}
	if err := os.Remove(tmp); err != nil {
		return err
	}
	remove = false
	return nil
}

func samePath(a, b string) (bool, error) {
	aa, err := filepath.Abs(a)
	if err != nil {
		return false, err
	}
	bb, err := filepath.Abs(b)
	if err != nil {
		return false, err
	}
	// shortcut: case-folding compare is for Windows; a POSIX pair that differs
	// only by case is treated as the same path. Upgrade if a player build needs it.
	return strings.EqualFold(filepath.Clean(aa), filepath.Clean(bb)), nil
}
