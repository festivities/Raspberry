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
	"strings"
	"testing"
)

func TestInspectWrongSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "short.ipa")
	if err := os.WriteFile(path, []byte("PK\x03\x04not-the-baseline"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Inspect(path)
	if !errors.Is(err, ErrBaseline) {
		t.Fatalf("wrong size: %v", err)
	}
	if !strings.Contains(err.Error(), "size") {
		t.Fatalf("want size in error: %v", err)
	}
	if strings.Contains(err.Error(), "not-the-baseline") {
		t.Fatalf("error leaked file bytes: %v", err)
	}
}

func TestInspectWrongHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zeros.ipa")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(BaselineSize); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = Inspect(path)
	if !errors.Is(err, ErrBaseline) {
		t.Fatalf("wrong hash: %v", err)
	}
	if strings.Contains(err.Error(), "read archive") || strings.Contains(err.Error(), "zip") {
		t.Fatalf("parsed ZIP before hash check: %v", err)
	}
	if !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("want sha256 in error: %v", err)
	}
}

func TestInspectNotRegular(t *testing.T) {
	dir := t.TempDir()
	_, err := Inspect(dir)
	if !errors.Is(err, ErrBaseline) {
		t.Fatalf("directory: %v", err)
	}
}

func TestInspectReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ro.ipa")
	body := []byte("read-only-input")
	if err := os.WriteFile(path, body, 0o444); err != nil {
		t.Fatal(err)
	}
	_, err := Inspect(path)
	if !errors.Is(err, ErrBaseline) {
		t.Fatalf("read-only inspect: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("input mutated: %q", got)
	}
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSymlink != 0 {
		t.Fatal("input replaced with a symlink")
	}
}

func TestInspectSnapshotIgnoresLaterReads(t *testing.T) {
	mach := synthMachO(t)
	good := writeZip(t, []zipEntry{{name: ExecutablePath, body: mach, mode: 0o755}})
	mutated := append([]byte(nil), mach...)
	binary.LittleEndian.PutUint32(mutated[4:], uint32(macho.CpuAmd64))
	bad := writeZip(t, []zipEntry{{name: ExecutablePath, body: mutated, mode: 0o755}})
	sum := sha256.Sum256(good)
	src := &flipSeeker{first: good, second: bad}
	rep, err := inspectReader(src, int64(len(good)), hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	if src.pass != 0 {
		t.Fatalf("re-read source after hashing (pass=%d)", src.pass)
	}
	if rep.Executable.MachO.CPU != "arm64" {
		t.Fatalf("parsed mutated bytes: %+v", rep.Executable.MachO)
	}
	wantExec := sha256.Sum256(mach)
	if rep.Executable.SHA256 != hex.EncodeToString(wantExec[:]) {
		t.Fatalf("executable digest %s", rep.Executable.SHA256)
	}
}

type flipSeeker struct {
	first, second []byte
	off           int64
	pass          int
}

func (f *flipSeeker) Read(p []byte) (int, error) {
	src := f.first
	if f.pass > 0 {
		src = f.second
	}
	if f.off >= int64(len(src)) {
		return 0, io.EOF
	}
	n := copy(p, src[f.off:])
	f.off += int64(n)
	return n, nil
}

func (f *flipSeeker) Seek(offset int64, whence int) (int64, error) {
	if whence != io.SeekStart || offset != 0 {
		return 0, errors.New("unsupported seek")
	}
	f.pass++
	f.off = 0
	return 0, nil
}

func (f *flipSeeker) ReadAt(p []byte, off int64) (int, error) {
	src := f.first
	if f.pass > 0 {
		src = f.second
	}
	if off < 0 || off > int64(len(src)) {
		return 0, io.EOF
	}
	n := copy(p, src[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func TestValidateName(t *testing.T) {
	ok := []string{
		ExecutablePath,
		"Payload/",
		"Payload/LINEPlay_Store.app/",
		"a",
	}
	for _, name := range ok {
		if err := validateName(name); err != nil {
			t.Fatalf("%q: %v", name, err)
		}
	}
	bad := map[string]string{
		"":              "empty",
		"/abs":          "absolute",
		`Payload\x`:     "backslash",
		"../x":          "traversal",
		"a/../b":        "traversal",
		"a/./b":         "traversal",
		"a//b":          "empty path",
		"a/\x00b":       "control",
		string(rune(1)): "control",
		"C:/x":          "drive-prefixed",
		"C:x":           "drive-prefixed",
		"c:foo":         "drive-prefixed",
		"Payload/C:bar": "drive-prefixed",
	}
	for name, want := range bad {
		err := validateName(name)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%q: got %v, want %q", name, err, want)
		}
	}
}

func TestReadBounded(t *testing.T) {
	got, err := readBounded(bytes.NewReader([]byte("abcd")), 4)
	if err != nil || string(got) != "abcd" {
		t.Fatalf("exact: %q %v", got, err)
	}
	got, err = readBounded(bytes.NewReader([]byte("abc")), 4)
	if err != nil || string(got) != "abc" {
		t.Fatalf("short: %q %v", got, err)
	}
	if _, err := readBounded(bytes.NewReader([]byte("abcde")), 4); err == nil {
		t.Fatal("over-limit accepted")
	}
	n := int64(0)
	if _, err := readBounded(&countReader{n: &n, rest: bytes.NewReader(bytes.Repeat([]byte{'x'}, 8))}, 4); err == nil {
		t.Fatal("over-limit accepted")
	}
	if n > 5 {
		t.Fatalf("read %d bytes past the cap", n)
	}
}

type countReader struct {
	n    *int64
	rest io.Reader
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.rest.Read(p)
	*c.n += int64(n)
	return n, err
}

func TestParseMachO(t *testing.T) {
	data := synthMachO(t)
	m, err := parseMachO(data)
	if err != nil {
		t.Fatal(err)
	}
	if m.Magic != "64-bit little-endian" || m.FileType != "executable" || m.CPU != "arm64" {
		t.Fatalf("header %+v", m)
	}
	if m.Platform != "ios" || m.MinOS != "15.0.0" || m.SDK != "18.0.0" {
		t.Fatalf("platform %+v", m)
	}
	if m.CryptID == nil || *m.CryptID != 0 || m.CryptSize == nil || *m.CryptSize != 0x1000 {
		t.Fatalf("encryption %+v", m)
	}

	min := synthMachOVersionMin(t)
	m, err = parseMachO(min)
	if err != nil {
		t.Fatal(err)
	}
	if m.Platform != "ios" || m.MinOS != "15.0.0" || m.SDK != "16.2.0" {
		t.Fatalf("version-min fallback %+v", m)
	}

	if _, err := parseMachO([]byte{1, 2}); err == nil {
		t.Fatal("truncated accepted")
	}
	fat := make([]byte, 4)
	binary.BigEndian.PutUint32(fat, macho.MagicFat)
	if _, err := parseMachO(fat); err == nil || !strings.Contains(err.Error(), "fat") {
		t.Fatalf("fat: %v", err)
	}
}

func TestPreflightMachO(t *testing.T) {
	good := synthMachO(t)
	if err := preflightMachO(good); err != nil {
		t.Fatal(err)
	}
	huge := append([]byte(nil), good...)
	binary.LittleEndian.PutUint32(huge[16:], 1<<24)
	binary.LittleEndian.PutUint32(huge[20:], 8)
	if err := preflightMachO(huge); err == nil || !strings.Contains(err.Error(), "count") {
		t.Fatalf("huge ncmd: %v", err)
	}
	over := append([]byte(nil), good...)
	binary.LittleEndian.PutUint32(over[20:], 1<<20)
	if err := preflightMachO(over); err == nil || !strings.Contains(err.Error(), "exceed") {
		t.Fatalf("huge cmdsz: %v", err)
	}
}

func TestInspectArchive(t *testing.T) {
	mach := synthMachO(t)
	raw := writeZip(t, []zipEntry{
		{name: "Payload/", mode: os.ModeDir | 0o755},
		{name: ExecutablePath, body: mach, mode: 0o755},
		{name: "Payload/LINEPlay_Store.app/Info.plist", body: []byte("not-parsed")},
	})
	ex, err := inspectArchive(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if ex.Path != ExecutablePath || ex.Size != int64(len(mach)) {
		t.Fatalf("executable %+v", ex)
	}
	if ex.SHA256 == "" || ex.MachO.CPU != "arm64" || ex.MachO.CryptID == nil {
		t.Fatalf("macho %+v", ex)
	}
}

func TestInspectArchiveRejects(t *testing.T) {
	mach := synthMachO(t)
	good := zipEntry{name: ExecutablePath, body: mach, mode: 0o755}

	t.Run("duplicate", func(t *testing.T) {
		raw := writeZip(t, []zipEntry{good, good})
		if _, err := inspectArchive(bytes.NewReader(raw), int64(len(raw))); err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("duplicate: %v", err)
		}
	})
	t.Run("traversal", func(t *testing.T) {
		raw := writeZip(t, []zipEntry{{name: "../LINEPlay_Store", body: mach}, good})
		if _, err := inspectArchive(bytes.NewReader(raw), int64(len(raw))); err == nil || !strings.Contains(err.Error(), "traversal") {
			t.Fatalf("traversal: %v", err)
		}
	})
	t.Run("absolute", func(t *testing.T) {
		raw := writeZip(t, []zipEntry{{name: "/Payload/x", body: []byte("x")}, good})
		if _, err := inspectArchive(bytes.NewReader(raw), int64(len(raw))); err == nil || !strings.Contains(err.Error(), "absolute") {
			t.Fatalf("absolute: %v", err)
		}
	})
	t.Run("backslash", func(t *testing.T) {
		raw := writeZip(t, []zipEntry{{name: `Payload\x`, body: []byte("x")}, good})
		if _, err := inspectArchive(bytes.NewReader(raw), int64(len(raw))); err == nil || !strings.Contains(err.Error(), "backslash") {
			t.Fatalf("backslash: %v", err)
		}
	})
	t.Run("drive", func(t *testing.T) {
		raw := writeZip(t, []zipEntry{{name: "C:/Payload/x", body: []byte("x")}, good})
		if _, err := inspectArchive(bytes.NewReader(raw), int64(len(raw))); err == nil || !strings.Contains(err.Error(), "drive-prefixed") {
			t.Fatalf("drive C:/: %v", err)
		}
		raw = writeZip(t, []zipEntry{{name: "C:x", body: []byte("x")}, good})
		if _, err := inspectArchive(bytes.NewReader(raw), int64(len(raw))); err == nil || !strings.Contains(err.Error(), "drive-prefixed") {
			t.Fatalf("drive C:x: %v", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		raw := writeZip(t, []zipEntry{
			{name: "Payload/link", body: []byte("target"), mode: os.ModeSymlink | 0o777},
			good,
		})
		if _, err := inspectArchive(bytes.NewReader(raw), int64(len(raw))); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("symlink: %v", err)
		}
	})
	t.Run("missing", func(t *testing.T) {
		raw := writeZip(t, []zipEntry{{name: "Payload/other", body: []byte("x")}})
		if _, err := inspectArchive(bytes.NewReader(raw), int64(len(raw))); err == nil || !strings.Contains(err.Error(), "missing") {
			t.Fatalf("missing: %v", err)
		}
	})
	t.Run("truncated", func(t *testing.T) {
		raw := writeZip(t, []zipEntry{good})
		cut := raw[:len(raw)/2]
		if _, err := inspectArchive(bytes.NewReader(cut), int64(len(cut))); err == nil {
			t.Fatal("truncated zip accepted")
		}
	})
}

type zipEntry struct {
	name string
	body []byte
	mode os.FileMode
}

func writeZip(t *testing.T, entries []zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Store}
		if e.mode != 0 {
			h.SetMode(e.mode)
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatalf("zip %q: %v", e.name, err)
		}
		if _, err := w.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func synthMachO(t *testing.T) []byte {
	t.Helper()
	bo := binary.LittleEndian
	build := make([]byte, 24)
	bo.PutUint32(build[0:], lcBuildVersion)
	bo.PutUint32(build[4:], 24)
	bo.PutUint32(build[8:], 2)       // ios
	bo.PutUint32(build[12:], 15<<16) // 15.0.0
	bo.PutUint32(build[16:], 18<<16) // 18.0.0
	bo.PutUint32(build[20:], 0)

	enc := make([]byte, 24)
	bo.PutUint32(enc[0:], lcEncryptionInfo64)
	bo.PutUint32(enc[4:], 24)
	bo.PutUint32(enc[8:], 0x4000)
	bo.PutUint32(enc[12:], 0x1000)
	bo.PutUint32(enc[16:], 0)
	bo.PutUint32(enc[20:], 0)

	hdr := make([]byte, 32)
	bo.PutUint32(hdr[0:], macho.Magic64)
	bo.PutUint32(hdr[4:], uint32(macho.CpuArm64))
	bo.PutUint32(hdr[8:], 0)
	bo.PutUint32(hdr[12:], uint32(macho.TypeExec))
	bo.PutUint32(hdr[16:], 2)
	bo.PutUint32(hdr[20:], uint32(len(build)+len(enc)))
	out := append(hdr, build...)
	return append(out, enc...)
}

func synthMachOVersionMin(t *testing.T) []byte {
	t.Helper()
	bo := binary.LittleEndian
	cmd := make([]byte, 16)
	bo.PutUint32(cmd[0:], lcVersionMinIPhoneOS)
	bo.PutUint32(cmd[4:], 16)
	bo.PutUint32(cmd[8:], 15<<16)       // 15.0.0
	bo.PutUint32(cmd[12:], 16<<16|2<<8) // 16.2.0
	hdr := make([]byte, 32)
	bo.PutUint32(hdr[0:], macho.Magic64)
	bo.PutUint32(hdr[4:], uint32(macho.CpuArm64))
	bo.PutUint32(hdr[12:], uint32(macho.TypeExec))
	bo.PutUint32(hdr[16:], 1)
	bo.PutUint32(hdr[20:], uint32(len(cmd)))
	return append(hdr, cmd...)
}
