package apk

import (
	"archive/zip"
	"bytes"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRepackPreservesRawBytesAndOrder(t *testing.T) {
	src := buildZip(t, []entry{
		{name: "b.txt", method: zip.Deflate, body: bytes.Repeat([]byte("bbbb"), 64), when: time.Date(2024, 5, 6, 7, 8, 10, 0, time.UTC)},
		{name: "a.txt", method: zip.Store, body: []byte("alpha-stored"), when: time.Date(2019, 1, 2, 3, 4, 6, 0, time.UTC)},
		{name: "dir/", method: zip.Store, body: nil, when: time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)},
	})
	dir := t.TempDir()
	in := filepath.Join(dir, "in.zip")
	out1 := filepath.Join(dir, "out1.zip")
	out2 := filepath.Join(dir, "out2.zip")
	if err := os.WriteFile(in, src, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Repack(in, out1, Options{}); err != nil {
		t.Fatal(err)
	}
	if err := Repack(in, out2, Options{}); err != nil {
		t.Fatal(err)
	}
	b1, err := os.ReadFile(out1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := os.ReadFile(out2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatal("repack was not deterministic")
	}
	if leftovers(t, dir, ".raspberry-") {
		t.Fatal("temp file left behind")
	}

	got := openZip(t, out1)
	if len(got.File) != 3 || got.File[0].Name != "b.txt" || got.File[1].Name != "a.txt" || got.File[2].Name != "dir/" {
		t.Fatalf("order %v", names(got))
	}
	srcZ := openReader(t, src)
	if !bytes.Equal(raw(t, srcZ.File[0]), raw(t, got.File[0])) {
		t.Fatal("deflate payload changed")
	}
	if !bytes.Equal(raw(t, srcZ.File[1]), raw(t, got.File[1])) {
		t.Fatal("stored payload changed")
	}
	if gotBody(t, got.File[1]) != "alpha-stored" {
		t.Fatal("stored body mismatch")
	}
	for _, f := range got.File {
		if !f.ModTime().Equal(fixedTime) {
			t.Fatalf("%s time %s", f.Name, f.ModTime())
		}
	}
}

func TestStripSignaturesOnlyWhenAsked(t *testing.T) {
	src := buildZip(t, []entry{
		{name: "hello.txt", method: zip.Store, body: []byte("hi"), when: fixedTime},
		{name: "META-INF/MANIFEST.MF", method: zip.Store, body: []byte("mf"), when: fixedTime},
		{name: "META-INF/CERT.SF", method: zip.Store, body: []byte("sf"), when: fixedTime},
		{name: "META-INF/CERT.RSA", method: zip.Store, body: []byte("rsa"), when: fixedTime},
		{name: "META-INF/keep.txt", method: zip.Store, body: []byte("keep"), when: fixedTime},
		{name: "META-INF/com/android/x", method: zip.Store, body: []byte("lib"), when: fixedTime},
	})
	dir := t.TempDir()
	in := filepath.Join(dir, "in.zip")
	if err := os.WriteFile(in, src, 0o644); err != nil {
		t.Fatal(err)
	}
	kept := filepath.Join(dir, "kept.zip")
	stripped := filepath.Join(dir, "stripped.zip")
	if err := Repack(in, kept, Options{}); err != nil {
		t.Fatal(err)
	}
	if err := Repack(in, stripped, Options{StripSignatures: true}); err != nil {
		t.Fatal(err)
	}
	if got := names(openZip(t, kept)); len(got) != 6 {
		t.Fatalf("default stripped signatures: %v", got)
	}
	got := names(openZip(t, stripped))
	want := []string{"hello.txt", "META-INF/keep.txt", "META-INF/com/android/x"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestRejectsDuplicateTraversalAndClobber(t *testing.T) {
	if err := checkName(`../x`); !errors.Is(err, ErrName) {
		t.Fatal(err)
	}
	if err := checkName(`foo/../../etc/passwd`); !errors.Is(err, ErrName) {
		t.Fatal(err)
	}
	if err := checkName(`/abs`); !errors.Is(err, ErrName) {
		t.Fatal(err)
	}
	if err := checkName(`a\b`); !errors.Is(err, ErrName) {
		t.Fatal(err)
	}
	if err := checkName(`foo//bar`); !errors.Is(err, ErrName) {
		t.Fatal(err)
	}
	if err := checkName("ok/dir/"); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.zip")
	if err := os.WriteFile(bad, dupZip(t), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "out.zip")
	err := Repack(bad, dst, Options{})
	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("dup: %v", err)
	}
	if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
		t.Fatal("duplicate repack created output")
	}

	trav := filepath.Join(dir, "trav.zip")
	if err := os.WriteFile(trav, buildZip(t, []entry{{name: "../x", method: zip.Store, body: []byte("no"), when: fixedTime}}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Repack(trav, dst, Options{}); !errors.Is(err, ErrName) {
		t.Fatalf("trav: %v", err)
	}

	keep := []byte("keep-me")
	if err := os.WriteFile(dst, keep, 0o644); err != nil {
		t.Fatal(err)
	}
	in := filepath.Join(dir, "in.zip")
	if err := os.WriteFile(in, buildZip(t, []entry{{name: "a.txt", method: zip.Store, body: []byte("a"), when: fixedTime}}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Repack(in, dst, Options{}); !errors.Is(err, ErrExists) {
		t.Fatalf("clobber: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, keep) {
		t.Fatal("destination was clobbered")
	}
	if err := Repack(in, in, Options{}); err == nil {
		t.Fatal("same path accepted")
	}
}

func TestConcurrentPublishOneWinner(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.zip")
	body := buildZip(t, []entry{{name: "a.txt", method: zip.Store, body: []byte("same"), when: fixedTime}})
	if err := os.WriteFile(in, body, 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "out.zip")
	var wg sync.WaitGroup
	errs := make([]error, 2)
	start := make(chan struct{})
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = Repack(in, dst, Options{})
		}(i)
	}
	close(start)
	wg.Wait()
	wins, loses := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, ErrExists):
			loses++
		default:
			t.Fatalf("publish: %v", err)
		}
	}
	if wins != 1 || loses != 1 {
		t.Fatalf("wins %d loses %d errs %v", wins, loses, errs)
	}
	if leftovers(t, dir, ".raspberry-") {
		t.Fatal("temp left behind")
	}
	if _, err := os.Stat(dst); err != nil {
		t.Fatal(err)
	}
}

func TestUpsertKeepsRawAndAppendsSorted(t *testing.T) {
	src := buildZip(t, []entry{
		{name: "a.txt", method: zip.Store, body: []byte("alpha-stored"), when: time.Date(2019, 1, 2, 3, 4, 6, 0, time.UTC)},
		{name: "classes3.dex", method: zip.Deflate, body: bytes.Repeat([]byte("old-dex"), 32), when: time.Date(2020, 2, 2, 0, 0, 0, 0, time.UTC)},
		{name: "z.txt", method: zip.Deflate, body: []byte("keep-z"), when: time.Date(2021, 3, 3, 0, 0, 0, 0, time.UTC)},
		{name: "META-INF/MANIFEST.MF", method: zip.Store, body: []byte("mf"), when: fixedTime},
	})
	repl := bytes.Repeat([]byte("new-dex"), 40)
	opt := Options{
		StripSignatures: true,
		Replacements:    map[string][]byte{"classes3.dex": repl},
		Additions: map[string][]byte{
			"lib/arm64-v8a/libraspberry.so":  []byte("so-b"),
			"classes5.dex":                   []byte("dex5"),
			"assets/raspberry/endpoint.json": []byte(`{"v":1}`),
		},
	}
	dir := t.TempDir()
	in := filepath.Join(dir, "in.zip")
	out1 := filepath.Join(dir, "out1.zip")
	out2 := filepath.Join(dir, "out2.zip")
	if err := os.WriteFile(in, src, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Repack(in, out1, opt); err != nil {
		t.Fatal(err)
	}
	if err := Repack(in, out2, opt); err != nil {
		t.Fatal(err)
	}
	b1, err := os.ReadFile(out1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := os.ReadFile(out2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatal("upsert repack was not deterministic")
	}
	srcZ := openReader(t, src)
	got := openZip(t, out1)
	want := []string{"a.txt", "classes3.dex", "z.txt", "assets/raspberry/endpoint.json", "classes5.dex", "lib/arm64-v8a/libraspberry.so"}
	if strings.Join(names(got), ",") != strings.Join(want, ",") {
		t.Fatalf("order %v", names(got))
	}
	if !bytes.Equal(raw(t, srcZ.File[0]), raw(t, got.File[0])) || srcZ.File[0].CRC32 != got.File[0].CRC32 {
		t.Fatal("unchanged store entry changed")
	}
	if !bytes.Equal(raw(t, srcZ.File[2]), raw(t, got.File[2])) || srcZ.File[2].CRC32 != got.File[2].CRC32 {
		t.Fatal("unchanged deflate entry changed")
	}
	if got.File[1].Method != zip.Deflate || gotBody(t, got.File[1]) != string(repl) || got.File[1].CRC32 != crc32.ChecksumIEEE(repl) {
		t.Fatal("replacement lost method or payload")
	}
	if got.File[3].Method != zip.Deflate || gotBody(t, got.File[3]) != `{"v":1}` || got.File[3].CRC32 != crc32.ChecksumIEEE([]byte(`{"v":1}`)) {
		t.Fatal("addition payload")
	}
	stored := buildZip(t, []entry{{name: "classes3.dex", method: zip.Store, body: []byte("old"), when: fixedTime}})
	storedIn := filepath.Join(dir, "stored.zip")
	storedOut := filepath.Join(dir, "stored-out.zip")
	if err := os.WriteFile(storedIn, stored, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Repack(storedIn, storedOut, Options{Replacements: map[string][]byte{"classes3.dex": []byte("new")}}); err != nil {
		t.Fatal(err)
	}
	sf := openZip(t, storedOut).File[0]
	if sf.Method != zip.Store || gotBody(t, sf) != "new" {
		t.Fatal("store replacement changed method")
	}
}

func TestUpsertRejects(t *testing.T) {
	src := buildZip(t, []entry{
		{name: "classes3.dex", method: zip.Store, body: []byte("old"), when: fixedTime},
		{name: "META-INF/MANIFEST.MF", method: zip.Store, body: []byte("mf"), when: fixedTime},
	})
	dir := t.TempDir()
	in := filepath.Join(dir, "in.zip")
	if err := os.WriteFile(in, src, 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		opt  Options
		want error
	}{
		{"missing", Options{Replacements: map[string][]byte{"libgame.so": []byte("x")}}, ErrMissing},
		{"overlap", Options{Replacements: map[string][]byte{"classes3.dex": []byte("a")}, Additions: map[string][]byte{"classes3.dex": []byte("b")}}, ErrOverlap},
		{"present", Options{Additions: map[string][]byte{"classes3.dex": []byte("x")}}, ErrPresent},
		{"bad", Options{Additions: map[string][]byte{"../x": []byte("x")}}, ErrName},
		{"strip", Options{StripSignatures: true, Replacements: map[string][]byte{"META-INF/MANIFEST.MF": []byte("x")}}, ErrOverlap},
	}
	for _, c := range cases {
		dst := filepath.Join(dir, c.name+".zip")
		err := Repack(in, dst, c.opt)
		if !errors.Is(err, c.want) {
			t.Fatalf("%s: %v", c.name, err)
		}
		if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
			t.Fatalf("%s created output", c.name)
		}
	}
	keep := []byte("keep-me")
	dst := filepath.Join(dir, "exists.zip")
	if err := os.WriteFile(dst, keep, 0o644); err != nil {
		t.Fatal(err)
	}
	err := Repack(in, dst, Options{Replacements: map[string][]byte{"classes3.dex": []byte("new")}})
	if !errors.Is(err, ErrExists) {
		t.Fatalf("clobber: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, keep) {
		t.Fatal("destination was clobbered")
	}
}

func TestNotZipLeavesNoOutput(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "nope.bin")
	out := filepath.Join(dir, "out.zip")
	if err := os.WriteFile(in, []byte("not a zip"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Repack(in, out, Options{}); err == nil {
		t.Fatal("expected error")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("output created")
	}
}

type entry struct {
	name   string
	method uint16
	body   []byte
	when   time.Time
}

func buildZip(t *testing.T, entries []entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: e.method}
		h.SetModTime(e.when)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
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

func dupZip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < 2; i++ {
		w, err := zw.Create("same.txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func openZip(t *testing.T, path string) *zip.Reader {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return openReader(t, b)
}

func openReader(t *testing.T, b []byte) *zip.Reader {
	t.Helper()
	r, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func raw(t *testing.T, f *zip.File) []byte {
	t.Helper()
	r, err := f.OpenRaw()
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func gotBody(t *testing.T, f *zip.File) string {
	t.Helper()
	r, err := f.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func names(r *zip.Reader) []string {
	out := make([]string, len(r.File))
	for i, f := range r.File {
		out[i] = f.Name
	}
	return out
}

func leftovers(t *testing.T, dir, prefix string) bool {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), prefix) {
			return true
		}
	}
	return false
}
