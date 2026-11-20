package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/festivities/raspberry/internal/ipa"
)

func TestIPAUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"ipa"}, &out, &errb); code != 2 {
		t.Fatalf("ipa: code %d %s", code, errb.String())
	}
	if out.Len() != 0 {
		t.Fatalf("ipa stdout %q", out.String())
	}
	if !strings.Contains(errb.String(), "ipa inspect") || !strings.Contains(errb.String(), "ipa patch") {
		t.Fatalf("ipa stderr %q", errb.String())
	}

	out.Reset()
	errb.Reset()
	if code := run([]string{"ipa", "help"}, &out, &errb); code != 0 {
		t.Fatalf("ipa help: code %d %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "ipa inspect") || !strings.Contains(out.String(), "ipa patch") {
		t.Fatalf("ipa help stdout %q", out.String())
	}

	out.Reset()
	errb.Reset()
	if code := run([]string{"ipa", "inspect"}, &out, &errb); code != 2 {
		t.Fatalf("inspect: code %d %s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "--ipa") {
		t.Fatalf("inspect stderr %q", errb.String())
	}

	out.Reset()
	errb.Reset()
	if code := run([]string{"ipa", "sign"}, &out, &errb); code != 2 {
		t.Fatalf("unknown: code %d", code)
	}
	if !strings.Contains(errb.String(), "unknown command") {
		t.Fatalf("unknown stderr %q", errb.String())
	}
}

func TestHelpMentionsIPA(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"help"}, &out, &errb); code != 0 {
		t.Fatalf("code %d %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "ipa inspect") || !strings.Contains(out.String(), "ipa patch") {
		t.Fatalf("help %q", out.String())
	}
	if errb.Len() != 0 {
		t.Fatalf("help stderr %q", errb.String())
	}
}

func TestIPAInspectWrongBaseline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fake.ipa")
	body := []byte("not-the-baseline")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"ipa", "inspect", "--ipa", path}, &out, &errb)
	if code != 1 {
		t.Fatalf("code %d %s", code, errb.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout %q", out.String())
	}
	if !strings.Contains(errb.String(), "baseline mismatch") {
		t.Fatalf("stderr %q", errb.String())
	}
	if strings.Contains(errb.String(), "not-the-baseline") {
		t.Fatalf("stderr leaked file bytes: %q", errb.String())
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("input mutated: %q", got)
	}
}

func TestIPAInspectMissingFlag(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"ipa", "inspect", "--apk", "x"}, &out, &errb); code != 2 {
		t.Fatalf("code %d %s", code, errb.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout %q", out.String())
	}
}

func TestIPAPatchUsage(t *testing.T) {
	dir := tempDir(t)
	fakeIPA := filepath.Join(dir, "in.ipa")
	if err := os.WriteFile(fakeIPA, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := []string{"--ipa", fakeIPA, "--endpoint", "example.test", "--out", dir}
	cases := map[string][]string{
		"no args":          {},
		"missing ipa":      {"--endpoint", "example.test", "--out", dir},
		"missing endpoint": {"--ipa", fakeIPA, "--out", dir},
		"missing out":      {"--ipa", fakeIPA, "--endpoint", "example.test"},
		"empty dylib":      append(append([]string(nil), base...), "--dylib", ""),
		"relative out":     {"--ipa", fakeIPA, "--endpoint", "example.test", "--out", "rel"},
		"bad port":         append(append([]string(nil), base...), "--port", "53=53"),
		"bad port format":  append(append([]string(nil), base...), "--port", "443"),
		"bad port zero":    append(append([]string(nil), base...), "--port", "443=0"),
		"bad endpoint":     append(append([]string(nil), base...), "--endpoint", "198.18.0.1"),
		"unknown flag":     append(append([]string(nil), base...), "--apk", fakeIPA),
		"extra arg":        append(append([]string(nil), base...), "junk"),
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			var out, errb bytes.Buffer
			if code := run(append([]string{"ipa", "patch"}, args...), &out, &errb); code != 2 {
				t.Fatalf("%s: code %d %s", name, code, errb.String())
			}
			if out.Len() != 0 {
				t.Fatalf("%s: stdout %q", name, out.String())
			}
		})
	}
}

func TestIPAPatchRefusesRepoAndSymlinkOut(t *testing.T) {
	dir := tempDir(t)
	fakeIPA := filepath.Join(dir, "in.ipa")
	if err := os.WriteFile(fakeIPA, []byte("not-the-baseline"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"file", "dir"} {
		root := fakeRepo(t, kind)
		outDir := filepath.Join(root, "out")
		var out, errb bytes.Buffer
		code := run([]string{"ipa", "patch", "--ipa", fakeIPA, "--endpoint", "example.test", "--out", outDir}, &out, &errb)
		if code != 2 || !strings.Contains(errb.String(), "git repository") {
			t.Fatalf("%s repo out: code %d %s", kind, code, errb.String())
		}
		if out.Len() != 0 {
			t.Fatalf("%s stdout %q", kind, out.String())
		}
		if _, err := os.Lstat(filepath.Join(outDir, ipaOutputName)); err == nil {
			t.Fatalf("%s wrote output", kind)
		}
	}

	realDir := filepath.Join(dir, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(dir, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Skip(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"ipa", "patch", "--ipa", fakeIPA, "--endpoint", "example.test", "--out", linkDir}, &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "symlink") {
		t.Fatalf("symlink out: code %d %s", code, errb.String())
	}
	if _, err := os.Lstat(filepath.Join(realDir, ipaOutputName)); err == nil {
		t.Fatal("symlink out wrote file")
	}
}

func TestIPAPatchErrorHandling(t *testing.T) {
	dir := tempDir(t)
	fakeIPA := filepath.Join(dir, "fake.ipa")
	if err := os.WriteFile(fakeIPA, []byte("not-the-baseline"), 0o600); err != nil {
		t.Fatal(err)
	}
	fakeDylib := filepath.Join(dir, "libraspberry.dylib")
	if err := os.WriteFile(fakeDylib, []byte("not-a-macho"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("wrong baseline", func(t *testing.T) {
		outDir := filepath.Join(dir, "out-wrong")
		if err := os.Mkdir(outDir, 0o700); err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		code := run([]string{
			"ipa", "patch",
			"--ipa", fakeIPA,
			"--endpoint", "example.test",
			"--port", "443=8443",
			"--out", outDir,
			"--dylib", fakeDylib,
		}, &out, &errb)
		if code != 1 {
			t.Fatalf("code %d %s", code, errb.String())
		}
		if out.Len() != 0 {
			t.Fatalf("stdout %q", out.String())
		}
		if !strings.Contains(errb.String(), "baseline mismatch") {
			t.Fatalf("stderr %q", errb.String())
		}
		if strings.Contains(errb.String(), "not-the-baseline") {
			t.Fatalf("stderr leaked input bytes: %q", errb.String())
		}
		if _, err := os.Lstat(filepath.Join(outDir, ipaOutputName)); err == nil {
			t.Fatalf("%s was written", ipaOutputName)
		}
	})

	t.Run("missing out dir", func(t *testing.T) {
		var out, errb bytes.Buffer
		code := run([]string{
			"ipa", "patch",
			"--ipa", fakeIPA,
			"--endpoint", "example.test",
			"--out", filepath.Join(dir, "missing-dir"),
			"--dylib", fakeDylib,
		}, &out, &errb)
		if code != 1 || out.Len() != 0 {
			t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
		}
	})

	t.Run("out is a file", func(t *testing.T) {
		var out, errb bytes.Buffer
		code := run([]string{
			"ipa", "patch",
			"--ipa", fakeIPA,
			"--endpoint", "example.test",
			"--out", fakeIPA,
			"--dylib", fakeDylib,
		}, &out, &errb)
		if code != 1 || !strings.Contains(errb.String(), "not a directory") {
			t.Fatalf("code %d stderr %q", code, errb.String())
		}
	})

	t.Run("refuses existing output", func(t *testing.T) {
		outDir := filepath.Join(dir, "out-existing")
		if err := os.Mkdir(outDir, 0o700); err != nil {
			t.Fatal(err)
		}
		existing := filepath.Join(outDir, ipaOutputName)
		if err := os.WriteFile(existing, []byte("keep-me"), 0o600); err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		code := run([]string{
			"ipa", "patch",
			"--ipa", fakeIPA,
			"--endpoint", "example.test",
			"--out", outDir,
			"--dylib", fakeDylib,
		}, &out, &errb)
		if code != 1 || !strings.Contains(errb.String(), "exists") {
			t.Fatalf("code %d stderr %q", code, errb.String())
		}
		got, err := os.ReadFile(existing)
		if err != nil || string(got) != "keep-me" {
			t.Fatalf("existing file mutated: %q err=%v", got, err)
		}
	})

	t.Run("refuses aliasing input", func(t *testing.T) {
		outDir := filepath.Join(dir, "out-alias")
		if err := os.Mkdir(outDir, 0o700); err != nil {
			t.Fatal(err)
		}
		aliasIPA := filepath.Join(outDir, ipaOutputName)
		if err := os.WriteFile(aliasIPA, []byte("keep-input"), 0o600); err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		code := run([]string{
			"ipa", "patch",
			"--ipa", aliasIPA,
			"--endpoint", "example.test",
			"--out", outDir,
			"--dylib", fakeDylib,
		}, &out, &errb)
		if code != 1 || !strings.Contains(errb.String(), "aliases") {
			t.Fatalf("code %d stderr %q", code, errb.String())
		}
		got, err := os.ReadFile(aliasIPA)
		if err != nil || string(got) != "keep-input" {
			t.Fatalf("aliased input mutated: %q err=%v", got, err)
		}
	})
}

func TestIPAPatchRealBaselineIPA(t *testing.T) {
	baselinePath := filepath.Join("..", "..", ".opencode", "line-play-artifacts", "jp.naver.lineplay_10.1.0_decrypted.ipa")
	if info, err := os.Stat(baselinePath); err != nil || !info.Mode().IsRegular() {
		t.Skip("locked baseline IPA not present")
	}

	dir := tempDir(t)
	dylibPath := filepath.Join(dir, "libraspberry.dylib")
	if err := os.WriteFile(dylibPath, syntheticCLIDylib(ipa.RequiredDylibID), 0o600); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")
	if err := os.Mkdir(outDir, 0o700); err != nil {
		t.Fatal(err)
	}

	var out, errb bytes.Buffer
	code := run([]string{
		"ipa", "patch",
		"--ipa", baselinePath,
		"--endpoint", "Cherry.Example.ORG",
		"--port", "443=8443",
		"--out", outDir,
		"--dylib", dylibPath,
	}, &out, &errb)
	if code != 0 {
		t.Fatalf("code %d stderr=%s", code, errb.String())
	}
	if errb.Len() != 0 {
		t.Fatalf("unexpected stderr %q", errb.String())
	}

	summary := out.String()
	finalPath := filepath.Join(outDir, ipaOutputName)
	for _, want := range []string{finalPath, "sha256 ", " bytes", "unsigned"} {
		if !strings.Contains(summary, want) {
			t.Fatalf("summary missing %q:\n%s", want, summary)
		}
	}
	if strings.Contains(strings.ToLower(summary), "cherry.example.org") || strings.Contains(summary, "8443") {
		t.Fatalf("summary leaked operator endpoint details:\n%s", summary)
	}

	info, err := os.Stat(finalPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("output mode=%#o, want 0600", info.Mode().Perm())
	}

	zr, err := zip.OpenReader(finalPath)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	if len(zr.File) != 3152 {
		t.Fatalf("output entries=%d, want 3152", len(zr.File))
	}
	var gotEndpoint []byte
	for _, f := range zr.File {
		if f.Name == "Payload/LINEPlay_Store.app/raspberry/endpoint.json" {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			gotEndpoint, err = io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	const wantEndpoint = `{"v":1,"host":"cherry.example.org","ports":{"10000":10000,"10123":10123,"443":8443,"80":80}}`
	if string(gotEndpoint) != wantEndpoint {
		t.Fatalf("packaged endpoint=%s, want %s", gotEndpoint, wantEndpoint)
	}
}

func syntheticCLIDylib(installName string) []byte {
	type exportSpec struct {
		name    string
		address uint64
	}
	exports := make([]exportSpec, len(ipa.RequiredExports))
	for i, name := range ipa.RequiredExports {
		exports[i] = exportSpec{name: "_" + name, address: 0x200 + uint64(i*0x20)}
	}
	sort.Slice(exports, func(i, j int) bool {
		return exports[i].name < exports[j].name
	})

	// Build a minimal flat-leaf export trie under root node 0.
	type edge struct {
		label string
		off   uint64
	}
	var terminals bytes.Buffer
	// Reserve space for root header: 1 byte terminal size (0) + 1 byte child count + edges.
	edges := make([]edge, len(exports))
	rootSize := 2
	for i, ex := range exports {
		rootSize += len(ex.name) + 1 + 2 // worst-case 2-byte ULEB128 offset
		edges[i] = edge{label: ex.name}
	}
	for iter := 0; iter < 4; iter++ {
		terminals.Reset()
		off := uint64(rootSize)
		for i, ex := range exports {
			edges[i].off = off
			var term []byte
			term = appendCLIULEB(term, 0) // flags = 0
			term = appendCLIULEB(term, ex.address)
			terminals.Write(appendCLIULEB(nil, uint64(len(term))))
			terminals.Write(term)
			terminals.WriteByte(0) // 0 children
			off = uint64(rootSize) + uint64(terminals.Len())
		}
		var root bytes.Buffer
		root.WriteByte(0) // no terminal at root
		root.WriteByte(byte(len(edges)))
		for _, e := range edges {
			root.WriteString(e.label)
			root.WriteByte(0)
			root.Write(appendCLIULEB(nil, e.off))
		}
		rootSize = root.Len()
	}
	var root bytes.Buffer
	root.WriteByte(0)
	root.WriteByte(byte(len(edges)))
	for _, e := range edges {
		root.WriteString(e.label)
		root.WriteByte(0)
		root.Write(appendCLIULEB(nil, e.off))
	}
	trie := append(root.Bytes(), terminals.Bytes()...)

	name := append([]byte(installName), 0)
	idSize := (24 + len(name) + 7) &^ 7
	commandsSize := 72 + idSize + 16
	trieOffset := 32 + commandsSize
	data := make([]byte, trieOffset+len(trie))

	binary.LittleEndian.PutUint32(data[0:], 0xfeedfacf)
	binary.LittleEndian.PutUint32(data[4:], 0x0100000c)
	binary.LittleEndian.PutUint32(data[12:], 6) // MH_DYLIB
	binary.LittleEndian.PutUint32(data[16:], 3)
	binary.LittleEndian.PutUint32(data[20:], uint32(commandsSize))

	off := 32
	binary.LittleEndian.PutUint32(data[off:], 0x19) // LC_SEGMENT_64
	binary.LittleEndian.PutUint32(data[off+4:], 72)
	copy(data[off+8:off+24], "__TEXT")
	binary.LittleEndian.PutUint64(data[off+24:], 0x100000000)
	binary.LittleEndian.PutUint64(data[off+32:], 0x1000)
	binary.LittleEndian.PutUint64(data[off+40:], 0)
	binary.LittleEndian.PutUint64(data[off+48:], uint64(len(data)))
	binary.LittleEndian.PutUint32(data[off+56:], 5)
	binary.LittleEndian.PutUint32(data[off+60:], 5)

	off += 72
	binary.LittleEndian.PutUint32(data[off:], 0xd) // LC_ID_DYLIB
	binary.LittleEndian.PutUint32(data[off+4:], uint32(idSize))
	binary.LittleEndian.PutUint32(data[off+8:], 24)
	copy(data[off+24:], name)

	off += idSize
	binary.LittleEndian.PutUint32(data[off:], 0x80000033) // LC_DYLD_EXPORTS_TRIE
	binary.LittleEndian.PutUint32(data[off+4:], 16)
	binary.LittleEndian.PutUint32(data[off+8:], uint32(trieOffset))
	binary.LittleEndian.PutUint32(data[off+12:], uint32(len(trie)))
	copy(data[trieOffset:], trie)
	return data
}

func appendCLIULEB(dst []byte, value uint64) []byte {
	for value >= 0x80 {
		dst = append(dst, byte(value)|0x80)
		value >>= 7
	}
	return append(dst, byte(value))
}
