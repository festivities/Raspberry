package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPortMapSet(t *testing.T) {
	m := portMap{}
	for _, s := range []string{"80=8080", "443=8443", "10000=10000", "10123=443"} {
		if err := m.Set(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	if m[443] != 8443 || m[10123] != 443 {
		t.Fatalf("map %v", m)
	}
	for _, s := range []string{"", "443", "443=", "=443", "443=0", "443=65536", "53=53", "443=abc", "abc=443"} {
		if err := (portMap{}).Set(s); err == nil {
			t.Fatalf("%q accepted", s)
		}
	}
}

func TestDescriptorAsset(t *testing.T) {
	d, asset, err := descriptorAsset("Example.TEST", map[int]int{443: 8443})
	if err != nil {
		t.Fatal(err)
	}
	if d.Host != "example.test" || d.MapPort(443) != 8443 || d.MapPort(80) != 80 {
		t.Fatalf("descriptor %+v", d)
	}
	// encoding/json emits struct fields in declaration order (v, host, ports).
	const want = `{"v":1,"host":"example.test","ports":{"10000":10000,"10123":10123,"443":8443,"80":80}}`
	if string(asset) != want {
		t.Fatalf("asset %s", asset)
	}
	if _, again, err := descriptorAsset("Example.TEST", map[int]int{443: 8443}); err != nil || !bytes.Equal(asset, again) {
		t.Fatalf("not deterministic: %v", err)
	}
	for _, host := range []string{"", "198.18.0.1", "a:b", "-bad.test", "host/name"} {
		if _, _, err := descriptorAsset(host, nil); err == nil {
			t.Fatalf("host %q accepted", host)
		}
	}
}

func TestPinAsset(t *testing.T) {
	if b, err := pinAsset(""); err != nil || b != nil {
		t.Fatalf("empty pin: %v %q", err, b)
	}
	up := strings.Repeat("AB", 32)
	b, err := pinAsset(up)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != strings.Repeat("ab", 32)+"\n" {
		t.Fatalf("asset %q", b)
	}
	for _, bad := range []string{"ab", strings.Repeat("zz", 32), strings.Repeat("a", 63)} {
		if _, err := pinAsset(bad); err == nil {
			t.Fatalf("pin %q accepted", bad)
		}
	}
}

func TestCheckClasspath(t *testing.T) {
	dir := t.TempDir()
	if err := checkClasspath(dir); err != nil {
		t.Fatal(err)
	}
	if err := checkClasspath(dir + string(os.PathListSeparator) + filepath.Join(dir, "*")); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", filepath.Join(dir, "missing"), filepath.Join(dir, "*.jar")} {
		if err := checkClasspath(bad); err == nil {
			t.Fatalf("classpath %q accepted", bad)
		}
	}
}

func TestPatchUsage(t *testing.T) {
	dir := t.TempDir()
	apk := filepath.Join(dir, "in.apk")
	if err := os.WriteFile(apk, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := []string{"--apk", apk, "--endpoint", "example.test", "--out", dir,
		"--keystore", filepath.Join(dir, "k.p12"), "--password-env", "RASPBERRY_TEST_PW"}
	cases := map[string][]string{
		"no args":        {},
		"missing out":    {"--apk", apk, "--endpoint", "example.test", "--keystore", filepath.Join(dir, "k.p12"), "--password-env", "X"},
		"missing apk":    {"--endpoint", "example.test", "--out", dir, "--keystore", filepath.Join(dir, "k.p12"), "--password-env", "X"},
		"relative out":   append(base[:4:4], "--out", "rel", "--keystore", filepath.Join(dir, "k.p12"), "--password-env", "X"),
		"both passwords": append(base[:len(base):len(base)], "--password-file", filepath.Join(dir, "pw")),
		"no password":    append(base[:len(base)-2:len(base)-2], "--keystore", filepath.Join(dir, "k.p12")),
		"bad port":       append(base[:len(base):len(base)], "--port", "53=53"),
		"bad pin":        append(base[:len(base):len(base)], "--dev-pin-sha256", "abc"),
		"bad endpoint":   append(base[:len(base):len(base)], "--endpoint", "198.18.0.1"),
		"extra arg":      append(base[:len(base):len(base)], "junk"),
	}
	for name, args := range cases {
		var out, errb bytes.Buffer
		if code := run(append([]string{"patch"}, args...), &out, &errb); code != 2 {
			t.Fatalf("%s: code %d %s", name, code, errb.String())
		}
		if out.Len() != 0 {
			t.Fatalf("%s: stdout %q", name, out.String())
		}
	}
}

func TestPatchWrongBaseline(t *testing.T) {
	dir := t.TempDir()
	apk := filepath.Join(dir, "synthetic.bin")
	if err := os.WriteFile(apk, []byte("not-the-baseline"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"patch", "--apk", apk, "--endpoint", "example.test",
		"--port", "443=8443", "--out", dir, "--keystore", filepath.Join(dir, "k.p12"),
		"--password-env", "RASPBERRY_TEST_PW"}, &out, &errb)
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
	if _, err := os.Lstat(filepath.Join(dir, outputName)); err == nil {
		t.Fatalf("%s was written", outputName)
	}
}

func TestPatchRefusesRepo(t *testing.T) {
	dir := t.TempDir()
	apk := filepath.Join(dir, "synthetic.bin")
	if err := os.WriteFile(apk, []byte("not-the-baseline"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"file", "dir"} {
		root := fakeRepo(t, kind)
		outDir := filepath.Join(root, "out")
		ks := filepath.Join(root, "k.p12")
		var out, errb bytes.Buffer
		code := run([]string{"patch", "--apk", apk, "--endpoint", "example.test",
			"--out", outDir, "--keystore", filepath.Join(dir, "k.p12"), "--password-env", "X"}, &out, &errb)
		if code != 2 || !strings.Contains(errb.String(), "git repository") {
			t.Fatalf("%s repo out: code %d %s", kind, code, errb.String())
		}
		if _, err := os.Lstat(filepath.Join(outDir, outputName)); err == nil {
			t.Fatalf("%s wrote output", kind)
		}
		out.Reset()
		errb.Reset()
		code = run([]string{"patch", "--apk", apk, "--endpoint", "example.test",
			"--out", dir, "--keystore", ks, "--password-env", "X"}, &out, &errb)
		if code != 2 || !strings.Contains(errb.String(), "git repository") {
			t.Fatalf("%s repo key: code %d %s", kind, code, errb.String())
		}
		if _, err := os.Lstat(ks); err == nil {
			t.Fatalf("%s wrote keystore", kind)
		}
		if _, err := os.Lstat(filepath.Join(dir, outputName)); err == nil {
			t.Fatalf("%s wrote output after repo key refusal", kind)
		}
	}
}

func TestKeygenRefusesRepo(t *testing.T) {
	for _, kind := range []string{"file", "dir"} {
		root := fakeRepo(t, kind)
		ks := filepath.Join(root, "new.p12")
		var out, errb bytes.Buffer
		code := run([]string{"keygen", "--keystore", ks, "--password-env", "X"}, &out, &errb)
		if code != 2 || !strings.Contains(errb.String(), "git repository") {
			t.Fatalf("%s: code %d %s", kind, code, errb.String())
		}
		if out.Len() != 0 {
			t.Fatalf("%s stdout %q", kind, out.String())
		}
		if _, err := os.Lstat(ks); err == nil {
			t.Fatalf("%s wrote %s", kind, ks)
		}
	}
}

func TestOutsideWorktreeRoot(t *testing.T) {
	for _, kind := range []string{"file", "dir"} {
		root := fakeRepo(t, kind)
		if err := outsideWorktree(root); err == nil || !strings.Contains(err.Error(), "git repository") {
			t.Fatalf("%s root: %v", kind, err)
		}
		if err := outsideWorktree(filepath.Join(root, "missing")); err == nil {
			t.Fatalf("%s child accepted", kind)
		}
	}
	ok := t.TempDir()
	if err := outsideWorktree(ok); err != nil {
		t.Fatal(err)
	}
}

func TestOutsideWorktreeSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip(err)
	}
	if err := outsideWorktree(filepath.Join(link, "out.apk")); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink ancestor: %v", err)
	}
}

func fakeRepo(t *testing.T, kind string) string {
	t.Helper()
	root := t.TempDir()
	git := filepath.Join(root, ".git")
	var err error
	if kind == "dir" {
		err = os.Mkdir(git, 0o700)
	} else {
		err = os.WriteFile(git, []byte("gitdir: nowhere\n"), 0o600)
	}
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestKeygenUsage(t *testing.T) {
	dir := t.TempDir()
	ks := filepath.Join(dir, "new.p12")
	cases := map[string][]string{
		"no args":        {},
		"missing pw":     {"--keystore", ks},
		"relative ks":    {"--keystore", "rel.p12", "--password-env", "X"},
		"both passwords": {"--keystore", ks, "--password-env", "X", "--password-file", filepath.Join(dir, "pw")},
		"relative pw":    {"--keystore", ks, "--password-file", "pw"},
		"extra arg":      {"--keystore", ks, "--password-env", "X", "junk"},
	}
	for name, args := range cases {
		var out, errb bytes.Buffer
		if code := run(append([]string{"keygen"}, args...), &out, &errb); code != 2 {
			t.Fatalf("%s: code %d %s", name, code, errb.String())
		}
		if out.Len() != 0 {
			t.Fatalf("%s: stdout %q", name, out.String())
		}
	}
	if _, err := os.Lstat(ks); err == nil {
		t.Fatalf("%s was written", ks)
	}
}
