package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	var out, err bytes.Buffer
	if code := run([]string{"version"}, &out, &err); code != 0 {
		t.Fatalf("code %d %s", code, err.String())
	}
	if out.String() != "raspberry 0.0.0-r0\n" {
		t.Fatalf("stdout %q", out.String())
	}
}

func TestVerifySynthetic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "synthetic.bin")
	body := []byte("not-the-baseline")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"verify", "--apk", path}, &out, &errb)
	if code != 1 {
		t.Fatalf("code %d", code)
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
}

func TestVerifyUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"verify"}, &out, &errb); code != 2 {
		t.Fatalf("code %d", code)
	}
	if !strings.Contains(errb.String(), "--apk") {
		t.Fatalf("stderr %q", errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := run(nil, &out, &errb); code != 2 {
		t.Fatalf("code %d", code)
	}
}
