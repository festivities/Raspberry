package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIPAUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"ipa"}, &out, &errb); code != 2 {
		t.Fatalf("ipa: code %d %s", code, errb.String())
	}
	if out.Len() != 0 {
		t.Fatalf("ipa stdout %q", out.String())
	}
	if !strings.Contains(errb.String(), "ipa inspect") {
		t.Fatalf("ipa stderr %q", errb.String())
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
	if !strings.Contains(out.String(), "ipa inspect") {
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
