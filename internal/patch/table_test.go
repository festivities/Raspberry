package patch

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLockedTables(t *testing.T) {
	arm64 := mustLoad(t, "patches/libgame-arm64.tbl")
	if arm64.ID != "airarmor-state6-arm64" || arm64.SHA256 != LibgameArm64SHA {
		t.Fatalf("arm64 id/hash %s %s", arm64.ID, arm64.SHA256)
	}
	if len(arm64.Edits) != 1 || arm64.Edits[0].Offset != 0x2f98021 {
		t.Fatalf("arm64 edit %+v", arm64.Edits)
	}
	if !bytes.Equal(arm64.Edits[0].Expected, []byte{0x00}) || !bytes.Equal(arm64.Edits[0].Replacement, []byte{0xf8}) {
		t.Fatalf("arm64 bytes")
	}

	armv7 := mustLoad(t, "patches/libgame-armv7.tbl")
	if armv7.ID != "airarmor-state6-armv7" || armv7.SHA256 != LibgameArmv7SHA {
		t.Fatalf("armv7 id/hash %s %s", armv7.ID, armv7.SHA256)
	}
	if len(armv7.Edits) != 1 || armv7.Edits[0].Offset != 0x13dc502 {
		t.Fatalf("armv7 edit %+v", armv7.Edits)
	}
	if !bytes.Equal(armv7.Edits[0].Expected, []byte{0x39}) || !bytes.Equal(armv7.Edits[0].Replacement, []byte{0x19}) {
		t.Fatalf("armv7 bytes")
	}
	if len(armv7.Windows) != 1 || armv7.Windows[0].Offset != 0x13dc500 || !bytes.Equal(armv7.Windows[0].Expected, []byte{0x40, 0xf2, 0x39, 0x33}) {
		t.Fatalf("armv7 window %+v", armv7.Windows)
	}
}

func TestApplySynthetic(t *testing.T) {
	buf := []byte{0x40, 0xf2, 0x39, 0x33, 0xaa}
	sum := sha256.Sum256(buf)
	tab, err := ParseTable(strings.NewReader("id synth\nsha256 " + hex.EncodeToString(sum[:]) + "\nwindow 0x0 40f23933\nedit 0x2 39 19 imm8\n"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Apply(buf, tab)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, []byte{0x40, 0xf2, 0x19, 0x33, 0xaa}) {
		t.Fatalf("out %x", out)
	}
	if !bytes.Equal(buf, []byte{0x40, 0xf2, 0x39, 0x33, 0xaa}) {
		t.Fatal("input mutated")
	}
}

func TestApplyRefusesUnknownHash(t *testing.T) {
	tab, err := ParseTable(strings.NewReader("id synth\nsha256 " + strings.Repeat("ab", 32) + "\nedit 0 00 01 x\n"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Apply([]byte{0x00}, tab)
	if !errors.Is(err, ErrHash) {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), "00") && strings.Contains(strings.ToLower(err.Error()), "byte") {
		t.Fatalf("error leaked input: %v", err)
	}
}

func TestApplyWrongBytes(t *testing.T) {
	buf := []byte{0x11}
	sum := sha256.Sum256(buf)
	tab, err := ParseTable(strings.NewReader("id synth\nsha256 " + hex.EncodeToString(sum[:]) + "\nedit 0 00 01 x\n"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Apply(buf, tab)
	if !errors.Is(err, ErrExpected) {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), "11") {
		t.Fatalf("error leaked input: %v", err)
	}
}

func TestApplyBounds(t *testing.T) {
	buf := []byte{0x00}
	sum := sha256.Sum256(buf)
	tab, err := ParseTable(strings.NewReader("id synth\nsha256 " + hex.EncodeToString(sum[:]) + "\nedit 0x10 00 01 x\n"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Apply(buf, tab)
	if !errors.Is(err, ErrBounds) {
		t.Fatalf("got %v", err)
	}
}

func TestParseRejectsSameBytes(t *testing.T) {
	_, err := ParseTable(strings.NewReader("id synth\nsha256 " + strings.Repeat("ab", 32) + "\nedit 0 00 00 x\n"))
	if !errors.Is(err, ErrTable) {
		t.Fatalf("got %v", err)
	}
}

func mustLoad(t *testing.T, rel string) Table {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	path := filepath.Join(filepath.Dir(file), "..", "..", rel)
	tab, err := LoadTable(path)
	if err != nil {
		t.Fatal(err)
	}
	return tab
}

func TestApplyFileRefusesExisting(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.bin")
	out := filepath.Join(dir, "out.bin")
	body := []byte{0x00}
	if err := os.WriteFile(in, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	tab, err := ParseTable(strings.NewReader("id synth\nsha256 " + hex.EncodeToString(sum[:]) + "\nedit 0 00 01 x\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyFile(in, out, tab); err == nil {
		t.Fatal("expected existing destination to fail")
	}
}
