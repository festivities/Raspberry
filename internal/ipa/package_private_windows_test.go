//go:build windows

package ipa

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestVerifyPrivateFileRejectsBroadWindowsACL(t *testing.T) {
	tmp, err := createPrivateTemp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := tmp.Name()
	defer os.Remove(path)
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "icacls.exe", path, "/grant", "*S-1-1-0:R").Run(); err != nil {
		t.Fatalf("add Everyone read ACE for regression: %v", err)
	}
	if err := verifyPrivateFile(path); err == nil {
		t.Fatal("file with an Everyone ACE was accepted as private")
	}
}

func TestPrivateTempACLIsAppliedBeforeBytesAreWritten(t *testing.T) {
	tmp, err := createPrivateTemp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	if err := verifyPrivateFile(tmp.Name()); err != nil {
		t.Fatalf("temporary file ACL is not private before writing: %v", err)
	}
	if _, err := tmp.Write([]byte("private test bytes")); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Sync(); err != nil {
		t.Fatal(err)
	}
}
