//go:build !windows

package ipa

import (
	"fmt"
	"os"
)

func createPrivateTemp(parent string) (*os.File, error) {
	f, err := os.CreateTemp(parent, ".raspberry-ipa-*.tmp")
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		return nil, cleanupPrivateTemp(f, err)
	}
	if err := verifyPrivateFile(f.Name()); err != nil {
		return nil, cleanupPrivateTemp(f, err)
	}
	return f, nil
}

func verifyPrivateFile(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 {
		return fmt.Errorf("ipa: package: file is not a regular 0600 file")
	}
	return nil
}
