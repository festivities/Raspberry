//go:build windows

package ipa

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

const (
	sddlRevision1                 = 1
	seFileObject                  = 1
	ownerSecurityInformation      = 0x1
	daclSecurityInformation       = 0x4
	securityDescriptorDACLProtect = 0x1000
	aclSizeInformation            = 2
	accessAllowedACEType          = 0
	fileAllAccess                 = 0x001F01FF
)

var (
	securityAdvapi32 = syscall.NewLazyDLL("advapi32.dll")
	procConvertSDDL  = securityAdvapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procGetSecurity  = securityAdvapi32.NewProc("GetSecurityInfo")
	procGetSDControl = securityAdvapi32.NewProc("GetSecurityDescriptorControl")
	procGetSDDACL    = securityAdvapi32.NewProc("GetSecurityDescriptorDacl")
	procGetACLInfo   = securityAdvapi32.NewProc("GetAclInformation")
	procGetACE       = securityAdvapi32.NewProc("GetAce")
)

type aclSizeInfo struct {
	ACECount   uint32
	BytesInUse uint32
	BytesFree  uint32
}

func createPrivateTemp(parent string) (*os.File, error) {
	sid, err := currentUserSID()
	if err != nil {
		return nil, err
	}
	sddl, err := syscall.UTF16PtrFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")")
	if err != nil {
		return nil, err
	}
	var descriptor unsafe.Pointer
	var descriptorSize uint32
	ok, _, callErr := procConvertSDDL.Call(
		uintptr(unsafe.Pointer(sddl)),
		sddlRevision1,
		uintptr(unsafe.Pointer(&descriptor)),
		uintptr(unsafe.Pointer(&descriptorSize)),
	)
	if err := windowsCallError(ok, callErr); err != nil {
		return nil, fmt.Errorf("ipa: package: create private Windows security descriptor: %w", err)
	}
	defer syscall.LocalFree(syscall.Handle(uintptr(descriptor)))
	if descriptor == nil {
		return nil, errors.New("ipa: package: Windows security descriptor is empty")
	}

	sa := syscall.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(syscall.SecurityAttributes{})),
		SecurityDescriptor: uintptr(descriptor),
	}
	for range 100 {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, err
		}
		path := filepath.Join(parent, ".raspberry-ipa-"+hex.EncodeToString(nonce[:])+".tmp")
		name, err := syscall.UTF16PtrFromString(path)
		if err != nil {
			return nil, err
		}
		handle, err := syscall.CreateFile(
			name,
			syscall.GENERIC_READ|syscall.GENERIC_WRITE|readControl,
			0,
			&sa,
			syscall.CREATE_NEW,
			syscall.FILE_ATTRIBUTE_NORMAL,
			0,
		)
		if errors.Is(err, syscall.ERROR_FILE_EXISTS) || errors.Is(err, syscall.ERROR_ALREADY_EXISTS) {
			continue
		}
		if err != nil {
			return nil, err
		}
		f := os.NewFile(uintptr(handle), path)
		if f == nil {
			_ = syscall.CloseHandle(handle)
			return nil, errors.New("ipa: package: create private Windows temporary file failed")
		}
		if err := verifyPrivateHandle(handle, sid); err != nil {
			return nil, cleanupPrivateTemp(f, err)
		}
		return f, nil
	}
	return nil, errors.New("ipa: package: could not allocate a unique temporary file")
}

const readControl = 0x00020000

func verifyPrivateFile(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return errors.New("ipa: package: file is not a regular file")
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := syscall.CreateFile(
		name,
		readControl,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(handle)
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&(syscall.FILE_ATTRIBUTE_DIRECTORY|syscall.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return errors.New("ipa: package: file is not a regular file")
	}
	sid, err := currentUserSID()
	if err != nil {
		return err
	}
	return verifyPrivateHandle(handle, sid)
}

func currentUserSID() (string, error) {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return "", err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String()
}

func verifyPrivateHandle(handle syscall.Handle, sid string) error {
	var owner, dacl, descriptor unsafe.Pointer
	status, _, _ := procGetSecurity.Call(
		uintptr(handle),
		seFileObject,
		ownerSecurityInformation|daclSecurityInformation,
		uintptr(unsafe.Pointer(&owner)),
		0,
		uintptr(unsafe.Pointer(&dacl)),
		0,
		uintptr(unsafe.Pointer(&descriptor)),
	)
	if status != 0 {
		return syscall.Errno(status)
	}
	defer syscall.LocalFree(syscall.Handle(uintptr(descriptor)))
	if descriptor == nil || owner == nil || dacl == nil {
		return errors.New("ipa: package: Windows file has no owner-only ACL")
	}
	ownerSID, err := (*syscall.SID)(owner).String()
	if err != nil {
		return err
	}
	if ownerSID != sid {
		return errors.New("ipa: package: Windows file owner is not the current user")
	}

	var control uint16
	var revision uint32
	ok, _, callErr := procGetSDControl.Call(
		uintptr(descriptor),
		uintptr(unsafe.Pointer(&control)),
		uintptr(unsafe.Pointer(&revision)),
	)
	if err := windowsCallError(ok, callErr); err != nil {
		return fmt.Errorf("ipa: package: read Windows file ACL control: %w", err)
	}
	if control&securityDescriptorDACLProtect == 0 {
		return errors.New("ipa: package: Windows file ACL is not protected from inheritance")
	}

	var present, defaulted uint32
	var queriedDACL unsafe.Pointer
	ok, _, callErr = procGetSDDACL.Call(
		uintptr(descriptor),
		uintptr(unsafe.Pointer(&present)),
		uintptr(unsafe.Pointer(&queriedDACL)),
		uintptr(unsafe.Pointer(&defaulted)),
	)
	if err := windowsCallError(ok, callErr); err != nil {
		return fmt.Errorf("ipa: package: read Windows file DACL: %w", err)
	}
	if present == 0 || queriedDACL == nil || queriedDACL != dacl {
		return errors.New("ipa: package: Windows file DACL is absent")
	}
	var aclInfo aclSizeInfo
	ok, _, callErr = procGetACLInfo.Call(
		uintptr(queriedDACL),
		uintptr(unsafe.Pointer(&aclInfo)),
		unsafe.Sizeof(aclInfo),
		aclSizeInformation,
	)
	if err := windowsCallError(ok, callErr); err != nil {
		return fmt.Errorf("ipa: package: read Windows ACL entries: %w", err)
	}
	if aclInfo.ACECount != 1 {
		return fmt.Errorf("ipa: package: Windows file ACL is not owner-only (%d ACEs)", aclInfo.ACECount)
	}
	var ace unsafe.Pointer
	ok, _, callErr = procGetACE.Call(
		uintptr(queriedDACL),
		0,
		uintptr(unsafe.Pointer(&ace)),
	)
	if err := windowsCallError(ok, callErr); err != nil {
		return fmt.Errorf("ipa: package: read Windows ACL entry: %w", err)
	}
	if ace == nil {
		return errors.New("ipa: package: Windows file ACL entry is absent")
	}
	header := unsafe.Slice((*byte)(ace), 4)
	aceSize := binary.LittleEndian.Uint16(header[2:])
	if header[0] != accessAllowedACEType || header[1] != 0 || aceSize < 8 {
		return errors.New("ipa: package: Windows file ACL entry is not an explicit allow")
	}
	mask := binary.LittleEndian.Uint32(unsafe.Slice((*byte)(unsafe.Add(ace, 4)), 4))
	aceSID, err := (*syscall.SID)(unsafe.Add(ace, 8)).String()
	if err != nil {
		return err
	}
	if mask != fileAllAccess || aceSID != sid {
		return errors.New("ipa: package: Windows file ACL grants access beyond the current user")
	}
	return nil
}

func windowsCallError(result uintptr, callErr error) error {
	if result != 0 {
		return nil
	}
	if callErr != nil && callErr != syscall.Errno(0) {
		return callErr
	}
	return errors.New("Windows security API call failed")
}
