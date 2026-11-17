// Package ipa provides locked IPA inspection and experimental in-memory loader
// preparation. Inspect is read-only and reports no entry contents, entitlements
// or credentials. The package never extracts, signs or installs an app.
package ipa

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	// Schema names this report format.
	Schema = "raspberry-ipa-inspect/1"
	// BaselineSize is the locked decrypted IPA length.
	BaselineSize int64 = 27000608
	// BaselineSHA256 is the locked decrypted IPA digest.
	BaselineSHA256 = "987fefccfc235cc73fdd6363c064887272575586f334b45fcb10d213a8772532"
	// ExecutablePath is the locked main executable member.
	ExecutablePath = "Payload/LINEPlay_Store.app/LINEPlay_Store"

	// Bundle identity below is a locked-baseline constant. It is not parsed
	// from Info.plist; the report labels it as such.
	BundleIdentifier = "jp.naver.lineplay"
	BundleVersion    = "10.1.0"
	BundleBuild      = "10.1.0.0"

	// A malicious deflate bomb must not make the inspector allocate without
	// bound. Real baseline members are far below these limits.
	maxExecutableBytes = 256 << 20
	maxArchiveEntries  = 100000
)

// ErrBaseline means the input is not the locked IPA.
var ErrBaseline = errors.New("ipa: baseline mismatch")

// Report is the inspect result. It contains metadata only.
type Report struct {
	Schema     string     `json:"schema"`
	Archive    Archive    `json:"archive"`
	Identity   Identity   `json:"identity"`
	Executable Executable `json:"executable"`
}

// Archive records the verified archive identity.
type Archive struct {
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	Verified bool   `json:"verified"`
}

// Identity is the locked bundle identity. Source says it is a constant, not a
// parse of untrusted metadata.
type Identity struct {
	Source   string `json:"source"`
	BundleID string `json:"bundle_id"`
	Version  string `json:"version"`
	Build    string `json:"build"`
}

// Executable records the main Mach-O member metadata.
type Executable struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	MachO  MachO  `json:"macho"`
}

// MachO is the confidently parsed Mach-O metadata. Optional fields are omitted
// when no matching load command was found.
type MachO struct {
	Magic     string  `json:"magic"`
	FileType  string  `json:"file_type"`
	CPU       string  `json:"cpu"`
	Subtype   uint32  `json:"subtype"`
	Platform  string  `json:"platform,omitempty"`
	MinOS     string  `json:"min_os,omitempty"`
	SDK       string  `json:"sdk,omitempty"`
	CryptID   *uint32 `json:"crypt_id,omitempty"`
	CryptSize *uint32 `json:"crypt_size,omitempty"`
}

// Inspect verifies the locked baseline by size and SHA-256 before opening the
// archive. It only reads path. Bytes are copied into an immutable snapshot;
// the ZIP is parsed from that snapshot, never from a second pass over path.
func Inspect(path string) (Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return Report{}, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return Report{}, err
	}
	if !st.Mode().IsRegular() {
		return Report{}, fmt.Errorf("%w: not a regular file", ErrBaseline)
	}
	if st.Size() != BaselineSize {
		return Report{}, fmt.Errorf("%w: size %d", ErrBaseline, st.Size())
	}
	return inspectReader(f, BaselineSize, BaselineSHA256)
}

// inspectReader reads at most wantSize+1 bytes once, checks the exact size and
// digest of that snapshot, then parses the same bytes. It never re-reads r.
func inspectReader(r io.Reader, wantSize int64, wantSHA string) (Report, error) {
	snap, err := readBounded(r, wantSize)
	if err != nil {
		return Report{}, err
	}
	if int64(len(snap)) != wantSize {
		return Report{}, fmt.Errorf("%w: size %d", ErrBaseline, len(snap))
	}
	sum := sha256.Sum256(snap)
	hexsum := hex.EncodeToString(sum[:])
	if hexsum != wantSHA {
		return Report{}, fmt.Errorf("%w: sha256 %s", ErrBaseline, hexsum)
	}
	exec, err := inspectArchive(bytes.NewReader(snap), int64(len(snap)))
	if err != nil {
		return Report{}, err
	}
	return Report{
		Schema:     Schema,
		Archive:    Archive{Size: wantSize, SHA256: hexsum, Verified: true},
		Identity:   Identity{Source: "locked-baseline-constants", BundleID: BundleIdentifier, Version: BundleVersion, Build: BundleBuild},
		Executable: exec,
	}, nil
}

// inspectArchive validates the ZIP shape and reads only the locked executable.
// It never trusts a member size to size an allocation.
func inspectArchive(r io.ReaderAt, size int64) (Executable, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return Executable{}, fmt.Errorf("ipa: read archive: %w", err)
	}
	if len(zr.File) > maxArchiveEntries {
		return Executable{}, fmt.Errorf("ipa: archive has too many entries")
	}

	seen := make(map[string]struct{}, len(zr.File))
	var target *zip.File
	for _, f := range zr.File {
		if err := validateName(f.Name); err != nil {
			return Executable{}, err
		}
		if _, ok := seen[f.Name]; ok {
			return Executable{}, fmt.Errorf("ipa: duplicate entry %q", f.Name)
		}
		seen[f.Name] = struct{}{}
		if f.Mode()&os.ModeSymlink != 0 {
			// Never follow or extract a symlink member.
			return Executable{}, fmt.Errorf("ipa: symlink entry %q", f.Name)
		}
		if f.Name == ExecutablePath {
			target = f
		}
	}
	if target == nil {
		return Executable{}, fmt.Errorf("ipa: executable %q is missing", ExecutablePath)
	}
	if !target.Mode().IsRegular() {
		return Executable{}, fmt.Errorf("ipa: executable is not a regular file")
	}

	data, err := readExecutable(target)
	if err != nil {
		return Executable{}, err
	}
	m, err := parseMachO(data)
	if err != nil {
		return Executable{}, err
	}
	sum := sha256.Sum256(data)
	return Executable{
		Path:   ExecutablePath,
		Size:   int64(len(data)),
		SHA256: hex.EncodeToString(sum[:]),
		MachO:  m,
	}, nil
}

// validateName rejects absolute, backslash, traversal and non-printable ZIP
// names. A trailing empty component is allowed only for a directory marker.
func validateName(name string) error {
	if name == "" {
		return errors.New("ipa: empty entry name")
	}
	if strings.HasPrefix(name, "/") {
		return fmt.Errorf("ipa: absolute entry name %q", name)
	}
	if strings.ContainsRune(name, '\\') {
		return fmt.Errorf("ipa: backslash in entry name %q", name)
	}
	if drivePrefixed(name) {
		return fmt.Errorf("ipa: drive-prefixed entry name %q", name)
	}
	for _, r := range name {
		if r == 0 || r < 0x20 || r == 0x7f {
			return fmt.Errorf("ipa: control character in entry name %q", name)
		}
	}
	parts := strings.Split(name, "/")
	for i, p := range parts {
		if p == "" {
			if i == len(parts)-1 {
				continue // directory marker
			}
			return fmt.Errorf("ipa: empty path component in %q", name)
		}
		if p == "." || p == ".." {
			return fmt.Errorf("ipa: traversal in entry name %q", name)
		}
		if drivePrefixed(p) {
			return fmt.Errorf("ipa: drive-prefixed entry name %q", name)
		}
	}
	return nil
}

// drivePrefixed reports a Windows drive prefix such as C:/x or C:x. Checked on
// every host so a ZIP cannot smuggle a volume path past a Unix inspector.
func drivePrefixed(name string) bool {
	if len(name) < 2 || name[1] != ':' {
		return false
	}
	c := name[0]
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func readExecutable(f *zip.File) ([]byte, error) {
	if f.UncompressedSize64 > uint64(maxExecutableBytes) {
		return nil, fmt.Errorf("ipa: executable declares %d bytes, over the limit", f.UncompressedSize64)
	}
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("ipa: open executable: %w", err)
	}
	defer rc.Close()
	data, err := readBounded(rc, maxExecutableBytes)
	if err != nil {
		return nil, err
	}
	if uint64(len(data)) != f.UncompressedSize64 {
		return nil, fmt.Errorf("ipa: executable size mismatch")
	}
	return data, nil
}

func readBounded(r io.Reader, max int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, fmt.Errorf("ipa: read: %w", err)
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("ipa: data is larger than %d bytes", max)
	}
	return data, nil
}

func parseMachO(data []byte) (MachO, error) {
	if err := preflightMachO(data); err != nil {
		return MachO{}, err
	}
	f, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		return MachO{}, fmt.Errorf("ipa: Mach-O: %w", err)
	}
	m := MachO{
		Magic:    magicString(f),
		FileType: fileTypeString(f.Type),
		CPU:      cpuString(f.Cpu),
		Subtype:  f.SubCpu,
	}
	if err := scanLoadCommands(data, f, &m); err != nil {
		return MachO{}, err
	}
	return m, nil
}

func preflightMachO(data []byte) error {
	if len(data) < 4 {
		return errors.New("ipa: executable is too short for Mach-O")
	}
	if isFatMagic(data[:4]) {
		return errors.New("ipa: universal (fat) Mach-O is not supported by inspect")
	}
	bo, magic, err := machoByteOrder(data[:4])
	if err != nil {
		return err
	}
	headerSize := 28
	if magic == macho.Magic64 {
		headerSize = 32
	}
	if len(data) < headerSize {
		return errors.New("ipa: Mach-O header is truncated")
	}
	ncmd := bo.Uint32(data[16:])
	cmdsz := bo.Uint32(data[20:])
	if cmdsz%4 != 0 || uint64(headerSize)+uint64(cmdsz) > uint64(len(data)) {
		return errors.New("ipa: Mach-O load commands exceed the file")
	}
	if uint64(ncmd) > uint64(cmdsz)/8 {
		return errors.New("ipa: Mach-O load command count exceeds the declared size")
	}
	end := headerSize + int(cmdsz)
	off := headerSize
	for i := uint32(0); i < ncmd; i++ {
		if off+8 > end {
			return errors.New("ipa: Mach-O load command block is truncated")
		}
		sz := bo.Uint32(data[off+4:])
		if sz < 8 || sz%4 != 0 || uint64(off)+uint64(sz) > uint64(end) {
			return fmt.Errorf("ipa: Mach-O load command %d has an invalid size", i)
		}
		off += int(sz)
	}
	if off != end {
		return errors.New("ipa: Mach-O load command sizes do not add up")
	}
	return nil
}

func machoByteOrder(ident []byte) (binary.ByteOrder, uint32, error) {
	be := binary.BigEndian.Uint32(ident)
	le := binary.LittleEndian.Uint32(ident)
	switch {
	case le == macho.Magic32 || le == macho.Magic64:
		return binary.LittleEndian, le, nil
	case be == macho.Magic32 || be == macho.Magic64:
		return binary.BigEndian, be, nil
	default:
		return nil, 0, errors.New("ipa: not a Mach-O executable")
	}
}

func isFatMagic(b []byte) bool {
	be := binary.BigEndian.Uint32(b)
	le := binary.LittleEndian.Uint32(b)
	return be == macho.MagicFat || le == macho.MagicFat || be == 0xcafebabf || le == 0xcafebabf
}

func magicString(f *macho.File) string {
	bits := "32-bit"
	if f.Magic == macho.Magic64 {
		bits = "64-bit"
	}
	order := "big-endian"
	if f.ByteOrder == binary.LittleEndian {
		order = "little-endian"
	}
	return bits + " " + order
}

func fileTypeString(t macho.Type) string {
	switch t {
	case macho.TypeObj:
		return "object"
	case macho.TypeExec:
		return "executable"
	case macho.TypeDylib:
		return "dylib"
	case macho.TypeBundle:
		return "bundle"
	default:
		return fmt.Sprintf("type-%d", uint32(t))
	}
}

func cpuString(c macho.Cpu) string {
	switch c {
	case macho.Cpu386:
		return "i386"
	case macho.CpuAmd64:
		return "x86_64"
	case macho.CpuArm:
		return "arm"
	case macho.CpuArm64:
		return "arm64"
	case macho.CpuPpc:
		return "ppc"
	case macho.CpuPpc64:
		return "ppc64"
	default:
		return fmt.Sprintf("cpu-0x%x", uint32(c))
	}
}

// Mach-O load command numbers used here (mach-o/loader.h). debug/macho exposes
// the header but not these platform/encryption commands.
const (
	lcVersionMinIPhoneOS = 0x25
	lcEncryptionInfo     = 0x21
	lcEncryptionInfo64   = 0x2c
	lcBuildVersion       = 0x32
)

func scanLoadCommands(data []byte, f *macho.File, m *MachO) error {
	headerSize := int64(28)
	if f.Magic == macho.Magic64 {
		headerSize = 32
	}
	end := headerSize + int64(f.Cmdsz)
	if end < headerSize || end > int64(len(data)) {
		return errors.New("ipa: Mach-O load commands exceed the file")
	}
	bo := f.ByteOrder
	off := headerSize
	for i := uint32(0); i < f.Ncmd; i++ {
		if off+8 > end {
			return errors.New("ipa: Mach-O load command block is truncated")
		}
		cmd := bo.Uint32(data[off:])
		sz := bo.Uint32(data[off+4:])
		if sz < 8 || sz%4 != 0 || off+int64(sz) > end {
			return fmt.Errorf("ipa: Mach-O load command %d has an invalid size", i)
		}
		body := data[off : off+int64(sz)]
		switch cmd {
		case lcBuildVersion:
			if sz < 24 {
				return errors.New("ipa: build-version command is truncated")
			}
			m.Platform = platformString(bo.Uint32(body[8:]))
			m.MinOS = versionString(bo.Uint32(body[12:]))
			m.SDK = versionString(bo.Uint32(body[16:]))
		case lcVersionMinIPhoneOS:
			if sz < 16 {
				return errors.New("ipa: minimum-version command is truncated")
			}
			if m.Platform == "" {
				m.Platform = "ios"
			}
			if m.MinOS == "" {
				m.MinOS = versionString(bo.Uint32(body[8:]))
			}
			if m.SDK == "" {
				m.SDK = versionString(bo.Uint32(body[12:]))
			}
		case lcEncryptionInfo:
			if sz < 20 {
				return errors.New("ipa: encryption command is truncated")
			}
			id := bo.Uint32(body[16:])
			cryptSize := bo.Uint32(body[12:])
			m.CryptID = &id
			m.CryptSize = &cryptSize
		case lcEncryptionInfo64:
			if sz < 24 {
				return errors.New("ipa: 64-bit encryption command is truncated")
			}
			id := bo.Uint32(body[16:])
			cryptSize := bo.Uint32(body[12:])
			m.CryptID = &id
			m.CryptSize = &cryptSize
		}
		off += int64(sz)
	}
	if off != end {
		return errors.New("ipa: Mach-O load command sizes do not add up")
	}
	return nil
}

func platformString(p uint32) string {
	switch p {
	case 1:
		return "macos"
	case 2:
		return "ios"
	case 3:
		return "tvos"
	case 4:
		return "watchos"
	case 5:
		return "bridgeos"
	case 6:
		return "maccatalyst"
	case 7:
		return "ios-simulator"
	case 8:
		return "tvos-simulator"
	case 9:
		return "watchos-simulator"
	case 10:
		return "driverkit"
	case 11:
		return "visionos"
	case 12:
		return "visionos-simulator"
	default:
		return fmt.Sprintf("platform-%d", p)
	}
}

func versionString(v uint32) string {
	return fmt.Sprintf("%d.%d.%d", v>>16, (v>>8)&0xff, v&0xff)
}
