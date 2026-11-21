package ipa

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/festivities/raspberry/internal/descriptor"
)

const (
	// RequiredDylibID is the required LC_ID_DYLIB install name for the embedded runtime dylib.
	RequiredDylibID = "@rpath/libraspberry.dylib"

	ownDylibZipPath      = "Payload/LINEPlay_Store.app/Frameworks/libraspberry.dylib"
	ownEndpointZipPath   = "Payload/LINEPlay_Store.app/raspberry/endpoint.json"
	ownEndpointParentDir = "Payload/LINEPlay_Store.app/raspberry"
	maxDylibSize         = 32 << 20
	maxEndpointJSONBytes = 4 << 10

	lcDyldInfo        = uint32(0x22)
	lcDyldInfoOnly    = uint32(0x80000022)
	lcDyldExportsTrie = uint32(0x80000033)

	zipDataDescriptor = uint16(0x8)
)

var (
	packageFixedTime = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

	// RequiredExports lists all ten symbols the runtime dylib must export directly from RX __TEXT.
	RequiredExports = []string{
		ExportNotice404DiagnosticEntry,
		ExportGetaddrinfo,
		ExportFreeaddrinfo,
		ExportGethostbyname,
		ExportConnect,
		ExportGuestUniqueCode,
		ExportLoginReady,
		ExportSessionReset,
		ExportCheckSessionError,
		ExportGuestGenerateError,
	}
)

// RangePair represents a half-open [Start, End) byte interval.
type RangePair struct {
	Start int
	End   int
}

// PackageReport summarizes a verified deterministic unsigned IPA build.
type PackageReport struct {
	SourceSHA       string
	SourceSize      int
	SourceEntries   int
	MainSHA         string
	MainSize        int
	MainChanged     []RangePair
	DylibSHA        string
	DylibSize       int
	DylibID         string
	ExportNames     []string
	DylibZipPath    string
	EndpointZipPath string
	EndpointSHA     string
	EndpointSize    int
	RetainedRaw     int
	PackageSHA      string
	PackageSize     int
	RepeatSHA       string
	RepeatSize      int
}

// PackageResult holds the verified unsigned IPA bytes and build metadata.
type PackageResult struct {
	Package []byte
	Report  PackageReport
}

type rawDigest struct {
	hash [32]byte
	size uint64
}

// BuildPackage verifies the locked baseline IPA, validates the arm64 runtime dylib
// and endpoint descriptor, patches the main executable in memory, and builds two
// deterministic unsigned IPA byte streams in memory.
func BuildPackage(sourceIPA, dylib, endpointJSONRaw []byte) (PackageResult, error) {
	if int64(len(sourceIPA)) != BaselineSize {
		return PackageResult{}, fmt.Errorf("%w: size %d", ErrBaseline, len(sourceIPA))
	}
	sourceHash := sha256.Sum256(sourceIPA)
	sourceSHA := hex.EncodeToString(sourceHash[:])
	if sourceSHA != BaselineSHA256 {
		return PackageResult{}, fmt.Errorf("%w: sha256 %s", ErrBaseline, sourceSHA)
	}
	exports := append([]string(nil), RequiredExports...)
	dylibSHA, err := validateDylib(dylib, RequiredDylibID, exports)
	if err != nil {
		return PackageResult{}, err
	}
	canonicalEndpoint, err := validateEndpointJSON(endpointJSONRaw)
	if err != nil {
		return PackageResult{}, err
	}

	sourceZip, err := parseSourceArchive(sourceIPA)
	if err != nil {
		return PackageResult{}, err
	}
	mainEntry, err := findUniqueMember(sourceZip, ExecutablePath)
	if err != nil {
		return PackageResult{}, err
	}
	originalMain, err := readZipMember(mainEntry, uint64(MainSize))
	if err != nil {
		return PackageResult{}, fmt.Errorf("ipa: package: read locked main member: %w", err)
	}
	if int64(len(originalMain)) != MainSize {
		return PackageResult{}, fmt.Errorf("ipa: package: main member size mismatch: %d", len(originalMain))
	}
	patchedMain, err := PatchMainExecutable(originalMain)
	if err != nil {
		return PackageResult{}, fmt.Errorf("ipa: package: patch main executable: %w", err)
	}
	if err := validateLoaderDependencyDelta(originalMain, patchedMain); err != nil {
		return PackageResult{}, err
	}
	mainChanged := changedRanges(originalMain, patchedMain)
	if err := validateMainWriteWindows(originalMain, patchedMain); err != nil {
		return PackageResult{}, err
	}

	pkgA, err := assembleArchive(sourceIPA, patchedMain, dylib, canonicalEndpoint)
	if err != nil {
		return PackageResult{}, fmt.Errorf("ipa: package: assemble package A in memory: %w", err)
	}
	pkgB, err := assembleArchive(sourceIPA, patchedMain, dylib, canonicalEndpoint)
	if err != nil {
		return PackageResult{}, fmt.Errorf("ipa: package: assemble package B in memory: %w", err)
	}
	if !bytes.Equal(pkgA, pkgB) {
		return PackageResult{}, errors.New("ipa: package: two independent in-memory package builds are not byte-identical")
	}
	retained, err := verifyPackage(sourceIPA, pkgA, patchedMain, dylib, canonicalEndpoint)
	if err != nil {
		return PackageResult{}, fmt.Errorf("ipa: package: verify in-memory package A: %w", err)
	}
	retainedB, err := verifyPackage(sourceIPA, pkgB, patchedMain, dylib, canonicalEndpoint)
	if err != nil {
		return PackageResult{}, fmt.Errorf("ipa: package: verify in-memory package B: %w", err)
	}
	if retained != retainedB {
		return PackageResult{}, errors.New("ipa: package: retained member counts differ between package builds")
	}
	pkgSHA := hashHex(pkgA)
	repeatSHA := hashHex(pkgB)

	return PackageResult{
		Package: pkgA,
		Report: PackageReport{
			SourceSHA:       sourceSHA,
			SourceSize:      len(sourceIPA),
			SourceEntries:   len(sourceZip.File),
			MainSHA:         hashHex(patchedMain),
			MainSize:        len(patchedMain),
			MainChanged:     mainChanged,
			DylibSHA:        dylibSHA,
			DylibSize:       len(dylib),
			DylibID:         RequiredDylibID,
			ExportNames:     exports,
			DylibZipPath:    ownDylibZipPath,
			EndpointZipPath: ownEndpointZipPath,
			EndpointSHA:     hashHex(canonicalEndpoint),
			EndpointSize:    len(canonicalEndpoint),
			RetainedRaw:     retained,
			PackageSHA:      pkgSHA,
			PackageSize:     len(pkgA),
			RepeatSHA:       repeatSHA,
			RepeatSize:      len(pkgB),
		},
	}, nil
}

// WritePackageAtomic writes data to a 0600 temporary file inside path's
// directory and publishes it atomically without overwriting symlinks or any
// existing destination file.
func WritePackageAtomic(path string, data []byte) error {
	if path == "" {
		return errors.New("ipa: package: output path is empty")
	}
	if len(data) == 0 {
		return errors.New("ipa: package: output data is empty")
	}
	parent := filepath.Dir(path)
	pst, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("ipa: package: output directory: %w", err)
	}
	if pst.Mode()&os.ModeSymlink != 0 || !pst.IsDir() {
		return errors.New("ipa: package: output parent is not a real directory")
	}
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("ipa: package: refusing symlink output path %s", path)
		}
		return fmt.Errorf("ipa: package: %s exists; refusing to overwrite", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	tmp, err := os.CreateTemp(parent, ".raspberry-ipa-*.tmp")
	if err != nil {
		return err
	}
	tempPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tempPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tempPath, path); err != nil {
		return err
	}
	if err := os.Remove(tempPath); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func validateEndpointJSON(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > maxEndpointJSONBytes {
		return nil, errors.New("ipa: package: endpoint JSON size is outside bounds")
	}
	desc, err := descriptor.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("ipa: package: endpoint JSON: %w", err)
	}
	canonical, err := json.Marshal(desc)
	if err != nil {
		return nil, errors.New("ipa: package: endpoint JSON canonical encoding failed")
	}
	if len(canonical) == 0 || len(canonical) > maxEndpointJSONBytes {
		return nil, errors.New("ipa: package: endpoint JSON canonical size exceeds bound")
	}
	if _, err := descriptor.Parse(canonical); err != nil {
		return nil, fmt.Errorf("ipa: package: endpoint JSON canonical validation failed: %w", err)
	}
	return canonical, nil
}

func validateDylibID(id string) error {
	if id == "" {
		return errors.New("ipa: package: LC_ID_DYLIB is required")
	}
	for _, r := range id {
		if r == 0 || r < 0x20 || r == 0x7f {
			return errors.New("ipa: package: LC_ID_DYLIB contains control characters")
		}
	}
	return nil
}

func validateDylib(data []byte, expectedID string, required []string) (string, error) {
	if len(data) == 0 || len(data) > maxDylibSize {
		return "", errors.New("ipa: package: dylib is empty or exceeds the size bound")
	}
	if err := validateDylibID(expectedID); err != nil {
		return "", err
	}
	if err := validateRuntimeDylib(data, expectedID, required); err != nil {
		return "", fmt.Errorf("ipa: package: dylib metadata: %w", err)
	}
	return hashHex(data), nil
}

func parseSourceArchive(snapshot []byte) (*zip.Reader, error) {
	zr, err := zip.NewReader(bytes.NewReader(snapshot), int64(len(snapshot)))
	if err != nil {
		return nil, fmt.Errorf("ipa: package: source IPA ZIP: %w", err)
	}
	if len(zr.File) == 0 || len(zr.File) > maxArchiveEntries {
		return nil, errors.New("ipa: package: source IPA entry count is outside bounds")
	}
	seen := make(map[string]struct{}, len(zr.File))
	for _, f := range zr.File {
		if err := validateName(f.Name); err != nil {
			return nil, err
		}
		if _, exists := seen[f.Name]; exists {
			return nil, fmt.Errorf("ipa: package: duplicate source archive member %q", f.Name)
		}
		seen[f.Name] = struct{}{}
		if f.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("ipa: package: source archive contains a symlink member %q", f.Name)
		}
		if strings.EqualFold(f.Name, ownDylibZipPath) {
			return nil, errors.New("ipa: package: source IPA already contains or case-collides with the own dylib dependency")
		}
		if strings.EqualFold(f.Name, ownEndpointZipPath) ||
			strings.EqualFold(strings.TrimSuffix(f.Name, "/"), ownEndpointParentDir) {
			return nil, errors.New("ipa: package: source IPA already contains or case-collides with the own endpoint descriptor path")
		}
	}
	return zr, nil
}

func findUniqueMember(zr *zip.Reader, name string) (*zip.File, error) {
	var found *zip.File
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		if found != nil {
			return nil, errors.New("ipa: package: duplicate locked executable member")
		}
		found = f
	}
	if found == nil {
		return nil, errors.New("ipa: package: locked executable member is missing")
	}
	if !found.Mode().IsRegular() {
		return nil, errors.New("ipa: package: locked executable member is not a regular file")
	}
	if found.Mode().Perm()&0o111 == 0 {
		return nil, errors.New("ipa: package: locked executable member has no execute permission")
	}
	return found, nil
}

func readZipMember(f *zip.File, max uint64) ([]byte, error) {
	if f.UncompressedSize64 > max || max > math.MaxInt64 {
		return nil, errors.New("ipa: package: archive member exceeds the read bound")
	}
	r, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if uint64(len(data)) != f.UncompressedSize64 || uint64(len(data)) > max {
		return nil, errors.New("ipa: package: archive member size disagrees with its central directory")
	}
	return data, nil
}

func assembleArchive(snapshot, patchedMain, dylib, endpointJSON []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(snapshot), int64(len(snapshot)))
	if err != nil {
		return nil, err
	}
	if _, err := parseSourceArchive(snapshot); err != nil {
		return nil, err
	}
	if len(patchedMain) == 0 || len(patchedMain) > maxExecutableBytes ||
		len(dylib) == 0 || len(endpointJSON) == 0 || len(endpointJSON) > maxEndpointJSONBytes {
		return nil, errors.New("ipa: package: replacement main, own dylib, or endpoint JSON has an invalid size")
	}
	mainEntry, err := findUniqueMember(zr, ExecutablePath)
	if err != nil {
		return nil, err
	}
	if mainEntry.UncompressedSize64 != uint64(len(patchedMain)) {
		return nil, errors.New("ipa: package: replacement main size does not match the source executable member")
	}

	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	if zr.Comment != "" {
		if err := zw.SetComment(zr.Comment); err != nil {
			return nil, err
		}
	}
	for _, f := range zr.File {
		if f.Name == ExecutablePath {
			if err := writeReplacement(zw, f, patchedMain); err != nil {
				return nil, fmt.Errorf("write replacement executable member: %w", err)
			}
			continue
		}
		if err := copyRawEntry(zw, f); err != nil {
			return nil, fmt.Errorf("copy retained member: %w", err)
		}
	}
	if err := writePayload(zw, ownDylibZipPath, zip.Deflate, dylib, nil, 0o755); err != nil {
		return nil, fmt.Errorf("append own dylib: %w", err)
	}
	if err := writePayload(zw, ownEndpointZipPath, zip.Deflate, endpointJSON, nil, 0o644); err != nil {
		return nil, fmt.Errorf("append endpoint JSON: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return append([]byte(nil), out.Bytes()...), nil
}

func copyRawEntry(zw *zip.Writer, f *zip.File) error {
	header := f.FileHeader
	header.SetModTime(packageFixedTime)
	header.Extra = stripTimeExtra(header.Extra)
	header.Flags &^= zipDataDescriptor
	dst, err := zw.CreateRaw(&header)
	if err != nil {
		return err
	}
	src, err := f.OpenRaw()
	if err != nil {
		return err
	}
	n, err := io.Copy(dst, src)
	if err != nil {
		return err
	}
	if uint64(n) != f.CompressedSize64 {
		return errors.New("retained raw compressed payload was short")
	}
	return nil
}

func writeReplacement(zw *zip.Writer, source *zip.File, body []byte) error {
	header := source.FileHeader
	header.SetModTime(packageFixedTime)
	header.Extra = stripTimeExtra(header.Extra)
	header.Flags &^= zipDataDescriptor
	dst, err := zw.CreateHeader(&header)
	if err != nil {
		return err
	}
	_, err = dst.Write(body)
	return err
}

func writePayload(zw *zip.Writer, name string, method uint16, body, extra []byte, mode os.FileMode) error {
	if method != zip.Store && method != zip.Deflate {
		return fmt.Errorf("unsupported replacement compression method %d", method)
	}
	header := &zip.FileHeader{Name: name, Method: method}
	header.SetModTime(packageFixedTime)
	header.Extra = stripTimeExtra(extra)
	header.SetMode(mode)
	w, err := zw.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

func stripTimeExtra(extra []byte) []byte {
	var out []byte
	for len(extra) >= 4 {
		id := binary.LittleEndian.Uint16(extra[:2])
		size := int(binary.LittleEndian.Uint16(extra[2:4]))
		if 4+size > len(extra) {
			break
		}
		field := extra[:4+size]
		extra = extra[4+size:]
		switch id {
		case 0x5455, 0x000a, 0x000d:
			continue
		default:
			out = append(out, field...)
		}
	}
	return out
}

func verifyPackage(sourceIPA, packed, expectedMain, expectedDylib, expectedEndpointJSON []byte) (int, error) {
	source, err := zip.NewReader(bytes.NewReader(sourceIPA), int64(len(sourceIPA)))
	if err != nil {
		return 0, err
	}
	out, err := zip.NewReader(bytes.NewReader(packed), int64(len(packed)))
	if err != nil {
		return 0, err
	}
	if len(out.File) != len(source.File)+2 {
		return 0, fmt.Errorf("output entry count %d, want %d", len(out.File), len(source.File)+2)
	}
	retained := 0
	for i, src := range source.File {
		dst := out.File[i]
		if src.Name != dst.Name {
			return 0, fmt.Errorf("entry order/name changed at index %d", i)
		}
		if src.Name == ExecutablePath {
			body, err := readZipMember(dst, uint64(MainSize))
			if err != nil {
				return 0, err
			}
			if !bytes.Equal(body, expectedMain) {
				return 0, errors.New("packaged main member differs from the in-memory patch")
			}
			if dst.Mode().Perm() != src.Mode().Perm() {
				return 0, errors.New("packaged main file permissions differ from the locked source")
			}
			continue
		}
		srcRaw, err := digestRawMember(src)
		if err != nil {
			return 0, err
		}
		dstRaw, err := digestRawMember(dst)
		if err != nil {
			return 0, err
		}
		if srcRaw != dstRaw ||
			src.Method != dst.Method ||
			src.CRC32 != dst.CRC32 ||
			src.UncompressedSize64 != dst.UncompressedSize64 ||
			src.CompressedSize64 != dst.CompressedSize64 {
			return 0, fmt.Errorf("retained raw payload/metadata changed for member index %d", i)
		}
		retained++
	}

	dylibAddition := out.File[len(out.File)-2]
	if dylibAddition.Name != ownDylibZipPath || dylibAddition.Method != zip.Deflate {
		return 0, errors.New("own-dylib addition path or compression method mismatch")
	}
	if dylibAddition.Mode().Perm() != 0o755 {
		return 0, errors.New("own-dylib addition is not marked executable")
	}
	if !dylibAddition.Modified.Equal(packageFixedTime) {
		return 0, errors.New("own-dylib addition timestamp is not fixed")
	}
	addedDylib, err := readZipMember(dylibAddition, uint64(len(expectedDylib)))
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(addedDylib, expectedDylib) {
		return 0, errors.New("own-dylib addition differs from the explicit input artifact")
	}

	endpointAddition := out.File[len(out.File)-1]
	if endpointAddition.Name != ownEndpointZipPath || endpointAddition.Method != zip.Deflate {
		return 0, errors.New("endpoint addition path or compression method mismatch")
	}
	if endpointAddition.Mode().Perm() != 0o644 {
		return 0, errors.New("endpoint addition permissions are not 0644")
	}
	if !endpointAddition.Modified.Equal(packageFixedTime) {
		return 0, errors.New("endpoint addition timestamp is not fixed")
	}
	addedEndpoint, err := readZipMember(endpointAddition, uint64(len(expectedEndpointJSON)))
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(addedEndpoint, expectedEndpointJSON) {
		return 0, errors.New("endpoint addition differs from the validated canonical descriptor")
	}
	return retained, nil
}

func digestRawMember(f *zip.File) (rawDigest, error) {
	r, err := f.OpenRaw()
	if err != nil {
		return rawDigest{}, err
	}
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return rawDigest{}, err
	}
	if uint64(n) != f.CompressedSize64 {
		return rawDigest{}, errors.New("retained raw compressed payload length mismatch")
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return rawDigest{hash: sum, size: uint64(n)}, nil
}

func validateMainWriteWindows(original, patched []byte) error {
	if len(original) != len(patched) {
		return errors.New("ipa: package: patch changed main executable size")
	}
	ranges := changedRanges(original, patched)
	allowed := []RangePair{
		{16, 24},
		{0x2058, 0x20a0},
		{0x3000, 0x3040},
		{0x3080, 0x3080 + len(ExportNotice404DiagnosticEntry) + 1},
		{0x3100, 0x313c},
		{0x3180, 0x3180 + len(ExportGetaddrinfo) + 1},
		{0x3200, 0x323c},
		{0x3280, 0x3280 + len(ExportFreeaddrinfo) + 1},
		{0x3300, 0x333c},
		{0x3380, 0x3380 + len(ExportGethostbyname) + 1},
		{0x3400, 0x343c},
		{0x3480, 0x3480 + len(ExportConnect) + 1},
		{0x3500, 0x3548},
		{0x3580, 0x3580 + len(ExportGuestUniqueCode) + 1},
		{0x3600, 0x360c},
		{0x3640, 0x3640 + loginReadyResolverWordCount*4},
		{0x3680, 0x3680 + len(ExportLoginReady) + 1},
		{int(gdprLoginReadyResolverRVA), int(gdprLoginReadyResolverRVA + gdprLoginReadyResolverWordCount*4)},
		{0x3700, 0x3700 + sessionResetResolverWordCount*4},
		{0x3780, 0x3780 + len(ExportSessionReset) + 1},
		{0x3800, 0x3800 + sessionResetResolverWordCount*4},
		{0x38c0, 0x38c0 + sessionResetResolverWordCount*4},
		{0x3980, 0x3980 + checkSessionResolverWordCount*4},
		{0x3a00, 0x3a00 + len(ExportCheckSessionError) + 1},
		{0x3a40, 0x3a40 + guestGenerateResolverWordCount*4},
		{0x3b00, 0x3b00 + len(ExportGuestGenerateError) + 1},
		{0x12d8be4, 0x12d8be8},
		{0x53af68, 0x53af6c},
		{0x538de4, 0x538de8},
		{0x53bc98, 0x53bc9c},
		{0xbfe3b8, 0xbfe3bc},
		{0xd1ba00, 0xd1ba04},
		{0x6af020, 0x6af024},
		{0x6b39bc, 0x6b39c0},
		{0xbdf494, 0xbdf498},
		{0x6ae0c8, 0x6ae0cc},
		{0x6b2a54, 0x6b2a58},
		{int(gdprLoginReadyCallsiteRVA), int(gdprLoginReadyCallsiteRVA + 4)},
		{0x1ac149c, 0x1ac14a0},
		{0x1ac1874, 0x1ac1878},
		{0x1ac1904, 0x1ac1908},
		{0x1ac1928, 0x1ac192c},
	}
	for _, changed := range ranges {
		found := false
		for _, permit := range allowed {
			if changed.Start >= permit.Start && changed.End <= permit.End {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("ipa: package: main executable changed outside approved windows [%#x,%#x)", changed.Start, changed.End)
		}
	}
	for _, permit := range allowed {
		if permit.End > len(original) {
			return fmt.Errorf("ipa: package: approved main window [%#x,%#x) exceeds executable size", permit.Start, permit.End)
		}
		if bytes.Equal(original[permit.Start:permit.End], patched[permit.Start:permit.End]) {
			return fmt.Errorf("ipa: package: expected main window [%#x,%#x) was not modified", permit.Start, permit.End)
		}
	}
	if got := binary.LittleEndian.Uint32(patched[0x53af68:]); got != autoGuestEntryPatchedWord {
		return fmt.Errorf("ipa: package: auto-guest-entry word at 0x53af68 = 0x%08x, want 0x%08x", got, autoGuestEntryPatchedWord)
	}
	for _, guard := range []struct {
		name  string
		start int
		end   int
	}{
		{name: "legacy login helper prologue", start: 0x538db8, end: 0x538de4},
		{name: "legacy login helper continuation", start: 0x538de8, end: 0x538df8},
		{name: "stock ARC return/retain continuation", start: 0x12d8be8, end: 0x12d8bf4},
		{name: "SetEndLoading entry prologue", start: 0x53ad08, end: 0x53ad28},
		{name: "avcookie.na check", start: 0x53ade0, end: 0x53adf0},
		{name: "cookie-present CheckAutoLogin tail", start: 0x53ae3c, end: 0x53ae4c},
		{name: "US COPPA check", start: 0x53aee0, end: 0x53aef8},
		{name: "SetEndLoading eligible tail prefix", start: 0x53af48, end: 0x53af68},
		{name: "SetEndLoading post-tail boundary", start: 0x53af6c, end: 0x53af70},
		{name: "Logout sessionout success prefix", start: 0x6aeff8, end: 0x6af020},
		{name: "Logout sessionout success suffix", start: 0x6af024, end: 0x6af02c},
		{name: "SNS Delete Avatar success prefix", start: 0xbdf478, end: 0xbdf494},
		{name: "SNS Delete Avatar success suffix", start: 0xbdf498, end: 0xbdf4a4},
		{name: "direct Delete Avatar success prefix", start: 0x6b398c, end: 0x6b39bc},
		{name: "direct Delete Avatar success suffix", start: 0x6b39c0, end: 0x6b39c8},
		{name: "checkSession error entry continuation", start: 0x6ae0cc, end: 0x6ae0f4},
		{name: "guest/generate handler prefix", start: 0x6b29e0, end: 0x6b2a54},
		{name: "guest/generate handler epilogue tail", start: 0x6b2a58, end: 0x6b2a60},
		{name: "case 10043 GDPR-ready branch prefix", start: 0x53c430, end: int(gdprLoginReadyCallsiteRVA)},
		{name: "case 10043 GDPR-ready branch continuation", start: int(gdprLoginReadyCallsiteRVA + 4), end: 0x53c440},
		{name: "guest generate prologue", start: 0x6bdd4c, end: 0x6bdd68},
		{name: "guest callsite1 prefix", start: 0x53bc8c, end: 0x53bc98},
		{name: "guest callsite1 suffix", start: 0x53bc9c, end: 0x53bca0},
		{name: "createGuestAccount prologue", start: 0xbfe388, end: 0xbfe3a4},
		{name: "guest callsite2 prefix", start: 0xbfe3a4, end: 0xbfe3b8},
		{name: "guest callsite3 prefix", start: 0xd1b9ec, end: 0xd1ba00},
		{name: "connect stub tail", start: 0x1ac14a0, end: 0x1ac14a8},
		{name: "freeaddrinfo stub tail", start: 0x1ac1878, end: 0x1ac1880},
		{name: "getaddrinfo stub tail", start: 0x1ac1908, end: 0x1ac1910},
		{name: "gethostbyname stub tail", start: 0x1ac192c, end: 0x1ac1934},
	} {
		if guard.end > len(original) {
			return fmt.Errorf("ipa: package: guard window [%#x,%#x) exceeds executable size", guard.start, guard.end)
		}
		if !bytes.Equal(original[guard.start:guard.end], patched[guard.start:guard.end]) {
			return fmt.Errorf("ipa: package: %s [%#x,%#x) was changed", guard.name, guard.start, guard.end)
		}
	}
	return nil
}

type dylibReference struct {
	command uint32
	name    string
}

func validateLoaderDependencyDelta(original, patched []byte) error {
	before, err := dylibReferences(original)
	if err != nil {
		return fmt.Errorf("ipa: package: baseline Mach-O dependencies: %w", err)
	}
	after, err := dylibReferences(patched)
	if err != nil {
		return fmt.Errorf("ipa: package: patched Mach-O dependencies: %w", err)
	}
	return validateAddedLoaderReference(before, after)
}

func validateAddedLoaderReference(before, after []dylibReference) error {
	if len(after) != len(before)+1 {
		return errors.New("ipa: package: patched main does not add exactly one dylib load command")
	}
	for i, old := range before {
		if after[i] != old {
			return errors.New("ipa: package: existing main-image dylib dependencies changed")
		}
		if strings.EqualFold(lastPathComponent(old.name), "libraspberry.dylib") {
			return errors.New("ipa: package: baseline already contains a dependency that conflicts with libraspberry.dylib")
		}
	}
	added := after[len(after)-1]
	if added.command != lcLoadDylib || added.name != LoaderPath {
		return errors.New("ipa: package: new main-image dependency does not match the exact loader path")
	}
	return nil
}

func dylibReferences(data []byte) ([]dylibReference, error) {
	file, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse Mach-O: %w", err)
	}
	var refs []dylibReference
	for _, load := range file.Loads {
		raw := load.Raw()
		if len(raw) < 8 {
			return nil, errors.New("truncated Mach-O load command")
		}
		command := binary.LittleEndian.Uint32(raw)
		switch command {
		case lcLoadDylib, lcIdDylib, lcLoadWeakDylib, lcReexportDylib, 0x20, lcLoadUpwardDylib:
		default:
			continue
		}
		if len(raw) < dylibCmdHeaderSize || uint64(binary.LittleEndian.Uint32(raw[4:])) != uint64(len(raw)) {
			return nil, errors.New("malformed Mach-O dylib load command")
		}
		nameOffset := binary.LittleEndian.Uint32(raw[8:])
		if nameOffset < dylibCmdHeaderSize {
			return nil, errors.New("Mach-O dylib name offset overlaps its load-command header")
		}
		name, err := cStringAt(raw, nameOffset)
		if err != nil {
			return nil, fmt.Errorf("Mach-O dylib load-command name: %w", err)
		}
		refs = append(refs, dylibReference{command: command, name: name})
	}
	return refs, nil
}

func lastPathComponent(name string) string {
	if slash := strings.LastIndexByte(name, '/'); slash >= 0 {
		return name[slash+1:]
	}
	return name
}

func changedRanges(before, after []byte) []RangePair {
	if len(before) != len(after) {
		return []RangePair{{0, maxInt(len(before), len(after))}}
	}
	var out []RangePair
	for i := 0; i < len(before); {
		if before[i] == after[i] {
			i++
			continue
		}
		start := i
		for i < len(before) && before[i] != after[i] {
			i++
		}
		out = append(out, RangePair{start, i})
	}
	return out
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func validateRuntimeDylib(data []byte, expectedID string, required []string) error {
	if len(data) < 32 || len(data) > maxDylibSize {
		return errors.New("dylib size is outside bounds")
	}
	if len(required) == 0 {
		return errors.New("required export list is empty")
	}
	file, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("dylib Mach-O parse: %w", err)
	}
	if file.Magic != macho.Magic64 || file.Cpu != macho.CpuArm64 || file.Type != macho.TypeDylib {
		return errors.New("dylib must be a thin little-endian arm64 MH_DYLIB")
	}
	idCount := 0
	for _, load := range file.Loads {
		raw := load.Raw()
		if len(raw) < 8 || binary.LittleEndian.Uint32(raw) != lcIdDylib {
			continue
		}
		if len(raw) < dylibCmdHeaderSize {
			return errors.New("LC_ID_DYLIB is truncated")
		}
		idCount++
		nameOffset := binary.LittleEndian.Uint32(raw[8:])
		if nameOffset < dylibCmdHeaderSize {
			return errors.New("LC_ID_DYLIB name offset overlaps its header")
		}
		name, err := cStringAt(raw, nameOffset)
		if err != nil {
			return err
		}
		if name != expectedID {
			return fmt.Errorf("LC_ID_DYLIB is %q, expected %q", name, expectedID)
		}
	}
	if idCount != 1 {
		return fmt.Errorf("expected one LC_ID_DYLIB, got %d", idCount)
	}

	var rxSegments []*macho.Segment
	var imageBase uint64 = math.MaxUint64
	for _, load := range file.Loads {
		seg, ok := load.(*macho.Segment)
		if !ok {
			continue
		}
		if seg.Addr < imageBase && seg.Memsz > 0 {
			imageBase = seg.Addr
		}
		if seg.Prot&2 != 0 && seg.Prot&4 != 0 {
			return errors.New("dylib contains a writable-executable segment")
		}
		if seg.Maxprot&2 != 0 && seg.Maxprot&4 != 0 {
			return errors.New("dylib permits a writable-executable segment")
		}
		if seg.Name == "__TEXT" && seg.Prot&4 != 0 && seg.Prot&2 == 0 &&
			seg.Maxprot&4 != 0 && seg.Maxprot&2 == 0 {
			rxSegments = append(rxSegments, seg)
		}
	}
	if len(rxSegments) == 0 || imageBase == math.MaxUint64 {
		return errors.New("dylib lacks an RX-only __TEXT segment")
	}

	exportTrie, err := dylibExportTrie(data, file)
	if err != nil {
		return err
	}

	for _, exportName := range required {
		if exportName == "" {
			return errors.New("required export name is empty")
		}
		if file.Symtab != nil {
			if err := validateOptionalSymbolDefinition(file, exportName); err != nil {
				return fmt.Errorf("required export %q: %w", exportName, err)
			}
		}
		exportAddr, err := findDirectExport(exportTrie, "_"+exportName)
		if err != nil {
			return fmt.Errorf("required export %q: %w", exportName, err)
		}
		if exportAddr > math.MaxUint64-imageBase {
			return fmt.Errorf("required export %q: address overflows image base", exportName)
		}
		exportVA := imageBase + exportAddr
		inRX := false
		for _, seg := range rxSegments {
			end := seg.Addr + seg.Memsz
			if end < seg.Addr {
				continue
			}
			if exportVA >= seg.Addr && exportVA < end {
				inRX = true
				break
			}
		}
		if !inRX {
			return fmt.Errorf("required export %q: dynamic export does not resolve inside the RX __TEXT segment", exportName)
		}
		if file.Symtab != nil {
			count := 0
			for _, sym := range file.Symtab.Syms {
				if sym.Name == "_"+exportName && sym.Value == exportVA {
					count++
				}
			}
			if count != 1 {
				return fmt.Errorf("required export %q: export-trie address does not match the unique symbol-table definition", exportName)
			}
		}
	}
	return nil
}

func validateOptionalSymbolDefinition(file *macho.File, exportName string) error {
	want := "_" + exportName
	count := 0
	for _, sym := range file.Symtab.Syms {
		if sym.Name != want {
			continue
		}
		if sym.Type&0x01 == 0 || sym.Type&0x0e != 0x0e || sym.Type&0x10 != 0 || sym.Sect == 0 {
			return errors.New("dylib export symbol is not a public section definition")
		}
		count++
	}
	if count != 1 {
		return fmt.Errorf("expected one public symbol-table definition for export, got %d", count)
	}
	return nil
}

func dylibExportTrie(data []byte, file *macho.File) ([]byte, error) {
	found := false
	var exportOff, exportSize uint64
	for _, load := range file.Loads {
		raw := load.Raw()
		if len(raw) < 8 {
			continue
		}
		cmd := binary.LittleEndian.Uint32(raw)
		var off, size uint32
		switch cmd {
		case lcDyldExportsTrie:
			if len(raw) < 16 {
				return nil, errors.New("LC_DYLD_EXPORTS_TRIE is truncated")
			}
			off = binary.LittleEndian.Uint32(raw[8:])
			size = binary.LittleEndian.Uint32(raw[12:])
		case lcDyldInfo, lcDyldInfoOnly:
			if len(raw) < 48 {
				return nil, errors.New("LC_DYLD_INFO export metadata is truncated")
			}
			off = binary.LittleEndian.Uint32(raw[40:])
			size = binary.LittleEndian.Uint32(raw[44:])
		default:
			continue
		}
		if size == 0 {
			continue
		}
		if found && (exportOff != uint64(off) || exportSize != uint64(size)) {
			return nil, errors.New("dylib contains ambiguous export-trie metadata")
		}
		found, exportOff, exportSize = true, uint64(off), uint64(size)
	}
	if !found || exportOff > uint64(len(data)) || exportSize > uint64(len(data))-exportOff {
		return nil, errors.New("dylib has no valid dynamic export trie")
	}
	return data[exportOff : exportOff+exportSize], nil
}

func findDirectExport(trie []byte, wanted string) (uint64, error) {
	var nodeOffset uint64
	var prefix string
	visited := make(map[uint64]struct{})
	for steps := 0; steps < 256; steps++ {
		if nodeOffset >= uint64(len(trie)) {
			return 0, errors.New("export trie references an invalid node")
		}
		if _, seen := visited[nodeOffset]; seen {
			return 0, errors.New("export trie contains a cycle")
		}
		visited[nodeOffset] = struct{}{}
		cursor := int(nodeOffset)
		terminalSize, err := readULEB(trie, &cursor)
		if err != nil || terminalSize > uint64(len(trie)-cursor) {
			return 0, errors.New("export trie terminal is malformed")
		}
		terminalStart := cursor
		terminalEnd := terminalStart + int(terminalSize)
		if prefix == wanted {
			if terminalSize == 0 {
				return 0, errors.New("requested export is absent")
			}
			terminal := trie[terminalStart:terminalEnd]
			terminalCursor := 0
			flags, err := readULEB(terminal, &terminalCursor)
			if err != nil || flags != 0 {
				return 0, errors.New("requested export is not a direct strong export")
			}
			address, err := readULEB(terminal, &terminalCursor)
			if err != nil || terminalCursor != len(terminal) {
				return 0, errors.New("requested export terminal is malformed")
			}
			return address, nil
		}
		if terminalEnd >= len(trie) {
			return 0, errors.New("export trie node has no child-count byte")
		}
		childCount := int(trie[terminalEnd])
		cursor = terminalEnd + 1
		matchCount := 0
		var nextOffset uint64
		var nextEdge string
		for i := 0; i < childCount; i++ {
			if cursor >= len(trie) {
				return 0, errors.New("export trie child is truncated")
			}
			rel := bytes.IndexByte(trie[cursor:], 0)
			if rel <= 0 {
				return 0, errors.New("export trie edge is malformed")
			}
			edge := string(trie[cursor : cursor+rel])
			cursor += rel + 1
			child, err := readULEB(trie, &cursor)
			if err != nil || child >= uint64(len(trie)) {
				return 0, errors.New("export trie child offset is invalid")
			}
			if strings.HasPrefix(wanted, prefix+edge) {
				matchCount++
				nextOffset, nextEdge = child, edge
			}
		}
		if matchCount != 1 {
			return 0, errors.New("requested export is absent or ambiguous")
		}
		prefix += nextEdge
		nodeOffset = nextOffset
	}
	return 0, errors.New("export trie traversal exceeded its bound")
}

func readULEB(data []byte, cursor *int) (uint64, error) {
	var value uint64
	for shift := uint(0); shift < 64; shift += 7 {
		if *cursor < 0 || *cursor >= len(data) {
			return 0, errors.New("truncated ULEB128")
		}
		next := data[*cursor]
		*cursor++
		payload := uint64(next & 0x7f)
		if shift == 63 && payload > 1 {
			return 0, errors.New("overflowing ULEB128")
		}
		value |= payload << shift
		if next&0x80 == 0 {
			return value, nil
		}
	}
	return 0, errors.New("overflowing ULEB128")
}

func cStringAt(data []byte, offset uint32) (string, error) {
	if uint64(offset) >= uint64(len(data)) {
		return "", errors.New("Mach-O string offset is outside the load command")
	}
	rest := data[offset:]
	n := bytes.IndexByte(rest, 0)
	if n < 0 {
		return "", errors.New("Mach-O string is not NUL terminated")
	}
	return string(rest[:n]), nil
}

func hashHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
