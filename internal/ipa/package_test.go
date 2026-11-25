package ipa

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/festivities/raspberry/internal/descriptor"
)

func allRequiredExports(baseAddr uint64) []syntheticExport {
	exports := make([]syntheticExport, len(RequiredExports))
	for i, name := range RequiredExports {
		exports[i] = syntheticExport{
			name:    "_" + name,
			address: baseAddr + uint64(i*0x20),
			flags:   0,
		}
	}
	return exports
}

func TestAssembleArchiveDeterministicAndPreservesRetainedRawMembers(t *testing.T) {
	sourceMain := []byte("synthetic-main-image-before")
	patchedMain := []byte("synthetic-main-image-after!")
	if len(sourceMain) != len(patchedMain) {
		t.Fatal("test main images must have equal lengths")
	}
	source := syntheticArchive(t, []syntheticMember{
		{name: infoPlistZipPath, body: []byte(
			"<?xml version=\"1.0\"?>\n<plist>\n<dict>\n" +
				"\t<key>UnrelatedBefore</key>\n\t<string>keep-before</string>\n" +
				"\t<key>UISupportedDevices</key>\n\t<array>\n" +
				"\t\t<string>iPhone14,2</string>\n\t\t<string>iPhone17,1</string>\n" +
				"\t</array>\n\t<key>UnrelatedAfter</key>\n\t<string>keep-after</string>\n" +
				"</dict>\n</plist>\n",
		), method: zip.Store},
		{name: ExecutablePath, body: sourceMain, method: zip.Deflate, mode: 0o755},
		{name: "Payload/LINEPlay_Store.app/Assets/data.bin", body: bytes.Repeat([]byte("asset"), 30), method: zip.Deflate},
	})
	dylib := []byte("synthetic-own-dylib")
	canonicalEndpoint, err := validateEndpointJSON([]byte(`{"v":1,"host":"Cherry.Example.ORG","note":"ignored","ports":{"443":8443}}`))
	if err != nil {
		t.Fatalf("valid placeholder endpoint rejected: %v", err)
	}
	const wantCanonical = `{"v":1,"host":"cherry.example.org","ports":{"10000":10000,"10123":10123,"443":8443,"80":80}}`
	if string(canonicalEndpoint) != wantCanonical {
		t.Fatalf("canonical endpoint=%s, want %s", canonicalEndpoint, wantCanonical)
	}

	pkgA, err := assembleArchive(source, patchedMain, dylib, canonicalEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	pkgB, err := assembleArchive(source, patchedMain, dylib, canonicalEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pkgA, pkgB) {
		t.Fatal("independent in-memory package builds differ")
	}
	retained, err := verifyPackage(source, pkgA, patchedMain, dylib, canonicalEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	if retained != 1 {
		t.Fatalf("retained raw members=%d, want 1", retained)
	}

	sourceZip, err := zip.NewReader(bytes.NewReader(source), int64(len(source)))
	if err != nil {
		t.Fatal(err)
	}
	packedZip, err := zip.NewReader(bytes.NewReader(pkgA), int64(len(pkgA)))
	if err != nil {
		t.Fatal(err)
	}
	if len(packedZip.File) != len(sourceZip.File)+2 {
		t.Fatalf("packed entry count=%d, want %d", len(packedZip.File), len(sourceZip.File)+2)
	}
	for i := range sourceZip.File {
		src, dst := sourceZip.File[i], packedZip.File[i]
		if src.Name != dst.Name {
			t.Fatalf("member order changed at %d: %q != %q", i, src.Name, dst.Name)
		}
		if src.Name == ExecutablePath {
			continue
		}
		if src.Name == infoPlistZipPath {
			srcBody, err := readZipMember(src, maxInfoPlistBytes)
			if err != nil {
				t.Fatal(err)
			}
			wantBody, err := addSupportedDevices(srcBody)
			if err != nil {
				t.Fatal(err)
			}
			dstBody, err := readZipMember(dst, maxInfoPlistBytes)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(dstBody, wantBody) {
				t.Fatal("packaged Info.plist differs from the exact supported-device update")
			}
			continue
		}
		srcRaw, err := digestRawMember(src)
		if err != nil {
			t.Fatal(err)
		}
		dstRaw, err := digestRawMember(dst)
		if err != nil {
			t.Fatal(err)
		}
		if srcRaw != dstRaw {
			t.Fatalf("raw compressed payload changed for %q", src.Name)
		}
		if src.Method != dst.Method || src.CRC32 != dst.CRC32 ||
			src.CompressedSize64 != dst.CompressedSize64 ||
			src.UncompressedSize64 != dst.UncompressedSize64 {
			t.Fatalf("compression metadata changed for %q", src.Name)
		}
	}

	dylibMember := packedZip.File[len(packedZip.File)-2]
	if dylibMember.Name != ownDylibZipPath || dylibMember.Mode().Perm() != 0o755 || !dylibMember.Modified.Equal(packageFixedTime) {
		t.Fatalf("unexpected dylib addition metadata: name=%q mode=%#o mod=%v", dylibMember.Name, dylibMember.Mode().Perm(), dylibMember.Modified)
	}
	endpointMember := packedZip.File[len(packedZip.File)-1]
	if endpointMember.Name != ownEndpointZipPath || endpointMember.Mode().Perm() != 0o644 || !endpointMember.Modified.Equal(packageFixedTime) {
		t.Fatalf("unexpected endpoint addition metadata: name=%q mode=%#o mod=%v", endpointMember.Name, endpointMember.Mode().Perm(), endpointMember.Modified)
	}
	endpointBody, err := readZipMember(endpointMember, maxEndpointJSONBytes)
	if err != nil {
		t.Fatal(err)
	}
	if string(endpointBody) != wantCanonical {
		t.Fatalf("packaged endpoint JSON=%s, want %s", endpointBody, wantCanonical)
	}
	parsed, err := descriptor.Parse(endpointBody)
	if err != nil {
		t.Fatalf("packaged endpoint JSON failed descriptor.Parse: %v", err)
	}
	if parsed.Host != "cherry.example.org" || parsed.MapPort(443) != 8443 {
		t.Fatalf("unexpected parsed endpoint: %+v", parsed)
	}
}

func TestAddSupportedDevicesPreservesPlistAndAddsExactIDs(t *testing.T) {
	source := []byte(
		"<?xml version=\"1.0\"?>\n<plist>\n<dict>\n" +
			"\t<key>UnrelatedBefore</key>\n\t<string>keep-before</string>\n" +
			"\t<key>UISupportedDevices</key>\n\t<array>\n" +
			"\t\t<string>iPhone14,2</string>\n\t\t<string>iPhone17,1</string>\n" +
			"\t</array>\n\t<key>UnrelatedAfter</key>\n\t<string>keep-after</string>\n" +
			"</dict>\n</plist>\n",
	)
	got, err := addSupportedDevices(source)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte(
		"<?xml version=\"1.0\"?>\n<plist>\n<dict>\n" +
			"\t<key>UnrelatedBefore</key>\n\t<string>keep-before</string>\n" +
			"\t<key>UISupportedDevices</key>\n\t<array>\n" +
			"\t\t<string>iPhone14,2</string>\n\t\t<string>iPhone17,1</string>\n" +
			"\t\t<string>iPhone17,2</string>\n\t\t<string>iPhone17,3</string>\n" +
			"\t\t<string>iPhone17,4</string>\n\t\t<string>iPhone17,5</string>\n" +
			"\t\t<string>iPhone18,1</string>\n\t\t<string>iPhone18,2</string>\n" +
			"\t\t<string>iPhone18,3</string>\n\t\t<string>iPhone18,4</string>\n" +
			"\t\t<string>iPhone18,5</string>\n\t\t<string>iPhone19,1</string>\n" +
			"\t\t<string>iPhone19,2</string>\n\t\t<string>iPhone19,3</string>\n" +
			"\t\t<string>iPhone19,4</string>\n\t\t<string>iPhone19,7</string>\n" +
			"\t</array>\n\t<key>UnrelatedAfter</key>\n\t<string>keep-after</string>\n" +
			"</dict>\n</plist>\n",
	)
	if !bytes.Equal(got, want) {
		t.Fatal("supported-device update changed bytes beyond the expected array insertion")
	}
	if again, err := addSupportedDevices(got); err != nil || !bytes.Equal(again, got) {
		t.Fatalf("supported-device update is not idempotent: err=%v", err)
	}
}

func TestAddSupportedDevicesRejectsMalformedArrayAnchor(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "missing anchor", data: []byte("<plist><dict/></plist>")},
		{name: "ambiguous anchor", data: []byte(supportedDevicesAnchor + supportedDevicesAnchor + supportedDevicesClose)},
		{name: "missing close", data: []byte(supportedDevicesAnchor)},
		{name: "nested entry", data: []byte(supportedDevicesAnchor + "\t\t<array>\n\t</array>")},
		{name: "malformed close", data: []byte(supportedDevicesAnchor + "\t</arrayish>")},
		{name: "duplicate device", data: []byte(supportedDevicesAnchor + strings.Repeat("\t\t<string>iPhone17,1</string>\n", 2) + supportedDevicesClose)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := addSupportedDevices(tc.data); err == nil {
				t.Fatal("malformed Info.plist supported-device array was accepted")
			}
		})
	}
}

func TestEndpointJSONValidationAndNoLeak(t *testing.T) {
	validCases := []string{
		`{"v":1,"host":"cherry.example.org"}`,
		`{"v":1,"host":"Cherry.Example.ORG","ports":{"80":8080,"443":8443,"10000":10000,"10123":10123}}`,
		`{"v":1,"host":"203.0.113.10"}`,
	}
	for _, tc := range validCases {
		if _, err := validateEndpointJSON([]byte(tc)); err != nil {
			t.Fatalf("valid endpoint %s rejected: %v", tc, err)
		}
	}

	const sentinelHost = "bad host"
	const sentinelSecret = "operator-secret-value"
	invalidCases := []struct {
		name string
		raw  []byte
	}{
		{name: "empty", raw: []byte("")},
		{name: "whitespace only", raw: []byte("  \n\t ")},
		{name: "invalid json", raw: []byte("{")},
		{name: "trailing data", raw: []byte(`{"v":1,"host":"cherry.example.org"} trailing`)},
		{name: "missing version", raw: []byte(`{"host":"cherry.example.org"}`)},
		{name: "wrong version", raw: []byte(`{"v":2,"host":"cherry.example.org"}`)},
		{name: "missing host", raw: []byte(`{"v":1}`)},
		{name: "url host", raw: []byte(`{"v":1,"host":"https://cherry.example.org"}`)},
		{name: "host with port", raw: []byte(`{"v":1,"host":"cherry.example.org:443"}`)},
		{name: "reserved marker ip", raw: []byte(`{"v":1,"host":"198.18.0.1"}`)},
		{name: "leading zero ip", raw: []byte(`{"v":1,"host":"01.2.3.4"}`)},
		{name: "bad host with secret", raw: []byte(`{"v":1,"host":"` + sentinelHost + `","secret":"` + sentinelSecret + `"}`)},
		{name: "port zero", raw: []byte(`{"v":1,"host":"cherry.example.org","ports":{"443":0}}`)},
		{name: "port too high", raw: []byte(`{"v":1,"host":"cherry.example.org","ports":{"443":65536}}`)},
		{name: "port string", raw: []byte(`{"v":1,"host":"cherry.example.org","ports":{"443":"8443"}}`)},
		{name: "port key disallowed", raw: []byte(`{"v":1,"host":"cherry.example.org","ports":{"22":22}}`)},
		{
			name: "oversized over 4KiB",
			raw:  append(append([]byte(`{"v":1,"host":"cherry.example.org","pad":"`), bytes.Repeat([]byte("a"), maxEndpointJSONBytes)...), []byte(`"}`)...),
		},
	}
	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateEndpointJSON(tc.raw)
			if err == nil {
				t.Fatalf("invalid endpoint %s was accepted", tc.name)
			}
			msg := err.Error()
			if strings.Contains(msg, sentinelHost) || strings.Contains(msg, sentinelSecret) || strings.Contains(msg, "cherry.example.org") || strings.Contains(msg, "8443") || strings.Contains(msg, "65536") {
				t.Fatalf("endpoint error leaked contents: %v", err)
			}
		})
	}
}

func TestParseSourceArchiveRejectsUnsafeDuplicateSymlinkAndDependencyNames(t *testing.T) {
	tests := []struct {
		name    string
		members []syntheticMember
	}{
		{
			name: "parent traversal",
			members: []syntheticMember{
				{name: "../outside", body: []byte("x"), method: zip.Store},
			},
		},
		{
			name: "absolute path",
			members: []syntheticMember{
				{name: "/outside", body: []byte("x"), method: zip.Store},
			},
		},
		{
			name: "backslash path",
			members: []syntheticMember{
				{name: `Payload\outside`, body: []byte("x"), method: zip.Store},
			},
		},
		{
			name: "duplicate name",
			members: []syntheticMember{
				{name: "Payload/a", body: []byte("x"), method: zip.Store},
				{name: "Payload/a", body: []byte("y"), method: zip.Store},
			},
		},
		{
			name: "symlink",
			members: []syntheticMember{
				{name: "Payload/link", body: []byte("target"), method: zip.Store, mode: os.ModeSymlink | 0o777},
			},
		},
		{
			name: "exact dependency",
			members: []syntheticMember{
				{name: ownDylibZipPath, body: []byte("old"), method: zip.Store},
			},
		},
		{
			name: "case-colliding dependency",
			members: []syntheticMember{
				{name: strings.ToUpper(ownDylibZipPath), body: []byte("old"), method: zip.Store},
			},
		},
		{
			name: "exact endpoint descriptor",
			members: []syntheticMember{
				{name: ownEndpointZipPath, body: []byte("{}"), method: zip.Store},
			},
		},
		{
			name: "case-colliding endpoint descriptor",
			members: []syntheticMember{
				{name: strings.ToUpper(ownEndpointZipPath), body: []byte("{}"), method: zip.Store},
			},
		},
		{
			name: "colliding endpoint parent file",
			members: []syntheticMember{
				{name: ownEndpointParentDir, body: []byte("x"), method: zip.Store},
			},
		},
		{
			name: "colliding endpoint parent dir",
			members: []syntheticMember{
				{name: ownEndpointParentDir + "/", body: nil, method: zip.Store},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := syntheticArchive(t, tt.members)
			if _, err := parseSourceArchive(data); err == nil {
				t.Fatal("unsafe source archive was accepted")
			}
		})
	}
}

func TestWritePackageAtomicCreatesPrivateFileAndRefusesOverwriteAndSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.ipa")
	data := []byte("synthetic package bytes")
	if err := WritePackageAtomic(path, data); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("published bytes differ")
	}
	if err := verifyPrivateFile(path); err != nil {
		t.Fatalf("published output is not private: %v", err)
	}
	if err := WritePackageAtomic(path, []byte("replacement")); err == nil {
		t.Fatal("existing output was overwritten")
	}

	target := filepath.Join(dir, "target.bin")
	if err := os.WriteFile(target, []byte("unchanged target"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "package-link.ipa")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := WritePackageAtomic(link, []byte("must not replace symlink")); err == nil {
		t.Fatal("symlink output path was accepted")
	}
	targetBytes, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(targetBytes) != "unchanged target" {
		t.Fatal("symlink-target file was changed")
	}

	realSub := filepath.Join(dir, "real-sub")
	if err := os.Mkdir(realSub, 0o700); err != nil {
		t.Fatal(err)
	}
	linkSub := filepath.Join(dir, "link-sub")
	if err := os.Symlink(realSub, linkSub); err != nil {
		t.Fatal(err)
	}
	if err := WritePackageAtomic(filepath.Join(linkSub, "out.ipa"), data); err == nil {
		t.Fatal("symlink parent directory was accepted")
	}

	if err := WritePackageAtomic("", data); err == nil {
		t.Fatal("empty path was accepted")
	}
	if err := WritePackageAtomic(filepath.Join(dir, "empty.ipa"), nil); err == nil {
		t.Fatal("empty data was accepted")
	}
}

func TestCreatePrivateTempIsPrivateBeforeFirstWrite(t *testing.T) {
	tmp, err := createPrivateTemp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	info, err := tmp.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("private temporary file has %d bytes before first write", info.Size())
	}
	if err := verifyPrivateFile(tmp.Name()); err != nil {
		t.Fatalf("temporary file is not private before first write: %v", err)
	}
}

func TestVerifyFileIdentityRejectsSubstitutedPath(t *testing.T) {
	dir := t.TempDir()
	original, err := os.CreateTemp(dir, "original-*")
	if err != nil {
		t.Fatal(err)
	}
	path := original.Name()
	info, err := original.Stat()
	if err != nil {
		original.Close()
		t.Fatal(err)
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verifyFileIdentity(path, info); err != nil {
		t.Fatalf("same file identity rejected: %v", err)
	}
	backup := filepath.Join(dir, "original-held-open")
	if err := os.Rename(path, backup); err != nil {
		t.Fatal(err)
	}
	if err := verifyFileIdentity(path, info); err == nil {
		t.Fatal("renamed original still passed identity check at its old path")
	}
	if err := os.WriteFile(path, []byte("substituted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyFileIdentity(path, info); err == nil {
		t.Fatal("substituted path passed the original file identity check")
	}
}

func TestBuildPackageRequiresLockedBaselineAndValidDylib(t *testing.T) {
	dylib := syntheticGuestAuthDylib(RequiredDylibID, allRequiredExports(0x200), 5)
	endpointRaw := []byte(`{"v":1,"host":"cherry.example.org"}`)

	if _, err := BuildPackage([]byte("not the locked IPA"), dylib, endpointRaw); err == nil {
		t.Fatal("unlocked source IPA was accepted")
	} else if !errors.Is(err, ErrBaseline) {
		t.Fatalf("wrong baseline error = %v, want ErrBaseline", err)
	}

	wrongHashIPA := make([]byte, BaselineSize)
	if _, err := BuildPackage(wrongHashIPA, dylib, endpointRaw); err == nil {
		t.Fatal("wrong-SHA256 source IPA was accepted")
	} else if !errors.Is(err, ErrBaseline) {
		t.Fatalf("wrong hash error = %v, want ErrBaseline", err)
	}

	if _, err := validateDylib([]byte("not-a-macho"), RequiredDylibID, RequiredExports); err == nil {
		t.Fatal("non-Mach-O dylib was accepted")
	}
	if _, err := validateDylib(dylib, "", RequiredExports); err == nil {
		t.Fatal("empty dylib ID metadata was accepted")
	}
	if _, err := validateDylib(dylib, "@rpath/bad\x00.dylib", RequiredExports); err == nil {
		t.Fatal("control character dylib ID was accepted")
	}
}

func TestDylibMetadataAndAllTenExportsValidation(t *testing.T) {
	if RequiredDylibID != "@rpath/libraspberry.dylib" {
		t.Fatalf("RequiredDylibID=%q, want @rpath/libraspberry.dylib", RequiredDylibID)
	}
	exports := allRequiredExports(0x200)
	data := syntheticGuestAuthDylib(RequiredDylibID, exports, 5)
	expected := hashHex(data)

	if err := validateRuntimeDylib(data, RequiredDylibID, RequiredExports); err != nil {
		t.Fatalf("valid synthetic dylib rejected: %v", err)
	}
	if got, err := validateDylib(data, RequiredDylibID, RequiredExports); err != nil || got != expected {
		t.Fatalf("valid dylib hash=%q err=%v", got, err)
	}
	if err := validateRuntimeDylib(data, "@rpath/wrong.dylib", RequiredExports); err == nil {
		t.Fatal("mismatched LC_ID_DYLIB accepted")
	}
	wrongIDDylib := syntheticGuestAuthDylib("@rpath/other.dylib", exports, 5)
	if _, err := validateDylib(wrongIDDylib, RequiredDylibID, RequiredExports); err == nil {
		t.Fatal("dylib with wrong LC_ID_DYLIB accepted")
	}

	writableExecutable := syntheticGuestAuthDylib(RequiredDylibID, exports, 7)
	if err := validateRuntimeDylib(writableExecutable, RequiredDylibID, RequiredExports); err == nil {
		t.Fatal("writable-executable text segment accepted")
	}

	// Verify removing ANY ONE of the 10 required exports causes refusal.
	for omitIdx, omitted := range RequiredExports {
		t.Run("missing_"+omitted, func(t *testing.T) {
			var subset []syntheticExport
			for i, ex := range exports {
				if i == omitIdx {
					continue
				}
				subset = append(subset, ex)
			}
			partial := syntheticGuestAuthDylib(RequiredDylibID, subset, 5)
			if err := validateRuntimeDylib(partial, RequiredDylibID, RequiredExports); err == nil {
				t.Fatalf("dylib missing %q was accepted by validateRuntimeDylib", omitted)
			} else if !strings.Contains(err.Error(), omitted) {
				t.Fatalf("error %q did not identify missing export %q", err.Error(), omitted)
			}
			if _, err := validateDylib(partial, RequiredDylibID, RequiredExports); err == nil {
				t.Fatalf("dylib missing %q was accepted by validateDylib", omitted)
			}
		})
	}

	// Verify making ANY ONE of the 10 required exports a re-export (flags != 0) causes refusal.
	for reexpIdx, name := range RequiredExports {
		t.Run("reexport_"+name, func(t *testing.T) {
			modified := append([]syntheticExport(nil), exports...)
			modified[reexpIdx].flags = 8
			reexpDylib := syntheticGuestAuthDylib(RequiredDylibID, modified, 5)
			if err := validateRuntimeDylib(reexpDylib, RequiredDylibID, RequiredExports); err == nil {
				t.Fatalf("dylib with re-exported %q was accepted", name)
			}
		})
	}

	// Verify export resolving outside RX __TEXT segment is rejected.
	outsideRX := append([]syntheticExport(nil), exports...)
	outsideRX[5].address = 0x2000 // __TEXT memsz in syntheticGuestAuthDylib is 0x1000
	badAddrDylib := syntheticGuestAuthDylib(RequiredDylibID, outsideRX, 5)
	if err := validateRuntimeDylib(badAddrDylib, RequiredDylibID, RequiredExports); err == nil {
		t.Fatal("dylib with export outside RX __TEXT was accepted")
	}
}

func TestDylibSymtabValidationChecksAllTenExports(t *testing.T) {
	exports := allRequiredExports(0x200)

	validWithSymtab := syntheticGuestAuthDylibWithSymtab(RequiredDylibID, exports, exports, 0x0f)
	if err := validateRuntimeDylib(validWithSymtab, RequiredDylibID, RequiredExports); err != nil {
		t.Fatalf("valid dylib with symtab rejected: %v", err)
	}

	// Missing one symbol in LC_SYMTAB must fail even if present in export trie.
	for omitIdx, omitted := range RequiredExports {
		t.Run("symtab_missing_"+omitted, func(t *testing.T) {
			var subset []syntheticExport
			for i, ex := range exports {
				if i == omitIdx {
					continue
				}
				subset = append(subset, ex)
			}
			bad := syntheticGuestAuthDylibWithSymtab(RequiredDylibID, exports, subset, 0x0f)
			if err := validateRuntimeDylib(bad, RequiredDylibID, RequiredExports); err == nil {
				t.Fatalf("dylib missing symtab definition for %q was accepted", omitted)
			}
		})
	}

	// Non-public symbol type (missing N_EXT) must fail.
	nonPublic := syntheticGuestAuthDylibWithSymtab(RequiredDylibID, exports, exports, 0x0e)
	if err := validateRuntimeDylib(nonPublic, RequiredDylibID, RequiredExports); err == nil {
		t.Fatal("non-public symtab symbol definition was accepted")
	}

	// Mismatched symtab address vs export trie address must fail.
	wrongAddrSyms := append([]syntheticExport(nil), exports...)
	wrongAddrSyms[5].address += 4
	mismatchedAddr := syntheticGuestAuthDylibWithSymtab(RequiredDylibID, exports, wrongAddrSyms, 0x0f)
	if err := validateRuntimeDylib(mismatchedAddr, RequiredDylibID, RequiredExports); err == nil {
		t.Fatal("mismatched symtab/export-trie address was accepted")
	}
}

func TestFindDirectExportRejectsReexportsAndMalformedTrie(t *testing.T) {
	trie := buildExportTrie(allRequiredExports(0x200))
	for i, name := range RequiredExports {
		want := uint64(0x200 + i*0x20)
		addr, err := findDirectExport(trie, "_"+name)
		if err != nil || addr != want {
			t.Fatalf("findDirectExport(%q)=(%#x, %v), want (%#x, nil)", name, addr, err, want)
		}
	}
	reexport := buildExportTrie([]syntheticExport{
		{name: "_" + ExportGuestUniqueCode, address: 0, flags: 8},
	})
	if _, err := findDirectExport(reexport, "_"+ExportGuestUniqueCode); err == nil {
		t.Fatal("re-exported symbol accepted")
	}
	if _, err := findDirectExport([]byte{0x80}, "_"+ExportGuestUniqueCode); err == nil {
		t.Fatal("malformed trie accepted")
	}
}

func TestLoaderDependencyInventoryAndExactDelta(t *testing.T) {
	original := syntheticMachOWithoutLoads()
	patched := syntheticMachOWithDylibLoad(LoaderPath, lcLoadDylib)
	if err := validateLoaderDependencyDelta(original, patched); err != nil {
		t.Fatalf("exact loader insertion rejected: %v", err)
	}
	refs, err := dylibReferences(patched)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0] != (dylibReference{command: lcLoadDylib, name: LoaderPath}) {
		t.Fatalf("dependency inventory=%+v", refs)
	}

	for _, tt := range []struct {
		name   string
		before []dylibReference
		after  []dylibReference
	}{
		{
			name:   "existing conflicting basename",
			before: []dylibReference{{command: lcLoadDylib, name: "@rpath/LIBRASPBERRY.DYLIB"}},
			after: append(
				[]dylibReference{{command: lcLoadDylib, name: "@rpath/LIBRASPBERRY.DYLIB"}},
				dylibReference{command: lcLoadDylib, name: LoaderPath},
			),
		},
		{
			name:   "wrong new path",
			before: nil,
			after:  []dylibReference{{command: lcLoadDylib, name: "@rpath/other.dylib"}},
		},
		{
			name:   "wrong command kind",
			before: nil,
			after:  []dylibReference{{command: lcLoadWeakDylib, name: LoaderPath}},
		},
		{
			name:   "existing dependency modified",
			before: []dylibReference{{command: lcLoadDylib, name: "@rpath/existing.dylib"}},
			after: []dylibReference{
				{command: lcLoadDylib, name: "@rpath/changed.dylib"},
				{command: lcLoadDylib, name: LoaderPath},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateAddedLoaderReference(tt.before, tt.after); err == nil {
				t.Fatal("unexpected dependency delta was accepted")
			}
		})
	}
}

func TestValidateMainWriteWindowsForFullPatch(t *testing.T) {
	const size = 0x1ac2000
	orig := make([]byte, size)
	patched := make([]byte, size)
	copy(patched, orig)

	approvedOffsets := []int{
		16,
		0x2058,
		0x3000,
		0x3080,
		0x3100,
		0x3180,
		0x3200,
		0x3280,
		0x3300,
		0x3380,
		0x3400,
		0x3480,
		0x3500,
		0x3580,
		0x3600,
		0x3640,
		0x3680,
		0x3700,
		0x3780,
		0x3800,
		0x38c0,
		0x3980,
		0x3a00,
		0x3a40,
		0x3b00,
		int(gdprLoginReadyResolverRVA),
		0x12d8be4,
		0x53af68,
		0x538de4,
		0x53bc98,
		0xbfe3b8,
		0xd1ba00,
		0x6af020,
		0x6b39bc,
		0xbdf494,
		0x6ae0c8,
		0x6b2a54,
		int(gdprLoginReadyCallsiteRVA),
		0x1ac149c,
		0x1ac1874,
		0x1ac1904,
		0x1ac1928,
		0x1438000,
	}
	for _, off := range approvedOffsets {
		if off == 0x1438000 {
			binary.LittleEndian.PutUint32(patched[off:], curlSNIGatePatchedWord)
			continue
		}
		if off == 0x53af68 {
			binary.LittleEndian.PutUint32(patched[off:], autoGuestEntryPatchedWord)
			continue
		}
		if off == int(gdprLoginReadyCallsiteRVA) {
			word, err := encodeArm64Branch(gdprLoginReadyCallsiteRVA, gdprLoginReadyResolverRVA, true)
			if err != nil {
				t.Fatal(err)
			}
			binary.LittleEndian.PutUint32(patched[off:], word)
			continue
		}
		patched[off] = 0x42
	}
	if err := validateMainWriteWindows(orig, patched); err != nil {
		t.Fatalf("approved write windows rejected: %v", err)
	}

	// Leaving any one approved window unmodified must fail.
	for _, omitOff := range approvedOffsets {
		missingOne := append([]byte(nil), patched...)
		if omitOff == 0x1438000 {
			copy(missingOne[0x1438000:0x1438004], orig[0x1438000:0x1438004])
		} else if omitOff == 0x53af68 {
			copy(missingOne[0x53af68:0x53af6c], orig[0x53af68:0x53af6c])
		} else if omitOff == int(gdprLoginReadyCallsiteRVA) {
			copy(missingOne[gdprLoginReadyCallsiteRVA:gdprLoginReadyCallsiteRVA+4], orig[gdprLoginReadyCallsiteRVA:gdprLoginReadyCallsiteRVA+4])
		} else {
			missingOne[omitOff] = orig[omitOff]
		}
		if err := validateMainWriteWindows(orig, missingOne); err == nil {
			t.Fatalf("missing modification in window at %#x was accepted", omitOff)
		}
	}

	// Wrong patched word at 0x53af68 must fail.
	badAutoWord := append([]byte(nil), patched...)
	binary.LittleEndian.PutUint32(badAutoWord[0x53af68:], autoGuestEntryPatchedWord+1)
	if err := validateMainWriteWindows(orig, badAutoWord); err == nil {
		t.Fatal("wrong auto-guest-entry word at 0x53af68 was accepted")
	}

	// A non-NOP SNI gate word must fail.
	badSNIWord := append([]byte(nil), patched...)
	binary.LittleEndian.PutUint32(badSNIWord[0x1438000:], curlSNIGatePatchedWord+1)
	if err := validateMainWriteWindows(orig, badSNIWord); err == nil {
		t.Fatal("wrong curl SNI gate word was accepted")
	}

	// Mutating outside approved windows must fail.
	badOutside := append([]byte(nil), patched...)
	badOutside[0x3c00] = 0x11
	if err := validateMainWriteWindows(orig, badOutside); err == nil {
		t.Fatal("write outside approved windows was accepted")
	}

	// Mutating the ARC continuation, SetEndLoading guards, createGuestAccount body, guest prologue, guest callsite guards, or any stub tail must fail.
	for _, guardOff := range []int{
		0x12d8be8,
		0x53ad08,
		0x53ade0,
		0x53ae3c,
		0x53aee0,
		0x53af48,
		0x53af67,
		0x53af6c,
		0x53c430,
		0x53c438,
		0x6bdd4c,
		0x53bc8c,
		0x53bc9c,
		0xbfe388,
		0xbfe3a4,
		0xd1b9ec,
		0x1ac14a0,
		0x1ac1878,
		0x1ac1908,
		0x1ac192c,
		0x1437ffc,
		0x1438028,
	} {
		badGuard := append([]byte(nil), patched...)
		badGuard[guardOff] = 0xff
		if err := validateMainWriteWindows(orig, badGuard); err == nil {
			t.Fatalf("guard mutation at %#x was accepted", guardOff)
		}
	}
}

func TestBuildPackageRealBaselineIPA(t *testing.T) {
	baselinePath := findBaselineIPAPath()
	if baselinePath == "" {
		t.Skip("locked baseline IPA not present")
	}
	sourceIPA, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	exports := allRequiredExports(0x200)
	dylib := syntheticGuestAuthDylib(RequiredDylibID, exports, 5)
	endpointRaw := []byte(`{"v":1,"host":"Cherry.Example.ORG","ports":{"443":8443}}`)

	res, err := BuildPackage(sourceIPA, dylib, endpointRaw)
	if err != nil {
		t.Fatalf("BuildPackage failed: %v", err)
	}
	r := res.Report
	if r.SourceSHA != BaselineSHA256 || int64(r.SourceSize) != BaselineSize {
		t.Fatalf("unexpected source report: sha=%s size=%d", r.SourceSHA, r.SourceSize)
	}
	if r.SourceEntries != 3150 || r.RetainedRaw != 3148 {
		t.Fatalf("unexpected entry counts: source=%d retained=%d", r.SourceEntries, r.RetainedRaw)
	}
	if r.DylibID != RequiredDylibID || r.DylibZipPath != ownDylibZipPath || r.EndpointZipPath != ownEndpointZipPath {
		t.Fatalf("unexpected dylib/endpoint paths: %+v", r)
	}
	if r.PackageSHA != r.RepeatSHA || r.PackageSize != r.RepeatSize || r.PackageSize != len(res.Package) {
		t.Fatalf("non-deterministic build report: %+v", r)
	}
	foundAutoGuestWindow := false
	for _, rng := range r.MainChanged {
		if rng.Start == 0x53af68 && rng.End <= 0x53af6c && rng.End > rng.Start {
			foundAutoGuestWindow = true
			break
		}
	}
	if !foundAutoGuestWindow {
		t.Fatalf("MainChanged missing [0x53af68,0x53af6c): %+v", r.MainChanged)
	}
	foundGDPRReadyWindow := false
	for _, rng := range r.MainChanged {
		if rng.Start == int(gdprLoginReadyCallsiteRVA) &&
			rng.End <= int(gdprLoginReadyCallsiteRVA+4) && rng.End > rng.Start {
			foundGDPRReadyWindow = true
			break
		}
	}
	if !foundGDPRReadyWindow {
		t.Fatalf("MainChanged missing [%#x,%#x): %+v", gdprLoginReadyCallsiteRVA, gdprLoginReadyCallsiteRVA+4, r.MainChanged)
	}
	const wantCanonical = `{"v":1,"host":"cherry.example.org","ports":{"10000":10000,"10123":10123,"443":8443,"80":80}}`
	wantSum := sha256.Sum256([]byte(wantCanonical))
	if r.EndpointSHA != hex.EncodeToString(wantSum[:]) || r.EndpointSize != len(wantCanonical) {
		t.Fatalf("unexpected endpoint digest/size: %+v", r)
	}

	outPath := filepath.Join(t.TempDir(), "out.ipa")
	if err := WritePackageAtomic(outPath, res.Package); err != nil {
		t.Fatal(err)
	}
	diskBytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(diskBytes, res.Package) {
		t.Fatal("written package bytes differ from in-memory package")
	}

	// Verify a dylib missing ANY ONE of the 10 required exports fails BuildPackage against the real IPA.
	for omitIdx, omitted := range RequiredExports {
		t.Run("missing_export_"+omitted, func(t *testing.T) {
			var subset []syntheticExport
			for i, ex := range exports {
				if i == omitIdx {
					continue
				}
				subset = append(subset, ex)
			}
			incomplete := syntheticGuestAuthDylib(RequiredDylibID, subset, 5)
			if _, err := BuildPackage(sourceIPA, incomplete, endpointRaw); err == nil {
				t.Fatalf("BuildPackage accepted dylib missing %s", omitted)
			}
		})
	}
}

type syntheticMember struct {
	name   string
	body   []byte
	method uint16
	mode   os.FileMode
}

type syntheticExport struct {
	name    string
	address uint64
	flags   uint64
}

func syntheticArchive(t *testing.T, members []syntheticMember) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for _, member := range members {
		h := &zip.FileHeader{Name: member.name, Method: member.method}
		h.SetModTime(time.Date(2024, 3, 4, 5, 6, 8, 0, time.UTC))
		h.Extra = append(
			[]byte{0xfe, 0xca, 0x03, 0x00, 0xaa, 0xbb, 0xcc},
			[]byte{0x55, 0x54, 0x05, 0x00, 0x01, 1, 2, 3, 4}...,
		)
		if member.mode != 0 {
			h.SetMode(member.mode)
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(member.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), out.Bytes()...)
}

func syntheticGuestAuthDylib(installName string, exports []syntheticExport, prot uint32) []byte {
	trie := buildExportTrie(exports)
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
	binary.LittleEndian.PutUint32(data[off:], lcSegment64)
	binary.LittleEndian.PutUint32(data[off+4:], 72)
	copy(data[off+8:off+24], "__TEXT")
	binary.LittleEndian.PutUint64(data[off+24:], 0x100000000)
	binary.LittleEndian.PutUint64(data[off+32:], 0x1000)
	binary.LittleEndian.PutUint64(data[off+40:], 0)
	binary.LittleEndian.PutUint64(data[off+48:], uint64(len(data)))
	binary.LittleEndian.PutUint32(data[off+56:], prot)
	binary.LittleEndian.PutUint32(data[off+60:], prot)

	off += 72
	binary.LittleEndian.PutUint32(data[off:], lcIdDylib)
	binary.LittleEndian.PutUint32(data[off+4:], uint32(idSize))
	binary.LittleEndian.PutUint32(data[off+8:], 24)
	copy(data[off+24:], name)

	off += idSize
	binary.LittleEndian.PutUint32(data[off:], lcDyldExportsTrie)
	binary.LittleEndian.PutUint32(data[off+4:], 16)
	binary.LittleEndian.PutUint32(data[off+8:], uint32(trieOffset))
	binary.LittleEndian.PutUint32(data[off+12:], uint32(len(trie)))
	copy(data[trieOffset:], trie)
	return data
}

func syntheticGuestAuthDylibWithSymtab(installName string, trieExports, symtabExports []syntheticExport, symType uint8) []byte {
	trie := buildExportTrie(trieExports)
	name := append([]byte(installName), 0)
	idSize := (24 + len(name) + 7) &^ 7
	// LC_SEGMENT_64 (72 + 80 = 152 with 1 section), LC_ID_DYLIB, LC_DYLD_EXPORTS_TRIE (16), LC_SYMTAB (24).
	segCmdSize := 72 + 80
	symtabCmdSize := 24
	commandsSize := segCmdSize + idSize + 16 + symtabCmdSize

	var strtab bytes.Buffer
	strtab.WriteByte(0)
	nlistBytes := make([]byte, len(symtabExports)*16)
	for i, ex := range symtabExports {
		strOff := uint32(strtab.Len())
		strtab.WriteString(ex.name)
		strtab.WriteByte(0)
		entry := nlistBytes[i*16 : (i+1)*16]
		binary.LittleEndian.PutUint32(entry[0:], strOff)
		entry[4] = symType
		entry[5] = 1 // sect 1 (__text)
		binary.LittleEndian.PutUint16(entry[6:], 0)
		binary.LittleEndian.PutUint64(entry[8:], 0x100000000+ex.address)
	}

	trieOffset := 32 + commandsSize
	symOffset := (trieOffset + len(trie) + 7) &^ 7
	strOffset := symOffset + len(nlistBytes)
	totalLen := strOffset + strtab.Len()
	data := make([]byte, totalLen)

	binary.LittleEndian.PutUint32(data[0:], 0xfeedfacf)
	binary.LittleEndian.PutUint32(data[4:], 0x0100000c)
	binary.LittleEndian.PutUint32(data[12:], 6) // MH_DYLIB
	binary.LittleEndian.PutUint32(data[16:], 4)
	binary.LittleEndian.PutUint32(data[20:], uint32(commandsSize))

	off := 32
	binary.LittleEndian.PutUint32(data[off:], lcSegment64)
	binary.LittleEndian.PutUint32(data[off+4:], uint32(segCmdSize))
	copy(data[off+8:off+24], "__TEXT")
	binary.LittleEndian.PutUint64(data[off+24:], 0x100000000)
	binary.LittleEndian.PutUint64(data[off+32:], 0x1000)
	binary.LittleEndian.PutUint64(data[off+40:], 0)
	binary.LittleEndian.PutUint64(data[off+48:], uint64(totalLen))
	binary.LittleEndian.PutUint32(data[off+56:], 5)
	binary.LittleEndian.PutUint32(data[off+60:], 5)
	binary.LittleEndian.PutUint32(data[off+64:], 1)
	secOff := off + 72
	copy(data[secOff:secOff+16], "__text")
	copy(data[secOff+16:secOff+32], "__TEXT")
	binary.LittleEndian.PutUint64(data[secOff+32:], 0x100000200)
	binary.LittleEndian.PutUint64(data[secOff+40:], 0x200)

	off += segCmdSize
	binary.LittleEndian.PutUint32(data[off:], lcIdDylib)
	binary.LittleEndian.PutUint32(data[off+4:], uint32(idSize))
	binary.LittleEndian.PutUint32(data[off+8:], 24)
	copy(data[off+24:], name)

	off += idSize
	binary.LittleEndian.PutUint32(data[off:], lcDyldExportsTrie)
	binary.LittleEndian.PutUint32(data[off+4:], 16)
	binary.LittleEndian.PutUint32(data[off+8:], uint32(trieOffset))
	binary.LittleEndian.PutUint32(data[off+12:], uint32(len(trie)))

	off += 16
	binary.LittleEndian.PutUint32(data[off:], 0x02) // LC_SYMTAB
	binary.LittleEndian.PutUint32(data[off+4:], uint32(symtabCmdSize))
	binary.LittleEndian.PutUint32(data[off+8:], uint32(symOffset))
	binary.LittleEndian.PutUint32(data[off+12:], uint32(len(symtabExports)))
	binary.LittleEndian.PutUint32(data[off+16:], uint32(strOffset))
	binary.LittleEndian.PutUint32(data[off+20:], uint32(strtab.Len()))

	copy(data[trieOffset:], trie)
	copy(data[symOffset:], nlistBytes)
	copy(data[strOffset:], strtab.Bytes())
	return data
}

func syntheticMachOWithoutLoads() []byte {
	data := make([]byte, 32)
	binary.LittleEndian.PutUint32(data[0:], 0xfeedfacf)
	binary.LittleEndian.PutUint32(data[4:], 0x0100000c)
	binary.LittleEndian.PutUint32(data[12:], 2) // MH_EXECUTE
	return data
}

func syntheticMachOWithDylibLoad(name string, command uint32) []byte {
	nameBytes := append([]byte(name), 0)
	commandSize := (24 + len(nameBytes) + 7) &^ 7
	data := make([]byte, 32+commandSize)
	binary.LittleEndian.PutUint32(data[0:], 0xfeedfacf)
	binary.LittleEndian.PutUint32(data[4:], 0x0100000c)
	binary.LittleEndian.PutUint32(data[12:], 2) // MH_EXECUTE
	binary.LittleEndian.PutUint32(data[16:], 1)
	binary.LittleEndian.PutUint32(data[20:], uint32(commandSize))
	binary.LittleEndian.PutUint32(data[32:], command)
	binary.LittleEndian.PutUint32(data[36:], uint32(commandSize))
	binary.LittleEndian.PutUint32(data[40:], 24)
	copy(data[56:], nameBytes)
	return data
}

type trieEdge struct {
	label string
	child *trieNode
}

type trieNode struct {
	hasTerminal bool
	flags       uint64
	address     uint64
	edges       []trieEdge
}

func buildExportTrie(exports []syntheticExport) []byte {
	root := &trieNode{}
	for _, ex := range exports {
		insertTrie(root, ex.name, ex.flags, ex.address)
	}
	var nodes []*trieNode
	var collect func(*trieNode)
	collect = func(n *trieNode) {
		sort.Slice(n.edges, func(i, j int) bool {
			return n.edges[i].label < n.edges[j].label
		})
		nodes = append(nodes, n)
		for _, e := range n.edges {
			collect(e.child)
		}
	}
	collect(root)

	offsets := make(map[*trieNode]uint64, len(nodes))
	for iter := 0; iter < 16; iter++ {
		changed := false
		var cursor uint64
		for _, n := range nodes {
			if offsets[n] != cursor {
				offsets[n] = cursor
				changed = true
			}
			cursor += uint64(len(encodeTrieNode(n, offsets)))
		}
		if !changed {
			break
		}
	}

	var out bytes.Buffer
	for _, n := range nodes {
		out.Write(encodeTrieNode(n, offsets))
	}
	return out.Bytes()
}

func insertTrie(node *trieNode, rem string, flags, address uint64) {
	if rem == "" {
		node.hasTerminal = true
		node.flags = flags
		node.address = address
		return
	}
	for i := range node.edges {
		edge := &node.edges[i]
		if edge.label[0] != rem[0] {
			continue
		}
		lcp := 0
		for lcp < len(edge.label) && lcp < len(rem) && edge.label[lcp] == rem[lcp] {
			lcp++
		}
		if lcp == len(edge.label) {
			insertTrie(edge.child, rem[lcp:], flags, address)
			return
		}
		mid := &trieNode{
			edges: []trieEdge{{label: edge.label[lcp:], child: edge.child}},
		}
		edge.label = edge.label[:lcp]
		edge.child = mid
		if lcp == len(rem) {
			mid.hasTerminal = true
			mid.flags = flags
			mid.address = address
		} else {
			mid.edges = append(mid.edges, trieEdge{
				label: rem[lcp:],
				child: &trieNode{hasTerminal: true, flags: flags, address: address},
			})
		}
		return
	}
	node.edges = append(node.edges, trieEdge{
		label: rem,
		child: &trieNode{hasTerminal: true, flags: flags, address: address},
	})
}

func encodeTrieNode(n *trieNode, offsets map[*trieNode]uint64) []byte {
	var terminal []byte
	if n.hasTerminal {
		terminal = appendULEB(terminal, n.flags)
		terminal = appendULEB(terminal, n.address)
	}
	var out []byte
	out = appendULEB(out, uint64(len(terminal)))
	out = append(out, terminal...)
	out = append(out, byte(len(n.edges)))
	for _, e := range n.edges {
		out = append(out, e.label...)
		out = append(out, 0)
		out = appendULEB(out, offsets[e.child])
	}
	return out
}

func appendULEB(dst []byte, value uint64) []byte {
	for value >= 0x80 {
		dst = append(dst, byte(value)|0x80)
		value >>= 7
	}
	return append(dst, byte(value))
}
