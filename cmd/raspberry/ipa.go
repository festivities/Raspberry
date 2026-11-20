package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/festivities/raspberry/internal/ipa"
)

const (
	ipaOutputName    = "raspberry-lineplay-10.1.0-unsigned.ipa"
	maxIPADylibBytes = 32 << 20
)

func cmdIPA(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usageIPA(stderr)
		return 2
	}
	switch args[0] {
	case "help", "-h", "-help", "--help":
		usageIPA(stdout)
		return 0
	case "inspect":
		return cmdIPAInspect(args[1:], stdout, stderr)
	case "patch":
		return cmdIPAPatch(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "raspberry ipa: unknown command %q\n", args[0])
		usageIPA(stderr)
		return 2
	}
}

func cmdIPAInspect(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ipa inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("ipa", "", "path to the baseline IPA")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *path == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "raspberry ipa inspect: --ipa is required")
		return 2
	}
	rep, err := ipa.Inspect(*path)
	if err != nil {
		fmt.Fprintf(stderr, "raspberry ipa inspect: %v\n", err)
		return 1
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		fmt.Fprintf(stderr, "raspberry ipa inspect: %v\n", err)
		return 1
	}
	return 0
}

func cmdIPAPatch(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ipa patch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ipaPath := fs.String("ipa", "", "pristine baseline IPA")
	host := fs.String("endpoint", "", "endpoint host (DNS name or IPv4 literal)")
	ports := portMap{}
	fs.Var(ports, "port", "repeatable <client-port>=<endpoint-port>; client ports 80, 443, 10000, 10123")
	outDir := fs.String("out", "", "absolute output directory outside every repository")
	dylibPath := fs.String("dylib", filepath.Join("build", "ios", "libraspberry.dylib"), "path to libraspberry.dylib")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "raspberry ipa patch: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if *ipaPath == "" || *host == "" || *outDir == "" {
		fmt.Fprintln(stderr, "raspberry ipa patch: --ipa, --endpoint and --out are required")
		return 2
	}
	if *dylibPath == "" {
		fmt.Fprintln(stderr, "raspberry ipa patch: --dylib cannot be empty")
		return 2
	}
	if !filepath.IsAbs(*outDir) {
		fmt.Fprintln(stderr, "raspberry ipa patch: --out must be an absolute path")
		return 2
	}
	if err := refusePrivate(*outDir); err != nil {
		fmt.Fprintf(stderr, "raspberry ipa patch: %v\n", err)
		return 2
	}
	_, asset, err := descriptorAsset(*host, ports)
	if err != nil {
		fmt.Fprintf(stderr, "raspberry ipa patch: %v\n", err)
		return 2
	}

	if st, err := os.Stat(*outDir); err != nil {
		fmt.Fprintf(stderr, "raspberry ipa patch: %v\n", err)
		return 1
	} else if !st.IsDir() {
		fmt.Fprintf(stderr, "raspberry ipa patch: %s is not a directory\n", *outDir)
		return 1
	}
	final := filepath.Join(*outDir, ipaOutputName)
	if err := refusePrivate(final); err != nil {
		fmt.Fprintf(stderr, "raspberry ipa patch: %v\n", err)
		return 2
	}
	if err := checkIPADistinctDestination(final, *ipaPath, *dylibPath); err != nil {
		fmt.Fprintf(stderr, "raspberry ipa patch: %v\n", err)
		return 1
	}
	if _, err := os.Lstat(final); err == nil {
		fmt.Fprintf(stderr, "raspberry ipa patch: %s exists; refusing to overwrite\n", final)
		return 1
	} else if !os.IsNotExist(err) {
		fmt.Fprintf(stderr, "raspberry ipa patch: %v\n", err)
		return 1
	}

	sourceIPA, err := readIPABaselineFile(*ipaPath)
	if err != nil {
		fmt.Fprintf(stderr, "raspberry ipa patch: %v\n", err)
		return 1
	}
	dylib, err := readBoundedRegularFile(*dylibPath, maxIPADylibBytes, "--dylib")
	if err != nil {
		fmt.Fprintf(stderr, "raspberry ipa patch: %v\n", err)
		return 1
	}

	res, err := ipa.BuildPackage(sourceIPA, dylib, asset)
	if err != nil {
		fmt.Fprintf(stderr, "raspberry ipa patch: %v\n", err)
		return 1
	}
	if err := ipa.WritePackageAtomic(final, res.Package); err != nil {
		fmt.Fprintf(stderr, "raspberry ipa patch: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "ipa patch: wrote %s (%d bytes, sha256 %s)\n", final, res.Report.PackageSize, res.Report.PackageSHA)
	fmt.Fprintln(stdout, "ipa patch: output IPA is unsigned; sign and install with your signing tool or vphone")
	return 0
}

func checkIPADistinctDestination(final string, inputs ...string) error {
	absFinal, err := filepath.Abs(final)
	if err != nil {
		return err
	}
	cleanFinal := filepath.Clean(absFinal)
	for _, in := range inputs {
		absIn, err := filepath.Abs(in)
		if err != nil {
			return err
		}
		if strings.EqualFold(cleanFinal, filepath.Clean(absIn)) {
			return fmt.Errorf("output path %s aliases an input path", final)
		}
	}
	return nil
}

func readIPABaselineFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: not a regular file", ipa.ErrBaseline)
	}
	if st.Size() != ipa.BaselineSize {
		return nil, fmt.Errorf("%w: size %d", ipa.ErrBaseline, st.Size())
	}
	data, err := io.ReadAll(io.LimitReader(f, ipa.BaselineSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != ipa.BaselineSize {
		return nil, fmt.Errorf("%w: size %d", ipa.ErrBaseline, len(data))
	}
	return data, nil
}

func readBoundedRegularFile(path string, maxBytes int64, label string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	if !st.Mode().IsRegular() || st.Size() == 0 {
		return nil, fmt.Errorf("%s: %s is not a regular file", label, path)
	}
	if st.Size() > maxBytes {
		return nil, fmt.Errorf("%s: %s exceeds %d byte limit", label, path, maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%s: %s exceeds %d byte limit", label, path, maxBytes)
	}
	return data, nil
}

func usageIPA(w io.Writer) {
	fmt.Fprintln(w, "usage: raspberry ipa inspect --ipa <file>")
	fmt.Fprintln(w, "       raspberry ipa patch --ipa <file> --endpoint <host> --out <dir>")
	fmt.Fprintln(w, "                           [--port 443=8443]... [--dylib <file>]")
}
