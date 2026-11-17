package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/festivities/raspberry/internal/ipa"
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

func usageIPA(w io.Writer) {
	fmt.Fprintln(w, "usage: raspberry ipa inspect --ipa <file>")
}
