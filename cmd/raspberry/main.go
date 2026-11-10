// Command raspberry is the patcher CLI. R0 verifies the locked baseline and
// prints the version. patch and keygen wait on the spike.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/festivities/raspberry/internal/baseline"
)

const version = "0.0.0-r0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "version", "-version", "--version":
		fmt.Fprintln(stdout, "raspberry", version)
		return 0
	case "help", "-h", "-help", "--help":
		usage(stdout)
		return 0
	case "verify":
		return cmdVerify(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "raspberry: unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
}

func cmdVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	apk := fs.String("apk", "", "path to the baseline APK")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *apk == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "raspberry verify: --apk is required")
		return 2
	}
	if err := baseline.Verify(*apk); err != nil {
		fmt.Fprintf(stderr, "raspberry verify: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "baseline ok")
	return 0
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: raspberry verify --apk <file>")
	fmt.Fprintln(w, "       raspberry version")
}
