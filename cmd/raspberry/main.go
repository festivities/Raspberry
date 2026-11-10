// Command raspberry is the patcher CLI: it verifies the locked baseline,
// patches it into a signed build, and creates the signing keystore.
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
	case "patch":
		return cmdPatch(args[1:], stdout, stderr)
	case "keygen":
		return cmdKeygen(args[1:], stdout, stderr)
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
	fmt.Fprintln(w, "       raspberry patch --apk <file> --endpoint <host> --out <dir> --keystore <file>")
	fmt.Fprintln(w, "                       (--password-file <file> | --password-env <name>) [--port 443=8443]...")
	fmt.Fprintln(w, "                       [--dev-pin-sha256 <64 hex>]")
	fmt.Fprintln(w, "       raspberry keygen --keystore <file> (--password-file <file> | --password-env <name>)")
	fmt.Fprintln(w, "       raspberry version")
	fmt.Fprintln(w, "patch is not a standalone builder: it needs scripts/build-native, build-dex, build-dexpatch, and the pinned JDK/SDK/smali tools. See docs/usage.md.")
	fmt.Fprintln(w, "--dev-pin-sha256 is an extra check after platform TLS. It does not trust a self-signed certificate and is omitted unless set.")
}
