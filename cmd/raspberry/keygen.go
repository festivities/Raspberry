package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/festivities/raspberry/internal/sign"
)

func cmdKeygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keystore := fs.String("keystore", "", "absolute new PKCS#12 keystore path outside every repository")
	alias := fs.String("alias", "raspberry", "keystore key alias")
	pwFile := fs.String("password-file", "", "owner-only file holding the password on one line")
	pwEnv := fs.String("password-env", "", "environment variable holding the password")
	keytool := fs.String("keytool", javaTool("keytool.exe"), "absolute keytool.exe")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "raspberry keygen: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if *keystore == "" {
		fmt.Fprintln(stderr, "raspberry keygen: --keystore is required")
		return 2
	}
	for _, p := range []struct{ flag, val string }{
		{"--keystore", *keystore}, {"--password-file", *pwFile},
	} {
		if p.val != "" && !filepath.IsAbs(p.val) {
			fmt.Fprintf(stderr, "raspberry keygen: %s must be an absolute path\n", p.flag)
			return 2
		}
	}
	if (*pwFile == "") == (*pwEnv == "") {
		fmt.Fprintln(stderr, "raspberry keygen: set exactly one of --password-file or --password-env")
		return 2
	}
	if err := refusePrivate(*keystore, *pwFile); err != nil {
		fmt.Fprintf(stderr, "raspberry keygen: %v\n", err)
		return 2
	}
	path, err := sign.Keygen(context.Background(), sign.KeygenRequest{
		Tools:    sign.Tools{Keytool: *keytool},
		Keystore: *keystore,
		Alias:    *alias,
		Password: sign.Secret{File: *pwFile, Env: *pwEnv},
		Timeout:  10 * time.Minute,
	})
	if err != nil {
		fmt.Fprintf(stderr, "raspberry keygen: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "keygen: wrote %s (alias %s)\n", path, *alias)
	fmt.Fprintln(stdout, "keygen: back it up; losing it means reinstalling every build made with it")
	return 0
}
