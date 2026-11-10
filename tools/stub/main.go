// Command stub is a loopback-only stand-in for a Cherry endpoint.
// It is not a public server and not a game emulator.
//
//	go run ./tools/stub -host <ENDPOINT_HOST> -name <DISPLAY_NAME> -http 127.0.0.1:<HTTP_PORT> -https 127.0.0.1:<HTTPS_PORT> -session 127.0.0.1:<SESSION_PORT> -gateway 127.0.0.1:<GATEWAY_PORT>
//
// Optional trusted RSA cert for the endpoint host (files stay outside the repo; keys are not written):
//
//	-cert <PEM_PATH> -key <PEM_PATH>
//
// Bind addresses must be loopback IPs. From an Android emulator, reach this process via 10.0.2.2.
// Redirect stdout yourself if you want a private log. This process does not open a log file.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
)

func main() {
	cfg, err := configFromFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(2)
	}
	lg := log.New(os.Stdout, "", log.LstdFlags)
	s, err := newStub(cfg, lg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := s.listenAndServe(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func configFromFlags(args []string) (config, error) {
	fs := flag.NewFlagSet("stub", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	host := fs.String("host", "", "endpoint host, DNS or IPv4 (required)")
	name := fs.String("name", "", "display name for /cherry/v1/info (required)")
	httpAddr := fs.String("http", "", "loopback HTTP listen address (required)")
	httpsAddr := fs.String("https", "", "loopback HTTPS listen address (required)")
	sessionAddr := fs.String("session", "", "loopback session listen address (required)")
	gatewayAddr := fs.String("gateway", "", "loopback gateway listen address (required)")
	certFile := fs.String("cert", "", "optional PEM certificate for the endpoint host")
	keyFile := fs.String("key", "", "optional PEM private key for the endpoint host")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	if fs.NArg() != 0 {
		return config{}, errors.New("unexpected arguments")
	}
	cfg := config{
		host:        *host,
		name:        *name,
		httpAddr:    *httpAddr,
		httpsAddr:   *httpsAddr,
		sessionAddr: *sessionAddr,
		gatewayAddr: *gatewayAddr,
		certFile:    *certFile,
		keyFile:     *keyFile,
	}
	if err := cfg.validate(); err != nil {
		return config{}, err
	}
	return cfg, nil
}
