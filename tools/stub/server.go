package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/festivities/raspberry/internal/descriptor"
)

const (
	contractVersion = 1
	stubVersion     = "0"
	maxNameLen      = 64
	maxLogToken     = 128
)

// Static-RSA suites are required by the stock client's old OpenSSL.
// Go leaves them off unless CipherSuites is set explicitly.
var staticRSASuites = []uint16{
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

type config struct {
	host        string
	name        string
	httpAddr    string
	httpsAddr   string
	sessionAddr string
	gatewayAddr string
	certFile    string
	keyFile     string

	httpPort    int
	httpsPort   int
	sessionPort int
	gatewayPort int
}

func (c *config) validate() error {
	host, err := canonicalEndpointHost(c.host)
	if err != nil {
		return err
	}
	c.host = host
	if err := validateDisplayName(c.name); err != nil {
		return err
	}
	if c.httpPort, err = validateListenAddr(c.httpAddr); err != nil {
		return fmt.Errorf("http: %w", err)
	}
	if c.httpsPort, err = validateListenAddr(c.httpsAddr); err != nil {
		return fmt.Errorf("https: %w", err)
	}
	if c.sessionPort, err = validateListenAddr(c.sessionAddr); err != nil {
		return fmt.Errorf("session: %w", err)
	}
	if c.gatewayPort, err = validateListenAddr(c.gatewayAddr); err != nil {
		return fmt.Errorf("gateway: %w", err)
	}
	if (c.certFile == "") != (c.keyFile == "") {
		return errors.New("cert and key must be set together")
	}
	return nil
}

// canonicalEndpointHost reuses the shared descriptor rules. Marshal then Parse
// so a host that only looks like an IPv4 literal cannot sneak through.
func canonicalEndpointHost(host string) (string, error) {
	raw, err := json.Marshal(descriptor.Descriptor{
		V:     1,
		Host:  host,
		Ports: map[int]int{80: 80, 443: 443, 10000: 10000, 10123: 10123},
	})
	if err != nil {
		return "", errors.New("host invalid")
	}
	d, err := descriptor.Parse(raw)
	if err != nil {
		return "", errors.New("host invalid")
	}
	return d.Host, nil
}

func validateDNS(host string) error {
	if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") || strings.Contains(host, "..") {
		return errors.New("invalid host")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return errors.New("invalid host")
		}
		for i, r := range label {
			ok := r == '-' || (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
			if !ok || ((i == 0 || i == len(label)-1) && r == '-') {
				return errors.New("invalid host")
			}
		}
	}
	return nil
}

func validateDisplayName(name string) error {
	if name == "" || len(name) > maxNameLen {
		return errors.New("name is required")
	}
	for _, r := range name {
		if unicode.IsControl(r) || r > unicode.MaxASCII {
			return errors.New("name has unsupported characters")
		}
	}
	return nil
}

// validateListenAddr refuses non-loopback binds. There is no public-bind flag.
// Port 0 is refused so a listener cannot silently take an ephemeral port.
func validateListenAddr(addr string) (int, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, errors.New("address must be <loopback-ip>:<port>")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() || ip.IsUnspecified() {
		return 0, errors.New("address must be a loopback IP")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return 0, errors.New("port must be 1-65535")
	}
	return n, nil
}

type stub struct {
	cfg    config
	log    *log.Logger
	auth   *authStore
	certs  *certCache
	pinned *tls.Certificate
}

func newStub(cfg config, lg *log.Logger) (*stub, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if lg == nil {
		lg = log.New(io.Discard, "", 0)
	}
	s := &stub{cfg: cfg, log: lg, auth: newAuthStore(), certs: newCertCache()}
	if cfg.certFile != "" {
		cert, err := loadPinnedRSA(cfg.certFile, cfg.keyFile, cfg.host, clock())
		if err != nil {
			return nil, err
		}
		s.pinned = cert
	}
	return s, nil
}

func (s *stub) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/cherry/v1/info", s.handleInfo)
	mux.HandleFunc("/auth/v1/discord/start", s.handleStart)
	mux.HandleFunc("/auth/v1/discord/callback", s.handleCallback)
	mux.HandleFunc("/auth/v1/exchange", s.handleExchange)
	mux.HandleFunc("/", s.handleOther)
	return s.logRequests(mux)
}

func (s *stub) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(sw, r)
		sni := "-"
		if r.TLS != nil {
			sni = r.TLS.ServerName
		}
		// Path only. Query, headers and bodies are never logged.
		s.log.Printf("sni=%s host=%s method=%s path=%s status=%d",
			logToken(sni), logToken(stripUserinfo(r.Host)), logToken(r.Method), logToken(r.URL.Path), sw.code)
	})
}

func (s *stub) handleInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errBody("invalid_request"))
		return
	}
	if !s.auth.allowInfo(clientIP(r), clock()) {
		writeJSON(w, http.StatusTooManyRequests, errBody("rate_limited"))
		return
	}
	writeJSON(w, http.StatusOK, infoBody{
		Contract: contractVersion,
		Name:     s.cfg.name,
		Server:   "raspberry-stub " + stubVersion,
		Auth:     []string{"dev-fake"},
		Ports: map[string]int{
			"80":    s.cfg.httpPort,
			"443":   s.cfg.httpsPort,
			"10000": s.cfg.gatewayPort,
			"10123": s.cfg.sessionPort,
		},
	})
}

func (s *stub) handleOther(w http.ResponseWriter, r *http.Request) {
	// Synthetic error only. This is not a game emulator.
	writeJSON(w, http.StatusNotImplemented, map[string]any{"error": "not_emulated", "ready": false})
}

type infoBody struct {
	Contract int            `json:"contract"`
	Name     string         `json:"name"`
	Server   string         `json:"server"`
	Auth     []string       `json:"auth"`
	Ports    map[string]int `json:"ports"`
}

func (s *stub) listenAndServe(ctx context.Context) error {
	if err := s.cfg.validate(); err != nil {
		return err
	}
	if s.pinned != nil {
		if err := validateLeaf(s.pinned, s.cfg.host, clock()); err != nil {
			return err
		}
	}
	httpLn, err := net.Listen("tcp", s.cfg.httpAddr)
	if err != nil {
		return err
	}
	httpsLn, err := net.Listen("tcp", s.cfg.httpsAddr)
	if err != nil {
		httpLn.Close()
		return err
	}
	sessionLn, err := net.Listen("tcp", s.cfg.sessionAddr)
	if err != nil {
		httpLn.Close()
		httpsLn.Close()
		return err
	}
	gatewayLn, err := net.Listen("tcp", s.cfg.gatewayAddr)
	if err != nil {
		httpLn.Close()
		httpsLn.Close()
		sessionLn.Close()
		return err
	}
	return s.serve(ctx, httpLn, httpsLn, sessionLn, gatewayLn)
}

func (s *stub) serve(ctx context.Context, httpLn, httpsLn, sessionLn, gatewayLn net.Listener) error {
	s.log.Printf("listen role=http addr=%s", httpLn.Addr())
	s.log.Printf("listen role=https addr=%s", httpsLn.Addr())
	s.log.Printf("listen role=session addr=%s", sessionLn.Addr())
	s.log.Printf("listen role=gateway addr=%s", gatewayLn.Addr())

	httpSrv := s.httpServer(false)
	httpsSrv := s.httpServer(true)
	errc := make(chan error, 4)
	go func() { errc <- ignoreClosed(httpSrv.Serve(httpLn)) }()
	go func() { errc <- ignoreClosed(httpsSrv.ServeTLS(httpsLn, "", "")) }()
	go func() { errc <- serveSink(ctx, sessionLn, "session", s.log) }()
	go func() { errc <- serveSink(ctx, gatewayLn, "gateway", s.log) }()

	select {
	case <-ctx.Done():
		shut, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = httpSrv.Shutdown(shut)
		_ = httpsSrv.Shutdown(shut)
		cancel()
		_ = sessionLn.Close()
		_ = gatewayLn.Close()
		for i := 0; i < 4; i++ {
			<-errc
		}
		return nil
	case err := <-errc:
		shut, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = httpSrv.Shutdown(shut)
		_ = httpsSrv.Shutdown(shut)
		cancel()
		_ = sessionLn.Close()
		_ = gatewayLn.Close()
		return err
	}
}

func (s *stub) httpServer(https bool) *http.Server {
	h := s.handler()
	if !https {
		h = refuseCleartextAuth(h)
	}
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
		// Server error lines can include the request URI. Discard them.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	if https {
		srv.TLSConfig = s.tlsConfig()
		srv.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	}
	return srv
}

func refuseCleartextAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth" || strings.HasPrefix(r.URL.Path, "/auth/") {
			writeHTML(w, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func ignoreClosed(err error) error {
	if err == nil || errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

type statusWriter struct {
	http.ResponseWriter
	code  int
	wrote bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.wrote {
		s.code = code
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if !s.wrote {
		s.code = http.StatusOK
		s.wrote = true
	}
	return s.ResponseWriter.Write(b)
}

func logToken(s string) string {
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= maxLogToken {
			break
		}
		if r <= ' ' || r == 0x7f || unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}

func stripUserinfo(host string) string {
	if i := strings.LastIndex(host, "@"); i >= 0 {
		return host[i+1:]
	}
	return host
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		return "unknown"
	}
	return host
}
