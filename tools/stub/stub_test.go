package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestStub(t *testing.T, lg *log.Logger) *stub {
	t.Helper()
	if lg == nil {
		lg = log.New(io.Discard, "", 0)
	}
	s, err := newStub(config{
		host:        "endpoint.example",
		name:        "synthetic",
		httpAddr:    "127.0.0.1:1",
		httpsAddr:   "127.0.0.1:2",
		sessionAddr: "127.0.0.1:3",
		gatewayAddr: "127.0.0.1:4",
	}, lg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func pkcePair(t *testing.T) (verifier, challenge, state string) {
	t.Helper()
	v := make([]byte, 32)
	s := make([]byte, 16)
	if _, err := rand.Read(v); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(s); err != nil {
		t.Fatal(err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(v)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	state = base64.RawURLEncoding.EncodeToString(s)
	return verifier, challenge, state
}

func do(h http.Handler, method, target, remote string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, body)
	req.Host = "endpoint.example"
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func startURL(challenge, ret, state, as string) string {
	q := url.Values{}
	q.Set("challenge", challenge)
	q.Set("return", ret)
	q.Set("state", state)
	if as != "" {
		q.Set("as", as)
	}
	return "/auth/v1/discord/start?" + q.Encode()
}

func TestInfoContract(t *testing.T) {
	s := newTestStub(t, nil)
	rec := do(s.handler(), http.MethodGet, "/cherry/v1/info", "127.0.0.1:9", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("headers %v", rec.Header())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 || got["contract"] != float64(1) || got["name"] != "synthetic" || got["server"] != "raspberry-stub 0" {
		t.Fatalf("info %s", rec.Body.String())
	}
	auth, _ := got["auth"].([]any)
	if len(auth) != 1 || auth[0] != "dev-fake" {
		t.Fatalf("auth %v", got["auth"])
	}
	ports, _ := got["ports"].(map[string]any)
	if ports["80"] != float64(1) || ports["443"] != float64(2) || ports["10000"] != float64(4) || ports["10123"] != float64(3) {
		t.Fatalf("ports %v", ports)
	}
}

func TestUnsafeReturnsAndState(t *testing.T) {
	s := newTestStub(t, nil)
	_, challenge, state := pkcePair(t)
	bad := []string{
		"https://127.0.0.1:1024/raspberry/cb",
		"http://localhost:1024/raspberry/cb",
		"http://127.0.0.1:1023/raspberry/cb",
		"http://127.0.0.1:65536/raspberry/cb",
		"http://127.0.0.1:1024/raspberry/cb/",
		"http://127.0.0.1:1024/raspberry/cb?x=1",
		"http://evil.example/phish",
		"http://127.0.0.1:1024/raspberry/cb#x",
		"raspberry://auth/",
		"raspberry://auth?x=1",
		"javascript://auth",
	}
	for _, ret := range bad {
		rec := do(s.handler(), http.MethodGet, startURL(challenge, ret, state, "alpha"), "127.0.0.1:9", nil)
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
			t.Fatalf("return %q status %d loc %q", ret, rec.Code, rec.Header().Get("Location"))
		}
		if strings.Contains(rec.Body.String(), "evil.example") || strings.Contains(rec.Body.String(), ret) {
			t.Fatalf("error page echoed return %q", ret)
		}
	}
	good := "http://127.0.0.1:1024/raspberry/cb"
	if rec := do(s.handler(), http.MethodGet, startURL(challenge, good, "short", "alpha"), "127.0.0.1:10", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("short state %d", rec.Code)
	}
	long := strings.Repeat("A", 65)
	if rec := do(s.handler(), http.MethodGet, startURL(challenge, good, long, "alpha"), "127.0.0.1:11", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("long state %d", rec.Code)
	}
	if rec := do(s.handler(), http.MethodGet, startURL(challenge, good, state+"=", "alpha"), "127.0.0.1:12", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("padded state %d", rec.Code)
	}
	if rec := do(s.handler(), http.MethodGet, startURL("not-a-challenge", good, state, "alpha"), "127.0.0.1:13", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad challenge %d", rec.Code)
	}
}

func TestAuthFlowReplayExpiryAndLogs(t *testing.T) {
	var buf bytes.Buffer
	s := newTestStub(t, log.New(&buf, "", 0))
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	restore := setClock(func() time.Time { return now })
	defer restore()

	verifier, challenge, state := pkcePair(t)
	ret := "raspberry://auth"
	rec := do(s.handler(), http.MethodGet, startURL(challenge, ret, state, "Alpha9"), "127.0.0.1:9", nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("start %d %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil || u.Host != "" || u.Path != "/auth/v1/discord/callback" {
		t.Fatalf("start location %q", loc)
	}
	if u.Query().Get("code") != "dev:Alpha9" {
		t.Fatalf("code %q", u.Query().Get("code"))
	}
	serverState := u.Query().Get("state")

	tampered := "/auth/v1/discord/callback?" + url.Values{"code": {"dev:Alpha9"}, "state": {serverState}, "return": {"http://evil.example/"}}.Encode()
	if rec := do(s.handler(), http.MethodGet, tampered, "127.0.0.1:9", nil); rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Fatalf("tampered callback %d %q", rec.Code, rec.Header().Get("Location"))
	}

	cb := "/auth/v1/discord/callback?" + url.Values{"code": {"dev:other"}, "state": {serverState}}.Encode()
	if rec := do(s.handler(), http.MethodGet, cb, "127.0.0.1:9", nil); rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Fatalf("wrong code consumed attempt? %d %q", rec.Code, rec.Header().Get("Location"))
	}

	cb = loc
	if !strings.HasPrefix(cb, "/") {
		t.Fatal(cb)
	}
	rec = do(s.handler(), http.MethodGet, cb, "127.0.0.1:9", nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback %d %s", rec.Code, rec.Body.String())
	}
	back, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || back.Scheme != "raspberry" || back.Host != "auth" {
		t.Fatalf("return %q", rec.Header().Get("Location"))
	}
	if back.Query().Get("state") != state || back.Query().Get("error") != "" {
		t.Fatalf("return query %v", back.Query())
	}
	ticket := back.Query().Get("ticket")
	if !validTicket(ticket) {
		t.Fatalf("ticket shape")
	}

	wrongBody := `{"ticket":"` + ticket + `","verifier":"` + strings.Repeat("A", 43) + `"}`
	rec = do(s.handler(), http.MethodPost, "/auth/v1/exchange", "127.0.0.1:9", strings.NewReader(wrongBody))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_request") {
		t.Fatalf("wrong verifier %d %s", rec.Code, rec.Body.String())
	}

	okBody := `{"ticket":"` + ticket + `","verifier":"` + verifier + `"}`
	rec = do(s.handler(), http.MethodPost, "/auth/v1/exchange", "127.0.0.1:9", strings.NewReader(okBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("exchange %d %s", rec.Code, rec.Body.String())
	}
	var minted struct {
		UniqueCode string `json:"uniqueCode"`
		Aid        string `json:"aid"`
		New        bool   `json:"new"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &minted); err != nil {
		t.Fatal(err)
	}
	if !minted.New || !uuidRe.MatchString(minted.UniqueCode) || minted.Aid == "" {
		t.Fatalf("minted %+v", minted)
	}
	rec = do(s.handler(), http.MethodPost, "/auth/v1/exchange", "127.0.0.1:9", strings.NewReader(okBody))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("replay %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(storeDump(s.auth), ticket) || strings.Contains(storeDump(s.auth), verifier) || strings.Contains(storeDump(s.auth), minted.UniqueCode) || strings.Contains(storeDump(s.auth), "Alpha9") {
		t.Fatal("store kept a credential in the clear")
	}
	sum := sha256.Sum256([]byte(minted.UniqueCode))
	if _, ok := s.auth.codes[hex.EncodeToString(sum[:])]; !ok {
		t.Fatal("uniqueCode hash was not stored")
	}

	logs := buf.String()
	for _, secret := range []string{ticket, verifier, minted.UniqueCode, challenge, serverState, "Alpha9", "?"} {
		if strings.Contains(logs, secret) {
			t.Fatalf("log contained %q\n%s", secret, logs)
		}
	}
	if !strings.Contains(logs, "path=/auth/v1/discord/start") || !strings.Contains(logs, "sni=-") {
		t.Fatalf("missing metadata log\n%s", logs)
	}

	verifier2, challenge2, state2 := pkcePair(t)
	rec = do(s.handler(), http.MethodGet, startURL(challenge2, "http://127.0.0.1:2048/raspberry/cb", state2, "Alpha9"), "127.0.0.1:9", nil)
	rec = do(s.handler(), http.MethodGet, rec.Header().Get("Location"), "127.0.0.1:9", nil)
	ticket2 := mustTicket(t, rec.Header().Get("Location"))
	now = now.Add(ticketTTL + time.Second)
	body2 := `{"ticket":"` + ticket2 + `","verifier":"` + verifier2 + `"}`
	rec = do(s.handler(), http.MethodPost, "/auth/v1/exchange", "127.0.0.1:9", strings.NewReader(body2))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired ticket %d %s", rec.Code, rec.Body.String())
	}

	_, challenge3, state3 := pkcePair(t)
	rec = do(s.handler(), http.MethodGet, startURL(challenge3, ret, state3, "Alpha9"), "127.0.0.1:9", nil)
	loc = rec.Header().Get("Location")
	now = now.Add(attemptTTL + time.Second)
	rec = do(s.handler(), http.MethodGet, loc, "127.0.0.1:9", nil)
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "error=expired") {
		t.Fatalf("expired attempt %d %q", rec.Code, rec.Header().Get("Location"))
	}

	verifier4, challenge4, state4 := pkcePair(t)
	rec = do(s.handler(), http.MethodGet, startURL(challenge4, ret, state4, "Alpha9"), "127.0.0.1:9", nil)
	rec = do(s.handler(), http.MethodGet, rec.Header().Get("Location"), "127.0.0.1:9", nil)
	ticket4 := mustTicket(t, rec.Header().Get("Location"))
	body4 := `{"ticket":"` + ticket4 + `","verifier":"` + verifier4 + `"}`
	rec = do(s.handler(), http.MethodPost, "/auth/v1/exchange", "127.0.0.1:9", strings.NewReader(body4))
	var again struct {
		Aid string `json:"aid"`
		New bool   `json:"new"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &again)
	if rec.Code != http.StatusOK || again.New || again.Aid != minted.Aid {
		t.Fatalf("stable aid %+v status %d", again, rec.Code)
	}
}

func TestExchangeIsSingleUse(t *testing.T) {
	s := newTestStub(t, nil)
	verifier, challenge, state := pkcePair(t)
	rec := do(s.handler(), http.MethodGet, startURL(challenge, "raspberry://auth", state, "alpha"), "127.0.0.1:9", nil)
	rec = do(s.handler(), http.MethodGet, rec.Header().Get("Location"), "127.0.0.1:9", nil)
	body := `{"ticket":"` + mustTicket(t, rec.Header().Get("Location")) + `","verifier":"` + verifier + `"}`
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := do(s.handler(), http.MethodPost, "/auth/v1/exchange", "127.0.0.1:9", strings.NewReader(body))
			codes <- rec.Code
		}()
	}
	wg.Wait()
	close(codes)
	ok, denied := 0, 0
	for code := range codes {
		switch code {
		case http.StatusOK:
			ok++
		case http.StatusUnauthorized:
			denied++
		default:
			t.Fatalf("status %d", code)
		}
	}
	if ok != 1 || denied != 1 {
		t.Fatalf("ok=%d denied=%d", ok, denied)
	}
}

func TestUnknownStateNoRedirect(t *testing.T) {
	s := newTestStub(t, nil)
	rec := do(s.handler(), http.MethodGet, "/auth/v1/discord/callback?code=dev:alpha&state=AAAAAAAAAAAAAAAAAAAAAA", "127.0.0.1:9", nil)
	if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Fatalf("unknown state %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestRateLimitDoesNotConsumeTicket(t *testing.T) {
	s := newTestStub(t, nil)
	now := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	restore := setClock(func() time.Time { return now })
	defer restore()
	verifier, challenge, state := pkcePair(t)
	rec := do(s.handler(), http.MethodGet, startURL(challenge, "raspberry://auth", state, "alpha"), "127.0.0.1:9", nil)
	rec = do(s.handler(), http.MethodGet, rec.Header().Get("Location"), "127.0.0.1:9", nil)
	ticket := mustTicket(t, rec.Header().Get("Location"))
	s.auth.mu.Lock()
	s.auth.exchHit["127.0.0.1"] = &window{at: make([]time.Time, maxExchPerMin)}
	for i := range s.auth.exchHit["127.0.0.1"].at {
		s.auth.exchHit["127.0.0.1"].at[i] = now
	}
	s.auth.mu.Unlock()
	body := `{"ticket":"` + ticket + `","verifier":"` + verifier + `"}`
	rec = do(s.handler(), http.MethodPost, "/auth/v1/exchange", "127.0.0.1:9", strings.NewReader(body))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("rate %d %s", rec.Code, rec.Body.String())
	}
	s.auth.mu.Lock()
	delete(s.auth.exchHit, "127.0.0.1")
	s.auth.mu.Unlock()
	rec = do(s.handler(), http.MethodPost, "/auth/v1/exchange", "127.0.0.1:9", strings.NewReader(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("ticket consumed by rate limit %d %s", rec.Code, rec.Body.String())
	}
}

func TestStartRateLimit(t *testing.T) {
	s := newTestStub(t, nil)
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	restore := setClock(func() time.Time { return now })
	defer restore()
	for i := 0; i < maxStartPerMin; i++ {
		_, challenge, state := pkcePair(t)
		rec := do(s.handler(), http.MethodGet, startURL(challenge, "raspberry://auth", state, "alpha"), "127.0.0.1:9", nil)
		if rec.Code != http.StatusFound {
			t.Fatalf("start %d status %d", i, rec.Code)
		}
		rec = do(s.handler(), http.MethodGet, rec.Header().Get("Location"), "127.0.0.1:9", nil)
		if rec.Code != http.StatusFound {
			t.Fatalf("callback %d", rec.Code)
		}
	}
	_, challenge, state := pkcePair(t)
	rec := do(s.handler(), http.MethodGet, startURL(challenge, "raspberry://auth", state, "alpha"), "127.0.0.1:9", nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected rate limit, got %d", rec.Code)
	}
}

func TestFlagsRefuseNonLoopbackAndDefaults(t *testing.T) {
	if _, err := configFromFlags(nil); err == nil {
		t.Fatal("missing flags were accepted")
	}
	_, err := configFromFlags([]string{
		"-host", "endpoint.example", "-name", "synthetic",
		"-http", "0.0.0.0:9", "-https", "127.0.0.1:9",
		"-session", "127.0.0.1:9", "-gateway", "127.0.0.1:9",
	})
	if err == nil {
		t.Fatal("non-loopback accepted")
	}
	_, err = configFromFlags([]string{
		"-host", "endpoint.example", "-name", "synthetic",
		"-http", "10.0.2.2:9", "-https", "127.0.0.1:9",
		"-session", "127.0.0.1:9", "-gateway", "127.0.0.1:9",
	})
	if err == nil {
		t.Fatal("emulator alias accepted as a bind address")
	}
	if _, err := validateListenAddr("127.0.0.1:0"); err == nil {
		t.Fatal("port 0 accepted")
	}
	for _, host := range []string{"127.1", "0x7f.0.0.1", "127.0.0.01"} {
		_, err := configFromFlags([]string{
			"-host", host, "-name", "synthetic",
			"-http", "127.0.0.1:9", "-https", "127.0.0.1:9",
			"-session", "127.0.0.1:9", "-gateway", "127.0.0.1:9",
		})
		if err == nil {
			t.Fatalf("host %s accepted", host)
		}
	}
	cfg, err := configFromFlags([]string{
		"-host", "endpoint.example", "-name", "synthetic",
		"-http", "127.0.0.1:9", "-https", "[::1]:9",
		"-session", "127.0.0.1:9", "-gateway", "127.0.0.1:9",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.httpPort != 9 || cfg.httpsPort != 9 {
		t.Fatalf("ports %+v", cfg)
	}
	cfg, err = configFromFlags([]string{
		"-host", "Endpoint.Example", "-name", "synthetic",
		"-http", "127.0.0.1:9", "-https", "127.0.0.1:9",
		"-session", "127.0.0.1:9", "-gateway", "127.0.0.1:9",
	})
	if err != nil || cfg.host != "endpoint.example" {
		t.Fatalf("canonical host %q err %v", cfg.host, err)
	}
}

func TestTrailingJSONDoesNotConsumeTicket(t *testing.T) {
	s := newTestStub(t, nil)
	verifier, ticket := mintFlow(t, s, "alpha")
	okBody := `{"ticket":"` + ticket + `","verifier":"` + verifier + `"}`
	bad := []string{
		okBody + "}",
		okBody + "]",
		`{"ticket":"` + ticket + `","ticket":"` + ticket + `","verifier":"` + verifier + `"}`,
	}
	for _, body := range bad {
		rec := do(s.handler(), http.MethodPost, "/auth/v1/exchange", "127.0.0.1:9", strings.NewReader(body))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %q status %d %s", body, rec.Code, rec.Body.String())
		}
	}
	rec := do(s.handler(), http.MethodPost, "/auth/v1/exchange", "127.0.0.1:9", strings.NewReader(okBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("legitimate ticket consumed %d %s", rec.Code, rec.Body.String())
	}
}

func TestExchangeRateResetsNextMinute(t *testing.T) {
	s := newTestStub(t, nil)
	now := time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC)
	restore := setClock(func() time.Time { return now })
	defer restore()
	verifier, ticket := mintFlow(t, s, "alpha")
	s.auth.mu.Lock()
	s.auth.exchHit["127.0.0.1"] = &window{at: make([]time.Time, maxExchPerMin)}
	for i := range s.auth.exchHit["127.0.0.1"].at {
		s.auth.exchHit["127.0.0.1"].at[i] = now
	}
	s.auth.mu.Unlock()
	body := `{"ticket":"` + ticket + `","verifier":"` + verifier + `"}`
	rec := do(s.handler(), http.MethodPost, "/auth/v1/exchange", "127.0.0.1:9", strings.NewReader(body))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("rate %d %s", rec.Code, rec.Body.String())
	}
	now = now.Add(time.Minute)
	rec = do(s.handler(), http.MethodPost, "/auth/v1/exchange", "127.0.0.1:9", strings.NewReader(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("next minute %d %s", rec.Code, rec.Body.String())
	}
}

func TestTTLExactBoundary(t *testing.T) {
	s := newTestStub(t, nil)
	now := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	restore := setClock(func() time.Time { return now })
	defer restore()
	verifier, ticket := mintFlow(t, s, "alpha")
	body := `{"ticket":"` + ticket + `","verifier":"` + verifier + `"}`
	now = now.Add(ticketTTL)
	rec := do(s.handler(), http.MethodPost, "/auth/v1/exchange", "127.0.0.1:9", strings.NewReader(body))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("ticket boundary %d %s", rec.Code, rec.Body.String())
	}
	_, challenge, state := pkcePair(t)
	rec = do(s.handler(), http.MethodGet, startURL(challenge, "raspberry://auth", state, "beta"), "127.0.0.1:9", nil)
	loc := rec.Header().Get("Location")
	now = now.Add(attemptTTL)
	rec = do(s.handler(), http.MethodGet, loc, "127.0.0.1:9", nil)
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "error=expired") {
		t.Fatalf("attempt boundary %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestCleartextAuthRefused(t *testing.T) {
	s := newTestStub(t, nil)
	plain := s.httpServer(false).Handler
	_, challenge, state := pkcePair(t)
	rec := do(plain, http.MethodGet, startURL(challenge, "raspberry://auth", state, "alpha"), "127.0.0.1:9", nil)
	if rec.Code < 400 || rec.Header().Get("Location") != "" {
		t.Fatalf("cleartext start %d %q", rec.Code, rec.Header().Get("Location"))
	}
	rec = do(plain, http.MethodPost, "/auth/v1/exchange", "127.0.0.1:9", strings.NewReader(`{"ticket":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","verifier":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`))
	if rec.Code < 400 || rec.Header().Get("Location") != "" {
		t.Fatalf("cleartext exchange %d", rec.Code)
	}
	if len(s.auth.attempts) != 0 || len(s.auth.tickets) != 0 {
		t.Fatal("cleartext auth minted state")
	}
	if rec := do(plain, http.MethodGet, "/cherry/v1/info", "127.0.0.1:9", nil); rec.Code != http.StatusOK {
		t.Fatalf("info on plain http %d", rec.Code)
	}
}

func TestSinkHardDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go serveSink(ctx, ln, "gateway", log.New(io.Discard, "", 0))
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 30; i++ {
			time.Sleep(400 * time.Millisecond)
			if _, err := c.Write([]byte{1}); err != nil {
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("trickle was not bounded")
	}
	if time.Since(start) > 4*time.Second {
		t.Fatalf("sink stayed open %s", time.Since(start))
	}
}

func TestPinnedCertNameAndExpiry(t *testing.T) {
	dir := t.TempDir()
	writePinned := func(t *testing.T, der []byte, key *rsa.PrivateKey) (string, string) {
		t.Helper()
		certPEM, keyPEM := pemPair(der, key)
		certPath := filepath.Join(dir, "c.pem")
		keyPath := filepath.Join(dir, "k.pem")
		if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		return certPath, keyPath
	}
	cfg := config{
		host: "endpoint.example", name: "synthetic",
		httpAddr: "127.0.0.1:1", httpsAddr: "127.0.0.1:2",
		sessionAddr: "127.0.0.1:3", gatewayAddr: "127.0.0.1:4",
	}
	der, key, err := mintTestCert("other.example")
	if err != nil {
		t.Fatal(err)
	}
	cfg.certFile, cfg.keyFile = writePinned(t, der, key)
	if _, err := newStub(cfg, nil); err == nil {
		t.Fatal("wrong SAN accepted")
	}
	der, key, err = mintTestCertWindow("endpoint.example", time.Now().Add(-2*time.Hour), time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	cfg.certFile, cfg.keyFile = writePinned(t, der, key)
	if _, err := newStub(cfg, nil); err == nil {
		t.Fatal("expired cert accepted")
	}
}

func TestOtherPathsAreNotEmulated(t *testing.T) {
	s := newTestStub(t, nil)
	rec := do(s.handler(), http.MethodGet, "/v4/account/guest/generate?uniqueCode=secret", "127.0.0.1:9", nil)
	if rec.Code != http.StatusNotImplemented || !strings.Contains(rec.Body.String(), "not_emulated") {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

func TestSinkLogsMetadataOnly(t *testing.T) {
	var buf safeBuf
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- serveSink(ctx, ln, "session", log.New(&buf, "", 0)) }()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	secret := "TOKEN-SECRET-DO-NOT-LOG"
	if _, err := c.Write([]byte(secret)); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(buf.String(), "event=close") {
		time.Sleep(20 * time.Millisecond)
	}
	logs := buf.String()
	if strings.Contains(logs, secret) || !strings.Contains(logs, "role=session") || !strings.Contains(logs, "proto=tcp") || !strings.Contains(logs, "event=accept") {
		t.Fatalf("sink log %q", logs)
	}
	cancel()
	select {
	case <-errc:
	case <-time.After(2 * time.Second):
		t.Fatal("sink did not stop")
	}
}

func TestStaticRSAHandshake(t *testing.T) {
	s := newTestStub(t, log.New(io.Discard, "", 0))
	cfg := s.tlsConfig()
	for _, id := range []uint16{
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	} {
		if !containsSuite(cfg.CipherSuites, id) {
			t.Fatalf("missing suite %x", id)
		}
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
			}(c)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := (&tls.Dialer{Config: &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "game.example",
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256},
	}}).DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	if state.CipherSuite != tls.TLS_RSA_WITH_AES_128_GCM_SHA256 {
		t.Fatalf("suite %x", state.CipherSuite)
	}
	if len(state.PeerCertificates) == 0 || !containsName(state.PeerCertificates[0].DNSNames, "game.example") {
		t.Fatal("per-sni cert missing")
	}
	if _, ok := state.PeerCertificates[0].PublicKey.(*rsa.PublicKey); !ok {
		t.Fatalf("public key %T", state.PeerCertificates[0].PublicKey)
	}

	badCtx, badCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer badCancel()
	_, err = (&tls.Dialer{Config: &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "lan3rd.line.me",
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256},
	}}).DialContext(badCtx, "tcp", ln.Addr().String())
	if err == nil {
		t.Fatal("blocked sni was accepted")
	}
}

func TestPinnedRSAOnly(t *testing.T) {
	dir := t.TempDir()
	certDER, key, err := mintTestCert("endpoint.example")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := pemPair(certDER, key)
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := newStub(config{
		host: "endpoint.example", name: "synthetic",
		httpAddr: "127.0.0.1:1", httpsAddr: "127.0.0.1:2",
		sessionAddr: "127.0.0.1:3", gatewayAddr: "127.0.0.1:4",
		certFile: certPath, keyFile: keyPath,
	}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	hello := &tls.ClientHelloInfo{ServerName: "endpoint.example"}
	got, err := s.certificate(hello)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Certificate[0], certDER) {
		t.Fatal("pinned cert was not used")
	}
	other, err := s.certificate(&tls.ClientHelloInfo{ServerName: "game.example"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(other.Certificate[0], certDER) {
		t.Fatal("pinned cert was reused for another sni")
	}

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "endpoint.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"endpoint.example"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ec.PublicKey, ec)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := x509.MarshalPKCS8PrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecKey}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newStub(config{
		host: "endpoint.example", name: "synthetic",
		httpAddr: "127.0.0.1:1", httpsAddr: "127.0.0.1:2",
		sessionAddr: "127.0.0.1:3", gatewayAddr: "127.0.0.1:4",
		certFile: certPath, keyFile: keyPath,
	}, nil); err == nil {
		t.Fatal("ecdsa cert accepted")
	}
}

func mintTestCert(name string) ([]byte, *rsa.PrivateKey, error) {
	return mintTestCertWindow(name, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
}

func mintTestCertWindow(name string, notBefore, notAfter time.Time) ([]byte, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{name},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	return der, key, nil
}

func mintFlow(t *testing.T, s *stub, as string) (verifier, ticket string) {
	t.Helper()
	verifier, challenge, state := pkcePair(t)
	rec := do(s.handler(), http.MethodGet, startURL(challenge, "raspberry://auth", state, as), "127.0.0.1:9", nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("start %d %s", rec.Code, rec.Body.String())
	}
	rec = do(s.handler(), http.MethodGet, rec.Header().Get("Location"), "127.0.0.1:9", nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback %d %s", rec.Code, rec.Body.String())
	}
	return verifier, mustTicket(t, rec.Header().Get("Location"))
}

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func mustTicket(t *testing.T, loc string) string {
	t.Helper()
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	ticket := u.Query().Get("ticket")
	if !validTicket(ticket) {
		t.Fatalf("ticket %q", ticket)
	}
	return ticket
}

func storeDump(a *authStore) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var b strings.Builder
	for k, at := range a.attempts {
		b.WriteString(k)
		b.WriteString(at.ret)
		b.WriteString(at.clientStat)
		b.WriteString(at.ident)
		b.WriteString(at.ip)
	}
	for k, tk := range a.tickets {
		b.WriteString(k)
		b.WriteString(tk.ident)
		b.Write(tk.challenge)
	}
	for k := range a.codes {
		b.WriteString(k)
	}
	for k := range a.seen {
		b.WriteString(k)
	}
	return b.String()
}

type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func containsSuite(list []uint16, id uint16) bool {
	for _, v := range list {
		if v == id {
			return true
		}
	}
	return false
}

func containsName(list []string, name string) bool {
	for _, v := range list {
		if v == name {
			return true
		}
	}
	return false
}
