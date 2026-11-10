package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	attemptTTL       = 10 * time.Minute
	ticketTTL        = 120 * time.Second
	maxStartPerMin   = 10
	maxStartPerHour  = 60
	maxExchPerMin    = 20
	maxInfoPerMin    = 60
	maxAttemptsPerIP = 8
	maxAttempts      = 128
	maxTickets       = 128
	maxSeen          = 128
	maxQueryLen      = 512
	maxBody          = 4096
	maxAsLen         = 32
)

// Exchange consumes a ticket only after the PKCE proof matches.
// A wrong verifier, a malformed body, an unexpected field, or a rate limit
// leaves the ticket unused. Expiry and replay are invalid_ticket and are not
// a successful use. Tickets and uniqueCodes are kept as SHA-256 keys only.

var (
	errInvalidRequest = errors.New("invalid_request")
	errInvalidTicket  = errors.New("invalid_ticket")
	errRateLimited    = errors.New("rate_limited")
)

var clock = time.Now

func setClock(now func() time.Time) func() {
	prev := clock
	if now == nil {
		now = time.Now
	}
	clock = now
	return func() { clock = prev }
}

type authStore struct {
	mu       sync.Mutex
	attempts map[string]*attempt
	tickets  map[string]*ticket
	seen     map[string]struct{}
	codes    map[string]struct{}
	startHit map[string]*window
	exchHit  map[string]*window
	infoHit  map[string]*window
}

type attempt struct {
	challenge  []byte
	ret        string
	clientStat string
	ident      string
	ip         string
	created    time.Time
	used       bool
}

type ticket struct {
	challenge []byte
	ident     string
	created   time.Time
	used      bool
}

type window struct {
	at []time.Time
}

func newAuthStore() *authStore {
	return &authStore{
		attempts: map[string]*attempt{},
		tickets:  map[string]*ticket{},
		seen:     map[string]struct{}{},
		codes:    map[string]struct{}{},
		startHit: map[string]*window{},
		exchHit:  map[string]*window{},
		infoHit:  map[string]*window{},
	}
}

func (a *authStore) allowInfo(ip string, now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.hit(a.infoHit, ip, now, maxInfoPerMin, 0)
}

func (s *stub) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || len(r.URL.RawQuery) > maxQueryLen {
		writeHTML(w, http.StatusBadRequest)
		return
	}
	q := r.URL.Query()
	if !oneEach(q, "challenge", "return", "state", "as") {
		writeHTML(w, http.StatusBadRequest)
		return
	}
	challenge := q.Get("challenge")
	ret := q.Get("return")
	state := q.Get("state")
	name, ok := fakeName(q)
	if !ok || !validChallenge(challenge) || !validReturn(ret) || !validState(state) {
		writeHTML(w, http.StatusBadRequest)
		return
	}
	ch, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil || len(ch) != 32 {
		writeHTML(w, http.StatusBadRequest)
		return
	}
	now := clock()
	serverState, err := s.auth.begin(clientIP(r), ch, ret, state, name, now)
	if errors.Is(err, errRateLimited) {
		writeJSON(w, http.StatusTooManyRequests, errBody("rate_limited"))
		return
	}
	if err != nil {
		writeHTML(w, http.StatusBadRequest)
		return
	}
	loc := "/auth/v1/discord/callback?" + url.Values{
		"code":  {"dev:" + name},
		"state": {serverState},
	}.Encode()
	redirectNoStore(w, r, loc)
}

func (s *stub) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || len(r.URL.RawQuery) > maxQueryLen {
		writeHTML(w, http.StatusBadRequest)
		return
	}
	q := r.URL.Query()
	if !oneEach(q, "code", "state") {
		writeHTML(w, http.StatusBadRequest)
		return
	}
	res, err := s.auth.callback(q.Get("code"), q.Get("state"), clock())
	if errors.Is(err, errRateLimited) {
		writeJSON(w, http.StatusTooManyRequests, errBody("rate_limited"))
		return
	}
	if err != nil {
		writeHTML(w, http.StatusBadRequest)
		return
	}
	if res.page != "" {
		loc, err := withQuery(res.ret, "error", res.page, "state", res.clientState)
		if err != nil {
			writeHTML(w, http.StatusBadRequest)
			return
		}
		redirectNoStore(w, r, loc)
		return
	}
	loc, err := withQuery(res.ret, "ticket", res.ticket, "state", res.clientState)
	if err != nil {
		writeHTML(w, http.StatusBadRequest)
		return
	}
	redirectNoStore(w, r, loc)
}

func (s *stub) handleExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.RawQuery != "" {
		writeJSON(w, http.StatusBadRequest, errBody("invalid_request"))
		return
	}
	if r.Body == nil {
		r.Body = http.NoBody
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	ticket, verifier, err := readExchange(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid_request"))
		return
	}
	code, aid, isNew, err := s.auth.exchange(clientIP(r), ticket, verifier, clock())
	if errors.Is(err, errRateLimited) {
		writeJSON(w, http.StatusTooManyRequests, errBody("rate_limited"))
		return
	}
	if errors.Is(err, errInvalidTicket) {
		writeJSON(w, http.StatusUnauthorized, errBody("invalid_ticket"))
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid_request"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"uniqueCode": code, "aid": aid, "new": isNew})
}

type callbackResult struct {
	ret         string
	clientState string
	ticket      string
	page        string
}

func (a *authStore) begin(ip string, challenge []byte, ret, state, name string, now time.Time) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.purge(now)
	if !a.hit(a.startHit, ip, now, maxStartPerMin, maxStartPerHour) {
		return "", errRateLimited
	}
	if a.countOpen(ip) >= maxAttemptsPerIP || len(a.attempts) >= maxAttempts {
		return "", errRateLimited
	}
	raw, err := randomToken(16)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(raw))
	key := hex.EncodeToString(sum[:])
	if _, exists := a.attempts[key]; exists {
		return "", errInvalidRequest
	}
	a.attempts[key] = &attempt{
		challenge:  append([]byte(nil), challenge...),
		ret:        ret,
		clientStat: state,
		ident:      identKey(identityName(name)),
		ip:         ip,
		created:    now,
	}
	return raw, nil
}

func (a *authStore) callback(code, state string, now time.Time) (callbackResult, error) {
	if !validState(state) || len(code) > maxAsLen+4 {
		return callbackResult{}, errInvalidRequest
	}
	sum := sha256.Sum256([]byte(state))
	key := hex.EncodeToString(sum[:])
	a.mu.Lock()
	defer a.mu.Unlock()
	a.purge(now)
	at, ok := a.attempts[key]
	if !ok {
		return callbackResult{}, errInvalidRequest
	}
	if at.used {
		return callbackResult{}, errInvalidRequest
	}
	if now.Sub(at.created) >= attemptTTL {
		res := callbackResult{ret: at.ret, clientState: at.clientStat, page: "expired"}
		at.used = true
		at.clientStat = ""
		at.challenge = nil
		return res, nil
	}
	name, ok := codeName(code)
	got := []byte(identKey(identityName(name)))
	if !ok || subtle.ConstantTimeCompare(got, []byte(at.ident)) != 1 {
		// Mismatch does not consume the attempt.
		return callbackResult{}, errInvalidRequest
	}
	if len(a.tickets) >= maxTickets {
		return callbackResult{}, errRateLimited
	}
	raw, err := randomToken(32)
	if err != nil {
		return callbackResult{}, err
	}
	tkSum := sha256.Sum256([]byte(raw))
	tkKey := hex.EncodeToString(tkSum[:])
	a.tickets[tkKey] = &ticket{
		challenge: append([]byte(nil), at.challenge...),
		ident:     at.ident,
		created:   now,
	}
	res := callbackResult{ret: at.ret, clientState: at.clientStat, ticket: raw}
	at.used = true
	at.clientStat = ""
	at.challenge = nil
	at.ret = ""
	return res, nil
}

func (a *authStore) exchange(ip, ticket, verifier string, now time.Time) (string, string, bool, error) {
	if !validTicket(ticket) || !validVerifier(verifier) {
		return "", "", false, errInvalidRequest
	}
	sum := sha256.Sum256([]byte(ticket))
	key := hex.EncodeToString(sum[:])
	proof := sha256.Sum256([]byte(verifier))
	a.mu.Lock()
	defer a.mu.Unlock()
	a.purge(now)
	if !a.hit(a.exchHit, ip, now, maxExchPerMin, 0) {
		return "", "", false, errRateLimited
	}
	tk, ok := a.tickets[key]
	if !ok || tk.used || now.Sub(tk.created) >= ticketTTL {
		return "", "", false, errInvalidTicket
	}
	if subtle.ConstantTimeCompare(proof[:], tk.challenge) != 1 {
		return "", "", false, errInvalidRequest
	}
	tk.used = true
	code, err := uniqueCode()
	if err != nil {
		tk.used = false
		return "", "", false, err
	}
	_, seen := a.seen[tk.ident]
	if !seen && len(a.seen) < maxSeen {
		a.seen[tk.ident] = struct{}{}
	}
	if len(a.codes) < 256 {
		sum := sha256.Sum256([]byte(code))
		a.codes[hex.EncodeToString(sum[:])] = struct{}{}
	}
	return code, stableAid(tk.ident), !seen, nil
}

func (a *authStore) purge(now time.Time) {
	for k, at := range a.attempts {
		age := now.Sub(at.created)
		// Keep an unused attempt past its TTL long enough for callback to
		// redirect error=expired. Abandoned rows drop at 2x TTL.
		if (at.used && age >= attemptTTL) || age >= 2*attemptTTL {
			delete(a.attempts, k)
		}
	}
	for k, tk := range a.tickets {
		if now.Sub(tk.created) >= ticketTTL {
			delete(a.tickets, k)
		}
	}
}

func (a *authStore) countOpen(ip string) int {
	n := 0
	for _, at := range a.attempts {
		if !at.used && at.ip == ip {
			n++
		}
	}
	return n
}

func (a *authStore) hit(m map[string]*window, ip string, now time.Time, perMin, perHour int) bool {
	if len(m) > 256 && m[ip] == nil {
		return false
	}
	w := m[ip]
	if w == nil {
		w = &window{}
		m[ip] = w
	}
	cutH := now.Add(-time.Hour)
	cutM := now.Add(-time.Minute)
	kept := w.at[:0]
	min := 0
	for _, t := range w.at {
		if perHour == 0 {
			if t.After(cutM) {
				kept = append(kept, t)
				min++
			}
			continue
		}
		if t.After(cutH) {
			kept = append(kept, t)
			if t.After(cutM) {
				min++
			}
		}
	}
	w.at = kept
	if min >= perMin || (perHour > 0 && len(w.at) >= perHour) {
		return false
	}
	w.at = append(w.at, now)
	return true
}

func readExchange(r io.Reader) (string, string, error) {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return "", "", errInvalidRequest
	}
	seen := map[string]struct{}{}
	var ticket, verifier string
	for dec.More() {
		keyTok, err := dec.Token()
		key, ok := keyTok.(string)
		if err != nil || !ok {
			return "", "", errInvalidRequest
		}
		if _, dup := seen[key]; dup {
			return "", "", errInvalidRequest
		}
		seen[key] = struct{}{}
		var val string
		if err := dec.Decode(&val); err != nil {
			return "", "", errInvalidRequest
		}
		switch key {
		case "ticket":
			ticket = val
		case "verifier":
			verifier = val
		default:
			return "", "", errInvalidRequest
		}
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') || len(seen) != 2 {
		return "", "", errInvalidRequest
	}
	if _, ok := seen["ticket"]; !ok {
		return "", "", errInvalidRequest
	}
	if _, ok := seen["verifier"]; !ok {
		return "", "", errInvalidRequest
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return "", "", errInvalidRequest
	}
	return ticket, verifier, nil
}

func fakeName(q url.Values) (string, bool) {
	if _, ok := q["as"]; !ok {
		return "dev", true
	}
	name := q.Get("as")
	if len(name) < 1 || len(name) > maxAsLen {
		return "", false
	}
	for _, r := range name {
		ok := r == '.' || r == '_' || r == '-' || (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
		if !ok {
			return "", false
		}
	}
	return name, true
}

func codeName(code string) (string, bool) {
	name, ok := strings.CutPrefix(code, "dev:")
	if !ok {
		return "", false
	}
	q := url.Values{"as": {name}}
	return fakeName(q)
}

func validChallenge(s string) bool {
	if len(s) != 43 {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

func validVerifier(s string) bool {
	return validChallenge(s)
}

func validTicket(s string) bool {
	return validChallenge(s)
}

func validState(s string) bool {
	if len(s) < 16 || len(s) > 64 || strings.ContainsAny(s, "+/=") {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil
}

func validReturn(ret string) bool {
	if len(ret) > 64 {
		return false
	}
	if ret == "raspberry://auth" {
		return true
	}
	const prefix = "http://127.0.0.1:"
	const suffix = "/raspberry/cb"
	if !strings.HasPrefix(ret, prefix) || !strings.HasSuffix(ret, suffix) {
		return false
	}
	port := strings.TrimSuffix(strings.TrimPrefix(ret, prefix), suffix)
	if port == "" || strings.HasPrefix(port, "0") || strings.ContainsAny(port, ":/?#@") {
		return false
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1024 || n > 65535 {
		return false
	}
	return ret == "http://127.0.0.1:"+strconv.Itoa(n)+"/raspberry/cb"
}

func oneEach(q url.Values, allow ...string) bool {
	ok := map[string]struct{}{}
	for _, k := range allow {
		ok[k] = struct{}{}
	}
	for k, vs := range q {
		if _, yes := ok[k]; !yes || len(vs) != 1 {
			return false
		}
	}
	return true
}

func identityName(as string) string { return "dev-" + as }

func withQuery(raw, k1, v1, k2, v2 string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || !validReturn(raw) {
		return "", errInvalidRequest
	}
	q := u.Query()
	q.Set(k1, v1)
	q.Set(k2, v2)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func uniqueCode() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	s := hex.EncodeToString(b[:])
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32], nil
}

func identKey(name string) string {
	sum := sha256.Sum256([]byte("raspberry-stub-ident:" + name))
	return hex.EncodeToString(sum[:])
}

func stableAid(identHash string) string {
	sum := sha256.Sum256([]byte("raspberry-stub-aid:" + identHash))
	return hex.EncodeToString(sum[:8])
}

func errBody(code string) map[string]string {
	return map[string]string{"error": code}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	setNoStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeHTML(w http.ResponseWriter, status int) {
	setNoStore(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write([]byte("<!doctype html><html><head><title>auth error</title></head><body>auth error</body></html>"))
}

func redirectNoStore(w http.ResponseWriter, r *http.Request, loc string) {
	setNoStore(w)
	http.Redirect(w, r, loc, http.StatusFound)
}

func setNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
}
