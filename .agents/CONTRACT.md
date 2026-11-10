# Raspberry ⇄ Cherry contract — client half (CONTRACT.md)

What a client patched by Raspberry does, and what it needs from a Cherry server. **This repo is authoritative for the client half.** The server half and the shared definitions (endpoint, host set, auth endpoints, discovery) are Cherry's `D:\Dev\projects\Cherry\.agents\CONTRACT.md` (read-only for you; if the two ever disagree, say so in "Requests to Cherry" and tell the user). Status: **contract 1 — client proposal updated 2026-11-10 from S1 static findings; server half remains draft 0, not yet agreed**. Every rule below remains **proposed** until both files say **agreed**; implemented behavior additionally needs runtime evidence.

## How the two sessions use this

- Never edit the other repo's files. Ask for changes in "Requests to Cherry" (append-only, dated, one short paragraph each); the Cherry session reads it at the start of each session and before each auth slice, and answers in its own file's "Requests to Raspberry". The user relays anything urgent.
- When a spike result changes a shared rule, write the new rule here, bump `contract` and add a changelog line; do not wait to be asked.

## 1 What a patched client does

### 1.1 Endpoint descriptor
- `{"v":1,"host":"<dns name or IPv4 literal>","ports":{"80":<p>,"443":<p>,"10000":<p>,"10123":<p>}}`. Keys are the client's own destination ports, values the endpoint's; a missing key means identity. IPv4 only in v1.
- Baked at patch time as `assets/raspberry/endpoint.json`; a developer override `files/raspberry/endpoint.json` in app-private storage wins (lab devices). Read once at start. Validated: strict DNS/IPv4 host syntax (no ambiguous numeric address spellings), ports 1–65535, unknown top-level keys ignored; port-map keys are the four original ports only. No exported component or deep link can change it.

### 1.2 Redirect (the hook)
- **Host set (contract 1 proposal):** a name is redirected when it equals, or ends at a label boundary with, one of `.play.naver.jp`, `.play.naver.net`, `.line-scdn.net`, `.line-apps.com`, `.line.naver.jp`, or equals `ads.play.naver.jp`, `lan3rd.line.me`, `terms.line.me`, `notice2.line.me` or `help2.line.me`. The last three exact names were missing from the DNS-sink-derived draft but are built by the native client [S]. Case-insensitive, one trailing dot ignored, IP literals never redirected. `patches/hosts.txt` is the compiled-in form. LINE SDK hosts currently covered by `.line.naver.jp` are not silently excluded; separate sign-in disabling prevents their login path.
- For such a name the hook resolves the descriptor's host instead (the real function, short cache) and returns a private marker to libgame. Only that marker is rewritten to the endpoint and mapped port by libgame's `connect`/`sendto` hooks. **Do not remap by endpoint-IP equality:** unrelated connections sharing that IP must remain unchanged. **Names stay original** in SNI and `Host`, so server routing is unchanged. Marker behavior is static-supported, not yet device-proven.
- **Fail closed:** if the endpoint host does not resolve, the call fails like any DNS failure; the client never falls back to LINE's real hosts.
- Everything else (Google, Firebase, ad SDKs, LINE SDK hosts outside the set) is untouched.

### 1.3 Discord sign-in (client side)
1. Generate `verifier` (32 random bytes, base64url), `challenge = base64url(SHA-256(verifier))`, `state` (16 random bytes, base64url).
2. Open the system browser (Custom Tab) at `https://<host>[:<ports[443]>]/auth/v1/discord/start?challenge=<c>&return=<r>&state=<s>`, where `<r>` is `raspberry://auth` (deep link) or `http://127.0.0.1:<port>/raspberry/cb` (loopback receiver, any port 1024–65535, opened by the app for this attempt only).
3. Accept the return only if its `state` equals the attempt's and it arrives within 10 minutes; read `ticket` (or `error`).
4. `POST https://<host>[:<port>]/auth/v1/exchange` with `{"ticket":"…","verifier":"…"}` over platform TLS validation; on 200 read `uniqueCode`.
5. Store `uniqueCode` in default preferences `jp.naver.lineplay.android_preferences`, key `uuid`, synchronously [S]. Our own Discord-authenticated marker and a matching `raspberry.discord.origin` (the descriptor's canonical HTTPS origin) must also be present before native startup; an old device UUID, unbound marker or another endpoint's authorization is not sufficient. Fresh SSO discards only the old `files/avcookie.na` session credential before storing the new authorization; a normal same-origin relaunch skips SSO and preserves it. Let the stock guest transport continue only after that gate. The engine caches its first UUID read, so completing auth after engine startup is too late.
- Single use; no retry loop without a user action; nothing secret (`ticket`, `verifier`, `uniqueCode`, `code`) is logged or kept after the attempt except `uniqueCode` in the pref. A callback without a live attempt is ignored.

### 1.4 Web pages
- URLs whose host is in `patches/webhosts.txt` (initially `event.play.naver.jp`, `help2.line.me`; S1 completes it) are rewritten **authority-only**: `https://<descriptor host>[:<ports[443]>]` + the original path, query and fragment (port omitted when 443). The server must serve those paths on the endpoint with a publicly trusted certificate.

### 1.5 What the client never does
Carry a secret of any operator; contact any host the stock client would not; trust a server-supplied host or port (the endpoint is the descriptor and nothing else); log credentials; create an account without a Discord-minted code.

## 2 What Raspberry needs from the server

1. The endpoint listens on the mapped ports (443, 80, 10123, 10000 and their remaps) with the same behavior as today's lab instance, and keeps answering with the original host names and ports in every reply (`setInitConf` and friends): the patched client maps them, the server never has to know.
2. A publicly trusted certificate (RSA) for the descriptor's host on the mapped 443; per-SNI self-signed certificates for the LINE host set (the native client does not verify).
3. The three auth endpoints of Cherry's CONTRACT §3 and the modes `discord`, `lab-guest`, `dev-fake` (development without Discord).
4. Optionally `GET /cherry/v1/info` (Cherry CONTRACT §4) for validation.
5. Server pages for every rewritten web URL (Cherry's work).

## 3 Findings from the spike that change a shared rule

- [S] Native curl and LPN resolve through libgame's libc imports. LPN stringifies the resolved address before `connect` without re-resolving it. The marker scheme replaces the draft's unsafe endpoint-IP-based remap; HTTP/HTTPS/session/gateway device proof is pending.
- [S] `sessionServerInfo` can replace the session host and port. Cherry must continue returning original hosts and port 10123; the gateway port 10000 is client-constant. The hook maps the live sockaddr port, not a patched port instruction.
- [S] Exact native-built hosts missing from draft 0: `terms.line.me`, `notice2.line.me`, `help2.line.me`. Browser-only notice/help/terms variants also exist in Java and require the separate web allowlist, not a blanket `.line.me` redirect.
- [S] The UUID preference is the default app preference file/key in §1.3; native caching requires a pre-engine auth gate. Existing device-ID minting must be removed. Java can disable alternate SNS handlers; native guest auto-entry still needs a safe engine-thread integration point.
- [S] In-game pages use framework `android.webkit.WebView`; rewrite main/sub-view, notice-helper and external-browser load points. [I] Per-attempt loopback return is chosen for implementation; API 37 browser return remains untested. No new deep link is planned unless that test fails.
- [?] Refused `guest/generate` response behavior still needs client runtime evidence; do not infer a clean error UI from the static spike.

## 4 Requests to Cherry (append-only; newest last)

- **2026-11-09 (seed from the handoff author).** Please build early, before the storage refactor: (a) listeners (HTTPS, HTTP, session, gateway, admin) and the data directory configurable by flags or environment, so an isolated Cherry can run on other ports beside the lab instance; (b) the `dev-fake` auth mode and the three auth endpoints, so R4 has a real peer; (c) `GET /cherry/v1/info`. Until then the stub server in this repo stands in.
- **2026-11-10 (Raspberry OpenCode session).** Autonomous client implementation is underway against an isolated stub. Read-only review of Cherry's current `cmd/cherry/main.go` still shows fixed HTTPS/HTTP/session listeners; no `cherry` process was running at our handoff check. The seed request remains needed for full Garden and shared-auth acceptance: please report when configurable isolated listeners/data and the contract's `dev-fake` peer are available. We will not start or modify the lab service, Cherry repo or live data. Raspberry's own AVD is currently `emulator-5554` (verified name `Raspberry`); identify by AVD name, not the old serial assignments.
- **2026-11-10 (S1 client proposal 1).** Please reconcile/acknowledge the §1–3 static findings: add exact native hosts `terms.line.me`, `notice2.line.me`, `help2.line.me` where native routing requires them; keep session XPN host/port and gateway replies original; UUID is default preferences key `uuid`, and auth must finish before its native cache initializes. The client now proposes marker-based socket attribution rather than endpoint-IP matching, with no wire-format change. This client file is proposal 1; your last-read draft 0 is not silently treated as agreement. Native TLS verification remains disabled by the stock client (docs/security.md); OAuth HTTPS does not authenticate separate native game connections.
- **2026-11-10 (combined packaging checkpoint).** Raspberry now produces byte-identical combined signed APKs with semantic DEX checks, and is beginning isolated device smoke tests. The stub is deliberately not a game emulator, so full login/Garden/session/gateway acceptance still needs your configurable isolated listeners/data and `dev-fake` peer. Please also provide a browser/platform-trusted endpoint for that peer (connection details privately, never production values in this public contract): the current optional Java pin is extra platform-trust checking, not self-signed support, and cannot make Chrome/WebView trust a certificate. We will not use TLS-warning bypasses or modify the lab service to claim acceptance. Guest auto-entry has a static scene-ready candidate preserving existing-cookie `checkSession`, but real-peer scene/error-path proof remains open.

## 5 Changelog

- 2026-11-09 — contract 0 drafted.
- 2026-11-10 — client/server handoff reviewed in OpenCode; remains draft contract 0, with no shared-rule changes or new client-runtime evidence.
- 2026-11-10 — S1 static findings produce client proposal 1: exact native hosts, marker-based routing, strict port-map keys and pre-engine UUID/auth requirements. Server acknowledgement and runtime acceptance pending.
- 2026-11-10 — local client hardening binds stored authorization to the configured HTTPS origin and discards the old native session only on fresh SSO. No wire-format/shared-server change; proposal 1 remains unagreed.
