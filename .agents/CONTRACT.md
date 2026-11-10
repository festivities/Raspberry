# Raspberry ⇄ Cherry contract — client half (CONTRACT.md)

What a client patched by Raspberry does, and what it needs from a Cherry server. **This repo is authoritative for the client half.** The server half and the shared definitions (endpoint, host set, auth endpoints, discovery) are Cherry's `D:\Dev\projects\Cherry\.agents\CONTRACT.md` (read-only for you; if the two ever disagree, say so in "Requests to Cherry" and tell the user). Status: **contract 0 — draft proposed 2026-11-09 by the handoff author**; the S1 spike (PLAN task 3) and the first auth slice on the Cherry side turn it into **contract 1**. Every rule below is **proposed** until both files say **agreed**.

## How the two sessions use this

- Never edit the other repo's files. Ask for changes in "Requests to Cherry" (append-only, dated, one short paragraph each); the Cherry session reads it at the start of each session and before each auth slice, and answers in its own file's "Requests to Raspberry". The user relays anything urgent.
- When a spike result changes a shared rule, write the new rule here, bump `contract` and add a changelog line; do not wait to be asked.

## 1 What a patched client does

### 1.1 Endpoint descriptor
- `{"v":1,"host":"<dns name or IPv4 literal>","ports":{"80":<p>,"443":<p>,"10000":<p>,"10123":<p>}}`. Keys are the client's own destination ports, values the endpoint's; a missing key means identity. IPv4 only in v1.
- Baked at patch time as `assets/raspberry/endpoint.json`; a developer override `files/raspberry/endpoint.json` in app-private storage wins (lab devices). Read once at start. Validated: host syntax, ports 1–65535, unknown keys ignored. No exported component or deep link can change it.

### 1.2 Redirect (the hook)
- **Host set (initial rule, mirrors Cherry's lab-proven DNS sink):** a name is redirected when it equals, or ends with, one of `.play.naver.jp`, `.play.naver.net`, `.line-scdn.net`, `.line-apps.com`, `.line.naver.jp`, or equals `ads.play.naver.jp` or `lan3rd.line.me`. Case-insensitive, trailing dot ignored, IP literals never redirected. S1 may narrow this list (for example to drop LINE SDK hosts) but must say why. `patches/hosts.txt` is the compiled-in form.
- For such a name the hook resolves the descriptor's host instead (the real function, short cache). `connect` rewrites the destination port through the map when the address is the endpoint's. **Names stay original** in SNI and `Host`, so Cherry's routing and per-SNI certificates are unchanged.
- **Fail closed:** if the endpoint host does not resolve, the call fails like any DNS failure; the client never falls back to LINE's real hosts.
- Everything else (Google, Firebase, ad SDKs, LINE SDK hosts outside the set) is untouched.

### 1.3 Discord sign-in (client side)
1. Generate `verifier` (32 random bytes, base64url), `challenge = base64url(SHA-256(verifier))`, `state` (16 random bytes, base64url).
2. Open the system browser (Custom Tab) at `https://<host>[:<ports[443]>]/auth/v1/discord/start?challenge=<c>&return=<r>&state=<s>`, where `<r>` is `raspberry://auth` (deep link) or `http://127.0.0.1:<port>/raspberry/cb` (loopback receiver, any port 1024–65535, opened by the app for this attempt only).
3. Accept the return only if its `state` equals the attempt's and it arrives within 10 minutes; read `ticket` (or `error`).
4. `POST https://<host>[:<port>]/auth/v1/exchange` with `{"ticket":"…","verifier":"…"}` over platform TLS validation; on 200 read `uniqueCode`.
5. Store `uniqueCode` where the stock guest flow reads the device UUID (pref `uuid`; exact location from S1) and let the stock guest login continue.
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

None yet (S1 not run). Record here: the final host list, the `uuid` pref location, the return channel actually chosen, any server behavior the stock client needs on a refused guest login, whether ports 10000/10123 can be remapped.

## 4 Requests to Cherry (append-only; newest last)

- **2026-11-09 (seed from the handoff author).** Please build early, before the storage refactor: (a) listeners (HTTPS, HTTP, session, gateway, admin) and the data directory configurable by flags or environment, so an isolated Cherry can run on other ports beside the lab instance; (b) the `dev-fake` auth mode and the three auth endpoints, so R4 has a real peer; (c) `GET /cherry/v1/info`. Until then the stub server in this repo stands in.

## 5 Changelog

- 2026-11-09 — contract 0 drafted.
- 2026-11-10 — client/server handoff reviewed in OpenCode; remains draft contract 0, with no shared-rule changes or new client-runtime evidence.
