# Raspberry — Plan (PLAN.md)

Handoff protocol, open tasks, design proposal, status and roadmap. Rules, lab facts and client facts: [AGENTS.md](AGENTS.md). The interface with Cherry servers: [CONTRACT.md](CONTRACT.md). Dated evidence and old pairs: [HISTORY.md](HISTORY.md). Implementation is in progress; the status table and current handoff supersede the original proposal.

## Handoff protocol (user instruction 2026-10-05, inherited from Cherry)

When the user says they are **moving to another conversation whose agent has no context at all**, the outgoing agent MUST record it here as **HANDOFF INITIATED** with a self-sufficient state snapshot, and the receiving agent MUST append **HANDOFF ACCEPTED** (dated, with any state corrections) once it has loaded context. Older INITIATED/ACCEPTED pairs move to HISTORY.md once accepted. Tell the user before writing a handoff so they can change the effort level.

### HANDOFF INITIATED — 2026-11-12 (user requested context handoff)

Receiving agent: read all of `AGENTS.md`, this checkpoint and the accepted snapshot below, `CONTRACT.md`, then `docs/{ios,patches,security,build,usage}.md`. Read Cherry's `.agents/CONTRACT.md` read-only for newer replies. Append HANDOFF ACCEPTED after loading context; preserve superseded handoff pairs in HISTORY.

**Work stopped for handoff.** No subagent or UI test is still running. The last verified Android state is the restored Discord gate on AVD Raspberry (`emulator-5559`, 1290×2796), with Phone permission denied and no synthetic fixture active. No app force-stop, emulator stop or stub shutdown was performed for this handoff; reverify their current identities/state before use. No capture was started by this slice. Do not touch Cherry/Jerry, the shared adb server, either archive, or Cherry's live services/data.

**Repo/delivery:** this handoff includes the completed static iOS assessment, partial Android routing evidence and iOS artifact-hygiene guards; it does not change the APK patch implementation or implement IPA patching. User explicitly requested commit/push if green. The incoming HEAD should be the handoff commit after `ec03477`; verify `git status`, `git log -1` and remote tracking rather than assuming delivery succeeded from this pre-commit text. The accepted snapshot's "no commit/push" statement describes its earlier checkpoint, not this delivery request.

**Results and limits:** iOS has Android's same abnormal-state set and an `[AA-006]` message path; no weaker-AirArmor conclusion, safe iOS patch or runtime acceptance is established. Android wrong-origin rejection passes; one native HTTPS request reaches the private stub with original Host/SNI. Startup is blocked by the stock Phone-permission requirement after denial. Preferences were restored with matching hash/owner/group/mode/SELinux metadata (mtime changed), and main verified screenshots/logs. Full OAuth, Garden, WebView, ten-minute compatibility, four-transport and DNS-leak acceptance remain open.

**Resume in this order:**
1. Reverify repo, Raspberry AVD identity and only the owned private stub. Do not recreate helpers or change permission/trust policies to get a green test.
2. Classify the stock Phone-permission dependency statically. Keep Phone denied; do not silently add a new permission bypass. Report any scope decision requiring the user.
3. Coordinate through this repo's CONTRACT for an isolated browser-trusted Cherry peer. Cherry's ongoing refactor belongs to its separate Claude Code session; its configurable listeners/`dev-fake`/discovery are server-reported available, not our end-to-end acceptance.
4. Keep iOS static-only until Mac/device access exists. `docs/ios.md` lists Xcode/signing prerequisites and PlayCover's smoke-only limitations. Further static investigation can trace the final generic-message handler, but do not invent a byte patch from matching state numbers.

**Private evidence/tools:** `%TEMP%\opencode\raspberry\ios-airarmor-20261112\ios-airarmor.md` and `ida-evidence.txt` (raw consumer/predicate evidence lines 1335–1632); `%TEMP%\opencode\raspberry\routing-20261112\routing-result.md`, screenshots, preference backup and bounded ADB helpers; earlier combined signed APK/fixture pointers remain under `continuation-20261110\`. The array-free wrapper is `routing-20261112\scripts\invoke-raspberry-adb.ps1`; read its README and use quoted `"-"` for its default-output sentinel. Capture outputs privately. Keys remain outside Git. An accidental one-file repo extraction was contained in private scratch, source/scratch IPA hashes reverified and repo `Payload` absence checked; no derived material is included in this commit.

**Verification [V, handoff rerun]:** full Go/native/repository gate, `go test -race -count=1 ./...`, Android core tests, DEX selftest and both native ABI builds passed. Java emitted only obsolete source/target-8 warnings. Review/check the final staged index before commit; these are host gates, not completed game acceptance.

### HANDOFF ACCEPTED — 2026-11-12 (OpenCode Raspberry session)

The accepted November 10 handoff and chronological continuation notes are preserved verbatim in HISTORY. Current checkpoint:

- **Scope/ownership:** user authorizes static assessment of the supplied decrypted iOS IPA; no iOS runtime exists yet. Cherry's refactor remains active in a separate Claude Code session. Its repo, data, services and Cherry/Jerry AVDs were not modified.
- **Repo:** started clean at `ec03477`; this slice changes documentation and iOS artifact-hygiene guards, not the APK patch implementation. No commit/push was made.
- **Host checks:** full Go/native/repository gate, uncached Go race tests, Android core tests, DEX selftest and both-ABI native builds passed. Added mixed-case/nested index regressions for IPA/dylib/app bundles/Payload/provisioning profiles pass.
- **iOS static slice complete [S]:** baseline and results in `docs/ios.md`; private report/evidence under `%TEMP%\opencode\raspberry\ios-airarmor-20261112\`. Event 6 reaches an app callback, an abnormal-state latch and an `[AA-006]` generic-message submission. Raw IDA predicates confirm Android's same abnormal set {1,4,5,6,9,10}; state 0 and values above 10 are normal. Re-sign triggering, final message/blocking effect, signing/installability and actual network/login/WebView paths remain unresolved. No iOS byte patch or weaker-security conclusion is justified. No iOS binary was patched or run.
- **Android lab [V]:** explicit-serial preflight verified `emulator-5559` = Raspberry, 1290×2796. Installed package version is 10.1.0.0; packaged descriptor matches the private owned stub, no app-private descriptor override. Stub process/listeners match its private config.
- **Synthetic Android result [V partial]:** wrong-origin fixture stayed behind the Discord gate and added no stub requests. Matched origin loaded both game/routing libraries and sent native HTTPS `GET /v4/setting/goodbye/cherry` with original Host/SNI `fapi.play.naver.jp`, status 501. Expected `/v4/setInitConf` was not observed. Gateway accept/close events prove neither a handshake nor four-transport coverage.
- **Current Android blocker/state:** after Phone permission was denied, the stock client demanded Phone access and showed FINISH/SETTING. No grant or permission workaround was applied. Tester restored original preferences with matching SHA-256 and owner/group/mode/SELinux metadata, removed its staging directory, and relaunched to the Discord gate. Main spot-checked wrong-origin, permission-error and restored-gate screenshots. Phone remains denied; no fixture is left active.
- **Main evidence verification:** independently checked native request log, both library maps, original-backup SHA-256 against post-restore device hash, and matching owner/group/mode/SELinux metadata (mtime changed during restoration). Private `routing-20261112\routing-result.md` indexes the exact evidence; no raw data or credentials were copied into Git.
- **Private tools/evidence:** `%TEMP%\opencode\raspberry\routing-20261112\` holds screenshots/logs and main-reviewed `scripts\raspberry-adb.ps1` plus array-free `scripts\invoke-raspberry-adb.ps1`. Use explicit-serial bounded ADB only; no implicit-selection Android MCP. The helper guards can reject `logcat -d`; do not bypass ownership checks to collect logs.
- **Server coordination:** Cherry reports configurable isolated listeners, `dev-fake` auth and discovery implemented (November 11 contract replies); browser-trusted TLS is still outstanding. Contract reconciliation and shared-auth acceptance are incomplete. Do not build from the other session's changing tree or operate its lab service.

**Next:** classify the Phone-permission dependency without granting it or silently adding a new bypass; obtain an isolated browser-trusted Cherry peer for real auth/game/web acceptance. Keep iOS static results separate from future Mac/PlayCover/device acceptance. OAuth, Garden, WebView, a 10-minute compatibility session, four transports and no-DNS-leak acceptance remain open.

**Tasks, in order (fix or classify each gap with evidence; tag every claim [S]/[V]/[I]/[?]):**

1. **Load context and recheck the lab — complete 2026-11-10.** APK hash/size, attached AVD identity, Cherry process absence and expected tool locations verified read-only. Commit/push permission granted; Raspberry AVD exists. See HISTORY for checks not performed. No device test or runtime acceptance was attempted.
   Defaults you may take without asking: install the missing build tools in user space from official release pages with verified checksums; choose a neutral Java package and URL scheme (no LINE names; for example `dev.raspberry`); keep the dev keystore outside the repo (`%LOCALAPPDATA%\Raspberry\keys\`, owner-only).
2. **R0 — Toolchain.** Install and record versions + SHA-256 in AGENTS: Android NDK (current LTS), `cmdline-tools`, apktool and smali/baksmali (or your chosen smali tooling), jadx CLI (optional). Create the Go module `github.com/festivities/raspberry`, the repo skeleton ("Design" layout), `scripts/check-repo` and a first CI-less gate script. Smoke test: unpack the APK into `work/`, re-zip it unchanged with a Go program, sign it with a throwaway key, install it on the AVD, and see whether it starts (it will probably show the AirArmor popup: that is task 4's evidence, so screenshot it and note which popup it is).
3. **S1 — Static spike.** Delegate to `reverse-engineer`, writing `%TEMP%\opencode\raspberry\spike-20261109\spike.md`, using per-job IDA copies, jadx on the DEX files and `aapt2`. Questions (answer each with addresses and tags; `INFERRED` where unproven):
   1. **Host inventory.** Every hostname the client can connect to: native (the host table at BSS 0x3BE4590 via `NaDataInvokerProtocol::baseHostName` 0x1ac4bb8 and the constructor `sub_14E6E48`; strings in `.rodata`) and Java (string constants in all four DEX files). Classify: must redirect (game hosts), must not redirect (Google/Firebase), third-party SDK traffic (AdMob, AppLovin, LINE SDK, tracking). Output the exact host list for `patches/hosts.txt` and say whether any host is built at run time (suffix rules needed?).
   2. **Resolution and connect path.** Which libc/NDK functions the native code uses to resolve and connect (`getaddrinfo`, `gethostbyname*`, `android_getaddrinfofornet`, `connect`, `sendto`…) and through which module's imports (`.rela.plt`/`.rela.dyn` of arm64 and armv7 `libgame.so`); whether libcurl's resolver is the threaded `getaddrinfo` one; how the LPN sockets (`XSystem`/`XInNetwork`) resolve and connect; whether `libchromview_android.so`, `libm0vie.so` or `libline-sdk-encryption.so` open sockets (they must NOT be hooked).
   3. **Ports.** Where 80/443 come from (URL scheme defaults), where the session port 10123 and the gateway port 10000 come from (`setInitConf.sessionServerInfo`, `parseConfigure` 0x1b3b67c, `GetGatewayServerPort` 0x2a17a20), and whether a port can be carried in the host string.
   4. **WebView.** Every URL loaded in a WebView or opened externally (Java `WebView.loadUrl`, `CustomTabs`, `ACTION_VIEW`, and native-built URLs passed to Java); whether in-game pages use `android.webkit.WebView` or `libchromview_android.so`; each call site's class and method; the cheapest rewrite point.
   5. **AirArmor.** Which callbacks fire for a re-signed APK (confirm state 6 on the AVD in task 2), exact bytes and offsets to make `IsAirArmorStateNormal` 0x200cf64 return true in arm64 and armv7, whether `libgame.so` is integrity-checked by `libm0vie.so` or elsewhere, whether a hook library name or a patched GOT can raise states 5/9/10. Do not hook or patch `libm0vie.so`.
   6. **Login.** What each login button calls in Java (`LoginAdapter`, LINE SDK, Facebook), where `InfoDeviceUUID` is called from, the SharedPreferences file and key of `uuid`, how the SNS button list is built (server-driven by `setInitConf`?), and the cheapest places to (a) run a Discord flow before the game starts and (b) substitute the minted code.
   7. **Early init.** Class and method order at startup (`LineplayApplication`, `LinePlay.onCreate`, `System.loadLibrary` calls, `android.line.s.Service`); where libgame and libm0vie are loaded; the earliest safe point to load `libraspberry.so` and run its constructor after libgame is relocated; whether adding a `classes5.dex` is enough or a method of an existing class must be edited.
   8. **DEX tooling.** Which smali/baksmali version round-trips these four DEX files; whether the single-method edits we need can be done by an in-place byte patch of the DEX instead (smaller, fully ours).
   9. **Estimate.** For each patch: files touched, size, risk, test.
4. **R1 — Endpoint hook.** Build `libraspberry.so` (NDK), load it from `LinePlay$5.run` after libgame and before `cusCocosInit`, GOT-patch `getaddrinfo`/`gethostbyname`/`connect`/`sendto` per the spike, implement host matching, the endpoint descriptor and the port remap (CONTRACT). **Acceptance:** with the stub server on non-default ports (and no DNS sink on the AVD), a fresh install starts, every request for a LINE host reaches the stub with the original SNI/Host on the mapped port (HTTPS, HTTP, session and gateway sockets all seen); third-party hosts are untouched; no LINE hostname is resolved by the device's resolver. Full Garden acceptance requires the configurable isolated Cherry peer, or an explicit decision to use the lab instance.
5. **R2 — Repackaged-client compatibility.** The patch table(s) and the verification step. **Acceptance:** a patched, re-signed APK runs a 10-minute session (login, Garden, MENU, a Square) without the re-signing dialog; document exactly what was changed and why.
6. **R3 — WebView rewrite.** **Acceptance:** the Lucky Spin odds page (and the gacha odds page) loads from the stub/Cherry host with a publicly trusted certificate or the dev pin; the page's URL path and query are unchanged and only the authority differs (CONTRACT).
7. **R4 — Discord sign-in (client side).** Against the stub's dev-fake provider first, then Cherry's `dev-fake` mode when the Cherry session has built it. **Acceptance:** fresh install → Discord flow in the browser → the app stores the minted code → stock guest login → Garden; relaunch skips login (persisted `avcookie.na`); a reinstall plus the same Discord identity returns the same account; a replayed or expired ticket is refused; an attempt started elsewhere cannot be completed by this device.
8. **R5 — Patcher CLI.** One reproducible command: `raspberry patch --apk <pristine.apk> --endpoint <host> [--port 443=<p> …] [--keystore <file>] --out <dir>`, plus `keygen`, `verify`. **Acceptance:** two runs produce byte-identical APKs; the diff against the input is exactly the intended entries; a wrong input hash is refused; no private value is written anywhere but the output APK. Docs: `docs/usage.md`, `docs/patches.md`, `docs/build.md`.
9. **R6 — End-to-end on the user's production endpoint** (the user's Oracle host, a real Discord application). The Cherry session reports when the endpoint is up; the user installs and tests; you fix what breaks.

**Hazards (carried from Cherry's lab, still true):**
- The AVDs `Cherry`/`Jerry` hold device-bound logins and a 433 MB dataset: never wipe or reuse them. Never restore a wholesale `accounts.json` and never edit the lab's data (it is the Cherry session's).
- `JAVA_HOME` on this machine points at the JDK's `bin` folder; set it correctly per process.
- Git Bash mangles absolute device paths (`MSYS_NO_PATHCONV=1`); PowerShell needs PowerShell syntax; bash heredocs misbehaved on this host: write scripts to files.
- Emulator taps that start low on the screen trigger the home gesture; the emulator's keyboard `input text` needs `%s` for spaces.
- An unrelated host process (YunDetectService, Baidu) owns loopback :10000; never stop it.

## Design (proposal by the Cherry session; verify against the spike, change with evidence)

**Principle:** one new native library and one small dex module of ours, a handful of byte patches, and as few edits of LINE's own code as the spike allows. The patcher is a Go program that copies the pristine APK entry by entry, replaces or adds only what is listed, and signs it.

**Components and layout**
- `cmd/raspberry/` — the CLI (`patch`, `keygen`, `verify`, `hosts`, `version`). `internal/apk` (deterministic zip read/write; entries copied byte-for-byte, fixed order and timestamps), `internal/patch` (patch tables with expected-bytes checks; DEX/smali edits), `internal/sign` (v1: build-tools `apksigner.jar` through the JDK; v1.1: a Go signer for APK Signature Scheme v2/v3 plus v1/JAR for API 23, and zip alignment, so a player needs no JDK/SDK), `internal/descriptor` (endpoint descriptor parse and validation, shared with the stub and the tests).
- `native/` — `libraspberry.so` (C, NDK; built for arm64-v8a, and armeabi-v7a only if the 32-bit build is kept; link with `-Wl,-z,max-page-size=16384`): `endpoint.c` (descriptor, host matching, port map; pure logic, unit-tested on the host with mingw gcc), `hook.c` (GOT patcher over `dl_iterate_phdr` for libgame only; `mprotect` around the write; no inline hooks), `jni.c` (`JNI_OnLoad`, config path).
- `android/` — Java sources compiled with `javac` + `d8` into an extra `classesN.dex`: `Raspberry` (entry called from a small smali shim in `LineplayApplication`), `Endpoint` (reads the descriptor), `DiscordLogin` (CONTRACT flow, Custom Tabs or `ACTION_VIEW`, loopback receiver or deep link, exchange call over platform TLS), `WebRewrite` (authority swap).
- `patches/` — our data only: `hosts.txt` (the LINE host set to redirect), `libgame-arm64.tbl`/`libgame-armv7.tbl` (offset, expected bytes, replacement bytes, comment), our own smali snippets, `webhosts.txt`.
- `tools/stub/` — a stub endpoint (Go) for isolated work: HTTPS with a self-signed certificate per SNI, plain HTTP, TCP sinks for the session and gateway ports, per-request log lines (`sni host method path status`, no bodies), `GET /cherry/v1/info` and the dev-fake auth endpoints of the CONTRACT. Runs on ports you choose.
- `docs/` (public: `usage.md`, `patches.md`, `build.md`), `scripts/` (`check-repo`, `build-native`, `build-dex`, `e2e`), `testdata/` (tiny synthetic fixtures only; no LINE data).

**Endpoint descriptor** (baked at patch time as `assets/raspberry/endpoint.json`; a developer override file `files/raspberry/endpoint.json` in app-private storage wins on rooted lab devices): `{"v":1,"host":"cherry.example.org","ports":{"80":80,"443":443,"10000":10000,"10123":10123}}`. Keys are the client's own destination ports, values the endpoint's. IPv4 only in v1. A runtime prompt for the endpoint is v2: a patched APK is built per operator anyway because LINE's code cannot be redistributed.

**Hook semantics (CONTRACT §Redirect; supersedes the original endpoint-IP proposal).** For a hostname in the compiled-in set: `getaddrinfo`/`gethostbyname` resolve the descriptor's host through libc, cache briefly, and return the reserved marker. Only marker-addressed `connect`/`sendto` calls are translated to the endpoint and mapped port. Never attribute connections by endpoint-IP equality. Names stay original in SNI/Host; unrelated connections go straight to libc.

**Early init.** The classes3 edit calls the new dex helper from `LinePlay$5.run`: gate before libgame startup, then load/configure `libraspberry` after libgame is loaded and before `cusCocosInit`. `JNI_OnLoad` only declares the JNI version; the explicit install call validates configuration and patches the GOT. Static ordering is established; no-traffic-before-install remains a device acceptance requirement.

**Discord sign-in (client side).** Default UX candidate: a pre-game overlay created in `LinePlay.onCreate` before the native init continues (a dialog with one button; Custom Tab to `https://<endpoint>/auth/v1/discord/start?...`; the return arrives on a loopback listener (no manifest change) or a deep link (manifest edit; avoid if possible); `POST /auth/v1/exchange`; write the minted code to the `uuid` pref; continue). Second candidate: hook `InfoDeviceUUID`/the guest button. Whichever it is: PKCE (`challenge = base64url(SHA-256(verifier))`), a `state` that must match an attempt this device started, single use; the return comes back to the device that began the attempt, so no cross-device confirmation is needed (a polling flow would need one).

**WebView rewrite.** `WebRewrite.url(String)` replaces the authority of LINE web URLs (`patches/webhosts.txt`) with `<host>:<ports[443]>`, keeping path and query; inserted at the call sites the spike lists (smali) or, if the pages use a client we can wrap, in the client.

**Signing and packaging.** Output goes to the directory given by `--out` (never inside a repo). The operator's own keystore signs it; `keygen` creates one outside the repo with owner-only permissions and warns that losing it means reinstalling. Same package name means the stock app must be uninstalled first (its signature differs).

**Tests.** Host unit tests for pure logic (descriptor parsing, host matching, port map, PKCE, patch application on synthetic binaries and a synthetic tiny APK); golden test of the patcher on the synthetic APK (byte-identical rerun); stub-server device tests through the `tester` agent; a final run against the lab Cherry (default ports at `10.0.2.2`) and then the user's production endpoint.

## Status (2026-11-12)

| Item | State |
| --- | --- |
| Context and lab handoff | HANDOFF INITIATED 2026-11-12; incoming acceptance pending; Raspberry last verified at emulator-5559 |
| Repo skeleton, gate, `check-repo` | implemented and tested |
| Toolchain installed and recorded | installed; versions/pins in docs/build.md |
| S1 static spike | private specs complete; public conclusions in docs/patches.md |
| Isolated protocol stub | implemented and race-tested; not a game emulator |
| R1 endpoint routing | wrong-origin gate passes; one mapped native HTTPS request; startup blocked by denied Phone permission; four-transport/DNS acceptance open |
| R2 repackaged-client compatibility | tables implemented; combined package reaches the Discord gate; no 10-minute session |
| R3 WebView rewrite | Java helper implemented; insertion proof and device acceptance pending |
| R4 Discord sign-in (client) | pre-auth, cancellation and Exit/relaunch pass; real OAuth and guest auto-entry pending |
| R5 patcher CLI | unified command/keygen and usage docs implemented; signed reruns byte-identical; pre-auth install passes |
| R6 production end-to-end | not started |
| iOS compatibility / AirArmor | bounded static assessment complete: same abnormal-state set, final message/re-sign effect unknown; no iOS runtime; CLI Android-only |

## Roadmap

1. **v0.1** routing library + stub + re-signing compatibility on the test AVD (tasks 2–5).
2. **v0.2** WebView rewrite and Discord sign-in against Cherry's dev-fake mode (tasks 6–7).
3. **v1.0** reproducible CLI, public docs, first GitHub release of our own artifacts only; production end-to-end on the user's endpoint (tasks 8–9).
4. **v1.1** self-contained patcher (Go signer and aligner; no JDK/SDK on the player's machine); `raspberry verify` for players.
5. **v2** optional: runtime endpoint prompt, a block list for third-party SDK traffic, armeabi-v7a support if wanted, other client versions only with a new baseline decision.

## Risks to watch

- The client may check more than the signing certificate (integrity of `libgame.so`, or a self-tracing child process); the spike and task 5 must prove the compatibility dialog is absent for a whole session, not just at start.
- libcurl or the LPN code may resolve names through a path the GOT patch does not cover; the stub test shows it (any device DNS query for a LINE host is a failure).
- Bionic's relro makes GOT pages read-only: `mprotect` is required; Android 17 might add restrictions.
- Custom Tabs/Chrome may treat a loopback redirect differently across devices; keep the deep-link variant as the fallback and describe the trade-off to the user (it needs a manifest edit).
- `smali`/`apktool` round trips of a 4-DEX multidex APK can break; prefer additive changes (a new dex plus a minimal in-place edit).
- Android 15+ 16 KB-page devices: our library must be 16 KB aligned (LINE's own libs are not ours to fix).
