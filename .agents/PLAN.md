# Raspberry — Plan (PLAN.md)

Handoff protocol, open tasks, design proposal, status and roadmap. Rules, lab facts and client facts: [AGENTS.md](AGENTS.md). The interface with Cherry servers: [CONTRACT.md](CONTRACT.md). Dated evidence and old pairs: [HISTORY.md](HISTORY.md). Implementation is in progress; the status table and current handoff supersede the original proposal.

## Handoff protocol (user instruction 2026-10-05, inherited from Cherry)

When the user says they are **moving to another conversation whose agent has no context at all**, the outgoing agent MUST record it here as **HANDOFF INITIATED** with a self-sufficient state snapshot, and the receiving agent MUST append **HANDOFF ACCEPTED** (dated, with any state corrections) once it has loaded context. Older INITIATED/ACCEPTED pairs move to HISTORY.md once accepted. Tell the user before writing a handoff so they can change the effort level.

### HANDOFF INITIATED — 2026-11-10 (user requested stop)

You are the receiving agent with no context. Read, in order: all of [AGENTS.md](AGENTS.md), this file, [CONTRACT.md](CONTRACT.md), then Cherry's server contract (read-only), then `docs/build.md`, `docs/patches.md`, `docs/security.md` and `docs/usage.md`. HISTORY is dated evidence and does not override this block. Do not edit Cherry's repo, archives, services, data or AVDs.

**Stopped.** The user stopped all implementation and device work for this handoff. No tester is running. The app `jp.naver.lineplay.android` was left force-stopped. No preference fixture is applied and no emulator capture was left running. The owned stub was not stopped; reverify it before use and do not assume its old PID is alive.

**Repo.** `main` includes pushed `24fbf88` (`feat: integrate deterministic APK patching`). This handoff commit pins the emulator console port and records this snapshot. Legacy `.claude/`, root `AGENTS.md` and root `CLAUDE.md` stay untouched.

**Lab port (user, 2026-11-10).** Raspberry's emulator console port is permanently **5559**. `scripts/start-emulator-raspberry.bat` starts it with `-port 5559`, `-gpu swiftshader_indirect -no-snapshot-load`, and no DNS sink. After a start from that script, the adb serial is `emulator-5559`. The process verified earlier this session was still `emulator-5554` = AVD Raspberry, Android 17/API 37, x86_64 + arm64-v8a, **1290×2796**, because it was started before the pin. Do not restart or kill it just to change ports. Before every device action, `adb devices -l` then `adb -s <serial> emu avd name` must print `Raspberry`. Cherry and Jerry are off-limits even if a serial matches an old note. Do not grant the phone permission.

**Verified, not a finished release.**

- [V host] Before `24fbf88`: Go/native gate, Android core tests, DEX self-test, both-ABI native builds and `go test -race ./...` passed. `raspberry patch` and `keygen` are implemented. Signing fails closed if hard-link publication cannot be used. Stored authorization requires the Discord marker, a valid UUID and `raspberry.discord.origin` equal to `https://` plus the descriptor's canonical HTTPS authority (omit port 443). Fresh SSO clears only `files/avcookie.na` before saving the new authorization; same-origin relaunch keeps it. Callback reads recheck the attempt before each read; one in-flight read may still use its existing 5-second timeout.
- [V packaging] Private combined signed reruns were byte-identical: exactly 3 replacements and 4 additions, one byte per native compatibility edit, no development pin, retained compressed payloads unchanged. The latest pair is `combined-327a93ebc60f424ebe9143f5db0e25fb`, named by `combined-latest-private.json`, under `%TEMP%\opencode\raspberry\continuation-20261110\`. Not in Git.
- [V device] Same-signer install on Raspberry. The Discord gate appears even when a stock UUID exists without our marker. Chrome rejects the self-signed stub with `NET::ERR_CERT_AUTHORITY_INVALID`; no bypass. Live cancellation stays on "Cancelled. Tap Discord to try again." with Retry disabled, including a later refresh; a new Discord tap clears it. Exit/relaunch returns to the initial gate and the marker stays absent. Main spot-checked those screenshots. The endpoint-bound package also installed and showed the initial gate.

**Not accepted.** Wrong-origin rejection and matched-origin native routing were not completed. The first wrong-origin run stopped on an empty activity filter without a screenshot; that is not a crash and not a pass. Preferences were restored to the backup hash, owner/group `10236:10236`, mode `660`, and the recorded SELinux label. The rerun was stopped before either fixture was applied; live preferences were not changed. No Garden, real Discord OAuth2 exchange, WebView, session, gateway or DNS-leak acceptance exists. Discord OAuth means OAuth2 SSO mediated by Cherry: browser sign-in, PKCE and state, a short-lived ticket, then `uniqueCode`. No Discord password or client secret is stored in the APK. Guest auto-entry is only the private static candidate `guest-entry-spec.md`; do not implement it until a real peer shows the scene. Native curl TLS verification remains disabled by the stock client.

**Private scratch.** `%TEMP%\opencode\raspberry\continuation-20261110\` holds the APKs, stub config/logs, evidence screenshots and `prepare-routing-fixture.py`. That script was reviewed and its `--selftest` passed. Invoke it as a file; never `python -c` (the shell scanner rejects inline dynamic execution). Keys stay in `%LOCALAPPDATA%\Raspberry\keys\`. None of this belongs in Git.

**Next, in order.**

1. Reverify the AVD by name. Do not restart Raspberry only to move it to port 5559.
2. Reverify the Raspberry stub, or restart only that stub. Never start or reconfigure Cherry.
3. Finish the synthetic rooted routing check in `routing-device-brief.md`: a wrong origin must stay on the Discord gate; the matched origin may reach native startup. Screenshot every result, even if `dumpsys` is empty. Restore the original preferences afterward. This is not OAuth acceptance.
4. Full login, Garden, WebView and four-transport acceptance waits for Cherry's configurable isolated peer and a browser-trusted certificate. Do not bypass a TLS warning or use the lab instance unless the user explicitly says so.

The earlier same-day quota interruption, red gate and partial-edit notes are historical and are in HISTORY. They are finished, not the current tree.

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

## Status (2026-11-10)

| Item | State |
| --- | --- |
| Context and lab handoff | HANDOFF INITIATED 2026-11-10; not yet accepted |
| Repo skeleton, gate, `check-repo` | implemented and tested |
| Toolchain installed and recorded | installed; versions/pins in docs/build.md |
| S1 static spike | private specs complete; public conclusions in docs/patches.md |
| Isolated protocol stub | implemented and race-tested; not a game emulator |
| R1 endpoint routing | library implemented; wrong-origin and native routing stopped before evidence |
| R2 repackaged-client compatibility | tables implemented; combined package reaches the Discord gate; no 10-minute session |
| R3 WebView rewrite | Java helper implemented; insertion proof and device acceptance pending |
| R4 Discord sign-in (client) | pre-auth, cancellation and Exit/relaunch pass; real OAuth and guest auto-entry pending |
| R5 patcher CLI | unified command/keygen and usage docs implemented; signed reruns byte-identical; pre-auth install passes |
| R6 production end-to-end | not started |

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
