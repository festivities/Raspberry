# Raspberry — Plan (PLAN.md)

Handoff protocol, open tasks, design proposal, status and roadmap. Rules, lab facts and client facts: [AGENTS.md](AGENTS.md). The interface with Cherry servers: [CONTRACT.md](CONTRACT.md). Dated evidence and old pairs: [HISTORY.md](HISTORY.md). Written 2026-11-09 ~01:30 by the Cherry session at the user's request; nothing in this repo is built yet.

## Handoff protocol (user instruction 2026-10-05, inherited from Cherry)

When the user says they are **moving to another conversation whose agent has no context at all**, the outgoing agent MUST record it here as **HANDOFF INITIATED** with a self-sufficient state snapshot, and the receiving agent MUST append **HANDOFF ACCEPTED** (dated, with any state corrections) once it has loaded context. Older INITIATED/ACCEPTED pairs move to HISTORY.md once accepted. Tell the user before writing a handoff so they can change the effort level.

### HANDOFF INITIATED — 2026-11-09 ~01:30 host time (Cherry session → new Raspberry session with no context)

You are the receiving agent with **zero context**. The user branched the work into two Claude Code sessions: you (the client patcher) and a **Cherry session** (the server, `D:\Dev\projects\Cherry`). Read, in this order:

1. All of [AGENTS.md](AGENTS.md), above all "Policies" (public repo hygiene, **never commit anything derived from the APK**, **preserve `D:\Dev\projects\Cherry\.opencode\line-play-artifacts` no matter what**, endpoint-agnostic, minimal modification, Discord-only), "Two sessions", "Tooling rules" (IDA: per-job copies of the PRISTINE database only), "Lab", "Client facts".
2. [CONTRACT.md](CONTRACT.md), then Cherry's `D:\Dev\projects\Cherry\.agents\CONTRACT.md` (the server half; read-only for you).
3. This block, "Design" and "Roadmap".
4. From Cherry's `.agents\AGENTS.md`: "Baseline", "Policies" (skim), "Architecture" (Protocol stacks, Key symbols, Auth), "Known client-inherent limits". **The Read tool refuses large reads: read files in chunks of 70–150 lines; some lines are very long, so Grep them or read them alone.** Do not edit Cherry's `JICAMA.md` or anything else in that repo.

**Focus (user, 2026-11-09):** "Handoff focuses on remaining open tasks." Everything here is open; there is no half-built feature. The order below is the order to work in. Ask the user only what is listed in task 1.

**State snapshot (2026-11-09 ~01:25, each line observed at that time):**
- **Repo:** `main` at `001a148` ("Initial commit": the MIT `LICENSE` only) plus the handoff commit that adds `.gitignore` and `.agents/`. Remote `git@github.com:festivities/Raspberry.git` (public, description "Patch LINE PLAY for use with Cherry"). No code exists.
- **Toolchain:** see AGENTS "Tooling rules". Present: JDK 25, Android SDK build-tools 36.0.0 (aapt2, zipalign, apksigner, d8), platform android-37.0, adb, emulator, Go 1.27.1, mingw gcc. **Missing: Android NDK, cmdline-tools, apktool, smali/baksmali, jadx CLI.**
- **Devices:** `emulator-5554` = AVD Cherry and `emulator-5556` = AVD Jerry belong to the Cherry session (do not touch). **No AVD for you exists yet.**
- **Lab Cherry instance** (the Cherry session's): PID 43976, built from `17f305b`, accepts guest logins, reachable from an emulator at `10.0.2.2` on 443/80/10123/10000.
- **Input APK:** present and verified, SHA-256 `aa6495a0…45d1` (AGENTS "Baseline"). Cherry's pristine IDA database exists (never open it; copy per job).
- **Decisions already made by the user (2026-11-09):** a separate repo for the patcher (this one); the APK must connect to ANY custom endpoint (build-time parameter, never hard-coded); only Discord sign-in, with no passwords stored anywhere; certificates may be patched if the in-game browser needs it; minimal modification; security is a requirement; "go with what you recommend" for the endpoint mechanism, which is the resolver/connect hook in "Design" (host-string rewriting is the fallback). The production endpoint's values are private to the user and the Cherry session; you never need them (the operator passes them to the patcher).

**Open tasks, in order (fix or classify each gap with evidence; tag every claim [S]/[V]/[I]/[?]):**

1. **Load context, recheck the lab, ask the user (one AskUserQuestion round, recommended option first).** Recheck: `git status`, `adb devices` plus `adb -s <serial> emu avd name` per serial, the lab Cherry's PID/path (`Get-Process cherry`), the toolchain, the APK hash. Append **HANDOFF ACCEPTED** with corrections. Ask exactly these, nothing more:
   - (a) **Commit policy:** may you commit and push verified work autonomously (as in Cherry, 2026-10-28)? Record the answer in AGENTS "Policies".
   - (b) **Test device:** please create a third AVD `Raspberry` (Android Studio Device Manager: same image as Jerry, android-37.0 google_apis x86_64, 1080×2424) **or** approve installing `cmdline-tools` so you can create it; and add the tap allow-rule for its serial to the project's `.claude/settings.json` (the agent may not edit Claude settings). Static work (tasks 2–3) does not wait for this.
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
4. **R1 — Endpoint hook.** Build `libraspberry.so` (NDK), load it from `LineplayApplication`, GOT-patch `getaddrinfo`/`gethostbyname*`/`connect` per the spike, implement host matching, the endpoint descriptor and the port remap ("Design", CONTRACT). **Acceptance:** with the stub server on non-default ports (and no DNS sink on the AVD), a fresh install starts, every request for a LINE host reaches the stub with the original SNI/Host on the mapped port (HTTPS, HTTP, session and gateway sockets all seen); third-party hosts are untouched; no LINE hostname is resolved by the device's resolver. Then repeat against the lab Cherry at `10.0.2.2` on default ports (guest login to the Garden).
5. **R2 — AirArmor.** The patch table(s) and the verification step. **Acceptance:** a patched, re-signed APK runs a 10-minute session (login, Garden, MENU, a Square) with no AirArmor popup; document exactly what was changed and why.
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

**Hook semantics (CONTRACT §Redirect).** For a hostname in the compiled-in set: `getaddrinfo`/`gethostbyname*` resolve the descriptor's host instead (calling the real function, cached with a short TTL), and `connect` rewrites the destination port when the address is the endpoint's and the port is in the map. Names stay original in SNI/Host, so the server's routing is unchanged. Anything else goes straight to the real functions.

**Early init.** The smali shim in `LineplayApplication` loads the dex module, then `System.loadLibrary("raspberry")` after libgame is loaded; the library installs the GOT patches in its `JNI_OnLoad`. The spike confirms the order and that no request precedes it.

**Discord sign-in (client side).** Default UX candidate: a pre-game overlay created in `LinePlay.onCreate` before the native init continues (a dialog with one button; Custom Tab to `https://<endpoint>/auth/v1/discord/start?...`; the return arrives on a loopback listener (no manifest change) or a deep link (manifest edit; avoid if possible); `POST /auth/v1/exchange`; write the minted code to the `uuid` pref; continue). Second candidate: hook `InfoDeviceUUID`/the guest button. Whichever it is: PKCE (`challenge = base64url(SHA-256(verifier))`), a `state` that must match an attempt this device started, single use; the return comes back to the device that began the attempt, so no cross-device confirmation is needed (a polling flow would need one).

**WebView rewrite.** `WebRewrite.url(String)` replaces the authority of LINE web URLs (`patches/webhosts.txt`) with `<host>:<ports[443]>`, keeping path and query; inserted at the call sites the spike lists (smali) or, if the pages use a client we can wrap, in the client.

**Signing and packaging.** Output goes to the directory given by `--out` (never inside a repo). The operator's own keystore signs it; `keygen` creates one outside the repo with owner-only permissions and warns that losing it means reinstalling. Same package name means the stock app must be uninstalled first (its signature differs).

**Tests.** Host unit tests for pure logic (descriptor parsing, host matching, port map, PKCE, patch application on synthetic binaries and a synthetic tiny APK); golden test of the patcher on the synthetic APK (byte-identical rerun); stub-server device tests through the `tester` agent; a final run against the lab Cherry (default ports at `10.0.2.2`) and then the user's production endpoint.

## Status (2026-11-09)

| Item | State |
| --- | --- |
| Repo skeleton, gate, `check-repo` | not started |
| Toolchain installed and recorded | not started |
| S1 static spike | not started |
| R1 endpoint hook | not started |
| R2 AirArmor | not started |
| R3 WebView rewrite | not started |
| R4 Discord sign-in (client) | not started |
| R5 patcher CLI | not started |
| R6 production end-to-end | not started |

## Roadmap

1. **v0.1** hook + stub + AirArmor on the test AVD (tasks 2–5).
2. **v0.2** WebView rewrite and Discord sign-in against Cherry's dev-fake mode (tasks 6–7).
3. **v1.0** reproducible CLI, public docs, first GitHub release of our own artifacts only; production end-to-end on the user's endpoint (tasks 8–9).
4. **v1.1** self-contained patcher (Go signer and aligner; no JDK/SDK on the player's machine); `raspberry verify` for players.
5. **v2** optional: runtime endpoint prompt, a block list for third-party SDK traffic, armeabi-v7a support if wanted, other client versions only with a new baseline decision.

## Risks to watch

- AirArmor may check more than the signing certificate (integrity of `libgame.so`, the ptrace child); the spike and task 5 must prove the popup is gone for a whole session, not just at start.
- libcurl or the LPN code may resolve names through a path the GOT patch does not cover; the stub test shows it (any device DNS query for a LINE host is a failure).
- Bionic's relro makes GOT pages read-only: `mprotect` is required; Android 17 might add restrictions.
- Custom Tabs/Chrome may treat a loopback redirect differently across devices; keep the deep-link variant as the fallback and describe the trade-off to the user (it needs a manifest edit).
- `smali`/`apktool` round trips of a 4-DEX multidex APK can break; prefer additive changes (a new dex plus a minimal in-place edit).
- Android 15+ 16 KB-page devices: our library must be 16 KB aligned (LINE's own libs are not ours to fix).
