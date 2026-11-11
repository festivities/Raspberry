# Raspberry — History (HISTORY.md)

Dated evidence, superseded snapshots, investigations and old handoff pairs, kept verbatim. This file never overrides [AGENTS.md](AGENTS.md), [PLAN.md](PLAN.md) or [CONTRACT.md](CONTRACT.md). Newest section last. Move an INITIATED/ACCEPTED pair here from PLAN once it is accepted and superseded.

## 2026-11-09 — repository created

- The user created `festivities/Raspberry` (public, MIT, "Patch LINE PLAY for use with Cherry") and asked the Cherry session to prepare this context. The Cherry session wrote `.gitignore` and `.agents/` (AGENTS, PLAN, CONTRACT, HISTORY) and left the first handoff in PLAN. No code exists.
- Facts first recorded that day (read-only, no device): the input APK's SHA-256 and structure (zip listing + `aapt2 dump`), the manifest's Application class `LineplayApplication` and launcher `LinePlay`, the absence of a `networkSecurityConfig`, the presence of `androidx.browser`; the plain-HTTP use of port 80 by the stock client and the lab-proven redirect set (Cherry's DNS sink suffixes), from a sweep of 360 Cherry lab logs.

## 2026-11-09 → 2026-11-10 — initial Raspberry handoff

The original handoff introduction and snapshot follow verbatim. Its task list and design remain in PLAN; the acceptance below supersedes stale setup facts.

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

### HANDOFF ACCEPTED — 2026-11-10 (OpenCode Raspberry session)

- Read all four Raspberry `.agents/` files, Cherry's server CONTRACT, and the requested Cherry baseline, policy, tooling, architecture/auth and client-limit context. Contract remains draft 0; no protocol changes or new client-runtime claims.
- User clarified **OpenCode**, supplied Raspberry's local APK path, and authorized autonomous commits and pushes of verified work. Both artifact archives remain read-only.
- User also prohibited global Python package installs: create a git-ignored `.venv` with `python -m venv .venv` before installing any needed Python dependencies. No packages or venv were installed in this context-only session.
- [V] Read-only worker verification: the supplied APK is 63,962,807 bytes with SHA-256 `aa6495a0430beef0c9a719a1f09fe836ff1c82a0f4f96235d47fffda070b45d1`, matching the baseline.
- [V] `adb devices -l` showed only `emulator-5554`; `emu avd name` identified it as **Raspberry**. Cherry/Jerry were not attached. Serials are not ownership: reverify AVD identity before each device test. No UI, installation, wipe or device write occurred.
- [V] `Get-Process -Name cherry` found no process. The old PID/listener snapshot is not current; no service was started, stopped or reconfigured.
- [V] Go 1.27.1, gcc 16.1.0, Temurin JDK 25.0.3, SDK build-tools 36.0.0 and aapt2 2.20-13193326 are present. `JAVA_HOME` still incorrectly includes `bin`. No SDK NDK/cmdline-tools directories or `%LOCALAPPDATA%\Raspberry` tool installation exist. No disk-wide tool search or individual zipalign/apksigner/d8 recheck was done; previous missing-tool claims otherwise remain unverified snapshots.
- Repo began at `168d30a` on `main`, with existing untracked `.claude/`, `AGENTS.md`, `CLAUDE.md` and `scripts/`. Leave these untouched and unstaged. This change updates context only; implementation, tool installation and APK/device acceptance are not started. Next work is R0 toolchain/repo gate, then S1 static spike.

## 2026-11-10 — implementation checkpoint

- Toolchain installation, repository foundation, isolated stub, native routing library, Java sign-in helper, DEX insertion tool, and signing/repack libraries were implemented and reviewed. The public conclusions are in `docs/build.md`, `docs/patches.md`, and `docs/security.md`.
- [V] The baseline copy matches the locked hash. Real repack outputs were byte-identical and preserved every retained compressed payload. Real signing outputs were byte-identical. A re-signed baseline package installed and launched on AVD Raspberry. Main visually confirmed the resulting phone-permission screen; no account action was taken.
- [V] The first launch showed language selection and permission dialogs, not a re-signing compatibility dialog. That observation covers only the unmodified re-signed baseline. It is not acceptance of the later compatibility, routing, web, or sign-in changes.
- Private analysis notes, generated packages, logs, and development keys remain outside Git. The next session starts from the continuation handoff in PLAN, not from this historical snapshot.

## 2026-11-10 — continuation handoff (outgoing snapshot, verbatim)

### HANDOFF INITIATED — 2026-11-10 (OpenCode continuation)

You are receiving an implementation in progress, not a finished release. Read AGENTS, CONTRACT, HISTORY, docs/build.md, docs/patches.md, and docs/security.md before editing. Raspberry is a compatibility patcher for a player's own discontinued game client and the player's own community server. Continue only the unfinished integration and acceptance work below. Do not generalize the client changes, inspect unrelated private data, or use instrumentation tools in acceptance runs.

**Current lab**

- AVD name `Raspberry` was verified at `emulator-5554`; the screen is 1290×2796. Reverify identity before every device action. Cherry and Jerry AVDs are off limits.
- No `cherry` process was running. Do not start or reconfigure Cherry services or data. Isolated work uses `tools/stub` on loopback ports chosen at runtime.
- The baseline APK copy matches the locked size and SHA-256. Both APK archives remain read-only.
- A re-signed baseline copy, with no compatibility, routing, or sign-in changes, installed and launched successfully. The first screens were language selection, a notification permission dialog, and a phone-call permission dialog. The tester stopped there and did not answer the phone dialog. Main visually confirmed that screen. Continue with **Don't allow** only if the next test needs to proceed; do not grant phone access.
- The private development key and password file already exist under `%LOCALAPPDATA%\Raspberry\keys\`. Do not print, commit, replace, or weaken them.

**Verified**

- Go foundation, descriptor validation, deterministic repack, owner-only signing, loopback stub, native routing library, Java sign-in helper, and DEX insertion tool are implemented in the working tree.
- Real-input repack preserved every retained compressed payload and produced byte-identical outputs. Real signing produced byte-identical signed outputs. The re-signed baseline installed and launched.
- The reserved routing address `198.18.0.1` must be rejected as an operator endpoint by every validator.

**Not yet accepted**

- Review fixes for the DEX insertion tool, Android certificate validation, and native startup ordering may still be running. Rerun their focused tests and review the diffs before trusting them.
- No combined package has yet been built, installed, or exercised. Do not describe routing, sign-in, web compatibility, or re-signing compatibility as device-accepted.
- The unified `patch` command and public usage document are not finished.
- Cherry has not yet provided the requested configurable isolated peer. Full Garden acceptance waits for that peer or an explicit user decision to use the lab instance.

**Next step:** finish and review the three pending fixes, run the full gate, then build one private combined package and test it on AVD Raspberry. Keep all generated packages, logs, keys, and analysis files outside Git.

## 2026-11-10 — resumed integration and first combined smoke

- The subagent quota interruption was resolved by the user. The interrupted CLI/auth/DEX work was finished, main-reviewed, and host-gated. Signing no longer falls back to replacement-capable Windows rename; unsupported hard-link filesystems fail closed. CLI safety tests use synthetic repository markers, including the repository-root and symlink cases.
- [V host] Go/native gate, Android core tests, both-ABI native builds, DEX self-test and `go test -race ./...` passed. The real DEX comparison verifies 8,438 classes, 56,288 untouched methods and 14 full expected edits, including range/wide/payload/register/exception operands. A Turkish-locale hostname regression failed before the `Locale.ROOT` fix and passed afterward.
- [V packaging] Two pairs of private combined builds (before and after the locale fix) produced byte-identical signed reruns. Each comparison found the intended three replacements/four additions, both one-byte compatibility edits, no development pin and unchanged retained compressed payloads. Obsolete upstream signing metadata, including `stamp-cert-sha256`, is removed; package/version/manifest/resources remain unchanged.
- [V device, first combined build only] Raspberry was reverified at `emulator-5554`, 1290×2796. Same-signer replacement installation succeeded. Main spot-checked the Discord overlay: an existing stock UUID without the Discord marker did not authorize native startup. The app stayed alive; no ART verification/linkage/fatal exception was found in the captured window. The stub saw no new auth/game HTTP request during this pre-auth test.
- [V device] Discord opened Chrome, whose first-run was completed without an account. Chrome rejected the self-signed stub with `NET::ERR_CERT_AUTHORITY_INVALID`; no warning bypass or trust-store change occurred. By the time the tester returned, the attempt was already failed. Retry then reopened the browser, which is expected for a failed attempt; that run did **not** establish cancellation of a live attempt. Main spot-checked the before/after screenshots rather than treating this as a confirmed defect.
- Exit/relaunch, the locale-fixed package and the explicitly synthetic rooted post-auth routing fixture were not reached in the first run. A subsequent tester was cancelled when the user changed agent models; a fresh tester was delegated recovery/state checks before continuing. No full OAuth/game/web/four-transport or no-DNS-leak acceptance follows from the pre-auth smoke.

### Follow-up smoke and hardening

- [V device] The live-cancellation display fix passed twice, including a refresh in a later minute, re-entering the browser from Discord, disabled Retry after cancellation, and Exit/relaunch with no authorization marker. Main spot-checked the cancellation and relaunch screenshots.
- Stored authorization was subsequently bound to the configured canonical HTTPS origin, and fresh SSO now discards only the previous `files/avcookie.na` credential. The new exact-file helper passed host tests for missing/file/directory cases and preservation of an unrelated sibling. Callback reads now recheck cancellation/expiry between reads; an in-flight read keeps the existing five-second timeout.
- [V packaging/device startup] The resulting endpoint-bound combined pair was again byte-identical, and the final package installed and displayed the initial gate. A wrong-origin fixture run was **inconclusive** because the tester stopped on an empty foreground-activity filter without taking a screenshot; this was not evidence of a crash or a passed origin guard. Preferences were restored to the backup hash with owner/mode/SELinux metadata preserved. Main independently confirmed the restored initial gate and an empty crash buffer. A fresh screenshot/log-based wrong-origin and matched-origin routing test is in progress.
- The inline Python refusal was a shell-scanner `dynamic-execution` analysis error on an arithmetic probe, not a denied device mutation. A static, inspectable stdlib fixture script was reviewed and self-tested; it writes only new private fixture files and changes no device state itself. Real device mutations still require the normal permission flow, secure staging and exact restoration.

## 2026-11-10 — stop for handoff

- The user stopped all implementation and device work and asked for a context handoff. The in-progress routing sentence above is historical: the rerun did not apply either fixture. Live preferences were left unchanged, the app was force-stopped, and no capture was running. The owned stub was not stopped.
- The user set Raspberry's emulator console port permanently to 5559. The startup script now passes `-port 5559`. The process verified earlier that day remained `emulator-5554` and was not restarted.
- The self-sufficient snapshot is PLAN's HANDOFF INITIATED block. `24fbf88` was already pushed before this handoff commit.

## 2026-11-12 — accepted November 10 handoff and continuation evidence

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

### HANDOFF ACCEPTED — 2026-11-12 (OpenCode Raspberry session)

- Loaded all four Raspberry context files, the server contract and the build/patch/security/usage docs. Started from clean `main` at `ec03477`; the 2026-11-10 snapshot above is historical, not current lab identity.
- User supplied the decrypted iOS 10.1.0 IPA in Raspberry's read-only archive and expanded scope to iOS compatibility assessment, starting with an evidence-based AirArmor comparison. The Android CLI remains APK-only; do not claim IPA support from a static assessment.
- Cherry's refactor is still active in a separate **Claude Code** session. Its 2026-11-11 contract reports configurable isolated listeners, `dev-fake` auth and discovery implemented; a browser-trusted peer certificate remains outstanding. No Cherry files, services, data or devices will be changed here.
- Android Go/native/repository gate and Go race tests pass again. Private iOS static analysis and the previously pending synthetic Android wrong-origin/routing smoke are delegated; results must be reviewed before acceptance claims.
- Android smoke did not reach fixtures: only AVDs Cherry/Jerry were attached; the Raspberry batch-launch attempt timed out. Main's later process inventory found no Raspberry emulator process. The tester stopped without changing preferences, app or stub state; a helper-script setup limitation prevented the retry. One implicit-selection Android MCP wait incorrectly targeted Cherry and failed; no screenshot or UI input occurred. Future tests must use explicit-serial bounded ADB only, as the project rules require. Wrong-origin/native routing remain unaccepted.
- User confirms no iOS runtime is available yet: static analysis only for this slice. macOS/device test prerequisites and PlayCover limitations are recorded in `docs/ios.md`.
- iOS artifact hygiene guards are implemented and main-reviewed: IPA/dylib/provisioning files and extracted `.app`/`Payload` trees are rejected by `check-repo`; mixed-case/nested synthetic regressions and the full gate pass. User subsequently made Raspberry AVD available; explicit-serial routing smoke was redelegated, with no result yet.
- First iOS static report and key IDA evidence main-reviewed: signature-verification failures feed event 6 and a debugger check feeds event 8, but blocking enforcement is not established. A targeted downstream event-consumer trace is delegated; do not label iOS weaker or invent a compatibility byte patch yet. Public baseline/findings and macOS prerequisites are in `docs/ios.md`; private evidence is `%TEMP%\opencode\raspberry\ios-airarmor-20261112\`.
- iOS downstream trace main-reviewed: event 6 can reach the registered app callback, a write-once abnormal-state latch at manager `+52`, and an `[AA-006]` generic-message submission. Mask `0x672` classifies the same abnormal set as Android ({1,4,5,6,9,10}); the final generic-message handler/re-sign trigger remain unresolved. Do not retain the earlier event-list-only reading or infer weakness from the separate `CNaCheatingBlockPopup` branch not being used. Raw consumer-predicate evidence is being preserved; no more tracing or iOS patch is required for this slice.
- iOS static slice complete: main inspected the appended raw setter/consumer/predicate disassembly and pseudocode (`ida-evidence.txt` lines 1335–1632). Unsigned range handling makes state 0 and states above 10 normal in the compact predicate; within 1–10 the abnormal set exactly matches Android. No iOS runtime, signing/installability, final message-effect or routing/login acceptance is claimed. Further iOS compatibility implementation waits on those explicit unknowns, not on an assumption that the SDK is missing or weaker.
- Android tooling recovery: private `%TEMP%\opencode\raspberry\routing-20261112\scripts\raspberry-adb.ps1` now supplies bounded explicit-serial calls, Raspberry identity rechecks and binary-safe private captures; its README gives invocations. Main reviewed it and reran the Windows PowerShell 5.1 host selftest successfully after fixing a PS7-only generic call. Tester is redelegated to execute the existing `preflight` entry first, not recreate the helper. This helper is not a permission bypass and must not be used on other AVDs.
- [V tester preflight] Raspberry is now verified at `emulator-5559`, 1290×2796, and the owned stub PID/executable/listeners match its private config. App/package/descriptor and routing checks still did not run: passing array arguments through `powershell -File` failed. A small private argv-forwarding wrapper is being prepared; no app action, fixture or preference mutation has occurred.
