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
