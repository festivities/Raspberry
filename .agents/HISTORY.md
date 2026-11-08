# Raspberry — History (HISTORY.md)

Dated evidence, superseded snapshots, investigations and old handoff pairs, kept verbatim. This file never overrides [AGENTS.md](AGENTS.md), [PLAN.md](PLAN.md) or [CONTRACT.md](CONTRACT.md). Newest section last. Move an INITIATED/ACCEPTED pair here from PLAN once it is accepted and superseded.

## 2026-11-09 — repository created

- The user created `festivities/Raspberry` (public, MIT, "Patch LINE PLAY for use with Cherry") and asked the Cherry session to prepare this context. The Cherry session wrote `.gitignore` and `.agents/` (AGENTS, PLAN, CONTRACT, HISTORY) and left the first handoff in PLAN. No code exists.
- Facts first recorded that day (read-only, no device): the input APK's SHA-256 and structure (zip listing + `aapt2 dump`), the manifest's Application class `LineplayApplication` and launcher `LinePlay`, the absence of a `networkSecurityConfig`, the presence of `androidx.browser`; the plain-HTTP use of port 80 by the stock client and the lab-proven redirect set (Cherry's DNS sink suffixes), from a sweep of 360 Cherry lab logs.
