# Patch inventory

Target: LINE PLAY 10.1.0.0, versionCode 254, APK SHA-256 `aa6495a0430beef0c9a719a1f09fe836ff1c82a0f4f96235d47fffda070b45d1`. Other inputs must be refused. Offsets below are **uncompressed ELF file offsets**, not offsets inside the APK.

Static findings are not device acceptance. Implementation and runtime checks are in progress; no patch here has yet passed a complete game session.

## Repackaged-client compatibility check

| Entry | Original SHA-256 | Offset | Expected → replacement |
| --- | --- | --- | --- |
| `lib/arm64-v8a/libgame.so` | `d824c3ef72ac1948f3c5a31619879384f4659c9306e6f5a1b04793334e795b04` | `0x2f98021` | `00` → `f8` |
| `lib/armeabi-v7a/libgame.so` | `8eadba34f30f971188f54010b9dcb5217f1000d2073911fed421edc646473ca7` | `0x13dc502` | `39` → `19` |

**Evidence:** static-confirmed in `NaExceptionManager::IsAirArmorStateNormal`. arm64 uses a signed jump-table byte indexed by state minus one; only state 6's entry changes to the normal branch. ARMv7 uses an abnormal-state bitmask; the edit clears only state 6's bit, changing `0x339` to `0x319`.

**Why:** let a player install their own re-signed copy while leaving every other compatibility state unchanged. States 1, 4, 5, 9 and 10 remain abnormal; this is not a blanket return-true change. `libm0vie.so` is untouched.

**Verify:** require the original library hash and expected bytes, check every modeled state before/after, then run the re-signed client without Frida, Xposed, or ptrace. A ten-minute login/Garden/menu/Square session without the compatibility dialog is still required.

**Risk:** the packed companion library may perform additional file checks. A static byte change alone does not prove successful startup or identify the callback a re-signed APK will actually produce.

## Endpoint routing

Own code: `libraspberry.so`, loaded after `libgame` and before the Cocos renderer initializes. Patch only libgame's GOT slots for `getaddrinfo`, `gethostbyname`, `connect` and `sendto`; do not hook protection, browser or LINE-encryption libraries.

For an allowlisted game hostname, resolve the configured endpoint and return an internal marker address. Only that marker is translated to the endpoint and mapped port at the socket boundary. Matching the endpoint IP itself is unsafe: unrelated destinations may share it. Keep the original URI hostname for Host/SNI. Fail closed when endpoint resolution or hook installation fails.

**Evidence:** both ABIs import those four libc functions. Native curl uses libc resolution; HttpSender passes its resolver sockaddr to `connect`. The LPN path stringifies the resolved IPv4 address and parses that same address before connecting; it does not perform a second DNS lookup. Session host and port can come from `sessionServerInfo`; the gateway port is a client constant. Neither port instruction needs a patch.

**Verify:** an isolated stub on remapped ports must observe original Host/SNI, HTTP, HTTPS and both game sockets. Confirm unrelated resolutions and connections are unchanged, including a connection sharing the endpoint IP. Confirm no allowlisted game hostname reaches device DNS. Actual UDP reply/source-address assumptions remain unproven.

## Startup, Discord and WebView integration

New Java code belongs in `classes5.dex`. The existing integration points are in `classes3.dex`:

- `LinePlay$5.run`: asynchronous Discord gate before native startup; load/configure the routing library after the game library loads and before `cusCocosInit`.
- `LoginAdapter.InfoDeviceUUID`: use only a Discord-minted UUID from the default app preferences (`jp.naver.lineplay.android_preferences`, key `uuid`); remove device-ID minting. Native code caches this value, so authentication must finish before engine initialization.
- LINE/Facebook and other SNS entry points: disable alternate sign-in paths without disabling unrelated activity results.
- `LinePlay.updateURLFromUiThread`, its sub-WebView counterpart, `LanLinkUtil.setCookieNLoadUrl`, and the game external-browser entry: rewrite allowlisted web authorities only, preserving raw path/query/fragment.

The proposed implementation uses a typed DEX writer for added references and branch/exception relocation. A naive code-item append with an unchanged DEX map is not accepted as proof of a valid patch. Keep the other three DEX entries, resources and manifest unchanged unless runtime evidence requires another integration point.

**Evidence:** in-game pages instantiate framework `android.webkit.WebView`. The stock SSL-error handlers do not proceed; keep that security property. The browser return is a per-attempt loopback listener, not a new exported component.

**Verify:** valid DEX layout and unchanged-method semantics, then an ART/device launch. Test fresh auth, persisted auth, wrong state/verifier, expiry/replay, cancellation, and authority-only URL rewriting. A self-signed lab pin for Java requests does not make Chrome or WebView trust a certificate.

**Risk:** early AirArmor user-ID registration happens before the startup runnable. If an absent UUID causes a failure, defer the real registration until authentication and preserve its result handling; do not suppress state 1 or unrelated protection checks. Automatic guest-transport entry after Discord also needs a verified engine-thread integration point.

See [security.md](security.md) for the stock native TLS limitation. These edits do not provide authenticated native transport.
