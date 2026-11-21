# Raspberry

**Patch your own copy of discontinued LINE PLAY (10.1.0) to connect to a community [Cherry](https://github.com/festivities/Cherry) server.**

Raspberry is an offline compatibility patcher for players and server operators. You supply your own copy of the final LINE PLAY 10.1.0 client (Android APK or decrypted iOS IPA) and the address of any Cherry server. Raspberry verifies the exact input hash, builds a deterministic patched package outside every repository, and never redistributes LINE's code, assets, or binaries.

## What Raspberry changes

1. **Operator-chosen endpoint.** Routes only LINE PLAY's game, notice, and CDN hostnames to the server and port map you specify at patch time. Unrelated traffic is untouched, and no server address is ever hard-coded.
2. **Discord-only sign-in & seamless re-authentication.** Authenticates players through the server's Discord OAuth2/SSO flow using PKCE and single-use tickets—no passwords are stored and the patched app holds no server secrets. After **Logout**, **Delete Avatar**, or session invalidation, the client clears only its own auth state and session cookie, prompts for fresh Discord sign-in, and continues directly into the game (or avatar creation) in the same process.
3. **In-app web pages & notices.** Rewrites allowlisted LINE web and notice URLs to your server's HTTPS authority over platform TLS so odds, help, and notice checks work without legacy LINE closure popups.
4. **Android re-signing compatibility.** Adjusts only the re-signed-APK compatibility check on Android while leaving every other check intact.

## Supported client inputs

Raspberry refuses any input whose size and SHA-256 do not match the locked final release:

| Platform | Package / Bundle | Version | Locked SHA-256 |
| --- | --- | --- | --- |
| **Android** | `jp.naver.lineplay.android` | `10.1.0.0` (versionCode `254`) | `aa6495a0430beef0c9a719a1f09fe836ff1c82a0f4f96235d47fffda070b45d1` |
| **iOS** | `jp.naver.lineplay` (decrypted `.ipa`) | `10.1.0` (build `10.1.0.0`) | `987fefccfc235cc73fdd6363c064887272575586f334b45fcb10d213a8772532` |

## Quick start — Android (Windows)

### Prerequisites
- Go 1.27+, JDK 25, Android SDK (`android-37.0`, build-tools `36.0.0`), Android NDK r30 (`30.0.16248370`), mingw `gcc` (for native host tests), and pinned `smali` 3.0.10 JARs. See [docs/build.md](docs/build.md) for exact versions and SHA-256 pins.

### 1. Build Raspberry's local artifacts
Run from the repository root (outputs stay in git-ignored `build/`):

```powershell
powershell -NoProfile -File scripts\build-native.ps1
powershell -NoProfile -File scripts\build-dex.ps1
powershell -NoProfile -File scripts\build-dexpatch.ps1
go build -o "$env:TEMP\raspberry\raspberry.exe" .\cmd\raspberry
```

### 2. Create a signing keystore (once, outside every repo)
Keep your keystore backed up—losing it means uninstalling the app before installing future updates.

```powershell
& "$env:TEMP\raspberry\raspberry.exe" keygen `
  --keystore "C:\path\outside\repos\raspberry.p12" `
  --password-file "C:\path\outside\repos\raspberry.password"
```

### 3. Patch and sign your APK

```powershell
& "$env:TEMP\raspberry\raspberry.exe" patch `
  --apk "C:\path\to\LINE_PLAY_10.1.0.0.apk" `
  --endpoint cherry.example.org `
  --port 443=8443 `
  --port 80=8080 `
  --port 10000=10000 `
  --port 10123=10123 `
  --out "C:\path\outside\repos\out" `
  --keystore "C:\path\outside\repos\raspberry.p12" `
  --password-file "C:\path\outside\repos\raspberry.password"
```

- Omit `--port` flags for any port that stays at its default (`80`, `443`, `10000`, `10123`).
- The output is written atomically as `raspberry-lineplay-10.1.0.0.apk` without overwriting an existing file.
- Install with `adb install raspberry-lineplay-10.1.0.0.apk` (or `adb install -r` for same-signer updates).

### Signing in on Android
1. Launch LINE PLAY and tap **Discord** on the sign-in prompt.
2. Complete Discord sign-in in the browser tab. The browser hands sign-in back to LINE PLAY and the game comes back to the front on its own. If your browser asks whether to open LINE PLAY, allow it.
3. The game automatically enters your account (or avatar creation for new accounts) without showing the legacy LINE login screen.

## Quick start — iOS (macOS)

### Prerequisites
- macOS with Xcode / `iPhoneOS` SDK and Go 1.27+ (see [docs/build.md](docs/build.md)).

### 1. Build Raspberry's iOS runtime and patch your IPA

```sh
./scripts/build-ios-runtime.sh
go run ./cmd/raspberry ipa inspect --ipa /path/to/LINE_PLAY_10.1.0_decrypted.ipa
go run ./cmd/raspberry ipa patch \
  --ipa /path/to/LINE_PLAY_10.1.0_decrypted.ipa \
  --endpoint cherry.example.org \
  --port 443=8443 \
  --out /path/outside/repos/out
```

- Outputs an unsigned `raspberry-lineplay-10.1.0-unsigned.ipa` atomically without overwriting existing files.
- Sign and install the output IPA with your preferred iOS signing / sideloading workflow.

## Security & known boundaries

- **No secrets in the app:** Only the operator's endpoint descriptor is embedded. Discord authentication is mediated by the Cherry server with PKCE (`S256`), random `state`, and short-lived single-use tickets.
- **Platform TLS vs. stock native libcurl:** Discord sign-in, token exchange, in-app WebView pages, and notice requests use platform TLS validation (your Cherry server needs a publicly trusted certificate for its operator hostname). Stock native game libcurl connections inherit the original client's disabled certificate verification—see [docs/security.md](docs/security.md).
- **Platform notes:** End-to-end launch, Discord sign-in, Garden, Logout → Discord → Garden, and Delete Avatar → Discord → avatar creation → Garden have been verified on Android 17 (`arm64-v8a`) and iOS (`myphone` virtual device). Physical-device iOS provisioning/sideloading and 32-bit `armeabi-v7a` Android runtime remain community-tested.

## Documentation

- [docs/usage.md](docs/usage.md) — full CLI command and flag reference
- [docs/build.md](docs/build.md) — pinned toolchains, checksums, and host gates
- [docs/patches.md](docs/patches.md) — exact patch inventory and verification status
- [docs/security.md](docs/security.md) — threat model, trust boundaries, and inherited limits
- [docs/ios.md](docs/ios.md) — iOS compatibility architecture and test notes

## License

MIT — see [LICENSE](LICENSE). This repository contains only original Raspberry code, patch tables, and documentation.
