<a id="readme-top"></a>

<div align="center">

<img src="https://raw.githubusercontent.com/hareru/public/e1589b69418775a0d32a6b166aa41f0dbc7403c9/raspberry/raspberry.svg" alt="Raspberry logo" width="200">

<h1>Raspberry</h1>

<p><b>Patch your own copy of discontinued LINE PLAY (10.1.0) to connect to a community <a href="https://github.com/festivities/Cherry">Cherry</a> server.</b></p>

[![Discord][discord-shield]][discord-url]
[![License][license-shield]][license-url]
[![Last commit][commit-shield]][commit-url]
[![Issues][issues-shield]][issues-url]
[![Stars][stars-shield]][stars-url]

<a href="docs/usage.md"><strong>Read the docs »</strong></a>
<br />
<a href="https://github.com/festivities/Raspberry/issues/new?labels=bug">Report a bug</a>
&middot;
<a href="https://github.com/festivities/Cherry">Cherry server</a>
&middot;
<a href="https://discord.gg/E9NNwhJmqN">Join the Discord</a>

</div>

> [!NOTE]
> For setup help and support, join our [Discord server](https://discord.gg/E9NNwhJmqN).

## Table of contents

- [About](#about)
- [Features](#features)
- [Supported clients](#supported-clients)
- [Getting started — Android (Windows)](#getting-started--android-windows)
- [Getting started — iOS (macOS)](#getting-started--ios-macos)
- [Security and known limits](#security-and-known-limits)
- [Troubleshooting](#troubleshooting)
- [Reporting issues](#reporting-issues)
- [Contributing](#contributing)
- [Documentation](#documentation)
- [License](#license)

## About

Raspberry is an offline compatibility patcher for players and server operators. You supply your own copy of the final LINE PLAY 10.1.0 client (Android APK or decrypted iOS IPA) and the address of any Cherry server. Raspberry checks the exact input hash, builds a deterministic patched package outside every repository, and never redistributes LINE's code, assets or binaries.

### Built with

- [Go](https://go.dev) (standard library only) — the patcher CLI
- C (Android NDK) — the native routing library
- Java — the Android sign-in and web-page module
- Objective-C / C (iOS SDK) — the iOS runtime

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Features

Raspberry makes only these compatibility changes:

- **Your server, not a hard-coded one.** Only LINE PLAY's game, notice and CDN hostnames go to the server and ports you choose at patch time. Other traffic is untouched.
- **Discord-only sign-in.** Players sign in through the server's Discord OAuth2 flow (PKCE, single-use tickets). No passwords are stored and the app holds no server secrets.
- **Seamless re-authentication.** After **Logout**, **Delete Avatar** or an expired session, the client clears only its own sign-in state, asks for Discord again and goes straight back into the game or avatar creation.
- **In-app web pages and notices.** Odds, help and notice pages load from your server over verified TLS, without the old LINE service-closure popups.
- **Android re-signing compatibility.** Only the check that blocks a re-signed APK is adjusted; every other check stays as it was.

Verified so far:

- [x] Launch, Discord sign-in and entering the Garden
- [x] Logout → Discord → Garden
- [x] Delete Avatar → Discord → avatar creation → Garden
- [x] Android 17 (`arm64-v8a`) emulator
- [x] iOS virtual device, and iPhone 15 Pro Max (iOS 27.0) via Sideloadly
- [ ] 32-bit `armeabi-v7a` Android devices
- [ ] Other physical iPhones and signing tools (results vary; see [docs/ios.md](docs/ios.md))

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Supported clients

Raspberry refuses any input whose size and SHA-256 do not match the final release:

| Platform | Package / bundle | Version | Locked SHA-256 |
| --- | --- | --- | --- |
| **Android** | `jp.naver.lineplay.android` | `10.1.0.0` (versionCode `254`) | `aa6495a0430beef0c9a719a1f09fe836ff1c82a0f4f96235d47fffda070b45d1` |
| **iOS** | `jp.naver.lineplay` (decrypted `.ipa`) | `10.1.0` (build `10.1.0.0`) | `987fefccfc235cc73fdd6363c064887272575586f334b45fcb10d213a8772532` |

> [!IMPORTANT]
> Raspberry does not provide the game. Bring your own copy of exactly these files.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Getting started — Android (Windows)

### Prerequisites

- Go 1.27+
- JDK 25
- Android SDK (`android-37.0`, build-tools `36.0.0`)
- Android NDK r30 (`30.0.16248370`)
- mingw `gcc` (native host tests)
- `smali` 3.0.10 JARs

Exact versions and SHA-256 pins are in [docs/build.md](docs/build.md).

### 1. Build Raspberry

Run from the repository root (outputs stay in the git-ignored `build/`):

```powershell
git clone https://github.com/festivities/Raspberry.git
cd Raspberry
powershell -NoProfile -File scripts\build-native.ps1
powershell -NoProfile -File scripts\build-dex.ps1
powershell -NoProfile -File scripts\build-dexpatch.ps1
go build -o "$env:TEMP\raspberry\raspberry.exe" .\cmd\raspberry
```

### 2. Create a signing keystore (once, outside every repository)

Back up your keystore. Losing it means uninstalling the app before you can install future updates.

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

- Leave out `--port` for any port that stays at its default (`80`, `443`, `10000`, `10123`).
- The output is `raspberry-lineplay-10.1.0.0.apk`. Raspberry never overwrites an existing file.
- Install with `adb install raspberry-lineplay-10.1.0.0.apk` (`adb install -r` for updates signed with the same key).

### 4. Sign in

1. Launch LINE PLAY and tap **Discord**.
2. Finish Discord sign-in in the browser tab. If the browser asks whether to open LINE PLAY, allow it. The game comes back to the front on its own.
3. The game enters your account (or avatar creation for a new account) without the old LINE login screen.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Getting started — iOS (macOS)

### Prerequisites

- macOS with Xcode (`iPhoneOS` SDK)
- Go 1.27+

See [docs/build.md](docs/build.md) for details.

### 1. Build the runtime and patch your IPA

```sh
./scripts/build-ios-runtime.sh
go run ./cmd/raspberry ipa inspect --ipa /path/to/LINE_PLAY_10.1.0_decrypted.ipa
go run ./cmd/raspberry ipa patch \
  --ipa /path/to/LINE_PLAY_10.1.0_decrypted.ipa \
  --endpoint cherry.example.org \
  --port 443=8443 \
  --out /path/outside/repos/out
```

- The output is an unsigned `raspberry-lineplay-10.1.0-unsigned.ipa`. Raspberry never overwrites an existing file.

### 2. Sign and install

- Sign and install the IPA with your usual sideloading tool (for example Sideloadly).
- To update an existing install, use the same signing identity and installed bundle ID so iOS treats it as an update rather than a second app.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Security and known limits

- **No secrets in the app.** Only the server address and ports are embedded. The Cherry server handles Discord sign-in with PKCE (`S256`), a random `state` and short-lived single-use tickets.
- **Verified TLS where Raspberry adds traffic.** Discord sign-in, the token exchange, in-app web pages and notice requests use the platform's certificate checks, so your server needs a publicly trusted certificate for its hostname.
- **Inherited limit.** The game's own native connections keep the original client's disabled certificate checks. See [docs/security.md](docs/security.md).

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Troubleshooting

- **`baseline mismatch`** — your APK or IPA is not the exact final release. Compare its SHA-256 with the table above.
- **Install fails on Android with a signature error** — the installed app was signed with a different key. Uninstall it first, or patch with your original keystore.
- **The iOS app does not open after sideloading** — see the iOS notes in [docs/ios.md](docs/ios.md), then ask in the support channel.

For anything else, join [our Discord server](https://discord.gg/E9NNwhJmqN) and ask in the support channel.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Reporting issues

Report bugs on the [GitHub issue tracker](https://github.com/festivities/Raspberry/issues). Search existing issues first to avoid duplicates.

Please include your platform and device, how you installed the app, what you expected and what happened. **Never attach** your APK/IPA, keystore, logs containing cookies or tokens, or your server's private details.

Server-side problems (accounts, Discord settings, missing game data) belong in [Cherry](https://github.com/festivities/Cherry/issues).

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Contributing

Pull requests are welcome. Before opening one:

1. Run the gate: `scripts\gate.ps1` on Windows or `scripts/gate.sh` on macOS.
2. Document any new or changed patch in [docs/patches.md](docs/patches.md) (target, evidence, why, how to verify, risk).
3. Keep the change minimal and endpoint-agnostic: no hard-coded server addresses.
4. **Never commit** anything taken from the game (APK/IPA, `.so`, `.dex`, extracted resources, decompiler output), signing keys or device logs. `scripts/check-repo` enforces this.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Documentation

- [docs/usage.md](docs/usage.md) — full CLI commands and flags
- [docs/build.md](docs/build.md) — pinned toolchains, checksums and host gates
- [docs/patches.md](docs/patches.md) — exact patch inventory and verification status
- [docs/security.md](docs/security.md) — threat model, trust boundaries and inherited limits
- [docs/ios.md](docs/ios.md) — iOS architecture and test notes

## License

Distributed under the MIT License. See [LICENSE](LICENSE). This repository contains only original Raspberry code, patch tables and documentation. LINE PLAY and its assets belong to their respective owners.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- MARKDOWN LINKS & IMAGES -->
[discord-shield]: https://img.shields.io/discord/894925535870865498?style=for-the-badge&logo=discord&logoColor=white&label=Discord&color=5865F2
[discord-url]: https://discord.gg/E9NNwhJmqN
[license-shield]: https://img.shields.io/github/license/festivities/Raspberry?style=for-the-badge
[license-url]: https://github.com/festivities/Raspberry/blob/main/LICENSE
[commit-shield]: https://img.shields.io/github/last-commit/festivities/Raspberry?style=for-the-badge
[commit-url]: https://github.com/festivities/Raspberry/commits/main
[issues-shield]: https://img.shields.io/github/issues/festivities/Raspberry?style=for-the-badge
[issues-url]: https://github.com/festivities/Raspberry/issues
[stars-shield]: https://img.shields.io/github/stars/festivities/Raspberry?style=for-the-badge
[stars-url]: https://github.com/festivities/Raspberry/stargazers
