# Usage

`raspberry` is a patch driver, not a single self-contained binary. It checks the locked LINE PLAY 10.1.0.0 APK, applies already-built artifacts with the pinned JDK, Android SDK and smali tools, and signs an APK outside every git repository. It does not download tools, embed a key, or redistribute the game.

Build the artifacts first, from the repository root. These scripts write only under the gitignored `build\` tree:

```
powershell -File scripts\build-native.ps1
powershell -File scripts\build-dex.ps1
powershell -File scripts\build-dexpatch.ps1
go build -o $env:TEMP\opencode\raspberry\raspberry.exe .\cmd\raspberry
```

`build-native.ps1` needs NDK r30 (`%LOCALAPPDATA%\Android\Sdk\ndk\30.0.16248370` unless `ANDROID_NDK_HOME` is set) and mingw gcc for its host tests. `build-dex.ps1` needs `javac`, SDK platform `android-37.0` and build-tools `36.0.0` `d8`. `build-dexpatch.ps1` needs JDK 25 and the pinned smali 3.0.10 jars at `%LOCALAPPDATA%\Raspberry\tools\smali\3.0.10\lib`. Pins and the reason those tools are not one executable are in [build.md](build.md).

Then, with the keystore and output directory outside every repository (for example under `%LOCALAPPDATA%\Raspberry\` and `%TEMP%\opencode\raspberry\`):

```
& $env:TEMP\opencode\raspberry\raspberry.exe patch `
  --apk <pristine.apk> `
  --endpoint <host> `
  --port 443=<https-port> `
  --out <absolute-dir-outside-any-repo> `
  --keystore <absolute-keystore-outside-any-repo> `
  --password-file <absolute-owner-only-password-file>
```

The signed file name is fixed: `raspberry-lineplay-10.1.0.0.apk`. An existing file is not overwritten.

Installing a build for a different HTTPS origin requires fresh Discord SSO; it does not reuse the previous operator's saved authorization. A fresh SSO clears the old game-session cookie, not accounts or downloaded assets. Losing/changing the APK signing key still requires uninstalling the old app before Android will accept the replacement.

## Commands

`verify --apk <file>` checks size and SHA-256 only. Any other input is refused. The error text is the size and digest, never file bytes.

`keygen --keystore <absolute-new-file> (--password-file <file> | --password-env <name>)` creates a 3072-bit RSA PKCS#12 keystore through the JDK `keytool`. The password is the store password and the key password. It is never an argument. Back up the keystore: losing it means reinstalling every build made with it. `sign` keeps the keystore owner-only and refuses a loose key at sign time.

`patch` requires `--apk`, `--endpoint`, `--out` and `--keystore`, plus exactly one of `--password-file` or `--password-env`. `--out` and `--keystore` must be absolute. Both, and the output file, are refused when they sit inside a git worktree, including this repository and the read-only game archives. Relative paths are refused before any APK byte is hashed and before any output file is created.

Repeatable `--port <client>=<endpoint>` accepts client ports 80, 443, 10000 and 10123. Omitted ports stay identity. The endpoint is a DNS name or an IPv4 literal; `198.18.0.1` is reserved by the native hook and rejected. The baked asset is the shared descriptor serializer (`v`, then `host`, then `ports`).

`--build` defaults to `build` and must already contain `native/arm64-v8a/libraspberry.so`, `native/armeabi-v7a/libraspberry.so` and `dex/classes5.dex`. `--patches` defaults to `patches` (`libgame-arm64.tbl`, `libgame-armv7.tbl`). `--dexpatch-classpath` defaults to `build\dexpatch` plus the pinned smali `lib\*`. `--java`, `--keytool`, `--zipalign` and `--apksigner` default to this lab's JDK and SDK build-tools 36.0.0 (`apksigner.jar`, not the `.bat`). Override them with absolute paths when the defaults are wrong. `JAVA_HOME` on this host may point at `bin`; the default lookup checks both.

After the native tables are applied, patch runs dexpatch `patch` and then dexpatch `verify` on `classes3.dex`. Verify must succeed before the APK is assembled or signed. Signing uses zipalign, then apksigner v1+v2+v3, then signature verification. JDK 25 may print a native-access warning on success; the process exit status is the result.

`--dev-pin-sha256` is optional and off by default. It is 64 hex characters, the SHA-256 of the endpoint leaf certificate, written only to `assets/raspberry/devPinSha256` when the flag is set. The client still requires platform certificate validation first; the pin is an extra check for that endpoint. It does not make a self-signed certificate trusted, and it does not change WebView or Chrome trust. A build that sets it prints a lab warning.

`version` prints `raspberry 0.0.0-r0`.

## Limits

Combined signed reruns have been verified byte-identical, with exactly the [documented entry changes](patches.md). Full game/auth/web acceptance is still pending. Native game TLS verification stays disabled in the stock client; see [security.md](security.md). The patcher does not fix that. A successful local sign is not evidence of production transport security. The DEX verifier checks untouched methods and full expected edited bodies; the command refuses to sign when that check fails.
