# Build

Raspberry is under development. The CLI combines the locally built artifacts and signs a player's own locked APK; see [usage.md](usage.md). Game/auth/web acceptance is separate from a successful build. No game binaries, decompiler output, signing keys or operator configuration belong in this repository.

## Tools

The Windows lab uses Go 1.27.1, mingw gcc 16.1.0, Temurin JDK 25.0.3 and Android SDK build-tools 36.0.0. Set `JAVA_HOME` to the JDK **root**, not its `bin` directory, for each build process. Existing build-tools provide aapt2 2.20-13193326, d8 8.10.9-dev, apksigner 0.9 and zipalign with `-P 16` support.

These additional tools were installed in user space and verified on 2026-11-10. Digests refer to downloaded archives/JARs, not extracted directories.

| Tool | Official download | SHA-256 |
| --- | --- | --- |
| NDK r30 LTS, 30.0.16248370 | [Windows ZIP](https://dl.google.com/android/repository/android-ndk-r30-windows.zip) | `b830098aaf18b67a42eb831c404e15e5f2990a474f054ac145b0bc957ac6d729` |
| cmdline-tools build 15859902, revision 22.0 | [Windows ZIP](https://dl.google.com/android/repository/commandlinetools-win-15859902_latest.zip) | `90ae805d20434428bffcb699c290860f19bb5f66a67e6b330067e3de801fb04a` |
| apktool 3.0.3 | [JAR](https://github.com/iBotPeaches/Apktool/releases/download/v3.0.3/apktool_3.0.3.jar) | `dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423` |
| jadx 1.5.6 | [ZIP](https://github.com/skylot/jadx/releases/download/v1.5.6/jadx-1.5.6.zip) | `545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974` |

Google's [NDK downloads page](https://developer.android.com/ndk/downloads) published only SHA-1 for this ZIP: `9bf167a1985fa7d4a036186b78f702eab9179408` (727,980,788 bytes). That upstream value was matched before extraction; the SHA-256 above is the resulting local pin, not an upstream SHA-256 claim. The other primary downloads matched upstream SHA-256 values.

NDK clang is 21.0.0. The lab installs NDK/cmdline-tools under the Android SDK, and other tools under `%LOCALAPPDATA%\Raspberry\tools\`. Tool wrappers correct `JAVA_HOME` only for their child process. No global environment changes or blanket `sdkmanager --licenses` invocation were made.

### Smali tooling

smali and baksmali 3.0.10 use the official [Google Maven release channel](https://github.com/google/smali). Both command wrappers run with a JAR classpath; these are not single executable JARs. Artifact URLs for the four smali components are `https://dl.google.com/dl/android/maven2/com/android/tools/smali/<artifact>/3.0.10/<artifact>-3.0.10.jar`.

| Artifact | SHA-256 |
| --- | --- |
| smali | `b54c34f7a1b769b1e637f8a26909c68f399c273f3e5cde3e308e91107c135305` |
| smali-baksmali | `7d6578dfe5c44f1984b64268e91834432b0942d49e08186a501039dd92b58213` |
| smali-dexlib2 | `688dee6a46962a4dd1774b64be926534b0b6504bfd5d5c9f89c0f5af284f50c1` |
| smali-util | `cc2ef8349765644e4b15371f2c9f77d69b5412a094a38fe5fd992a124b7322fe` |

Runtime dependencies from Maven Central, with their Maven coordinates and pinned JAR SHA-256:

| Coordinates | SHA-256 |
| --- | --- |
| org.antlr:antlr:3.5.2 | `5ac36c2acfb0a0f3d37dafe20b5b570f2643e2d000c648d44503c2738be643df` |
| org.antlr:antlr-runtime:3.5.2 | `ce3fc8ecb10f39e9a3cddcbb2ce350d272d9cd3d0b1e18e6fe73c3b9389c8734` |
| org.antlr:stringtemplate:3.2.1 | `f66ce72e965e5301cb0f020e54d2ba6ad76feb91b3cbfc30dbbf00c06a6df6d7` |
| org.jcommander:jcommander:1.85 | `fa7552d2831a2b20778d86851d093edca68fbc0a77f792b6223110e4fae67a70` |
| com.google.guava:guava:31.1-android | `32ac2ed709d96d278b5d2e3e5cea178fa4939939c525fb647532f013308db309` |
| com.google.code.findbugs:jsr305:3.0.2 | `766ad2a0783f2687962c8ad74ceecc38a28b9f72a2d085ee438b7813e928d0c7` |
| com.google.guava:failureaccess:1.0.1 | `a171ee4c734dd2da837e4b16be9df4661afab72a41adaf31eb84dfdaf936ca26` |
| com.google.guava:listenablefuture:9999.0-empty-to-avoid-conflict-with-guava | `b372a037d4230aa57fbeffdef30fd6123f9c0c2db85d0aced00c91b974f33f99` |

The Google Maven components and jcommander matched upstream SHA-256 sidecars; other Maven dependencies matched upstream SHA-1 before these SHA-256 pins were recorded. Annotation-only checker-qual, error_prone_annotations and j2objc-annotations were not installed. Revisit that omission if a later tool invocation reports missing classes from those packages.

A synthetic javac → d8 → baksmali → smali → baksmali check passed. That is not proof that the game's four DEX files round-trip correctly; the static spike must test them separately.

## Signing checks

Always align **before** signing. The existing tools verified the pristine APK's signature and expected package/version on a private working copy. JDK 25's native-access warning can be suppressed for apksigner with `java --enable-native-access=ALL-UNNAMED -jar ...`; do not mistake stderr warnings for a failed process without checking the exit status.

Signing keys and APK outputs must be outside every repository. Two private combined builds were byte-identical after signing. The retained compressed payloads matched the baseline, with exactly the documented replacements/additions and signing-metadata changes. Signing publishes with a no-replace hard link; filesystems that cannot hard-link fail closed.

## Python

Never use global host Python for this project. Create a repository-local `.venv` before running host Python, including standard-library scripts; `.venv/` is ignored. Invoke `.venv/bin/python` on macOS or `.venv\Scripts\python.exe` on Windows. Ask before installing Python packages or other tools. IDAPython runs inside IDA.

## macOS host checks

User-approved Go 1.27.4 (darwin/arm64) is installed at the standard **`/usr/local/go`** location, owned by root/wheel and available through `~/.zshrc`'s `/usr/local/go/bin` PATH entry. It was initially installed in a Raspberry-named user tools directory, then moved with the user's administrator approval; the old Go directory is gone. A new interactive zsh reports Go 1.27.4 and `GOROOT=/usr/local/go`. The [official archive](https://go.dev/dl/go1.27.4.darwin-arm64.tar.gz), 68,231,011 bytes, matched upstream SHA-256 `91a44a2b8a716600ad94a4f143e156116620db8828086a6e3602291be9bd0bb4` before extraction. The host gate sets `GOTOOLCHAIN=local` to prevent automatic toolchain downloads. No unrelated shell configuration was changed.

Run `bash scripts/gate.sh` with Go, `gofmt`, Git and a C compiler on the process PATH (`CC` may select the compiler). This is the Bash counterpart to the Windows host gate, not an Android/iOS SDK build or device-acceptance test. It runs formatting, vet, Go tests, native host tests and repository-hygiene checks. Native executables and synthetic index fixtures are created in private temporary directories, not in the repository.

The index-only hygiene check and its synthetic regressions can run independently:

```sh
bash scripts/check-repo_test.sh
bash scripts/check-repo.sh
```

Existing Xcode 27.2 provides an iPhoneOS 27.2 SDK and Apple clang/signing tools on the November 17 macOS host; no additional iOS SDK installation is currently needed. Avoid `simctl` for this vphone workflow: an inventory call unexpectedly triggered a CoreSimulator service replacement on first use. This did not establish that an iOS simulator runtime was installed. Use `vphone-launchpad-cli` for the existing virtual iPhone; see [ios.md](ios.md) for the runtime-evidence limits.

### Experimental iOS loader probe

`bash scripts/build-ios-loader.sh` builds only Raspberry's logging-only arm64 dylib under ignored `build/ios/`. It uses the installed iPhoneOS SDK, minimum iOS 15.0 and dylib current/compatibility versions 1.0.0. It does not download tools, package an IPA or invoke a provisioning/signing workflow; the Apple linker may add its own ad-hoc Mach-O signature.

`internal/ipa.AddLoader` is a hash-locked, in-memory preparation primitive, not a public IPA-patching command. Its output requires re-signing. Private developer packages were installed only through vphoned, which bypasses installd/provisioning. See [patches.md](patches.md) and [ios.md](ios.md); this probe implements neither endpoint routing nor Discord sign-in.
