# iOS compatibility assessment

The initial static assessment of the supplied decrypted LINE PLAY 10.1.0 IPA is complete, with the unresolved questions below. Raspberry's CLI still accepts only its locked Android APK; it does not patch or sign IPAs. The source archive stays read-only, and extracted binaries, disassembly and analysis databases stay outside Git.

No iOS runtime is available (user, 2026-11-12). Static results cannot establish that re-signing, AirArmor, login, networking or gameplay works on a device.

## Static findings (2026-11-12)

- **[S] Baseline:** 27,000,608 bytes; IPA SHA-256 `987fefccfc235cc73fdd6363c064887272575586f334b45fcb10d213a8772532`. Bundle `jp.naver.lineplay`, version 10.1.0 / build 10.1.0.0. The package requires iOS 15.0 and supports iPhone/iPad. The main executable is arm64 for an iOS device, not Simulator.
- **[S] Decryption is not signing:** the main executable and nine embedded Mach-O frameworks have `cryptid=0` in the inspected encryption commands. Signature data remains, but no embedded provisioning profile was found. Signature validity and installability have not been checked with Apple tools.
- **[S] Protection code is present:** AirArmor-related `asdk` type information, bundle/Mach-O signature verification and debugger detection were found. `sub_101451DC0` feeds a signature-verification-failure result into event **6** in `sub_101451338`; a `sysctl`/`P_TRACED` check feeds event **8**. Other detector names are present, but names alone do not prove those checks run.
- **[S] App-level handling is present:** a worker dispatches event 6 to the callback registered during `AppController` launch. The callback reaches state setter `sub_1010A1810` (field `+52`), whose latch and game-tick consumer use mask `0x672`. Its set bits classify states **1, 4, 5, 6, 9 and 10** as abnormal, matching Android's documented set. This is not merely an SDK event list.
- **[S] State 6 has a message path:** `sub_1010A09BC` calls `sub_1010A0AF0`, which builds localized text containing `[AA-006]` and submits a generic message through `sub_1001F9A24`. It does not enter the later inspected `CNaCheatingBlockPopup` branch. That named branch's absence does not mean the generic message is harmless.
- **[?] Final effect remains unresolved:** the concrete handler behind the generic message dispatch has not been recovered. Whether a legitimate re-sign triggers event 6, and whether `[AA-006]` becomes visible or blocks gameplay, need further evidence. A verifier skip predicate tests a global for null; no platform-specific PlayCover exemption was identified.

**Comparison:** the inspected iOS build has signature verification, event dispatch and the same abnormal-state classification as Android. There is no evidence here that it has weaker AirArmor enforcement. No iOS compatibility byte patch is justified at this checkpoint. Keep the Android state-6 patch Android-only; establish the actual iOS message effect and whether a legitimate re-sign triggers a blocker first.

Network/crypto imports, WebKit linkage and permissive ATS settings were inventoried, but actual game/login/WebView call paths and TLS verification were not traced. Android's disabled native certificate verification must not be assumed to apply to iOS.

## Later macOS testing

- **Apple Silicon Mac:** needed for [PlayCover](https://docs.playcover.io/getting_started/download_playcover.html). It runs device apps through a wrapper, not a conventional iOS emulator. It is a possible launch/rendering smoke-test environment, not evidence of iPhone AirArmor behavior. LINE PLAY compatibility is untested.
- **Xcode and Command Line Tools:** provide the Apple SDK/build tools for Raspberry's own native code, plus LLDB, `codesign`, `otool` and device/crash-log tooling. Xcode's Simulator requires simulator-targeted binaries; a decrypted device IPA is not directly a Simulator build, even when both use arm64 ([Apple TN3117](https://developer.apple.com/documentation/technotes/tn3117-resolving-build-errors-for-apple-silicon)).
- **For device acceptance:** an iPhone/iPad, USB connection, compatible OS and a valid development/ad-hoc signing and provisioning path for the app and its required entitlements. Enable [Developer Mode](https://developer.apple.com/documentation/xcode/enabling-developer-mode-on-a-device) if the device/signing workflow requires it. Keep certificates, private keys and provisioning profiles outside Git. Exact entitlement requirements must be checked before choosing a signing tool; decrypted does not mean installable unsigned.
- **Test server:** an isolated Cherry instance and a browser-trusted HTTPS endpoint for OAuth and web pages. Do not bypass certificate warnings or use Cherry's live lab data to claim acceptance.

Start with a re-signed baseline copy, then the smallest compatibility patch if one is needed, comparing logs/screens before adding routing and authentication changes. Record any modifications PlayCover itself makes. Do not enable its [jailbreak/protection bypass](https://docs.playcover.io/settings/jailbreak_bypass.html) features in an AirArmor acceptance run. Frida is optional for separate diagnostic work, not a prerequisite or an acceptance-test dependency.

PlayCover's [official releases](https://github.com/PlayCover/PlayCover/releases) should be checked again when a Mac is available; choose and record the exact version then. Do not weaken macOS system protections as a default setup step.
