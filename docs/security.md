# Security boundaries

Raspberry patches a player's own, hash-checked LINE PLAY 10.1.0.0 APK. It does not distribute the game, store Discord passwords or embed an operator's secrets. The endpoint is operator configuration, not a secret.

The iOS 10.1.0 IPA is under active, separate assessment; the inspector and logging-only loader probe are not a complete patcher. Static review found the same abnormal AirArmor state set and disabled verification in the inspected native CurlWrapper, not weaker enforcement or permission to alter protection behavior. Apple networking retains a separate trust boundary. See [ios.md](ios.md).

For iOS, never replace the shared device UUID with a Discord credential: it also feeds telemetry and cookie/request state. A narrower guest-auth argument is under investigation. The stock URL callback logs complete URLs before forwarding to SDKs, so confidential auth callbacks must be intercepted before that path. No deployed iOS auth gate, credential storage policy or routing acceptance is established.

## Required checks

- Redirect only the documented game-host allowlist. Unrelated traffic must remain unchanged even when it shares an IP address with the endpoint. Endpoint failures must not fall back to LINE's hosts.
- Validate the endpoint hostname and destination ports. Only patch-time configuration and app-private storage may supply them; browser callbacks cannot change them.
- Authenticate Java-side endpoint requests with platform TLS validation. A development certificate pin must be explicit, endpoint-scoped and loudly identified as a lab option; it is not a trust-all switch.
- Bind each Discord attempt to this device with random state and S256 PKCE. Accept only a live attempt's matching return, then exchange a short-lived, single-use ticket. Do not log credentials or callback query strings.
- Change only the client's re-signing compatibility case. Unrelated compatibility states are outside the patch's scope.
- Keep keystores, password files, patched APKs, raw logs, captures and APK-derived analysis outside Git. Package installations must not modify global Python.

These are acceptance requirements, not a claim that unfinished components have passed testing. See `.agents/PLAN.md` for implementation status.

The current `--dev-pin-sha256` implementation is an **additional** leaf-certificate check after platform trust, scoped to Java endpoint requests. It does not yet provide the planned self-signed lab mode and cannot change Chrome, Custom Tabs or WebView trust. Those browsers still require a trusted endpoint certificate; do not bypass their certificate warnings to claim sign-in or web acceptance.

Stored authorization is bound to the descriptor's canonical HTTPS origin. Changing that origin, or finding an older unbound marker, requires fresh SSO rather than sending the saved code to another operator. Fresh SSO removes only the old `files/avcookie.na` game-session credential before saving the new authorization; failure to remove it stops authorization. Accounts, downloaded assets and other preferences are not deleted. Ordinary same-origin relaunch preserves the session.

Java notice requests use their own scoped authority rewrite, not the native resolver hook. Recognized LINE targets require validated configuration, use the mapped HTTP/HTTPS port and do not follow redirects; HTTPS keeps platform trust plus any explicitly configured additional pin. The notice-list cache has a separate endpoint-origin marker. Migration removes only the two notice tables' cached content/read history and four list cursor/time keys, then commits the marker last; a failure returns through the SDK's error path before cache use or request construction. This is not a general notice filter, account cleanup or whole-SDK cache reset.

## Inherited native-transport limit

Static analysis recorded in `.agents/AGENTS.md` shows that the stock native libcurl stack disables certificate and hostname verification. Preserving original Host/SNI while redirecting sockets **does not fix that**. Native game credentials and session traffic remain vulnerable to an active network attacker. Plain HTTP and the game's legacy socket protocols are not authenticated HTTPS either.

Platform TLS validation for OAuth, discovery and WebView pages does not protect separate native connections. Do not describe a patched client as providing authenticated native transport, and do not use a successful local smoke test as evidence of production transport security. Hardening this requires a separately verified client/server design; this document does not authorize weakening Java TLS or unrelated client compatibility checks as a workaround.

The server must enforce Discord-only account issuance and authorization independently. A client-side overlay is not a server security boundary.
