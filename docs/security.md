# Security boundaries

Raspberry patches a player's own, hash-checked LINE PLAY 10.1.0.0 APK. It does not distribute the game, store Discord passwords or embed an operator's secrets. The endpoint is operator configuration, not a secret.

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

## Inherited native-transport limit

Static analysis recorded in `.agents/AGENTS.md` shows that the stock native libcurl stack disables certificate and hostname verification. Preserving original Host/SNI while redirecting sockets **does not fix that**. Native game credentials and session traffic remain vulnerable to an active network attacker. Plain HTTP and the game's legacy socket protocols are not authenticated HTTPS either.

Platform TLS validation for OAuth, discovery and WebView pages does not protect separate native connections. Do not describe a patched client as providing authenticated native transport, and do not use a successful local smoke test as evidence of production transport security. Hardening this requires a separately verified client/server design; this document does not authorize weakening Java TLS or unrelated client compatibility checks as a workaround.

The server must enforce Discord-only account issuance and authorization independently. A client-side overlay is not a server security boundary.
