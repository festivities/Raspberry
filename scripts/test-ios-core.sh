#!/usr/bin/env bash
# Host tests for Foundation/C iOS cores, including fake browser ownership.
# Compiles pure C sources, then links their objects with Objective-C sources.
set -eu

here=$(CDPATH= cd -- "$(dirname "$0")" && pwd -P) || {
    printf 'test-ios-core: cannot locate scripts directory\n' >&2
    exit 1
}
root=$(CDPATH= cd -- "$here/.." && pwd -P) || {
    printf 'test-ios-core: cannot locate repository root\n' >&2
    exit 1
}

fail() {
    printf 'test-ios-core: %s\n' "$*" >&2
    exit 1
}

command -v clang >/dev/null 2>&1 || fail 'clang not found'
tmp_root=${TMPDIR:-/tmp}
tmp_root=$(CDPATH= cd -- "$tmp_root" && pwd -P) || fail 'cannot canonicalize TMPDIR'
case "$tmp_root" in
    */opencode) ;;
    *) tmp_root=$tmp_root/opencode ;;
esac
mkdir -p "$tmp_root" || fail "cannot create private scratch root $tmp_root"
tmp_root=$(CDPATH= cd -- "$tmp_root" && pwd -P) || fail 'cannot canonicalize private scratch root'
tmp=$(mktemp -d "$tmp_root/raspberry-ios-core.XXXXXX") || fail 'cannot create private test directory'
chmod 700 "$tmp" || fail 'cannot secure private test directory'
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

clang -std=c11 -Wall -Wextra -Werror \
    -I"$root/ios" \
    "$root/ios/enqueue_probe_image_test.c" \
    -o "$tmp/enqueue_probe_image_test" || fail 'compile enqueue image-selector tests'

"$tmp/enqueue_probe_image_test" || fail 'enqueue image-selector tests failed'

clang -std=c11 -Wall -Wextra -Werror \
    -I"$root/ios" \
    "$root/ios/RBCurlProbe.c" "$root/ios/curl_probe_test.c" \
    -o "$tmp/curl_probe_test" || fail 'compile cURL-probe host-fake tests'

"$tmp/curl_probe_test" || fail 'cURL-probe host-fake tests failed'

if command -v xcrun >/dev/null 2>&1; then
    if sdk=$(xcrun --sdk iphoneos --show-sdk-path 2>/dev/null) &&
        [ -d "$sdk" ]; then
        xcrun --sdk iphoneos clang -target arm64-apple-ios15.0 \
            -isysroot "$sdk" -std=c11 -Wall -Wextra -Werror \
            -I"$root/ios" -c "$root/ios/RBCurlProbe.c" \
            -o "$tmp/RBCurlProbe-ios15.o" ||
            fail 'cross-compile cURL-probe core for iOS 15'
    fi
fi

clang -std=c11 -Wall -Wextra -Werror \
    -I"$root/native" \
    -c "$root/native/endpoint.c" \
    -o "$tmp/endpoint.o" || fail 'compile endpoint.c'

clang -fobjc-arc -Wall -Wextra -Werror \
    -I"$root/ios" -I"$root/native" \
    "$root/ios/RBEndpoint.m" "$root/ios/endpoint_test.m" "$tmp/endpoint.o" \
    -framework Foundation \
    -o "$tmp/endpoint_test" || fail 'compile Foundation endpoint tests'

"$tmp/endpoint_test" || fail 'endpoint tests failed'

clang -fobjc-arc -Wall -Wextra -Werror \
    -I"$root/ios" -I"$root/native" \
    "$root/ios/RBEndpoint.m" "$root/ios/RBURLRewrite.m" \
    "$root/ios/url_rewrite_test.m" "$tmp/endpoint.o" \
    -framework Foundation \
    -o "$tmp/url_rewrite_test" || fail 'compile Foundation URL-rewrite tests'

"$tmp/url_rewrite_test" || fail 'URL-rewrite tests failed'

clang -fblocks -fobjc-arc -Wall -Wextra -Werror \
    -I"$root/ios" -I"$root/native" \
    "$root/ios/RBEndpoint.m" "$root/ios/RBAuthAttempt.m" "$root/ios/auth_attempt_test.m" "$tmp/endpoint.o" \
    -framework Foundation -framework Security \
    -o "$tmp/auth_attempt_test" || fail 'compile Foundation auth-attempt tests'

"$tmp/auth_attempt_test" || fail 'auth-attempt tests failed'

clang -DRB_AUTH_EXCHANGE_TESTING=1 -fblocks -fobjc-arc -Wall -Wextra -Werror \
    -I"$root/ios" -I"$root/native" \
    "$root/ios/RBEndpoint.m" "$root/ios/RBAuthAttempt.m" \
    "$root/ios/RBAuthExchangeClient.m" "$root/ios/auth_exchange_test.m" "$tmp/endpoint.o" \
    -framework Foundation -framework Security \
    -o "$tmp/auth_exchange_test" || fail 'compile Foundation auth-exchange tests'

"$tmp/auth_exchange_test" || fail 'auth-exchange tests failed'

clang -fblocks -fobjc-arc -Wall -Wextra -Werror \
    -I"$root/ios" -I"$root/native" \
    "$root/ios/RBEndpoint.m" "$root/ios/RBAuthAttempt.m" \
    "$root/ios/RBAuthBrowserSession.m" "$root/ios/browser_session_test.m" \
    "$tmp/endpoint.o" \
    -framework Foundation -framework Security \
    -o "$tmp/browser_session_test" || fail 'compile Foundation browser-session fake tests'

"$tmp/browser_session_test" || fail 'browser-session fake tests failed'

clang -fblocks -fobjc-arc -Wall -Wextra -Werror \
    -I"$root/ios" -I"$root/native" \
    "$root/ios/RBEndpoint.m" "$root/ios/RBAuthAttempt.m" \
    "$root/ios/RBAuthBrowserSession.m" "$root/ios/RBAuthExchangeClient.m" \
    "$root/ios/RBAuthStore.m" "$root/ios/RBAuthFlowCoordinator.m" \
    "$root/ios/auth_flow_coordinator_test.m" "$tmp/endpoint.o" \
    -framework Foundation -framework Security -framework CoreFoundation \
    -o "$tmp/auth_flow_coordinator_test" ||
    fail 'compile Foundation auth-flow coordinator fake tests'

"$tmp/auth_flow_coordinator_test" ||
    fail 'auth-flow coordinator fake tests failed'

clang -fblocks -fobjc-arc -Wall -Wextra -Werror \
    -I"$root/ios" \
    "$root/ios/RBAuthUIKitLifecycleStatusGate.m" \
    "$root/ios/auth_uikit_lifecycle_status_gate_test.m" \
    -framework Foundation \
    -o "$tmp/auth_uikit_lifecycle_status_gate_test" ||
    fail 'compile UIKit lifecycle status-gate tests'

"$tmp/auth_uikit_lifecycle_status_gate_test" ||
    fail 'UIKit lifecycle status-gate tests failed'

clang -fobjc-arc -Wall -Wextra -Werror \
    -I"$root/ios" \
    "$root/ios/RBAuthCallbackSanitizer.m" \
    "$root/ios/auth_callback_sanitizer_test.m" \
    -framework Foundation \
    -o "$tmp/auth_callback_sanitizer_test" ||
    fail 'compile Foundation auth-callback sanitizer tests'

"$tmp/auth_callback_sanitizer_test" ||
    fail 'auth-callback sanitizer tests failed'

clang -DRB_NOTICE_ROUTE_TESTING=1 -fblocks -fobjc-arc -Wall -Wextra -Werror \
    -I"$root/ios" -I"$root/native" \
    "$root/ios/RBEndpoint.m" "$root/ios/RBURLRewrite.m" \
    "$root/ios/RBNoticeRouteClient.m" "$root/ios/RBNoticeRouteErrorAdapter.m" \
    "$root/ios/notice_route_client_test.m" "$tmp/endpoint.o" \
    -framework Foundation \
    -o "$tmp/notice_route_client_test" ||
    fail 'compile Foundation notice-route client tests'

"$tmp/notice_route_client_test" ||
    fail 'notice-route client tests failed'

clang -fobjc-arc -Wall -Wextra -Werror \
    -I"$root/ios" -I"$root/native" \
    "$root/ios/RBEndpoint.m" "$root/ios/RBAuthStore.m" \
    "$root/ios/auth_store_test.m" "$tmp/endpoint.o" \
    -framework Foundation -framework CoreFoundation \
    -o "$tmp/auth_store_test" ||
    fail 'compile Foundation auth-store tests'

"$tmp/auth_store_test" ||
    fail 'auth-store tests failed'

clang -fblocks -fobjc-arc -Wall -Wextra -Werror \
    -I"$root/ios" -I"$root/native" \
    "$root/ios/RBEndpoint.m" "$root/ios/RBAuthAttempt.m" \
    "$root/ios/RBAuthBrowserSession.m" "$root/ios/RBAuthExchangeClient.m" \
    "$root/ios/RBAuthStore.m" "$root/ios/RBAuthFlowCoordinator.m" \
    "$root/ios/RBAuthGuestCredentialGate.m" \
    "$root/ios/auth_guest_credential_gate_test.m" "$tmp/endpoint.o" \
    -framework Foundation -framework Security -framework CoreFoundation \
    -o "$tmp/auth_guest_credential_gate_test" ||
    fail 'compile Foundation auth-guest-credential-gate tests'

"$tmp/auth_guest_credential_gate_test" ||
    fail 'auth-guest-credential-gate tests failed'

clang -std=c11 -Wall -Wextra -Werror \
    -I"$root/ios" -I"$root/native" \
    "$root/ios/RBSocketRouter.c" "$root/ios/socket_router_test.c" "$tmp/endpoint.o" \
    -lpthread \
    -o "$tmp/socket_router_test" ||
    fail 'compile iOS socket-router tests'

"$tmp/socket_router_test" ||
    fail 'iOS socket-router tests failed'

if command -v xcrun >/dev/null 2>&1; then
    if sdk=$(xcrun --sdk iphoneos --show-sdk-path 2>/dev/null) &&
        [ -d "$sdk" ]; then
        xcrun --sdk iphoneos clang -target arm64-apple-ios15.0 \
            -isysroot "$sdk" -std=c11 -Wall -Wextra -Werror \
            -I"$root/native" -c "$root/native/endpoint.c" \
            -o "$tmp/endpoint-ios15.o" ||
            fail 'cross-compile endpoint C core for iOS 15'

        xcrun --sdk iphoneos clang -target arm64-apple-ios15.0 \
            -isysroot "$sdk" -std=c11 -Wall -Wextra -Werror \
            -I"$root/ios" -I"$root/native" -c "$root/ios/RBSocketRouter.c" \
            -o "$tmp/RBSocketRouter-ios15.o" ||
            fail 'cross-compile RBSocketRouter for arm64 iOS 15'

        for source in RBEndpoint RBURLRewrite RBAuthAttempt RBAuthBrowserSession \
            RBAuthExchangeClient RBAuthFlowCoordinator RBAuthStore \
            RBAuthGuestCredentialGate \
            RBNoticeRouteClient RBNoticeRouteErrorAdapter \
            RBAuthUIKitOwnerConditions RBASWebAuthenticationSessionDriver \
            RBAuthUIKitLifecycleStatusGate RBAuthUIKitLifecycleBinding \
            RBAuthCallbackSanitizer; do
            xcrun --sdk iphoneos clang -target arm64-apple-ios15.0 \
                -isysroot "$sdk" -fblocks -fobjc-arc \
                -Wall -Wextra -Werror \
                -I"$root/ios" -I"$root/native" \
                -c "$root/ios/$source.m" \
                -o "$tmp/$source-ios15.o" ||
                fail "cross-compile $source for arm64 iOS 15"
        done
        printf 'iOS core arm64 SDK compile: ok\n'
    fi
fi
