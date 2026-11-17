#!/usr/bin/env bash
# Host-only tests for the pure-C image selector and Foundation endpoint/auth cores.
# Compiles pure C sources, then links the endpoint object with Objective-C sources.
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
    -I"$root/native" \
    -c "$root/native/endpoint.c" \
    -o "$tmp/endpoint.o" || fail 'compile endpoint.c'

clang -fobjc-arc -Wall -Wextra -Werror \
    -I"$root/ios" -I"$root/native" \
    "$root/ios/RBEndpoint.m" "$root/ios/endpoint_test.m" "$tmp/endpoint.o" \
    -framework Foundation \
    -o "$tmp/endpoint_test" || fail 'compile Foundation endpoint tests'

"$tmp/endpoint_test" || fail 'endpoint tests failed'

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
