#!/usr/bin/env bash
# Build the arm64 iOS 15 Raspberry runtime dylib from tracked ios/ and native/
# sources to build/ios/libraspberry.dylib (or an optional $1 / OUT path).
# Does not download tools or run a packaging/signing workflow.
set -euo pipefail

here=$(CDPATH= cd -- "$(dirname "$0")" && pwd -P) || {
    printf 'build-ios-runtime: cannot locate scripts directory\n' >&2
    exit 1
}
root=$(CDPATH= cd -- "$here/.." && pwd -P) || {
    printf 'build-ios-runtime: cannot locate repository root\n' >&2
    exit 1
}

fail() {
    printf 'build-ios-runtime: %s\n' "$*" >&2
    exit 1
}

command -v xcrun >/dev/null 2>&1 || fail 'xcrun not found'
sdk=$(xcrun --sdk iphoneos --show-sdk-path) || fail 'iPhoneOS SDK not found'

c_sources=(
    "$root/native/endpoint.c"
    "$root/ios/RBSocketRouter.c"
)

objc_sources=(
    "$root/ios/RBRaspberryRuntime.m"
    "$root/ios/RBEndpoint.m"
    "$root/ios/RBURLRewrite.m"
    "$root/ios/RBWebURLRouter.m"
    "$root/ios/RBNoticeRouteClient.m"
    "$root/ios/RBNoticeRouteErrorAdapter.m"
    "$root/ios/RBAuthAttempt.m"
    "$root/ios/RBAuthBrowserSession.m"
    "$root/ios/RBAuthExchangeClient.m"
    "$root/ios/RBAuthFlowCoordinator.m"
    "$root/ios/RBAuthStore.m"
    "$root/ios/RBAuthGuestCredentialGate.m"
    "$root/ios/RBAuthSignInSessionController.m"
    "$root/ios/RBAuthUIKitOwnerConditions.m"
    "$root/ios/RBASWebAuthenticationSessionDriver.m"
    "$root/ios/RBAuthUIKitLifecycleStatusGate.m"
    "$root/ios/RBAuthUIKitLifecycleBinding.m"
    "$root/ios/RBAuthUIKitSignInOverlay.m"
    "$root/ios/RBAuthCallbackSanitizer.m"
)

for src in "${c_sources[@]}" "${objc_sources[@]}"; do
    test -f "$src" || fail "missing $src"
done

requested=${1:-${OUT:-$root/build/ios/libraspberry.dylib}}
case "$requested" in
    /*) ;;
    *) requested=$PWD/$requested ;;
esac
out_dir=$(dirname "$requested")
out_name=$(basename "$requested")
test -n "$out_name" && test "$out_name" != "." && test "$out_name" != "/" ||
    fail 'output must name a file'
mkdir -p "$out_dir" || fail "cannot create $out_dir"
out_dir=$(CDPATH= cd -- "$out_dir" && pwd -P) || fail 'cannot resolve output directory'
out=$out_dir/$out_name

case "$out" in
    "$root"/build/*) ;;
    "$root"/*) fail 'repository output must be under ignored build/' ;;
    *) ;;
esac
test ! -L "$out" || fail 'refusing a symlink output'
test ! -d "$out" || fail 'output path is a directory'

tmp_root=${TMPDIR:-/tmp}
tmp_root=$(CDPATH= cd -- "$tmp_root" && pwd -P) || fail 'cannot canonicalize TMPDIR'
case "$tmp_root" in
    */opencode) ;;
    *) tmp_root=$tmp_root/opencode ;;
esac
mkdir -p "$tmp_root" || fail "cannot create private scratch root $tmp_root"
tmp_root=$(CDPATH= cd -- "$tmp_root" && pwd -P) || fail 'cannot canonicalize private scratch root'
tmp=$(mktemp -d "$tmp_root/raspberry-ios-runtime.XXXXXX") || fail 'cannot create temporary build directory'
chmod 700 "$tmp" || fail 'cannot secure temporary build directory'
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

printf '%s\n' \
    '_rb_ios_notice_404_diagnostic_entry' \
    '_rb_ios_getaddrinfo' \
    '_rb_ios_freeaddrinfo' \
    '_rb_ios_gethostbyname' \
    '_rb_ios_connect' \
    '_rb_ios_guest_unique_code' > "$tmp/exported-symbols.list"

xcrun --sdk iphoneos clang \
    -target arm64-apple-ios15.0 -isysroot "$sdk" \
    -std=c11 -Wall -Wextra -Werror -fvisibility=hidden \
    -I"$root/native" \
    -c "$root/native/endpoint.c" \
    -o "$tmp/endpoint-ios15.o" || fail 'compile endpoint.c failed'

xcrun --sdk iphoneos clang \
    -target arm64-apple-ios15.0 -isysroot "$sdk" \
    -std=c11 -Wall -Wextra -Werror -fvisibility=hidden \
    -I"$root/ios" -I"$root/native" \
    -c "$root/ios/RBSocketRouter.c" \
    -o "$tmp/socket-router-ios15.o" || fail 'compile RBSocketRouter.c failed'

xcrun --sdk iphoneos clang -dynamiclib \
    -target arm64-apple-ios15.0 -isysroot "$sdk" \
    -fblocks -fobjc-arc -Wall -Wextra -Werror -fvisibility=hidden \
    -I"$root/ios" -I"$root/native" \
    "${objc_sources[@]}" \
    "$tmp/socket-router-ios15.o" \
    "$tmp/endpoint-ios15.o" \
    -framework Foundation -framework CoreFoundation -framework CoreGraphics -framework UIKit \
    -framework AuthenticationServices -framework Security -framework QuartzCore -framework WebKit \
    -Wl,-install_name,@rpath/libraspberry.dylib \
    -current_version 1.0.0 \
    -compatibility_version 1.0.0 \
    -Wl,-exported_symbols_list,"$tmp/exported-symbols.list" \
    -o "$out" || fail 'clang dynamiclib link failed'

archs=$(xcrun lipo -archs "$out") || fail 'cannot inspect output architecture'
test "$archs" = arm64 || fail "output architecture is $archs, want arm64 only"

install_name=$(xcrun otool -D "$out" | tail -n +2 | tr -d '[:space:]')
if [ "$install_name" != "@rpath/libraspberry.dylib" ]; then
    fail "unexpected install name '$install_name' in $out"
fi

expected_exports=$(LC_ALL=C sort "$tmp/exported-symbols.list")
exported=$(xcrun nm -gU "$out" | awk '{print $NF}' | LC_ALL=C sort)
if [ "$exported" != "$expected_exports" ]; then
    fail "unexpected exported symbols in $out: $exported"
fi

printf 'build-ios-runtime: %s\n' "$out"
