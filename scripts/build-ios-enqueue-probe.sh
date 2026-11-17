#!/usr/bin/env bash
# Build the arm64 iOS 15 diagnostic enqueue probe to a private or ignored path.
# This compiles only our loader and probe sources; it does not sign, package,
# install, or launch the resulting dylib.
set -euo pipefail

here=$(CDPATH= cd -- "$(dirname "$0")" && pwd -P) || {
    printf 'build-ios-enqueue-probe: cannot locate scripts directory\n' >&2
    exit 1
}
root=$(CDPATH= cd -- "$here/.." && pwd -P) || {
    printf 'build-ios-enqueue-probe: cannot locate repository root\n' >&2
    exit 1
}

fail() {
    printf 'build-ios-enqueue-probe: %s\n' "$*" >&2
    exit 1
}

command -v xcrun >/dev/null 2>&1 || fail 'xcrun not found'
sdk=$(xcrun --sdk iphoneos --show-sdk-path) || fail 'iPhoneOS SDK not found'
loader=$root/ios/loader.m
probe_m=$root/ios/enqueue_probe.m
probe_s=$root/ios/enqueue_probe.S
for src in "$loader" "$probe_m" "$probe_s"; do
    test -f "$src" || fail "missing $src"
done

requested=${1:-$root/build/ios/libraspberry-enqueue-probe.dylib}
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

xcrun --sdk iphoneos clang \
    -Wall -Wextra -Werror \
    -arch arm64 \
    -miphoneos-version-min=15.0 \
    -fobjc-arc \
    -dynamiclib \
    -install_name '@rpath/libraspberry.dylib' \
    -current_version 1.0.0 \
    -compatibility_version 1.0.0 \
    -isysroot "$sdk" \
    -o "$out" \
    "$loader" "$probe_m" "$probe_s" || fail 'clang failed'

archs=$(xcrun lipo -archs "$out") || fail 'cannot inspect output architecture'
test "$archs" = arm64 || fail "output architecture is $archs, want arm64 only"
load_info=$(xcrun otool -L "$out") || fail 'cannot inspect dylib identity'
printf '%s\n' "$load_info" | grep -Fq \
    '@rpath/libraspberry.dylib (compatibility version 1.0.0, current version 1.0.0)' ||
    fail 'unexpected install name or dylib version'
load_commands=$(xcrun otool -l "$out") || fail 'cannot inspect output load commands'
if printf '%s\n' "$load_commands" | grep -q 'LC_CODE_SIGNATURE'; then
    fail 'refusing linker-signed output'
fi

printf 'build-ios-enqueue-probe: %s\n' "$out"
