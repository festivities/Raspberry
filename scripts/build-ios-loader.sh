#!/usr/bin/env bash
# Build the tiny iOS loader dylib with the already-installed iPhoneOS SDK.
# Does not download tools or run a packaging/signing workflow.
# clang/ld64 may emit an ad-hoc Mach-O signature; this script does not
# call codesign or produce an IPA.
set -eu

here=$(CDPATH= cd -- "$(dirname "$0")" && pwd -P) || {
    printf 'build-ios-loader: cannot locate scripts directory\n' >&2
    exit 1
}
root=$(CDPATH= cd -- "$here/.." && pwd -P) || {
    printf 'build-ios-loader: cannot locate repository root\n' >&2
    exit 1
}

fail() {
    printf 'build-ios-loader: %s\n' "$*" >&2
    exit 1
}

command -v xcrun >/dev/null 2>&1 || fail 'xcrun not found'
sdk=$(xcrun --sdk iphoneos --show-sdk-path) || fail 'iPhoneOS SDK not found'
src=$root/ios/loader.m
test -f "$src" || fail "missing $src"

out=${1:-$root/build/ios/libraspberry.dylib}
mkdir -p "$(dirname "$out")" || fail "cannot create $(dirname "$out")"

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
    "$src" || fail 'clang failed'

printf 'build-ios-loader: %s\n' "$out"
