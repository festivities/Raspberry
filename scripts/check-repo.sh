#!/usr/bin/env bash
# Fail if the git index holds APK/IPA-derived files, keys, private config, raw logs,
# compiled downloads, a .venv, or oversized blobs.
# Tracked paths only (git ls-files). Untracked work is ignored.
# No size exemption: a tiny testdata/*.so is still forbidden.
# Usage: scripts/check-repo.sh [--repo-root DIR]

set -u
export LC_ALL=C

die() {
    printf 'check-repo: %s\n' "$*" >&2
    exit 1
}

root=''
case "${1:-}" in
    --repo-root)
        if [ "$#" -lt 2 ]; then
            die '--repo-root needs a directory'
        fi
        root=$2
        ;;
    '')
        ;;
    *)
        root=$1
        ;;
esac
if [ -z "$root" ]; then
    here=$(CDPATH= cd -- "$(dirname "$0")" && pwd -P) || die 'cannot locate script directory'
    root=$here/..
fi
cd "$root" || die "cannot enter $root"
root=$(pwd -P)

command -v git >/dev/null 2>&1 || die 'git not found on PATH'

tmp=$(mktemp "${TMPDIR:-/tmp}/raspberry-check-repo.XXXXXX") || die 'mktemp failed'
trap 'rm -f "$tmp"' EXIT HUP INT TERM
if ! git -C "$root" ls-files -s -z >"$tmp"; then
    die 'git ls-files failed'
fi

max_bytes=1048576

lower() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

# Component rules. The path is lowercased and wrapped in slashes so every
# component boundary is a literal '/'.
forbidden_path() {
    local p=$1 t re
    t=/$p/
    case "$t" in
        */assets/* | */res/* | */smali/* | */payload/* | */.venv/*) return 0 ;;
    esac
    re='(^|/)smali_classes[0-9]+/'
    [[ $t =~ $re ]] && return 0
    re='(^|/)lib/(arm64-v8a|armeabi-v7a|armeabi|x86_64|x86)/'
    [[ $t =~ $re ]] && return 0
    # Any path component whose name ends in .app, at any depth.
    re='[^/]*[.]app/'
    [[ $t =~ $re ]] && return 0
    re='(^|/)(resources[.]arsc|androidmanifest[.]xml|classes[0-9]*[.]dex)$'
    [[ $p =~ $re ]] && return 0
    re='^(work|build|out|dist|local|[.]opencode)(/|$)'
    [[ $p =~ $re ]] && return 0
    return 1
}

private_config() {
    local p=$1 base=$2
    case "$base" in
        raspberry.local.* | *.local.json | *.local.toml | .env | .env.*) return 0 ;;
    esac
    case "/$p/" in
        */secrets/*) return 0 ;;
    esac
    return 1
}

banned_ext() {
    case "$1" in
        .apk | .xapk | .apks | .aab | .ipa | .dex | .odex | .vdex | .oat | .art | .so | .dylib | .smali) return 0 ;;
        .mobileprovision | .provisionprofile) return 0 ;;
        .i64 | .idb | .id0 | .id1 | .id2 | .nam | .til) return 0 ;;
        .keystore | .jks | .p12 | .pfx | .pem | .key | .secret) return 0 ;;
        .log | .pcap | .pcapng | .cap | .har) return 0 ;;
        .exe | .dll | .sys | .class | .jar | .obj | .lib | .pyc | .pyo | .wasm) return 0 ;;
    esac
    return 1
}

fail=0
count=0
tab=$(printf '\t')

while IFS= read -r -d '' rec; do
    case "$rec" in
        *"$tab"*) ;;
        *)
            printf 'check-repo: unparsable index record\n'
            fail=1
            continue
            ;;
    esac
    meta=${rec%%"$tab"*}
    path=${rec#*"$tab"}
    read -r _ sha _ <<<"$meta"
    if [ -z "${sha:-}" ]; then
        printf 'check-repo: unparsable index meta for %s\n' "$path"
        fail=1
        continue
    fi
    if ! size=$(git -C "$root" cat-file -s "$sha" 2>/dev/null); then
        printf 'check-repo: size failed for %s\n' "$path"
        fail=1
        continue
    fi
    case "$size" in
        '' | *[!0-9]*)
            printf 'check-repo: size failed for %s\n' "$path"
            fail=1
            continue
            ;;
    esac
    count=$((count + 1))

    path=${path//\\//}
    p=$(lower "$path")
    base=${p##*/}
    ext=''
    case "$base" in
        ?*.*) ext=".${base##*.}" ;;
    esac

    if [ "$size" -gt "$max_bytes" ]; then
        printf 'check-repo: oversized %s (%s bytes)\n' "$path" "$size"
        fail=1
        continue
    fi
    if private_config "$p" "$base" || forbidden_path "$p" || banned_ext "$ext"; then
        printf 'check-repo: forbidden %s\n' "$path"
        fail=1
    fi
done <"$tmp"

if [ "$fail" -ne 0 ]; then
    exit 1
fi
printf 'check-repo: ok (%d tracked)\n' "$count"
exit 0
