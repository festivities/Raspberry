#!/usr/bin/env bash
# Isolated index fixture for check-repo. Never touches the product repo index.
set -u

here=$(CDPATH= cd -- "$(dirname "$0")" && pwd -P) || {
    printf 'check-repo test: cannot locate scripts directory\n' >&2
    exit 1
}
checker=$here/check-repo.sh
[ -f "$checker" ] || {
    printf 'check-repo test: missing %s\n' "$checker" >&2
    exit 1
}

# Keep the fixture's git commands independent of the user's global config,
# which could ignore one of the synthetic file names.
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1

base=${TMPDIR:-/tmp}/opencode/raspberry/check-repo-test
mkdir -p "$base" || {
    printf 'check-repo test: cannot create %s\n' "$base" >&2
    exit 1
}
repo=$(mktemp -d "$base/repo.XXXXXX") || {
    printf 'check-repo test: mktemp failed\n' >&2
    exit 1
}
trap 'rm -rf "$repo"' EXIT HUP INT TERM

run_check() {
    bash "$checker" --repo-root "$repo" 2>&1
}

expect_pass() {
    local label=$1 out
    if ! out=$(run_check); then
        printf 'check-repo test: %s was rejected: %s\n' "$label" "$out" >&2
        exit 1
    fi
}

assert_reject() {
    local rel=$1 bytes=${2:-0} path out
    path=$repo/$rel
    mkdir -p "$(dirname "$path")" || exit 1
    if [ "$bytes" -gt 0 ]; then
        dd if=/dev/zero of="$path" bs=1 count=0 seek="$bytes" 2>/dev/null || {
            printf 'check-repo test: cannot size %s\n' "$rel" >&2
            exit 1
        }
    else
        printf 'synthetic\n' >"$path" || exit 1
    fi
    git -C "$repo" add -- "$rel" || {
        printf 'check-repo test: git add failed for %s\n' "$rel" >&2
        exit 1
    }
    if out=$(run_check); then
        printf 'check-repo test: expected reject %s, got pass: %s\n' "$rel" "$out" >&2
        exit 1
    fi
    git -C "$repo" rm -q --cached -- "$rel" || {
        printf 'check-repo test: git rm --cached failed for %s\n' "$rel" >&2
        exit 1
    }
    rm -f "$path"
    printf 'check-repo test: rejected %s\n' "$rel"
}

git -C "$repo" init -q || {
    printf 'check-repo test: git init failed\n' >&2
    exit 1
}
printf 'package main\n' >"$repo/main.go" || exit 1
mkdir -p "$repo/testdata" || exit 1
printf 'synthetic\n' >"$repo/testdata/note.txt" || exit 1
git -C "$repo" add -- main.go testdata/note.txt || {
    printf 'check-repo test: git add accepted source failed\n' >&2
    exit 1
}
expect_pass 'accepted source'

# Untracked files are not scanned; only the index matters.
printf 'synthetic\n' >"$repo/untracked.so" || exit 1
expect_pass 'untracked file'
rm -f "$repo/untracked.so"

# Windows parity cases (scripts/check-repo_test.ps1).
assert_reject 'testdata/x.so' 0
assert_reject 'testdata/tiny.IPA' 0
assert_reject 'testdata/tiny.DyLiB' 0
assert_reject 'nested/Foo.ApP/Contents/MacOS/executable' 0
assert_reject 'nested/pAyLoAd/executable' 0
assert_reject 'profiles/operator.MoBiLePrOvIsIoN' 0
assert_reject 'profiles/operator.PrOvIsIoNpRoFiLe' 0
assert_reject '.venv/x.py' 0
assert_reject 'device.key' 0
assert_reject 'oversizedfile' 1048577

# Additional component/name rules that the Windows list does not exercise.
assert_reject 'assets/note.txt' 0
assert_reject 'res/note.txt' 0
assert_reject 'lib/arm64-v8a/note' 0
assert_reject 'smali_classes5/note' 0
assert_reject 'classes5.DEX' 0
assert_reject 'secrets/note' 0
assert_reject 'raspberry.local.json' 0
assert_reject 'nested/with spaces/Foo.ApP/executable' 0
assert_reject $'nested/with\ttab/pAyLoAd/executable' 0
assert_reject $'nested/with\nnewline/tiny.IPA' 0

expect_pass 'accepted source after rejects'
printf 'check-repo test: ok\n'
exit 0
