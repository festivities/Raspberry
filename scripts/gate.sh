#!/usr/bin/env bash
# CI-less host gate for macOS/Bash: gofmt, vet, test, native host tests,
# check-repo self-test and check-repo. Windows still uses scripts/gate.ps1.
set -u

here=$(CDPATH= cd -- "$(dirname "$0")" && pwd -P) || {
    printf 'gate: cannot locate scripts directory\n' >&2
    exit 1
}
root=$(CDPATH= cd -- "$here/.." && pwd -P) || {
    printf 'gate: cannot locate repository root\n' >&2
    exit 1
}
cd "$root" || {
    printf 'gate: cannot enter %s\n' "$root" >&2
    exit 1
}

fail() {
    printf 'gate: %s\n' "$*" >&2
    exit 1
}

# Canonicalize the temporary root before any child runs. macOS exposes /var as
# a symlink to /private/var; the fail-closed path checks reject symlink
# ancestors on purpose, so test fixtures must start from a canonical path.
# This canonicalizes the host's test scratch only; production code still
# refuses symlinked user-supplied paths.
tmp_root=${TMPDIR:-/tmp}
tmp_root=$(CDPATH= cd -- "$tmp_root" && pwd -P) || fail "cannot canonicalize TMPDIR=$tmp_root"
case "$tmp_root" in
    */opencode) ;;
    *) tmp_root=$tmp_root/opencode ;;
esac
mkdir -p "$tmp_root" || fail "cannot create test temporary root $tmp_root"
TMPDIR=$(CDPATH= cd -- "$tmp_root" && pwd -P) || fail 'cannot canonicalize test temporary root'
export TMPDIR
# Never install another Go toolchain implicitly while running a host gate.
export GOTOOLCHAIN=local
printf 'gate: TMPDIR %s\n' "$TMPDIR"

command -v git >/dev/null 2>&1 || fail 'git not found on PATH'
command -v go >/dev/null 2>&1 || fail 'go not found on PATH; the Go toolchain is required for this gate'
command -v gofmt >/dev/null 2>&1 || fail 'gofmt not found on PATH; the Go toolchain is required for this gate'

printf 'gate: gofmt\n'
dirty=$(gofmt -l .) || fail 'gofmt failed'
if [ -n "$dirty" ]; then
    printf 'gofmt -l is not empty:\n%s\n' "$dirty"
    exit 1
fi

printf 'gate: go vet\n'
go vet ./... || fail 'go vet failed'

printf 'gate: go test\n'
go test ./... || fail 'go test failed'

# shortcut: each native test is one C file, no extra libs. Upgrade when a harness is needed.
tests=()
if [ -d "$root/native" ]; then
    while IFS= read -r t; do
        tests+=("$t")
    done < <(find "$root/native" -type f \( -name '*_test.c' -o -name 'test_*.c' \) | LC_ALL=C sort)
fi

if [ "${#tests[@]}" -eq 0 ]; then
    printf 'gate: no native tests\n'
else
    cc=${CC:-cc}
    command -v "$cc" >/dev/null 2>&1 || fail "native tests present but C compiler '$cc' not found (set CC)"
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/raspberry-gate.XXXXXX") || fail 'mktemp failed'
    chmod 700 "$tmp" || fail 'cannot protect temporary directory'
    trap 'rm -rf "$tmp"' EXIT HUP INT TERM
    printf 'gate: native tests (%d)\n' "${#tests[@]}"
    i=0
    for t in "${tests[@]}"; do
        i=$((i + 1))
        exe=$tmp/nativetest-$i
        printf 'gate: native test %s\n' "${t#"$root"/}"
        "$cc" -std=c11 -Wall -Werror -o "$exe" "$t" || fail "native compile failed: $t"
        "$exe" || fail "native test failed: $t"
    done
fi

[ -f "$here/check-repo.sh" ] || fail "missing $here/check-repo.sh"
printf 'gate: check-repo test\n'
bash "$here/check-repo_test.sh" || fail 'check-repo test failed'

printf 'gate: check-repo\n'
bash "$here/check-repo.sh" || fail 'check-repo failed'

printf 'gate: ok\n'
exit 0
