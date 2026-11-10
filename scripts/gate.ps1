# CI-less gate: gofmt, vet, test, native host tests if any exist, check-repo.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $root

Write-Host 'gate: gofmt'
$dirty = @( & gofmt -l . )
if ($LASTEXITCODE -ne 0) { exit 1 }
if ($dirty.Count -gt 0) {
    Write-Host 'gofmt -l is not empty:'
    $dirty | ForEach-Object { Write-Host $_ }
    exit 1
}

Write-Host 'gate: go vet'
& go vet ./...
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host 'gate: go test'
& go test ./...
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# shortcut: each native test is one C file, no extra libs. Upgrade when a harness is needed.
$native = Join-Path $root 'native'
if (Test-Path -LiteralPath $native) {
    $tests = @(Get-ChildItem -LiteralPath $native -Recurse -File -Filter '*.c' | Where-Object {
            $_.Name -like '*_test.c' -or $_.Name -like 'test_*.c'
        })
    if ($tests.Count -gt 0) {
        Write-Host "gate: native tests ($($tests.Count))"
        $natRoot = Join-Path $env:TEMP 'opencode\raspberry'
        New-Item -ItemType Directory -Force -Path $natRoot | Out-Null
        foreach ($t in $tests) {
            $exe = Join-Path $natRoot ('nativetest-' + [guid]::NewGuid().ToString('n') + '.exe')
            & gcc -std=c11 -Wall -Werror -o $exe $t.FullName
            if ($LASTEXITCODE -ne 0) { exit 1 }
            & $exe
            $code = $LASTEXITCODE
            Remove-Item -LiteralPath $exe -Force -ErrorAction SilentlyContinue
            if ($code -ne 0) { exit $code }
        }
    } else {
        Write-Host 'gate: no native tests'
    }
} else {
    Write-Host 'gate: no native tests'
}

Write-Host 'gate: check-repo test'
& powershell.exe -NoProfile -File (Join-Path $PSScriptRoot 'check-repo_test.ps1')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host 'gate: check-repo'
& powershell.exe -NoProfile -File (Join-Path $PSScriptRoot 'check-repo.ps1')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
exit 0
