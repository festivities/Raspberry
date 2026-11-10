# Isolated index fixture for check-repo. Never touches the product repo index.
$ErrorActionPreference = 'Stop'
$checker = Join-Path $PSScriptRoot 'check-repo.ps1'
$repo = Join-Path $env:TEMP ('opencode\raspberry\check-repo-test\' + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Force -Path $repo | Out-Null

function Invoke-Check([string]$root) {
    $script:checkOut = (& powershell.exe -NoProfile -File $checker -RepoRoot $root 2>&1 | Out-String).Trim()
    return $LASTEXITCODE
}

try {
    & git -C $repo init -q
    if ($LASTEXITCODE -ne 0) { throw 'git init failed' }
    Set-Content -LiteralPath (Join-Path $repo 'main.go') -Value "package main`r`n" -Encoding ascii
    New-Item -ItemType Directory -Force -Path (Join-Path $repo 'testdata') | Out-Null
    Set-Content -LiteralPath (Join-Path $repo 'testdata\note.txt') -Value "synthetic`r`n" -Encoding ascii
    & git -C $repo add -- main.go testdata/note.txt
    if ($LASTEXITCODE -ne 0) { throw 'git add accepted source failed' }
    if ((Invoke-Check $repo) -ne 0) { throw "accepted source was rejected: $checkOut" }

    function Assert-Reject([string]$rel, [string]$text, [int64]$bytes) {
        $path = Join-Path $repo ($rel -replace '/', '\')
        $parent = Split-Path -Parent $path
        if (-not [string]::IsNullOrEmpty($parent)) {
            New-Item -ItemType Directory -Force -Path $parent | Out-Null
        }
        if ($bytes -gt 0) {
            $fs = [System.IO.File]::Create($path)
            try { $fs.SetLength($bytes) } finally { $fs.Close() }
        } else {
            Set-Content -LiteralPath $path -Value $text -Encoding ascii
        }
        & git -C $repo add -- $rel
        if ($LASTEXITCODE -ne 0) { throw "git add failed for $rel" }
        $code = Invoke-Check $repo
        & git -C $repo rm -q --cached -- $rel
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
        if ($code -eq 0) { throw "expected reject ${rel}: $checkOut" }
        Write-Host "check-repo test: rejected $rel"
    }

    Assert-Reject 'testdata/x.so' 'not-a-real-lib' 0
    Assert-Reject '.venv/x.py' 'print(1)' 0
    Assert-Reject 'device.key' 'not-a-real-key' 0
    Assert-Reject 'oversizedfile' '' (1MB + 1)
    if ((Invoke-Check $repo) -ne 0) { throw "accepted source failed after rejects: $checkOut" }
    Write-Host 'check-repo test: ok'
} finally {
    if (Test-Path -LiteralPath $repo) {
        Remove-Item -LiteralPath $repo -Recurse -Force
    }
}
exit 0
