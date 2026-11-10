# Fail if the git index holds APK-derived files, keys, private config, raw logs,
# compiled downloads, a .venv, or oversized blobs.
# Tracked paths only (git ls-files). Untracked work is ignored.
# No size exemption: a tiny testdata/*.so is still forbidden.
param(
    [string]$RepoRoot
)
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
}
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

$OutputEncoding = [System.Text.Encoding]::UTF8
$listed = & git -C $RepoRoot ls-files -s -z
if ($LASTEXITCODE -ne 0) {
    Write-Host 'check-repo: git ls-files failed'
    exit 1
}

$maxBytes = 1MB
$bannedExt = @(
    '.apk', '.xapk', '.apks', '.aab', '.dex', '.odex', '.vdex', '.oat', '.art', '.so', '.smali',
    '.i64', '.idb', '.id0', '.id1', '.id2', '.nam', '.til',
    '.keystore', '.jks', '.p12', '.pfx', '.pem', '.key', '.secret',
    '.log', '.pcap', '.pcapng', '.cap', '.har',
    '.exe', '.dll', '.sys', '.class', '.jar', '.obj', '.lib', '.pyc', '.pyo', '.wasm'
)

function Test-ForbiddenPath([string]$path) {
    $p = $path.ToLowerInvariant()
    if ($p -match '(^|/)(assets|res|smali)(/|$)') { return $true }
    if ($p -match '(^|/)smali_classes[0-9]+(/|$)') { return $true }
    if ($p -match '(^|/)lib/(arm64-v8a|armeabi-v7a|armeabi|x86_64|x86)(/|$)') { return $true }
    if ($p -match '(^|/)(resources\.arsc|androidmanifest\.xml|classes[0-9]*\.dex)$') { return $true }
    if ($p -match '^(work|build|out|dist|local|\.opencode)(/|$)') { return $true }
    if ($p -match '(^|/)\.venv(/|$)') { return $true }
    return $false
}

function Test-PrivateConfig([string]$path) {
    $p = $path.ToLowerInvariant()
    $base = [System.IO.Path]::GetFileName($p)
    if ($base -like 'raspberry.local.*') { return $true }
    if ($base -like '*.local.json' -or $base -like '*.local.toml') { return $true }
    if ($base -eq '.env' -or $base -like '.env.*') { return $true }
    if ($p -match '(^|/)secrets(/|$)') { return $true }
    return $false
}

$fail = $false
$count = 0
$parts = @($listed -split "`0")
foreach ($part in $parts) {
    if ([string]::IsNullOrEmpty($part)) { continue }
    $tab = $part.IndexOf("`t")
    if ($tab -lt 0) {
        Write-Host 'check-repo: unparsable index record'
        $fail = $true
        continue
    }
    $meta = $part.Substring(0, $tab)
    $path = ($part.Substring($tab + 1) -replace '\\', '/')
    $bits = $meta -split ' '
    if ($bits.Length -lt 2) {
        Write-Host "check-repo: unparsable index meta for $path"
        $fail = $true
        continue
    }
    $sha = $bits[1]
    $sizeText = & git -C $RepoRoot cat-file -s $sha
    if ($LASTEXITCODE -ne 0) {
        Write-Host "check-repo: size failed for $path"
        $fail = $true
        continue
    }
    $size = [int64](($sizeText | Out-String).Trim())
    $count++

    $ext = [System.IO.Path]::GetExtension($path).ToLowerInvariant()
    if ($size -gt $maxBytes) {
        Write-Host "check-repo: oversized $path ($size bytes)"
        $fail = $true
        continue
    }
    if ((Test-PrivateConfig $path) -or (Test-ForbiddenPath $path) -or ($bannedExt -contains $ext)) {
        Write-Host "check-repo: forbidden $path"
        $fail = $true
    }
}

if ($fail) { exit 1 }
Write-Host "check-repo: ok ($count tracked)"
exit 0
