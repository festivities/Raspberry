# Build libraspberry.so for arm64-v8a and armeabi-v7a. Output stays under the
# ignored build tree unless -Out says otherwise. Does not archive the libraries.
param(
    [string]$Ndk,
    [string]$Out
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($Ndk)) {
    if ($env:ANDROID_NDK_HOME) { $Ndk = $env:ANDROID_NDK_HOME }
    elseif ($env:ANDROID_NDK_ROOT) { $Ndk = $env:ANDROID_NDK_ROOT }
    else { $Ndk = Join-Path $env:LOCALAPPDATA 'Android\Sdk\ndk\30.0.16248370' }
}
if ([string]::IsNullOrWhiteSpace($Out)) {
    $Out = Join-Path $root 'build\native'
}
$clang = Join-Path $Ndk 'toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe'
if (-not (Test-Path -LiteralPath $clang)) {
    Write-Host "build-native: clang missing: $clang"
    exit 1
}
$src = @(
    (Join-Path $root 'native\jni.c'),
    (Join-Path $root 'native\hook.c'),
    (Join-Path $root 'native\endpoint.c')
)
foreach ($abi in @('arm64-v8a', 'armeabi-v7a')) {
    $target = $(if ($abi -eq 'arm64-v8a') { 'aarch64-linux-android23' } else { 'armv7a-linux-androideabi23' })
    $dir = Join-Path $Out $abi
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $so = Join-Path $dir 'libraspberry.so'
    & $clang --target=$target -std=c11 -Wall -Werror -O2 -fPIC -fvisibility=hidden -shared `
        '-Wl,-z,max-page-size=16384' -o $so @src -ldl -llog
    if ($LASTEXITCODE -ne 0) { exit 1 }
    if (-not (Test-Path -LiteralPath $so)) {
        Write-Host "build-native: missing $so"
        exit 1
    }
    Write-Host "build-native: $so"
}

$gcc = Get-Command gcc -ErrorAction SilentlyContinue
if (-not $gcc) {
    Write-Host 'build-native: gcc missing'
    exit 1
}
$natRoot = Join-Path $env:TEMP 'opencode\raspberry'
New-Item -ItemType Directory -Force -Path $natRoot | Out-Null
$tests = @(Get-ChildItem -LiteralPath (Join-Path $root 'native') -Recurse -File -Filter '*.c' | Where-Object {
        $_.Name -like '*_test.c' -or $_.Name -like 'test_*.c'
    })
if ($tests.Count -eq 0) {
    Write-Host 'build-native: no host tests'
    exit 1
}
Push-Location -LiteralPath $root
foreach ($t in $tests) {
    $exe = Join-Path $natRoot ('nativetest-' + [guid]::NewGuid().ToString('n') + '.exe')
    & gcc -std=c11 -Wall -Werror -o $exe $t.FullName
    if ($LASTEXITCODE -ne 0) { Pop-Location; exit 1 }
    & $exe
    $code = $LASTEXITCODE
    Remove-Item -LiteralPath $exe -Force -ErrorAction SilentlyContinue
    if ($code -ne 0) { Pop-Location; exit $code }
}
Pop-Location
Write-Host 'build-native: host tests ok'
exit 0
