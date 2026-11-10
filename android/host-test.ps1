# Host checks for the Android-free core. No Android SDK and no device.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$src = Join-Path $root 'android\src\dev\raspberry\core'
$test = Join-Path $root 'android\host-test'
$out = Join-Path $env:TEMP 'opencode\raspberry\android-host-test'
if (Test-Path -LiteralPath $out) {
    Remove-Item -LiteralPath $out -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $out | Out-Null
$files = @(Get-ChildItem -LiteralPath $src, $test -Recurse -Filter *.java | ForEach-Object { $_.FullName })
& javac --release 8 -encoding UTF-8 -d $out $files
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& java -cp $out dev.raspberry.core.CoreTest
exit $LASTEXITCODE
