# Compile android/src and dex it to build/dex/classes5.dex (git-ignored).
# javac --release 8 against the SDK android.jar, then d8 --min-api 23.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$src = Join-Path $root 'android\src'
$sdk = Join-Path $env:LOCALAPPDATA 'Android\Sdk'
$androidJar = Join-Path $sdk 'platforms\android-37.0\android.jar'
$d8 = Join-Path $sdk 'build-tools\36.0.0\d8.bat'
if (-not (Test-Path -LiteralPath $androidJar)) { throw "missing $androidJar" }
if (-not (Test-Path -LiteralPath $d8)) { throw "missing $d8" }

$javac = (Get-Command javac -ErrorAction Stop).Source
$env:JAVA_HOME = Split-Path -Parent (Split-Path -Parent $javac)

$dexDir = Join-Path $root 'build\dex'
$classes = Join-Path $dexDir 'classes'
if (Test-Path -LiteralPath $classes) {
    Remove-Item -LiteralPath $classes -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $classes | Out-Null
$files = @(Get-ChildItem -LiteralPath $src -Recurse -Filter *.java | ForEach-Object { $_.FullName })
& javac --release 8 -encoding UTF-8 -classpath $androidJar -d $classes $files
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$classFiles = @(Get-ChildItem -LiteralPath $classes -Recurse -Filter *.class | ForEach-Object { $_.FullName })
$dex = Join-Path $dexDir 'classes.dex'
$out = Join-Path $dexDir 'classes5.dex'
if (Test-Path -LiteralPath $dex) { Remove-Item -LiteralPath $dex -Force }
if (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out -Force }
& $d8 --min-api 23 --lib $androidJar --output $dexDir $classFiles
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
if (-not (Test-Path -LiteralPath $dex)) { throw 'd8 did not write classes.dex' }
Move-Item -LiteralPath $dex -Destination $out
Write-Host "build-dex: $out"
exit 0
