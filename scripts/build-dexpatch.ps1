# Compile tools/dexpatch against the pinned smali 3.0.10 dexlib2 and run the synthetic selftest.
# Output class files go to build/dexpatch (gitignored). No APK, no device, no new dependencies.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Javac = "C:\Program Files\Eclipse Adoptium\jdk-25.0.3+9\bin\javac.exe"
$Java = "C:\Program Files\Eclipse Adoptium\jdk-25.0.3+9\bin\java.exe"
$Lib = "$env:LOCALAPPDATA\Raspberry\tools\smali\3.0.10\lib\*"
$Src = Join-Path $Root "tools\dexpatch\src"
$Out = Join-Path $Root "build\dexpatch"
if (-not (Test-Path $Javac)) { throw "javac missing: $Javac" }
if (-not (Test-Path (Join-Path $env:LOCALAPPDATA "Raspberry\tools\smali\3.0.10\lib\smali-dexlib2-3.0.10.jar"))) {
    throw "smali 3.0.10 dexlib2 missing"
}
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$files = Get-ChildItem -Path $Src -Filter *.java -Recurse | ForEach-Object { $_.FullName }
& $Javac -encoding UTF-8 -cp $Lib -d $Out @files
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $Java -cp "$Out;$Lib" dev.raspberry.dexpatch.Main selftest
exit $LASTEXITCODE
