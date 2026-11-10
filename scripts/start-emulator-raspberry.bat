@echo off
set "EMULATOR=%LOCALAPPDATA%\Android\Sdk\emulator\emulator.exe"
if not exist "%EMULATOR%" (
  echo emulator.exe not found: "%EMULATOR%"
  exit /b 1
)
echo Starting AVD Raspberry.
start "Raspberry AVD" "%EMULATOR%" -avd Raspberry -netdelay none -netspeed full -gpu swiftshader_indirect -no-snapshot-load -port 5559
