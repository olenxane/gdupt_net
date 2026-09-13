@echo off
rem Build lan-relay + relayprobe from THIS source folder.
rem Output goes to the sibling release folder: ..\lan-relay-release\bin\
rem (override: build.bat <output-dir>)
rem Requires Go 1.25+ on PATH.
setlocal
set OUT=%~dp0..\lan-relay-release\bin
if not "%~1"=="" set OUT=%~1
cd /d "%~dp0" || goto :fail
if not exist "%OUT%" mkdir "%OUT%"

echo [1/2] Building lan-relay.exe ...
go build -trimpath -ldflags "-s -w" -o "%OUT%\lan-relay.exe" .
if errorlevel 1 goto :fail

echo [2/2] Building relayprobe.exe ...
go build -o "%OUT%\relayprobe.exe" .\cmd\relayprobe
if errorlevel 1 goto :fail

echo.
echo Build OK:
echo   %OUT%\lan-relay.exe     (relay gateway)
echo   %OUT%\relayprobe.exe    (TCP/UDP probe tool)
exit /b 0

:fail
echo Build FAILED.
exit /b 1
