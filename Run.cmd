@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Unblock VPN
cd /d "%~dp0"
set /a EMPTY=0

set "XV=%~dp0Unblock-ExpressVPN.ps1"
set "WS=%~dp0Unblock-Windscribe.ps1"

rem Files that arrived from the internet carry a blocked flag that stops
rem PowerShell from running them; clear it before doing anything else.
for %%F in ("%XV%" "%WS%") do (
    if exist "%%~F" powershell -NoProfile -ExecutionPolicy Bypass -Command "Unblock-File -LiteralPath '%%~F' -ErrorAction SilentlyContinue" >nul 2>&1
)

:menu
cls
echo.
echo    Unblock VPN
echo    ===========
echo    Gets ExpressVPN or Windscribe working on networks that block them.
echo.
echo    Before anything else: turn ON your proxy (v2rayN / Clash / Nekoray /
echo    Hiddify / sing-box) and check that it opens a blocked site in your
echo    browser. These tools lend that proxy to the VPN client - without it,
echo    nothing here can work.
echo.
echo    ExpressVPN
echo      1   Diagnose            what is broken (changes nothing)
echo      2   Apply the fix       asks for administrator
echo      3   Scan regions        disconnect the VPN first
echo      4   Connect and test
echo      5   Revert the fix      asks for administrator
echo      W   Why did it fail     read the last attempt out of the log
echo      A   Repair adapter      when W blames the network adapter
echo.
echo    Windscribe                no administrator needed
echo      6   Diagnose            what is broken (changes nothing)
echo      7   Start it fixed      relaunch with its API through the proxy
echo      8   Scan cities         fast, which locations answer (about a minute)
echo      T   Test protocols      which ones connect (takes a few minutes)
echo      9   Desktop shortcut    always start it the right way
echo      R   Undo Windscribe     remove shortcut, start it normally
echo.
echo      0   Exit
echo.
set "choice="
set /p "choice=   Choose: "

rem With no console attached set /p leaves the variable untouched, which would
rem spin this menu forever; give up after a few empty reads.
if not defined choice (
    set /a EMPTY+=1
    if !EMPTY! geq 3 exit /b 0
    goto menu
)
set /a EMPTY=0

if "%choice%"=="1" ( set "PS1=%XV%" & set "ACT=diagnose"  & goto run )
if "%choice%"=="2" ( set "PS1=%XV%" & set "ACT=apply"     & goto run )
if "%choice%"=="3" ( set "PS1=%XV%" & set "ACT=scan"      & goto run )
if "%choice%"=="4" ( goto test )
if "%choice%"=="5" ( set "PS1=%XV%" & set "ACT=revert"    & goto run )
if /i "%choice%"=="W" ( set "PS1=%XV%" & set "ACT=why"    & goto run )
if /i "%choice%"=="A" ( set "PS1=%XV%" & set "ACT=repair" & goto run )
if "%choice%"=="6" ( set "PS1=%WS%" & set "ACT=diagnose"  & goto run )
if "%choice%"=="7" ( set "PS1=%WS%" & set "ACT=launch"    & goto run )
if "%choice%"=="8" ( set "PS1=%WS%" & set "ACT=scan"      & goto run )
if /i "%choice%"=="T" ( set "PS1=%WS%" & set "ACT=protocols" & goto run )
if "%choice%"=="9" ( set "PS1=%WS%" & set "ACT=shortcut"  & goto run )
if /i "%choice%"=="R" ( set "PS1=%WS%" & set "ACT=revert" & goto run )
if "%choice%"=="0" exit /b 0
goto menu

:test
echo.
set "REG="
set /p "REG=   Region slug, or press Enter to pick one automatically: "
echo.
if "%REG%"=="" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%XV%" -Action test
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%XV%" -Action test -Region "%REG%"
)
echo.
pause
goto menu

:run
if not exist "%PS1%" (
    echo.
    echo   %PS1% is missing. Keep both .ps1 files next to this one.
    echo.
    pause
    goto menu
)
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -Action %ACT%
echo.
pause
goto menu
