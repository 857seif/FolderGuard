@echo off
title FolderGuard - Full Installer
color 0A


>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    echo Requesting Administrator privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
    pushd "%CD%"
    CD /D "%~dp0"

echo.
echo  ============================================
echo       FolderGuard Ultimate - Full Installer
echo  ============================================
echo.

set "FOLDER=C:\ProgramData\FolderGuard"
set "SYSMON_DIR=C:\SysmonTemp"
set "CONFIG=%FOLDER%\sysmon-config-ultimate.xml"

cd /d "%FOLDER%"

echo  [1/6] Fixing config file permissions...
if exist "%CONFIG%" (
    takeown /f "%CONFIG%" >nul 2>&1
    icacls "%CONFIG%" /grant Administrators:F >nul 2>&1
    icacls "%CONFIG%" /grant SYSTEM:F >nul 2>&1
    icacls "%CONFIG%" /grant Users:R >nul 2>&1
    echo       Config permissions fixed.
) else (
    echo       [!] WARNING: sysmon-config-ultimate.xml not found!
    echo       Make sure the file exists in C:\ProgramData\FolderGuard
    pause
    exit /b
)

echo  [2/6] Cleaning old temp files...
if exist "%SYSMON_DIR%" rd /s /q "%SYSMON_DIR%" >nul 2>&1
mkdir "%SYSMON_DIR%" >nul 2>&1

echo  [3/6] Downloading latest Sysmon from Microsoft...
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile '%SYSMON_DIR%\Sysmon.zip' -UseBasicParsing } catch { exit 1 }"

if not exist "%SYSMON_DIR%\Sysmon.zip" (
    echo.
    echo  [X] Download failed. Check your internet connection.
    pause
    exit /b
)

echo  [4/6] Extracting Sysmon...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Expand-Archive -Path '%SYSMON_DIR%\Sysmon.zip' -DestinationPath '%SYSMON_DIR%' -Force"

if not exist "%SYSMON_DIR%\Sysmon64.exe" (
    echo.
    echo  [X] Extraction failed. Sysmon64.exe not found.
    pause
    exit /b
)

echo  [5/6] Installing Sysmon with config...
"%SYSMON_DIR%\Sysmon64.exe" -accepteula -i "%CONFIG%"

if %errorLevel% neq 0 (
    echo.
    echo  First attempt failed. Trying force reinstall...
    "%SYSMON_DIR%\Sysmon64.exe" -u force >nul 2>&1
    timeout /t 2 >nul
    "%SYSMON_DIR%\Sysmon64.exe" -accepteula -i "%CONFIG%"
)

echo.
echo  [6/6] Cleaning temporary files...
rd /s /q "%SYSMON_DIR%" >nul 2>&1

echo.
echo  ============================================
echo              Installation Done!
echo  ============================================
echo.
echo  Now open FolderGuard_Ultimate.exe
echo  and click "Start Protection"
echo.
pause