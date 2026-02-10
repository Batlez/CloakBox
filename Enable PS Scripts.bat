@echo off
setlocal EnableDelayedExpansion

:: Check for administrator privileges
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo.
    echo ========================================
    echo ERROR: Administrator rights required!
    echo ========================================
    echo.
    echo This script must be run as Administrator to modify registry settings.
    echo.
    echo Right-click this file and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

echo.
echo ========================================
echo PowerShell Script Enabler
echo ========================================
echo.
echo This script will:
echo  - Set PowerShell execution policy to Unrestricted
echo  - Enable script execution in Windows policies
echo  - Unblock all .ps1 files in this folder
echo.
echo WARNING: This reduces security. Only proceed if you trust
echo          the PowerShell scripts in this directory.
echo.

choice /M "Do you wish to proceed"
if errorlevel 2 goto abort

echo.
echo [1/4] Setting ExecutionPolicy in PowerShell registry...
Reg.exe add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "Unrestricted" /f >nul 2>&1
if %errorlevel% NEQ 0 (
    echo [FAILED] Could not modify PowerShell registry key
    goto abort
)
echo [OK] PowerShell ExecutionPolicy set to Unrestricted

echo.
echo [2/4] Setting ExecutionPolicy in Windows Policies...
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "Unrestricted" /f >nul 2>&1
if %errorlevel% NEQ 0 (
    echo [WARNING] Could not set ExecutionPolicy in Policies ^(may not exist^)
) else (
    echo [OK] Windows Policies ExecutionPolicy set
)

echo.
echo [3/4] Enabling script execution in Windows Policies...
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\PowerShell" /v "EnableScripts" /t REG_DWORD /d "1" /f >nul 2>&1
if %errorlevel% NEQ 0 (
    echo [WARNING] Could not enable scripts in Policies ^(may not exist^)
) else (
    echo [OK] Script execution enabled
)

echo.
echo [4/4] Unblocking PowerShell scripts in current directory...
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -Path '%~dp0' -Recurse -Filter '*.ps1' | Unblock-File -Confirm:$false"
if %errorlevel% NEQ 0 (
    echo [WARNING] Failed to unblock some files
) else (
    echo [OK] All .ps1 files unblocked
)

echo.
echo ========================================
echo SUCCESS! PowerShell scripts enabled.
echo ========================================
echo.
echo You can now run PowerShell scripts (.ps1 files) without restrictions.
echo.
goto end

:abort
echo.
echo ========================================
echo Script execution aborted or failed
echo ========================================
echo.
echo Possible reasons:
echo  - Not running as Administrator
echo  - Registry keys are protected by Group Policy
echo  - Antivirus blocking registry changes
echo.

:end
pause
exit /b 0