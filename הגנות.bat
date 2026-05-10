@echo off
chcp 65001 >nul

:: ── הרמת הרשאות אוטומטית ─────────────────────────────────────────────────────
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Set s=CreateObject("Shell.Application") > "%temp%\_elev.vbs"
    echo s.ShellExecute "%~f0", "", "", "runas", 1 >> "%temp%\_elev.vbs"
    wscript "%temp%\_elev.vbs"
    del "%temp%\_elev.vbs" >nul 2>&1
    exit /b
)

:MENU
cls
echo.
echo   ================================
echo      ניהול הגנות Windows
echo   ================================
echo.
echo   1   כיבוי הגנות (לצמיתות)
echo   2   כיבוי הגנות (לפי זמן)
echo   3   הפעלת הגנות מחדש
echo.
set /p choice="  בחר אפשרות: "

if "%choice%"=="1" goto DISABLE_PERM
if "%choice%"=="2" goto TIMER_MENU
if "%choice%"=="3" goto ENABLE
echo   בחירה לא תקינה
timeout /t 2 >nul
goto MENU

:: ─────────────────────────────────────────────────────────────────────────────
:DISABLE_PERM
cls
echo.
echo   מכבה הגנות...
call :DO_DISABLE
echo.
echo   הגנות כובו בהצלחה
echo.
pause
exit /b

:: ─────────────────────────────────────────────────────────────────────────────
:TIMER_MENU
cls
echo.
echo   ================================
echo      בחר משך זמן
echo   ================================
echo.
echo   1    5  דקות
echo   2    15 דקות
echo   3    25 דקות
echo   4    35 דקות
echo   5    45 דקות
echo   6    55 דקות
echo   7    65 דקות
echo   8    75 דקות
echo   9    85 דקות
echo   10   95 דקות
echo   11   105 דקות
echo   12   115 דקות
echo   13   שעתיים
echo.
set /p tchoice="  בחר אפשרות: "

if "%tchoice%"=="1"  set MINS=5
if "%tchoice%"=="2"  set MINS=15
if "%tchoice%"=="3"  set MINS=25
if "%tchoice%"=="4"  set MINS=35
if "%tchoice%"=="5"  set MINS=45
if "%tchoice%"=="6"  set MINS=55
if "%tchoice%"=="7"  set MINS=65
if "%tchoice%"=="8"  set MINS=75
if "%tchoice%"=="9"  set MINS=85
if "%tchoice%"=="10" set MINS=95
if "%tchoice%"=="11" set MINS=105
if "%tchoice%"=="12" set MINS=115
if "%tchoice%"=="13" set MINS=120
if not defined MINS (echo   בחירה לא תקינה & timeout /t 2 >nul & goto TIMER_MENU)

call :DO_DISABLE

:: יצירת Scheduled Task לשחזור אוטומטי
schtasks /delete /tn "SecurityAutoRestore" /f >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$t=(Get-Date).AddMinutes(%MINS%); $a=New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c \"%~f0\" _restore'; $tr=New-ScheduledTaskTrigger -Once -At $t; $s=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5); Register-ScheduledTask -TaskName SecurityAutoRestore -Action $a -Trigger $tr -Settings $s -RunLevel Highest -Force | Out-Null"

for /f "tokens=1-2 delims=:" %%a in ("%time%") do (
    set /a "rh=%%a, rm=%%b+%MINS%, rh+=rm/60, rm%%=60"
)
if %rh% geq 24 set /a rh-=24
if %rm% lss 10 set rmstr=0%rm% & goto SKIP_RM
set rmstr=%rm%
:SKIP_RM
if %rh% lss 10 set rhstr=0%rh% & goto SKIP_RH
set rhstr=%rh%
:SKIP_RH

cls
echo.
echo   הגנות כובו בהצלחה
echo   ישוחזרו אוטומטית בשעה %rhstr%:%rmstr%
echo.
pause
exit /b

:: ─────────────────────────────────────────────────────────────────────────────
:ENABLE
cls
echo.
echo   מפעיל הגנות...
call :DO_ENABLE
schtasks /delete /tn "SecurityAutoRestore" /f >nul 2>&1
echo.
echo   הגנות הוחזרו בהצלחה
echo.
pause
exit /b

:: ─────────────────────────────────────────────────────────────────────────────
:: שחזור אוטומטי מ-Scheduled Task
if "%1"=="_restore" (
    call :DO_ENABLE
    schtasks /delete /tn "SecurityAutoRestore" /f >nul 2>&1
    exit /b
)

:: ─────────────────────────────────────────────────────────────────────────────
:DO_DISABLE
:: Defender
powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableScriptScanning $true -DisableArchiveScanning $true -SubmitSamplesConsent 2 -MAPSReporting 0" >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableOnAccessProtection /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableIOAVProtection /t REG_DWORD /d 1 /f >nul
net stop WinDefend >nul 2>&1
sc config WinDefend start= disabled >nul 2>&1
:: SmartScreen
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d Off /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 0 /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation /t REG_DWORD /d 0 /f >nul
:: Smart App Control
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy" /v VerifiedAndReputablePolicyState /t REG_DWORD /d 0 /f >nul
:: UAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f >nul
:: Firewall
netsh advfirewall set allprofiles state off >nul
exit /b

:: ─────────────────────────────────────────────────────────────────────────────
:DO_ENABLE
:: Defender
powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -DisableScriptScanning $false -DisableArchiveScanning $false -SubmitSamplesConsent 1 -MAPSReporting 2" >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableOnAccessProtection /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableIOAVProtection /f >nul 2>&1
sc config WinDefend start= auto >nul 2>&1
net start WinDefend >nul 2>&1
:: SmartScreen
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d On /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 1 /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation /t REG_DWORD /d 1 /f >nul
:: UAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 5 /f >nul
:: Firewall
netsh advfirewall set allprofiles state on >nul
exit /b
