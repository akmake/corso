# ============================================================
#  disable_windows_security.ps1
#  מנטרל את כל שכבות האבטחה של Windows
#  מיועד לסביבת פיתוח / OSINT / כלי Docker ו-Python
#  הרץ כ-Administrator
# ============================================================

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Host "ERROR: יש להריץ כ-Administrator (לחץ ימני -> Run as Administrator)" -ForegroundColor Red
    pause
    exit 1
}

$ErrorActionPreference = "SilentlyContinue"

function Write-Step($msg) { Write-Host "`n>> $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "   [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "   [--] $msg" -ForegroundColor Yellow }

Write-Host "============================================================" -ForegroundColor Magenta
Write-Host "  Windows Security Disabler — סביבת פיתוח / OSINT" -ForegroundColor Magenta
Write-Host "============================================================" -ForegroundColor Magenta

# ─── 1. Windows Defender — כיבוי מלא ────────────────────────────────────────
Write-Step "Windows Defender — כיבוי Real-Time Protection וכל הסורקים"

Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisablePrivacyMode $true
Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true
Set-MpPreference -DisableArchiveScanning $true
Set-MpPreference -DisableIntrusionPreventionSystem $true
Set-MpPreference -DisableScriptScanning $true
Set-MpPreference -SubmitSamplesConsent 2
Set-MpPreference -MAPSReporting 0
Set-MpPreference -HighThreatDefaultAction 6
Set-MpPreference -ModerateThreatDefaultAction 6
Set-MpPreference -LowThreatDefaultAction 6
Set-MpPreference -SevereThreatDefaultAction 6
Write-OK "Defender real-time protection כובה"

# ─── 2. כיבוי Defender דרך Registry (עמיד יותר) ─────────────────────────────
Write-Step "Registry — DisableAntiSpyware + DisableAntiVirus"

$defenderKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
If (-NOT (Test-Path $defenderKey)) { New-Item -Path $defenderKey -Force | Out-Null }
Set-ItemProperty -Path $defenderKey -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $defenderKey -Name "DisableAntiVirus"   -Value 1 -Type DWord -Force

$rtpKey = "$defenderKey\Real-Time Protection"
If (-NOT (Test-Path $rtpKey)) { New-Item -Path $rtpKey -Force | Out-Null }
Set-ItemProperty -Path $rtpKey -Name "DisableRealtimeMonitoring"      -Value 1 -Type DWord -Force
Set-ItemProperty -Path $rtpKey -Name "DisableBehaviorMonitoring"       -Value 1 -Type DWord -Force
Set-ItemProperty -Path $rtpKey -Name "DisableOnAccessProtection"       -Value 1 -Type DWord -Force
Set-ItemProperty -Path $rtpKey -Name "DisableScanOnRealtimeEnable"     -Value 1 -Type DWord -Force
Set-ItemProperty -Path $rtpKey -Name "DisableIOAVProtection"           -Value 1 -Type DWord -Force
Write-OK "Registry keys הוגדרו"

# ─── 3. כיבוי שירות WinDefend ────────────────────────────────────────────────
Write-Step "שירות WinDefend — עצירה + Startup=Disabled"

Stop-Service -Name WinDefend -Force
Set-Service  -Name WinDefend -StartupType Disabled
Write-OK "שירות WinDefend הופסק"

# ─── 4. SmartScreen — כיבוי מלא ─────────────────────────────────────────────
Write-Step "SmartScreen — כיבוי לכל הרמות"

# System level
$ssKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
Set-ItemProperty -Path $ssKey -Name "SmartScreenEnabled" -Value "Off" -Type String -Force

# Edge / App
$edgeKey = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
If (-NOT (Test-Path $edgeKey)) { New-Item -Path $edgeKey -Force | Out-Null }
Set-ItemProperty -Path $edgeKey -Name "SmartScreenEnabled" -Value 0 -Type DWord -Force

# App & Browser Control
$absKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost"
If (-NOT (Test-Path $absKey)) { New-Item -Path $absKey -Force | Out-Null }
Set-ItemProperty -Path $absKey -Name "EnableWebContentEvaluation" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $absKey -Name "PreventOverride"            -Value 0 -Type DWord -Force

$policyKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
If (-NOT (Test-Path $policyKey)) { New-Item -Path $policyKey -Force | Out-Null }
Set-ItemProperty -Path $policyKey -Name "EnableSmartScreen" -Value 0 -Type DWord -Force
Write-OK "SmartScreen כובה בכל הרמות"

# ─── 5. Smart App Control ────────────────────────────────────────────────────
Write-Step "Smart App Control — כיבוי"

$sacKey = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy"
Set-ItemProperty -Path $sacKey -Name "VerifiedAndReputablePolicyState" -Value 0 -Type DWord -Force
Write-OK "Smart App Control כובה (נדרש רסטארט לתוקף מלא)"

# ─── 6. User Account Control (UAC) — הורדה לרמה נמוכה ────────────────────────
Write-Step "UAC — הורדה לרמה נמוכה (ללא הפתעות מיותרות)"

$uacKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $uacKey -Name "EnableLUA"                    -Value 0 -Type DWord -Force
Set-ItemProperty -Path $uacKey -Name "ConsentPromptBehaviorAdmin"   -Value 0 -Type DWord -Force
Set-ItemProperty -Path $uacKey -Name "PromptOnSecureDesktop"        -Value 0 -Type DWord -Force
Write-OK "UAC כובה"

# ─── 7. הוספת Exclusions לתיקיות הרלוונטיות ─────────────────────────────────
Write-Step "Exclusions — הוספת חריגים לתיקיות הפרויקטים ו-Docker"

$excludePaths = @(
    "$env:USERPROFILE\Documents\GitHub",
    "$env:USERPROFILE\AppData\Local\Docker",
    "$env:USERPROFILE\AppData\Local\Programs\Python",
    "C:\Program Files\Docker",
    "C:\ProgramData\DockerDesktop",
    "$env:TEMP"
)

foreach ($p in $excludePaths) {
    if (Test-Path $p) {
        Add-MpPreference -ExclusionPath $p
        Write-OK "Exclusion: $p"
    } else {
        Write-Warn "לא קיים (דולג): $p"
    }
}

# Exclusion על תהליכים
$excludeProcesses = @("python.exe","python3.exe","docker.exe","dockerd.exe","node.exe","npm.cmd","git.exe")
foreach ($proc in $excludeProcesses) {
    Add-MpPreference -ExclusionProcess $proc
}
Write-OK "Process exclusions הוגדרו (python, docker, node, git)"

# ─── 8. Windows Firewall — כיבוי כל הפרופילים ───────────────────────────────
Write-Step "Windows Firewall — כיבוי"

Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
Write-OK "Firewall כובה לכל הפרופילים"

# ─── סיכום ───────────────────────────────────────────────────────────────────
Write-Host "`n============================================================" -ForegroundColor Magenta
Write-Host "  הושלם בהצלחה!" -ForegroundColor Green
Write-Host "  מומלץ לבצע רסטארט לתוקף מלא של Smart App Control ו-UAC" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Magenta

$restart = Read-Host "`nלבצע רסטארט עכשיו? (y/n)"
if ($restart -eq "y") {
    Restart-Computer -Force
}
