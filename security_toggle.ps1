# הרץ כ-Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Host "יש להריץ כ-Administrator (לחץ ימני -> Run as Administrator)" -ForegroundColor Red
    pause; exit
}

$ErrorActionPreference = "SilentlyContinue"
$TaskName = "SecurityToggle_AutoRestore"
$ScriptPath = $MyInvocation.MyCommand.Path

# ─── כיבוי ───────────────────────────────────────────────────────────────────
function Disable-All {
    Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true `
                     -DisableIOAVProtection $true -DisableScriptScanning $true `
                     -DisableArchiveScanning $true -SubmitSamplesConsent 2 -MAPSReporting 0

    $k = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    if (-not (Test-Path $k)) { New-Item $k -Force | Out-Null }
    Set-ItemProperty $k "DisableAntiSpyware" 1 -Type DWord -Force
    $r = "$k\Real-Time Protection"
    if (-not (Test-Path $r)) { New-Item $r -Force | Out-Null }
    foreach ($n in @("DisableRealtimeMonitoring","DisableBehaviorMonitoring","DisableOnAccessProtection","DisableIOAVProtection")) {
        Set-ItemProperty $r $n 1 -Type DWord -Force
    }
    Stop-Service WinDefend -Force
    Set-Service  WinDefend -StartupType Disabled

    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "SmartScreenEnabled" "Off" -Force
    $s = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    if (-not (Test-Path $s)) { New-Item $s -Force | Out-Null }
    Set-ItemProperty $s "EnableSmartScreen" 0 -Type DWord -Force

    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy" "VerifiedAndReputablePolicyState" 0 -Type DWord -Force

    $u = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-ItemProperty $u "EnableLUA" 0 -Type DWord -Force
    Set-ItemProperty $u "ConsentPromptBehaviorAdmin" 0 -Type DWord -Force

    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
}

# ─── הדלקה ───────────────────────────────────────────────────────────────────
function Enable-All {
    Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false `
                     -DisableIOAVProtection $false -DisableScriptScanning $false `
                     -DisableArchiveScanning $false -SubmitSamplesConsent 1 -MAPSReporting 2

    $k = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    Remove-ItemProperty $k "DisableAntiSpyware" -Force
    $r = "$k\Real-Time Protection"
    foreach ($n in @("DisableRealtimeMonitoring","DisableBehaviorMonitoring","DisableOnAccessProtection","DisableIOAVProtection")) {
        Remove-ItemProperty $r $n -Force
    }
    Set-Service  WinDefend -StartupType Automatic
    Start-Service WinDefend

    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "SmartScreenEnabled" "On" -Force
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen" 1 -Type DWord -Force

    $u = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-ItemProperty $u "EnableLUA" 1 -Type DWord -Force
    Set-ItemProperty $u "ConsentPromptBehaviorAdmin" 5 -Type DWord -Force

    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

# ─── טיימר ───────────────────────────────────────────────────────────────────
function Set-Timer($minutes) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    $action    = New-ScheduledTaskAction -Execute "PowerShell.exe" `
                    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -AutoRestore"
    $trigger   = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($minutes)
    $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
                           -Settings $settings -Principal $principal -Force | Out-Null
}

# ─── מצב שחזור אוטומטי (מופעל מ-Scheduled Task) ──────────────────────────────
param([switch]$AutoRestore)
if ($AutoRestore) {
    Enable-All
    exit
}

# ─── תפריט ראשי ──────────────────────────────────────────────────────────────
Clear-Host
Write-Host ""
Write-Host "  ================================" -ForegroundColor Cyan
Write-Host "     ניהול הגנות Windows" -ForegroundColor Cyan
Write-Host "  ================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  1  כיבוי הגנות (לצמיתות)" -ForegroundColor Red
Write-Host "  2  כיבוי הגנות (לפי זמן)" -ForegroundColor Yellow
Write-Host "  3  הפעלת הגנות מחדש" -ForegroundColor Green
Write-Host ""
$choice = Read-Host "  בחר אפשרות"

# ─── אפשרות 1 — כיבוי לצמיתות ───────────────────────────────────────────────
if ($choice -eq "1") {
    Write-Host "`n  מכבה הגנות..." -ForegroundColor Red
    Disable-All
    Write-Host "  ✓ הגנות כובו" -ForegroundColor Red
    pause
}

# ─── אפשרות 2 — כיבוי לפי זמן ───────────────────────────────────────────────
elseif ($choice -eq "2") {
    Clear-Host
    Write-Host ""
    Write-Host "  ================================" -ForegroundColor Yellow
    Write-Host "     בחר משך זמן" -ForegroundColor Yellow
    Write-Host "  ================================" -ForegroundColor Yellow
    Write-Host ""

    $times = @(5,15,25,35,45,55,65,75,85,95,105,115,120)
    for ($i = 0; $i -lt $times.Count; $i++) {
        $m = $times[$i]
        if ($m -lt 60) {
            $label = "$m דקות"
        } elseif ($m -eq 60) {
            $label = "שעה"
        } elseif ($m -eq 120) {
            $label = "שעתיים"
        } else {
            $h = [math]::Floor($m / 60)
            $min = $m % 60
            $label = "שעה" + $(if ($h -gt 1) { " ו-$($h*60-60)" } else { "" }) + " ו-$min דקות"
        }
        Write-Host ("  {0,-3} {1}" -f ($i+1), $label)
    }

    Write-Host ""
    $t = Read-Host "  בחר אפשרות"

    if ($t -match '^\d+$' -and [int]$t -ge 1 -and [int]$t -le $times.Count) {
        $minutes = $times[[int]$t - 1]
        $restoreAt = (Get-Date).AddMinutes($minutes).ToString("HH:mm")

        Write-Host "`n  מכבה הגנות..." -ForegroundColor Yellow
        Disable-All
        Set-Timer $minutes

        Write-Host "  ✓ הגנות כובו" -ForegroundColor Yellow
        Write-Host "  ✓ ישוחזרו אוטומטית בשעה $restoreAt" -ForegroundColor Cyan
    } else {
        Write-Host "  בחירה לא תקינה" -ForegroundColor Red
    }
    pause
}

# ─── אפשרות 3 — הפעלה מחדש ───────────────────────────────────────────────────
elseif ($choice -eq "3") {
    Write-Host "`n  מפעיל הגנות..." -ForegroundColor Green
    Enable-All
    Write-Host "  ✓ הגנות הוחזרו" -ForegroundColor Green
    pause
}

else {
    Write-Host "  בחירה לא תקינה" -ForegroundColor Red
    pause
}
