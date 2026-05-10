# Disable Smart App Control via registry
# Requires: Run as Administrator + Restart

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Host "ERROR: Run this script as Administrator (right-click -> Run as Administrator)" -ForegroundColor Red
    pause
    exit 1
}

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy"

try {
    # VerifiedAndReputablePolicyState: 0=Off, 1=On, 2=Evaluation
    Set-ItemProperty -Path $regPath -Name "VerifiedAndReputablePolicyState" -Value 0 -Type DWord -Force
    Write-Host "Smart App Control disabled successfully." -ForegroundColor Green
} catch {
    Write-Host "Failed to set registry: $_" -ForegroundColor Red
    pause
    exit 1
}

$restart = Read-Host "Restart now to apply changes? (y/n)"
if ($restart -eq "y") {
    Restart-Computer -Force
}
