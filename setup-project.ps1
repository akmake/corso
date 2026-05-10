[CmdletBinding()]
param(
    [switch]$IncludeReact
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $ScriptRoot

$LogFile = Join-Path $ScriptRoot "setup-install.log"
"[{0}] [INFO] Starting Python Courses setup in {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $ScriptRoot | Set-Content -Encoding UTF8 -LiteralPath $LogFile

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet("INFO", "OK", "WARN", "ERR")][string]$Level = "INFO"
    )

    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Add-Content -LiteralPath $LogFile -Value $line

    switch ($Level) {
        "OK" { Write-Host $line -ForegroundColor Green }
        "WARN" { Write-Host $line -ForegroundColor Yellow }
        "ERR" { Write-Host $line -ForegroundColor Red }
        default { Write-Host $line -ForegroundColor Gray }
    }
}

function Write-Section {
    param([Parameter(Mandatory = $true)][string]$Title)
    Write-Host ""
    Write-Host "==================================================================" -ForegroundColor DarkCyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host "==================================================================" -ForegroundColor DarkCyan
}

function Refresh-SessionPath {
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $parts = @($machinePath, $userPath) | Where-Object { $_ -and $_.Trim() -ne "" }
    $env:Path = $parts -join ";"
}

function Test-CommandExists {
    param([Parameter(Mandatory = $true)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Invoke-Step {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @(),
        [Parameter(Mandatory = $true)][string]$Description
    )

    Write-Log $Description "INFO"
    & $FilePath @Arguments
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "$Description failed (exit code $exitCode)."
    }
}

function Test-IsAdministrator {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-WingetPackage {
    param(
        [Parameter(Mandatory = $true)][string]$PackageId,
        [Parameter(Mandatory = $true)][string]$DisplayName
    )

    if (-not (Test-CommandExists "winget")) {
        throw "winget was not found. Install Microsoft App Installer, then rerun setup."
    }

    $alreadyInstalled = $false
    try {
        $installed = (& winget list --id $PackageId --exact --accept-source-agreements 2>$null | Out-String)
        if ($installed -match [Regex]::Escape($PackageId)) {
            $alreadyInstalled = $true
        }
    } catch {
        $alreadyInstalled = $false
    }

    if ($alreadyInstalled) {
        Write-Log "$DisplayName already installed." "OK"
        return
    }

    Write-Log "Installing $DisplayName via winget ($PackageId)." "INFO"
    $args = @(
        "install",
        "--id", $PackageId,
        "--exact",
        "--silent",
        "--accept-package-agreements",
        "--accept-source-agreements"
    )

    if (Test-IsAdministrator) {
        $args += @("--scope", "machine")
    } else {
        $args += @("--scope", "user")
    }

    try {
        Invoke-Step -FilePath "winget" -Arguments $args -Description "winget install $DisplayName"
    } catch {
        Write-Log "Scoped install failed for $DisplayName, retrying default scope..." "WARN"
        $fallbackArgs = @(
            "install",
            "--id", $PackageId,
            "--exact",
            "--silent",
            "--accept-package-agreements",
            "--accept-source-agreements"
        )
        Invoke-Step -FilePath "winget" -Arguments $fallbackArgs -Description "winget install $DisplayName (fallback)"
    }

    Refresh-SessionPath
}

function Get-PythonCommand {
    if (Test-CommandExists "python") { return "python" }
    if (Test-CommandExists "py") { return "py" }
    return $null
}

function Assert-Paths {
    $needed = @(
        "python\main.py",
        "python\requirements-courses.txt"
    )

    foreach ($relative in $needed) {
        $full = Join-Path $ScriptRoot $relative
        if (-not (Test-Path -LiteralPath $full)) {
            throw "Missing required file: $relative"
        }
    }

    if ($IncludeReact) {
        $clientPkg = Join-Path $ScriptRoot "client\package.json"
        if (-not (Test-Path -LiteralPath $clientPkg)) {
            throw "Missing required file for React setup: client\package.json"
        }
    }
}

try {
    Write-Section "Python Courses Auto Setup"
    Assert-Paths

    Write-Section "1) Install Python"
    if (-not (Get-PythonCommand)) {
        Ensure-WingetPackage -PackageId "Python.Python.3.12" -DisplayName "Python 3.12"
    } else {
        Write-Log "Python already exists in PATH." "OK"
    }

    Refresh-SessionPath
    $pythonCmd = Get-PythonCommand
    if (-not $pythonCmd) {
        throw "Python is still unavailable after installation."
    }

    $pythonVersion = & $pythonCmd -c "import sys; print('.'.join(map(str, sys.version_info[:3])))"
    Write-Log "Python version: $pythonVersion" "OK"

    Write-Section "2) Create Virtual Environment"
    $venvPath = Join-Path $ScriptRoot "python\.venv"
    $venvPython = Join-Path $venvPath "Scripts\python.exe"

    if (-not (Test-Path -LiteralPath $venvPython)) {
        Invoke-Step -FilePath $pythonCmd -Arguments @("-m", "venv", $venvPath) -Description "Creating python virtual environment"
    } else {
        Write-Log "Virtual environment already exists: $venvPath" "OK"
    }

    Write-Section "3) Install Courses Dependencies"
    Invoke-Step -FilePath $venvPython -Arguments @("-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel") -Description "Upgrading pip toolchain"
    Invoke-Step -FilePath $venvPython -Arguments @("-m", "pip", "install", "-r", (Join-Path $ScriptRoot "python\requirements-courses.txt")) -Description "Installing python courses requirements"

    if ($IncludeReact) {
        Write-Section "4) Optional React Setup"
        if (-not (Test-CommandExists "node")) {
            Ensure-WingetPackage -PackageId "OpenJS.NodeJS.LTS" -DisplayName "Node.js LTS"
        } else {
            Write-Log "Node.js already exists in PATH." "OK"
        }

        Refresh-SessionPath
        if (-not (Test-CommandExists "node")) { throw "Node.js is still unavailable after installation." }
        if (-not (Test-CommandExists "npm")) { throw "npm is still unavailable after installation." }

        $clientDir = Join-Path $ScriptRoot "client"
        Push-Location -LiteralPath $clientDir
        try {
            if (Test-Path -LiteralPath "package-lock.json") {
                Invoke-Step -FilePath "npm" -Arguments @("ci") -Description "Installing React client dependencies with npm ci"
            } else {
                Invoke-Step -FilePath "npm" -Arguments @("install") -Description "Installing React client dependencies with npm install"
            }
        } finally {
            Pop-Location
        }
        Write-Log "React dependencies installed." "OK"
    } else {
        Write-Log "React setup skipped (Python courses only mode)." "INFO"
    }

    Write-Section "5) Validate Runtime"
    Invoke-Step -FilePath $venvPython -Arguments @("-c", "import fastapi, yt_dlp, imageio_ffmpeg, faster_whisper; print('IMPORT_OK')") -Description "Validating required python imports"

    Write-Section "Setup Completed"
    Write-Log "Done. Installed only Python + courses dependencies." "OK"
    if ($IncludeReact) {
        Write-Log "React is ready too." "OK"
    }
    Write-Log "Run API:" "INFO"
    Write-Log "cd python && .\\.venv\\Scripts\\python.exe -m uvicorn main:app --reload --host 0.0.0.0 --port 8000" "INFO"
    if ($IncludeReact) {
        Write-Log "Run React UI:" "INFO"
        Write-Log "npm --prefix client run dev" "INFO"
    }
} catch {
    Write-Log $_.Exception.Message "ERR"
    Write-Log "Setup failed. Review log: $LogFile" "ERR"
    exit 1
}
