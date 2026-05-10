@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "PS_SCRIPT=%SCRIPT_DIR%setup-project.ps1"

if not exist "%PS_SCRIPT%" (
  echo [ERROR] setup-project.ps1 was not found.
  exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" %*
set "EXIT_CODE=%ERRORLEVEL%"

if not "%EXIT_CODE%"=="0" (
  echo.
  echo [ERROR] Setup failed. Check setup-install.log for details.
  exit /b %EXIT_CODE%
)

echo.
echo [OK] Setup completed successfully.
exit /b 0
