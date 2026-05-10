@echo off
PowerShell -Command "Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%~dp0security_toggle.ps1""' -Verb RunAs"
