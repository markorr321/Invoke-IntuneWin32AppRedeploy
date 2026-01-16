<#
.SYNOPSIS
    Detects failed Intune Win32 app installations.

.DESCRIPTION
    This script scans the Intune Management Extension registry keys to identify
    Win32 applications that have failed to install. It searches for EnforcementStateMessage
    properties containing non-zero error codes (excluding success codes 0 and 3010).

    Designed for use as an Intune Proactive Remediation detection script.
    Returns exit code 1 if failures are detected, exit code 0 if no failures.

.AUTHOR
    Mark Orr

.COMPANY
    First American

.NOTES
    File Name: Win32AppRedeploy-Detect.ps1
    Requires: Run as SYSTEM context in Intune
#>

# Ensure we're running in 64-bit PowerShell (required for correct registry access)
if ($env:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
    # Running in 32-bit PowerShell on 64-bit OS, relaunch in 64-bit
    $scriptPath = $MyInvocation.MyCommand.Path
    & "$env:SystemRoot\SysNative\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Bypass -File $scriptPath
    exit $LASTEXITCODE
}

# Start Logging
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
Start-Transcript "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\App_Failure_Detection_$timestamp.log"


#### SCRIPT ENTRY POINT ####

$win32AppsKeyPath = 'HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps'

# Check if the registry path exists
if (!(Test-Path $win32AppsKeyPath)) {
    Write-Host "Intune Management Extension Win32Apps registry path not found. No apps deployed."
    Stop-Transcript
    exit 0
}

$appSubKeys = Get-ChildItem -Path $win32AppsKeyPath -Recurse -ErrorAction SilentlyContinue

$failureCount = 0
foreach ($subKey in $appSubKeys) {
    if ($subKey.PSChildName -eq 'EnforcementStateMessage') {
        $msg = Get-ItemProperty -Path $subKey.PSPath -Name EnforcementStateMessage -ErrorAction SilentlyContinue
        if ($msg.EnforcementStateMessage -match '"ErrorCode":(-?\d+|null)') {
            $code = $matches[1]
            if ($code -ne "null") {
                $codeInt = [int]$code
                if (($codeInt -ne 0) -and ($codeInt -ne 3010)) {
                    Write-Host "Failure found: ErrorCode $codeInt"
                    $failureCount++
                }
            }
        }
    }
}

# Output the result
if ($failureCount -gt 0) {
    Write-Host "Total failures: $failureCount"
    Stop-Transcript
    exit 1
}
else {
    Write-Host "No failures detected."
    Stop-Transcript
    exit 0
}
