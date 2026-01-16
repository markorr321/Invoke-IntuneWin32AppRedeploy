<#PSScriptInfo
.VERSION 2.1.0
.GUID 3f8e7d2a-5c4b-4e9f-a1d6-8b7c3e2f1a0d
.AUTHOR Mark Orr
.COPYRIGHT (c) 2026 Orr365. All rights reserved.
.DESCRIPTION Forces a redeploy of Intune Win32 applications by clearing local registry state and restarting the Intune Management Extension service. Uses Microsoft Graph for app name resolution.
.TAGS Intune Win32App Redeploy MicrosoftGraph Endpoint
.LICENSEURI https://github.com/markorr321/Invoke-IntuneWin32AppRedeploy/blob/main/LICENSE
.PROJECTURI https://github.com/markorr321/Invoke-IntuneWin32AppRedeploy
.ICONURI
.EXTERNALMODULEDEPENDENCIES Microsoft.Graph.Authentication
#>

[CmdletBinding()]
param (
    [Alias('Online')]
    [switch] $fetchOnline,

    [switch] $excludeSystemApp
)

function Invoke-IntuneWin32AppRedeploy {
    [CmdletBinding()]
    param (
        [Alias('Online')]
        [switch] $fetchOnline,

        [switch] $excludeSystemApp
    )

    #region helper functions
    function _getTargetName {
        param ([string] $id)

        if (!$id) { return $null }
        if ($id -eq 'device' -or $id -eq '00000000-0000-0000-0000-000000000000' -or $id -eq 'S-0-0-00-0000000000-0000000000-000000000-000') {
            return 'Device'
        } elseif ($id -match "^S-1-5-21") {
            try {
                return ((New-Object System.Security.Principal.SecurityIdentifier($id)).Translate([System.Security.Principal.NTAccount])).Value
            } catch {
                return 'User-Assigned'
            }
        } else {
            return 'User-Assigned'
        }
    }

    function _getIntuneAppName {
        param ([string] $appID)
        if ($script:intuneApp) {
            $app = $script:intuneApp | Where-Object { $_.Id -eq $appID }
            if ($app) { return $app.DisplayName }
        }
        return $null
    }

    function _connectToGraph {
        # Ensure NuGet provider is installed
        if (!(Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
            Write-Host "Installing NuGet provider..." -ForegroundColor Yellow
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
        }

        # Check for Microsoft.Graph.Authentication module and install if missing
        if (!(Get-Module 'Microsoft.Graph.Authentication' -ListAvailable)) {
            Write-Host "Installing required module: Microsoft.Graph.Authentication..." -ForegroundColor Yellow
            try {
                Install-Module 'Microsoft.Graph.Authentication' -Scope AllUsers -Force -AllowClobber -ErrorAction Stop
            } catch {
                throw "Failed to install module 'Microsoft.Graph.Authentication': $_"
            }
        }

        # Import the module
        Write-Host "Loading Microsoft Graph module..." -ForegroundColor Cyan
        Import-Module 'Microsoft.Graph.Authentication' -ErrorAction Stop

        # Get access token using MSAL with browser authentication
        $clientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"  # Microsoft Graph PowerShell client ID

        Write-Host "Connecting to Microsoft Graph (browser auth)..." -ForegroundColor Cyan

        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

            # Load MSAL assembly from the Graph module
            $msalPath = (Get-Module Microsoft.Graph.Authentication -ListAvailable | Select-Object -First 1).ModuleBase
            $msalDll = Get-ChildItem -Path $msalPath -Recurse -Filter "Microsoft.Identity.Client.dll" | Select-Object -First 1
            if ($msalDll) {
                Add-Type -Path $msalDll.FullName -ErrorAction SilentlyContinue
            }

            # Build MSAL public client application
            $publicClient = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create($clientId).
                WithAuthority("https://login.microsoftonline.com/common").
                WithRedirectUri("http://localhost").
                Build()

            # Acquire token interactively using system browser
            [string[]]$scopeArray = @('https://graph.microsoft.com/DeviceManagementApps.Read.All')
            $authResult = $publicClient.AcquireTokenInteractive($scopeArray).
                WithPrompt([Microsoft.Identity.Client.Prompt]::SelectAccount).
                WithUseEmbeddedWebView($false).
                ExecuteAsync().GetAwaiter().GetResult()

            # Connect to Graph using the access token
            $secureToken = ConvertTo-SecureString $authResult.AccessToken -AsPlainText -Force
            Connect-MgGraph -AccessToken $secureToken -NoWelcome -ErrorAction Stop | Out-Null
            Write-Host "Connected to Microsoft Graph" -ForegroundColor Green
        } catch {
            throw "Failed to connect to Microsoft Graph: $_"
        }

        # Fetch Intune apps
        Write-Host "Fetching Intune apps..." -ForegroundColor Cyan
        $script:intuneApp = @()
        $uri = "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps?`$select=id,displayName"
        do {
            $response = Invoke-MgGraphRequest -Uri $uri -Method GET
            $script:intuneApp += $response.value | ForEach-Object {
                [PSCustomObject]@{ Id = $_.id; DisplayName = $_.displayName }
            }
            $uri = $response.'@odata.nextLink'
        } while ($uri)
        Write-Host "Found $($script:intuneApp.Count) apps" -ForegroundColor Green
    }

    function _getFailedApps {
        $failedApps = @()
        $win32AppsKeyPath = 'HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps'
        $appSubKeys = Get-ChildItem -Path $win32AppsKeyPath -Recurse -ErrorAction SilentlyContinue

        foreach ($subKey in $appSubKeys) {
            if ($subKey.PSChildName -eq 'EnforcementStateMessage') {
                $msg = Get-ItemProperty -Path $subKey.PSPath -Name EnforcementStateMessage -ErrorAction SilentlyContinue
                if ($msg.EnforcementStateMessage -match '"ErrorCode":(-?\d+|null)') {
                    $code = $matches[1]
                    if ($code -ne "null") {
                        $codeInt = [int]$code
                        if (($codeInt -ne 0) -and ($codeInt -ne 3010)) {
                            # Parse the path to get userId and appId
                            # Path: HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\{userId}\{appId}_1\EnforcementStateMessage
                            $pathParts = $subKey.PSPath -replace 'Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\', '' -split '\\'
                            if ($pathParts.Count -ge 6) {
                                $userId = $pathParts[4]
                                $appIdWithVersion = $pathParts[5]
                                $appId = $appIdWithVersion -replace '_\d+$', ''

                                if ($excludeSystemApp -and $userId -eq "00000000-0000-0000-0000-000000000000") {
                                    continue
                                }

                                $displayName = _getIntuneAppName $appId
                                $failedApps += [PSCustomObject]@{
                                    Scope       = _getTargetName $userId
                                    DisplayName = $displayName
                                    Id          = $appId
                                    ErrorCode   = $codeInt
                                    ScopeId     = $userId
                                }
                            }
                        }
                    }
                }
            }
        }
        return $failedApps
    }

    function _getAllApps {
        $allApps = @()
        $win32AppsKeyPath = 'HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps'

        foreach ($userKey in (Get-ChildItem $win32AppsKeyPath -ErrorAction SilentlyContinue)) {
            $userId = Split-Path $userKey.Name -Leaf

            if ($excludeSystemApp -and $userId -eq "00000000-0000-0000-0000-000000000000") {
                continue
            }

            $appIds = Get-ChildItem $userKey.PSPath -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty PSChildName |
                ForEach-Object { $_ -replace "_\d+$" } |
                Select-Object -Unique

            foreach ($appId in $appIds) {
                # Skip GRS folder
                if ($appId -eq 'GRS') { continue }

                $newestRecord = Get-ChildItem $userKey.PSPath |
                    Where-Object { $_.PSChildName -Match ([regex]::escape($appId)) } |
                    Sort-Object -Descending -Property PSChildName |
                    Select-Object -First 1

                $errorCode = 0
                # Check EnforcementStateMessage subkey
                $enforcementSubKey = Get-ChildItem $newestRecord.PSPath -ErrorAction SilentlyContinue |
                    Where-Object { $_.PSChildName -eq 'EnforcementStateMessage' }
                if ($enforcementSubKey) {
                    $msg = Get-ItemProperty -Path $enforcementSubKey.PSPath -Name EnforcementStateMessage -ErrorAction SilentlyContinue
                    if ($msg.EnforcementStateMessage -match '"ErrorCode":(-?\d+|null)') {
                        $code = $matches[1]
                        if ($code -ne "null") {
                            $errorCode = [int]$code
                        }
                    }
                }

                $displayName = _getIntuneAppName $appId
                $allApps += [PSCustomObject]@{
                    Scope       = _getTargetName $userId
                    DisplayName = $displayName
                    Id          = $appId
                    ErrorCode   = $errorCode
                    ScopeId     = $userId
                }
            }
        }
        return $allApps
    }

    function _redeployApps {
        param ([array]$apps)

        if (!$apps -or $apps.Count -eq 0) {
            Write-Warning "No apps to redeploy"
            return
        }

        $win32AppKeys = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps" -Recurse -Depth 2 |
            Select-Object PSChildName, PSPath, PSParentPath

        foreach ($app in $apps) {
            $appId = $app.Id
            $scopeId = $app.ScopeId
            if ($scopeId -eq 'device') { $scopeId = "00000000-0000-0000-0000-000000000000" }

            $appName = if ($app.DisplayName) { $app.DisplayName } else { $appId }
            Write-Warning "Preparing redeploy for $appName (scope $($app.Scope))"

            # Delete app registry key
            $win32AppKeyToDelete = $win32AppKeys | Where-Object {
                $_.PSChildName -Match "^$appId`_\d+" -and $_.PSParentPath -Match "\\$scopeId$"
            }

            if ($win32AppKeyToDelete) {
                $win32AppKeyToDelete | ForEach-Object {
                    Write-Verbose "Deleting $($_.PSPath)"
                    Remove-Item $_.PSPath -Force -Recurse
                }

                # Clear GRS entries
                $grsPath = "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\$scopeId\GRS"
                if (Test-Path $grsPath) {
                    Get-ChildItem -Path $grsPath | ForEach-Object {
                        $grsProps = $_ | Get-ItemProperty
                        if ($grsProps.psobject.Properties.Name -contains $appId) {
                            Write-Warning "Deleting GRS entry for $appName"
                            Remove-Item $_.PSPath -Force -Recurse
                        }
                    }
                }
            } else {
                Write-Warning "App $appName registry key not found - may already be removed"
            }
        }

        Write-Warning "Restarting Intune Management Extension service..."
        Restart-Service IntuneManagementExtension -Force
        Write-Host "Redeploy initiated. Apps should reinstall within a few minutes." -ForegroundColor Green
    }

    #endregion helper functions

    #region main
    # Ensure we're running in 64-bit PowerShell (required for correct registry access)
    if ($env:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
        Write-Host "Relaunching in 64-bit PowerShell..." -ForegroundColor Yellow
        $scriptPath = $MyInvocation.MyCommand.Path
        if (!$scriptPath) { $scriptPath = $PSCommandPath }
        $argList = "-ExecutionPolicy Bypass -File `"$scriptPath`""
        if ($fetchOnline) { $argList += " -Online" }
        if ($excludeSystemApp) { $argList += " -excludeSystemApp" }
        & "$env:SystemRoot\SysNative\WindowsPowerShell\v1.0\powershell.exe" $argList
        return
    }

    # Auto-elevate to admin if not already
    if (! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "Elevating to administrator..." -ForegroundColor Yellow
        $scriptPath = $MyInvocation.MyCommand.Path
        if (!$scriptPath) { $scriptPath = $PSCommandPath }
        $argList = "-NoExit -NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
        if ($fetchOnline) { $argList += " -Online" }
        if ($excludeSystemApp) { $argList += " -excludeSystemApp" }
        Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
        return
    }

    # Connect to Graph first if -Online specified
    if ($fetchOnline) {
        _connectToGraph
    }

    # Show menu
    Write-Host ""
    Write-Host "=====================================" -ForegroundColor Cyan
    Write-Host "  Intune Win32 App Redeploy Tool" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. Select apps to reinstall (GridView)" -ForegroundColor White
    Write-Host "2. Reinstall all failed apps" -ForegroundColor White
    Write-Host "3. Exit" -ForegroundColor White
    Write-Host ""
    $choice = Read-Host "Enter choice (1-3)"

    switch ($choice) {
        "1" {
            # Option 1: Show all apps in GridView for selection
            Write-Host "Loading apps..." -ForegroundColor Cyan
            $allApps = _getAllApps

            if (!$allApps -or $allApps.Count -eq 0) {
                Write-Warning "No deployed Win32 apps detected"
                return
            }

            # Filter out apps without DisplayName if online mode
            if ($fetchOnline) {
                $appsToShow = $allApps | Where-Object { $_.DisplayName }
            } else {
                $appsToShow = $allApps
            }

            $selectedApps = $appsToShow | Out-GridView -PassThru -Title "Select app(s) to redeploy"

            if (!$selectedApps) {
                Write-Warning "No apps selected"
                return
            }

            _redeployApps $selectedApps
        }
        "2" {
            # Option 2: Automatically redeploy all failed apps
            Write-Host "Scanning for failed apps..." -ForegroundColor Cyan
            $failedApps = _getFailedApps

            if (!$failedApps -or $failedApps.Count -eq 0) {
                Write-Host "No failed apps detected!" -ForegroundColor Green
                return
            }

            Write-Host ""
            Write-Host "Found $($failedApps.Count) failed app(s):" -ForegroundColor Yellow
            foreach ($app in $failedApps) {
                $appName = if ($app.DisplayName) { $app.DisplayName } else { $app.Id }
                Write-Host "  - $appName (Error: $($app.ErrorCode))" -ForegroundColor Red
            }
            Write-Host ""

            $confirm = Read-Host "Redeploy all failed apps? (Y/N)"
            if ($confirm -eq 'Y' -or $confirm -eq 'y') {
                _redeployApps $failedApps
            } else {
                Write-Host "Cancelled" -ForegroundColor Yellow
            }
        }
        "3" {
            Write-Host "Exiting..." -ForegroundColor Yellow
            return
        }
        default {
            Write-Warning "Invalid choice"
        }
    }
    #endregion main
}

# Auto-execute when script is run directly
Invoke-IntuneWin32AppRedeploy @PSBoundParameters
