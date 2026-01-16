<#
.SYNOPSIS
Forces redeploy of selected Win32App deployed from Intune.

.DESCRIPTION
Forces redeploy of selected Win32App deployed from Intune.
OutGridView is used to output found Apps.
Redeploy means that corresponding registry keys will be deleted from registry and service IntuneManagementExtension will be restarted.

.PARAMETER Online
Switch for getting Apps and User names from Intune, so locally used IDs can be translated to them.

.PARAMETER excludeSystemApp
Switch for excluding Apps targeted to SYSTEM.

.EXAMPLE
.\Invoke-IntuneWin32AppRedeploy-Standalone.ps1

Get and show Win32App(s) deployed from Intune to this computer. Selected ones will be then redeployed.

.EXAMPLE
.\Invoke-IntuneWin32AppRedeploy-Standalone.ps1 -Online

Get and show Win32App(s) deployed from Intune with friendly names. Selected ones will be then redeployed.

.EXAMPLE
.\Invoke-IntuneWin32AppRedeploy-Standalone.ps1 -Online -excludeSystemApp

Get and show Win32App(s) with friendly names, excluding device-targeted apps.

.NOTES
Author: Mark Orr
Original Author: @AndrewZtrhgf
Updated for Microsoft.Graph module
#>

[CmdletBinding()]
param (
    [Alias('Online')]
    [switch] $fetchOnline,

    [switch] $excludeSystemApp
)

#region helper function
function _getTargetName {
    param ([string] $id)

    Write-Verbose "Translating $id"

    if (!$id) {
        Write-Verbose "id was null"
        return
    } elseif ($id -eq 'device') {
        return 'Device'
    }

    $errPref = $ErrorActionPreference
    $ErrorActionPreference = "Stop"
    try {
        if ($id -eq '00000000-0000-0000-0000-000000000000' -or $id -eq 'S-0-0-00-0000000000-0000000000-000000000-000') {
            return 'Device'
        } elseif ($id -match "^S-1-5-21") {
            # it is local account
            return ((New-Object System.Security.Principal.SecurityIdentifier($id)).Translate([System.Security.Principal.NTAccount])).Value
        } else {
            # it is Entra ID account
            if ($fetchOnline) {
                return ($script:intuneUser | Where-Object { $_.Id -eq $id }).UserPrincipalName
            } else {
                return $id
            }
        }
    } catch {
        Write-Warning "Unable to translate $id to account name ($_)"
        $ErrorActionPreference = $errPref
        return $id
    }
}

function _getIntuneApp {
    param ([string] $appID)

    $script:intuneApp | Where-Object { $_.Id -eq $appID }
}
#endregion helper function

#region prepare
if (! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    throw "Run as administrator"
}

if ($fetchOnline) {
    # Ensure NuGet provider is installed
    if (!(Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
        Write-Host "Installing NuGet provider..." -ForegroundColor Yellow
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
    }

    # Check for Microsoft.Graph modules and install if missing
    $requiredModules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Devices.CorporateManagement', 'Microsoft.Graph.Users')
    foreach ($module in $requiredModules) {
        if (!(Get-Module $module -ListAvailable)) {
            Write-Host "Installing required module: $module..." -ForegroundColor Yellow
            try {
                Install-Module $module -Scope AllUsers -Force -AllowClobber -ErrorAction Stop
            } catch {
                throw "Failed to install module '$module': $_"
            }
        }
    }

    # Import the modules
    foreach ($module in $requiredModules) {
        Import-Module $module -ErrorAction Stop
    }

    # Connect to Microsoft Graph (interactive authentication)
    $requiredScopes = @('DeviceManagementApps.Read.All', 'User.Read.All')
    try {
        # Always disconnect and reconnect to ensure fresh authentication
        Disconnect-MgGraph -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
    } catch {
        throw "Failed to connect to Microsoft Graph: $_"
    }

    Write-Verbose "Getting Intune data"

    # Get mobile apps using Microsoft Graph
    $script:intuneApp = Get-MgDeviceAppManagementMobileApp -All -Property Id, DisplayName |
        Select-Object Id, DisplayName

    # Get users
    $script:intuneUser = Get-MgUser -All -Property Id, UserPrincipalName |
        Select-Object Id, UserPrincipalName
}
#endregion prepare

#region get data
$win32App = foreach ($app in (Get-ChildItem "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps" -ErrorAction SilentlyContinue)) {
    $userEntraObjectID = Split-Path $app.Name -Leaf

    if ($excludeSystemApp -and $userEntraObjectID -eq "00000000-0000-0000-0000-000000000000") {
        Write-Verbose "Skipping system deployments"
        continue
    }

    $userWin32AppRoot = $app.PSPath
    $win32AppIDList = Get-ChildItem $userWin32AppRoot | Select-Object -ExpandProperty PSChildName | ForEach-Object { $_ -replace "_\d+$" } | Select-Object -Unique

    $win32AppIDList | ForEach-Object {
        $win32AppID = $_

        Write-Verbose "Processing App ID $win32AppID"

        $newestWin32AppRecord = Get-ChildItem $userWin32AppRoot | Where-Object { $_.PSChildName -Match ([regex]::escape($win32AppID)) } | Sort-Object -Descending -Property PSChildName | Select-Object -First 1

        $lastUpdatedTimeUtc = Get-ItemPropertyValue $newestWin32AppRecord.PSPath -Name LastUpdatedTimeUtc
        try {
            $complianceStateMessage = Get-ItemPropertyValue "$($newestWin32AppRecord.PSPath)\ComplianceStateMessage" -Name ComplianceStateMessage -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        } catch {
            Write-Verbose "`tUnable to get Compliance State Message data"
        }

        $lastError = $complianceStateMessage.ErrorCode
        if (!$lastError) { $lastError = 0 }

        if ($fetchOnline) {
            $property = [ordered]@{
                "Scope"              = _getTargetName $userEntraObjectID
                "DisplayName"        = (_getIntuneApp $win32AppID).DisplayName
                "Id"                 = $win32AppID
                "LastUpdatedTimeUtc" = $lastUpdatedTimeUtc
                "ProductVersion"     = $complianceStateMessage.ProductVersion
                "LastError"          = $lastError
                "ScopeId"            = $userEntraObjectID
            }
        } else {
            $property = [ordered]@{
                "ScopeId"            = _getTargetName $userEntraObjectID
                "Id"                 = $win32AppID
                "LastUpdatedTimeUtc" = $lastUpdatedTimeUtc
                "ProductVersion"     = $complianceStateMessage.ProductVersion
                "LastError"          = $lastError
            }
        }

        New-Object -TypeName PSObject -Property $property
    }
}
#endregion get data

#region let user redeploy chosen app
if ($win32App) {
    $hasDisplayNameProp = $win32App | Get-Member -Name DisplayName
    $appToRedeploy = $win32App | Where-Object { if ($hasDisplayNameProp) { if ($_.DisplayName) { $true } } else { $true } } | Out-GridView -PassThru -Title "Pick app(s) for redeploy"

    if (!$appToRedeploy) {
        Write-Warning "No apps selected for redeploy"
        exit
    }

    $win32AppKeys = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps" -Recurse -Depth 2 | Select-Object PSChildName, PSPath, PSParentPath

    $appToRedeploy | ForEach-Object {
        $appId = $_.id
        $scopeId = $_.scopeId
        if ($scopeId -eq 'device') { $scopeId = "00000000-0000-0000-0000-000000000000" }
        Write-Warning "Preparing redeploy for app $appId (scope $scopeId)"

        $win32AppKeyToDelete = $win32AppKeys | Where-Object { $_.PSChildName -Match "^$appId`_\d+" -and $_.PSParentPath -Match "\\$scopeId$" }

        if ($win32AppKeyToDelete) {
            $win32AppKeyToDelete | ForEach-Object {
                Write-Verbose "Deleting $($_.PSPath)"
                Remove-Item $_.PSPath -Force -Recurse
            }
        } else {
            throw "BUG??? App $appId with scope $scopeId wasn't found in the registry"
        }
    }

    Write-Warning "Invoking redeploy (by restarting service IntuneManagementExtension). Redeploy can take several minutes!"
    Restart-Service IntuneManagementExtension -Force
} else {
    Write-Warning "No deployed Win32App detected"
}
#endregion let user redeploy chosen app
