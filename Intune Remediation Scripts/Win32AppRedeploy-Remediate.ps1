<#
.SYNOPSIS
    Remediates failed Intune Win32 app installations by clearing cached state.

.DESCRIPTION
    This script identifies failed Win32 app installations and removes the associated
    registry keys to allow Intune to retry the installation. It clears:
    - App status keys per user
    - Reporting cache keys
    - GRS (Global Remediation Script) tracking keys using LastHashValue

    After clearing the registry keys, it restarts the Intune Management Extension
    service to trigger a fresh installation attempt.

    Designed for use as an Intune Proactive Remediation remediation script.

.AUTHOR
    Mark Orr

.COMPANY
    First American

.NOTES
    File Name: Win32AppRedeploy-Remediate.ps1
    Requires: Run as SYSTEM context in Intune
#>

# Start Logging
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
Start-Transcript "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\App_Failure_Remediation_$timestamp.log"

#### BEGIN FUNCTIONS ####

<#
    .SYNOPSIS
    Retrieves the last hash value for a specific user and app ID.
    
    .DESCRIPTION
    This function gets the LastHashValue property from the registry for a given user and app ID.

    .PARAMETER userObjectId
    The object ID of the user.

    .PARAMETER appId
    The ID of the app.

    .OUTPUTS
    The last hash value as a string.
#>
function Get-LastHashValue {
    param (
        [string]$userObjectId,
        [string]$appId
    )

    $reportingKeyPath = "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\Reporting\$userObjectId\$appId\ReportCache\$userObjectId"
    if (Test-Path -Path $reportingKeyPath) {
        $reportingKey = Get-ItemProperty -Path $reportingKeyPath -Name LastHashValue -ErrorAction SilentlyContinue
        return $reportingKey.LastHashValue
    }

    return $null
}

<#
    .SYNOPSIS
    Removes the registry keys for a failed app installation.
    
    .DESCRIPTION
    This function removes the registry keys associated with a failed app installation to trigger a reinstallation attempt.

    .PARAMETER userObjectId
    The object ID of the user.

    .PARAMETER appId
    The ID of the app.

    .PARAMETER lastHashValue
    The last hash value for the app.
#>
function Remove-FailedAppRegistryKeys {
    param (
        [string]$userObjectId,
        [string]$appId,
        [string]$lastHashValue
    )

    $pathsToRemove = @(
        "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\$userObjectId\$appId", # App status per user
        "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\Reporting\$userObjectId\$appId", # Reporting key
        "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\$userObjectId\GRS\$lastHashValue" # GRS using last hash value
    )

    foreach ($path in $pathsToRemove) {
        if (Test-Path -Path $path) {
            Remove-Item -Path $path -Recurse -Force
            Write-Host "Removed registry key: $path"
        }
        else {
            Write-Host "Registry key not found: $path"
        }
    }
}

<#
    .SYNOPSIS
    Retrieves the username from an object ID.
    
    .DESCRIPTION
    This function maps a user object ID to a username by searching the registry.

    .PARAMETER ObjectID
    The object ID of the user.

    .OUTPUTS
    The username as a string.
#>
function Get-UsernameFromObjectID {
    param (
        [string]$ObjectID
    )

    $userSIDs = Get-ChildItem -Path 'Registry::HKEY_USERS\'

    foreach ($userSID in $userSIDs) {
        $identityKeyPath = "Registry::HKEY_USERS\$($userSID.PSChildName)\Software\Microsoft\Office\16.0\Common\Identity"
        if (Test-Path -Path $identityKeyPath) {
            $identityKey = Get-ItemProperty -Path $identityKeyPath
            if ($identityKey.ConnectedAccountWamAad -eq $ObjectID) {
                return $identityKey.ADUserName
            }
        }
    }

    return $null
}

<#
    .SYNOPSIS
    Retrieves the error description for a given error code.
    
    .DESCRIPTION
    This function maps an error code to a descriptive message.

    .PARAMETER errorCode
    The error code as an integer.

    .OUTPUTS
    The error description as a string.
#>
function Get-ErrorDescription {
    param (
        [int]$errorCode
    )

    $errorCodes = @{
        0x00000000 = "The action completed successfully."
        0x0000000D = "The data is invalid."
        0x00000057 = "One of the parameters was invalid."
        0x00000078 = "This value is returned when a custom action attempts to call a function that can't be called from custom actions. The function returns the value ERROR_CALL_NOT_IMPLEMENTED."
        0x000004EB = "If Windows Installer determines a product might be incompatible with the current operating system, it displays a dialog box informing the user and asking whether to try to install anyway. This error code is returned if the user chooses not to try the installation."
        0x80070641 = "The Windows Installer service couldn't be accessed. Contact your support personnel to verify that the Windows Installer service is properly registered."
        0x80070642 = "The user canceled installation."
        0x80070643 = "A fatal error occurred during installation."
        0x80070644 = "Installation suspended, incomplete."
        0x80070645 = "This action is only valid for products that are currently installed."
        0x80070646 = "The feature identifier isn't registered."
        0x80070647 = "The component identifier isn't registered."
        0x80070648 = "This is an unknown property."
        0x80070649 = "The handle is in an invalid state."
        0x8007064A = "The configuration data for this product is corrupt. Contact your support personnel."
        0x8007064B = "The component qualifier not present."
        0x8007064C = "The installation source for this product isn't available. Verify that the source exists and that you can access it."
        0x8007064D = "This installation package can't be installed by the Windows Installer service. You must install a Windows service pack that contains a newer version of the Windows Installer service."
        0x8007064E = "The product is uninstalled."
        0x8007064F = "The SQL query syntax is invalid or unsupported."
        0x80070650 = "The record field does not exist."
        0x80070652 = "Another installation is already in progress. Complete that installation before proceeding with this install. For information about the mutex, see _MSIExecute Mutex."
        0x80070653 = "This installation package couldn't be opened. Verify that the package exists and is accessible, or contact the application vendor to verify that this is a valid Windows Installer package."
        0x80070654 = "This installation package couldn't be opened. Contact the application vendor to verify that this is a valid Windows Installer package."
        0x80070655 = "There was an error starting the Windows Installer service user interface. Contact your support personnel."
        0x80070656 = "There was an error opening installation log file. Verify that the specified log file location exists and is writable."
        0x80070657 = "This language of this installation package isn't supported by your system."
        0x80070658 = "There was an error applying transforms. Verify that the specified transform paths are valid."
        0x80070659 = "This installation is forbidden by system policy. Contact your system administrator."
        0x8007065A = "The function couldn't be executed."
        0x8007065B = "The function failed during execution."
        0x8007065C = "An invalid or unknown table was specified."
        0x8007065D = "The data supplied is the wrong type."
        0x8007065E = "Data of this type isn't supported."
        0x8007065F = "The Windows Installer service failed to start. Contact your support personnel."
        0x80070660 = "The Temp folder is either full or inaccessible. Verify that the Temp folder exists and that you can write to it."
        0x80070661 = "This installation package isn't supported on this platform. Contact your application vendor."
        0x80070662 = "Component isn't used on this machine."
        0x80070663 = "This patch package couldn't be opened. Verify that the patch package exists and is accessible, or contact the application vendor to verify that this is a valid Windows Installer patch package."
        0x80070664 = "This patch package couldn't be opened. Contact the application vendor to verify that this is a valid Windows Installer patch package."
        0x80070665 = "This patch package can't be processed by the Windows Installer service. You must install a Windows service pack that contains a newer version of the Windows Installer service."
        0x80070666 = "Another version of this product is already installed. Installation of this version can't continue. To configure or remove the existing version of this product, use Add/Remove Programs in Control Panel."
        0x80070667 = "Invalid command line argument. Consult the Windows Installer SDK for detailed command-line help."
        0x80070668 = "The current user isn't permitted to perform installations from a client session of a server running the Terminal Server role service."
        0x80070669 = "The installer has initiated a restart. This message indicates success."
        0x8007066A = "The installer can't install the upgrade patch because the program being upgraded may be missing or the upgrade patch updates a different version of the program. Verify that the program to be upgraded exists on your computer and that you have the correct upgrade patch."
        0x8007066B = "The patch package isn't permitted by system policy."
        0x8007066C = "One or more customizations aren't permitted by system policy."
        0x8007066D = "Windows Installer doesn't permit installation from a Remote Desktop Connection."
        0x8007066E = "The patch package isn't a removable patch package."
        0x8007066F = "The patch isn't applied to this product."
        0x80070670 = "No valid sequence could be found for the set of patches."
        0x80070671 = "Patch removal was disallowed by policy."
        0x80070672 = "The XML patch data is invalid."
        0x80070673 = "Administrative user failed to apply patch for a per-user managed or a per-machine application that'is in advertised state."
        0x80070674 = "Windows Installer isn't accessible when the computer is in Safe Mode. Exit Safe Mode and try again or try using system restore to return your computer to a previous state. Available beginning with Windows Installer version 4.0."
        0x80070675 = "Couldn't perform a multiple-package transaction because rollback has been disabled. Multiple-package installations can't run if rollback is disabled. Available beginning with Windows Installer version 4.5."
        0x80070676 = "The app that you're trying to run isn't supported on this version of Windows. A Windows Installer package, patch, or transform that has not been signed by Microsoft can't be installed on an ARM computer."
        0x80070BB8 = "A restart is required to complete the install. This message indicates success. This does not include installs where the ForceReboot action is run."
        # Add more error codes as needed
    }

    $hexCode = [convert]::ToString($errorCode, 16).ToUpper()
    $hexCode = '0x' + $hexCode.PadLeft(8, '0')

    if ($errorCodes.ContainsKey($hexCode)) {
        return $errorCodes[$hexCode]
    }
    else {
        return "Unknown error code."
    }
}

#### SCRIPT ENTRY POINT ####

# Find failed Win32 app states
$win32AppsKeyPath = 'HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps'
$appSubKeys = Get-ChildItem -Path $win32AppsKeyPath -Recurse

$failureCount = 0
foreach ($subKey in $appSubKeys) {
    if ($subKey.PSChildName -eq 'EnforcementStateMessage') {
        $msg = Get-ItemProperty -Path $subKey.PSPath -Name EnforcementStateMessage -ErrorAction SilentlyContinue
        if ($msg.EnforcementStateMessage -match '"ErrorCode":(-?\d+|null)') {
            $code = $matches[1]
            if ($code -ne "null") {
                $codeInt = [int]$code
                if (($codeInt -ne 0) -and ($codeInt -ne 3010)) {
                    $failureCount++

                    # Parse the parent path to extract User and App ID
                    # Path format: SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\{userId}\{appId}_1
                    $parentPath = $subKey.PSParentPath -replace 'Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\', ''
                    $splitPath = $parentPath -split '\\'
                    $userObjectId = $splitPath[4]
                    $appId = $splitPath[5] -replace '_\d+$', ''  # Remove the _1 suffix

                    # Get the username
                    $userName = Get-UsernameFromObjectID -ObjectID $userObjectId

                    # Get the error description
                    $errorDescription = Get-ErrorDescription -errorCode $codeInt

                    # Output the formatted message
                    Write-Host "Installation of AppID: $appId failed for user $userName with error code: $codeInt - $errorDescription"

                    # Get the LastHashValue
                    $lastHashValue = Get-LastHashValue -userObjectId $userObjectId -appId $appId

                    if ($lastHashValue) {
                        Remove-FailedAppRegistryKeys -userObjectId $userObjectId -appId $appId -lastHashValue $lastHashValue
                    }
                    else {
                        Remove-FailedAppRegistryKeys -userObjectId $userObjectId -appId $appId
                    }
                }
            }
        }
    }
}

# If any failures were found, restart the Intune Management Extension
if ($failureCount -gt 0) {
    Write-Host "Detected $failureCount failures."
    Write-Host "Restarting Intune Management Extension service..."
    Restart-Service -Name 'IntuneManagementExtension' -Force -PassThru
}
else {
    Write-Host "No failures detected."
}

Stop-Transcript
