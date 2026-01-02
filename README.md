# Invoke-IntuneWin32AppRedeploy

Force redeploy of Intune Win32 applications using Microsoft Graph.

## Description

This script forces a redeploy of Intune Win32 apps by clearing the local registry state and restarting the Intune Management Extension service. Useful when an app deployment is stuck, failed, or needs to be re-evaluated.

## Requirements

- Windows device managed by Intune
- PowerShell 5.1 or later
- Run as Administrator
- Microsoft Graph modules (only if using `-Online`):
  - Microsoft.Graph.Authentication
  - Microsoft.Graph.DeviceManagement
  - Microsoft.Graph.Users

## Installation

### From PowerShell Gallery
```powershell
Install-Script -Name Invoke-IntuneWin32AppRedeploy-MgGraph
```

### From Azure DevOps (Private)
```powershell
$cred = Get-Credential
Register-PSRepository -Name "PowerShell-Repo" `
    -SourceLocation "https://pkgs.dev.azure.com/Orr365/PowerShell-Repo/_packaging/PowerShell-Repo/nuget/v2" `
    -InstallationPolicy Trusted `
    -Credential $cred

Install-Script -Name Invoke-IntuneWin32AppRedeploy-MgGraph -Repository PowerShell-Repo -Credential $cred
```

## Usage

```powershell
# Load the script
. Invoke-IntuneWin32AppRedeploy-MgGraph.ps1

# Basic usage - shows app IDs only
Invoke-IntuneWin32AppRedeploy

# With friendly names from Intune (prompts for Graph login)
Invoke-IntuneWin32AppRedeploy -Online

# Exclude device-targeted apps
Invoke-IntuneWin32AppRedeploy -Online -excludeSystemApp
```

## Parameters

| Parameter | Description |
|-----------|-------------|
| `-Online` | Connect to Microsoft Graph to resolve app and user display names |
| `-excludeSystemApp` | Exclude apps targeted to the device (SYSTEM context) |

## How It Works

1. Reads Win32 app deployment data from the local registry
2. Optionally fetches app/user names from Microsoft Graph
3. Displays apps in a grid view for selection
4. Deletes registry keys for selected apps
5. Restarts the Intune Management Extension service
6. Intune re-evaluates and redeploys the selected apps

## Common Use Cases

- App installation stuck in "Installing" or "Pending" state
- App deployment failed and not retrying
- Need to force reinstall after manual uninstallation
- Testing app packages during development
- Re-evaluating detection rules after changes

## Author

Mark Orr - [Orr365](https://github.com/markorr321)

## License

MIT License - see [LICENSE](LICENSE) for details.
