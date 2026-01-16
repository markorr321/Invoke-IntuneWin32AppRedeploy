# Invoke-IntuneWin32AppRedeploy

Force redeploy of Intune Win32 applications using Microsoft Graph.

## Description

This script forces a redeploy of Intune Win32 apps by clearing the local registry state (including GRS entries) and restarting the Intune Management Extension service. Useful when an app deployment is stuck, failed, or needs to be re-evaluated.

## Features

- Interactive menu with options to select specific apps or redeploy all failed apps
- Auto-elevation to administrator
- Browser-based authentication for Microsoft Graph
- Clears both app registry keys and GRS (Global Re-evaluation Schedule) entries
- Detects failed apps by parsing error codes from registry

## Requirements

- Windows device managed by Intune
- PowerShell 5.1 or later
- Microsoft.Graph.Authentication module (auto-installed if missing when using `-Online`)

## Installation

```powershell
Install-Script -Name Invoke-IntuneWin32AppRedeploy
```

## Usage

```powershell
# Basic usage - shows app IDs only (no Graph connection)
Invoke-IntuneWin32AppRedeploy

# With friendly names from Intune (opens browser for Graph login)
Invoke-IntuneWin32AppRedeploy -Online

# Exclude device-targeted apps
Invoke-IntuneWin32AppRedeploy -Online -excludeSystemApp
```

## Menu Options

1. **Select apps to reinstall (GridView)** - Shows all deployed Win32 apps in a grid view for manual selection
2. **Reinstall all failed apps** - Automatically detects and redeploys apps with non-zero error codes
3. **Exit** - Close the tool

## Parameters

| Parameter | Alias | Description |
|-----------|-------|-------------|
| `-fetchOnline` | `-Online` | Connect to Microsoft Graph to resolve app display names |
| `-excludeSystemApp` | | Exclude apps targeted to the device (SYSTEM context) |

## How It Works

1. Auto-elevates to administrator if not already running elevated
2. Connects to Microsoft Graph (if `-Online` specified) using browser authentication
3. Reads Win32 app deployment data from the local registry
4. Displays menu for user to choose action
5. For selected apps:
   - Deletes registry keys for the app
   - Clears GRS (Global Re-evaluation Schedule) entries
6. Restarts the Intune Management Extension service
7. Intune re-evaluates and redeploys the selected apps

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
