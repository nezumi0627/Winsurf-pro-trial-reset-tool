# LappySID - System Identification Reset Tool

## Overview

LappySID is a powerful Windows tool that allows you to modify system identification information, including user SID, profile paths, and computer name. It's particularly useful for resetting trial periods for various applications, including Windsurf software.

![LappySID Screenshot](https://via.placeholder.com/800x450.png?text=LappySID+Screenshot)

## Features

- **Read and analyze current user SID and system information**
- **Generate random system identification data**
- **One-click identity reset** (change computer name and SID registry information)
- **Backup and restore SID information** (in case something goes wrong)
- **Modify specific SID properties** (state flags, profile paths, etc.)
- **Easy-to-use PowerShell interface**

## Quick Start Guide for Resetting Windsurf Trial Period

### Prerequisites
- Windows 10/11
- Administrator privileges
- PowerShell 5.1 or higher
- An existing Windsurf account that hasn't been activated

### 3-Step Process

1. **Prepare an unactivated Windsurf account**
   - Make sure you have a Windsurf account that hasn't been activated or has expired
   - Log out of any active Windsurf sessions

2. **Use LappySID to change your system environment**
   - Run LappySID.ps1 as Administrator
   - Choose option 6 "One-Click Random Identity"
   - Confirm the changes when prompted
   - Restart your computer when the process completes

3. **Log in and enjoy a fresh trial period**
   - Start Windsurf application
   - Log in with your account
   - The system will recognize your computer as a new device
   - A new trial period will be activated automatically

## Detailed Instructions

### Installation

1. Download the LappySID.ps1 script from this repository
2. Right-click the script and select "Run with PowerShell" (or open PowerShell as Administrator and navigate to the script)
3. If you encounter an execution policy error, run the following command in PowerShell (as Administrator):
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
   ```

### Using LappySID

The main menu provides 7 options:

1. **Read Current User SID**
   - Displays detailed information about the current user's Security Identifier
   - Shows profile path, state flags, and other relevant information

2. **Generate Random SID Information**
   - Displays randomly generated SID information for reference purposes
   - No changes are made to your system

3. **Backup SID**
   - Creates a backup of any SID in the system
   - Backups are stored in `%USERPROFILE%\Documents\SID_Backups`
   - Essential before making any changes

4. **Restore SID from backup**
   - Restores previously backed up SID information
   - Can be used to revert changes if issues occur

5. **Change SID properties**
   - Allows manual modification of specific SID properties:
     - Profile path
     - State flags
     - Profile load time
     - Computer name
     - Current user profile path

6. **One-Click Random Identity**
   - The recommended option for trial resets
   - Automatically changes:
     - Computer name (to a random value)
     - SID state flags
     - Profile load time
     - Other SID registry properties
   - Keeps the same profile path to maintain login capabilities
   - Creates automatic backup before proceeding

7. **Exit**
   - Exits the application

### How It Works

LappySID modifies registry entries related to system identification, primarily in:
```
HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\[SID]
```

By changing these values, applications that rely on hardware identification to track trial usage will recognize your system as a new device, often resulting in a fresh trial period.

The tool maintains your existing profile path so you can continue to use your user account without issues, while changing other identification parameters that applications use for tracking.

### Troubleshooting

- **Cannot run the script**: Make sure you're running PowerShell as Administrator and have set the appropriate execution policy.
- **Changes not taking effect**: Ensure you've restarted your computer after applying changes.
- **Login issues after changes**: Use the restore function to revert to your last backup.
- **Application still recognizes old profile**: Some applications use additional tracking methods. Try using the "Apply Random Values to All Properties" option in the "Change SID properties" menu.

## Important Notes

- **Always create a backup** before making changes
- **Some applications may use additional methods** to track installations
- **Use responsibly** and in accordance with software license agreements
- **Cannot guarantee functionality** with all applications

## Technical Details

LappySID modifies various Windows registry keys including:

- Profile image path (optional)
- SID state flags
- Profile load time
- RefCount
- Flags
- FullProfile flag
- Computer name

## License

This tool is provided "as is" without warranty of any kind. Use at your own risk.

## Disclaimer

This tool is intended for educational purposes and legitimate use cases such as development and testing. The authors do not endorse using this tool to circumvent software licensing or trial limitations in violation of terms of service. 