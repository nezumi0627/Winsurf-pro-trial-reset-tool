# Define the backup directory
$backupDir = "$env:USERPROFILE\Documents\SID_Backups"

# Check if running as administrator
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to read current user SID
function Get-CurrentUserSID {
    try {
        # Get current user's SID
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $sid = $currentUser.User.Value
        
        # Get profile path from registry
        $sidPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
        $profilePath = ""
        
        if (Test-Path $sidPath) {
            $profilePath = (Get-ItemProperty -Path $sidPath -Name "ProfileImagePath" -ErrorAction SilentlyContinue).ProfileImagePath
        }
        
        # Get username
        $username = $currentUser.Name
        
        # Display SID information
        Write-Host "\nCurrent User SID Information:" -ForegroundColor Cyan
        Write-Host "Username: $username" -ForegroundColor White
        Write-Host "SID: $sid" -ForegroundColor White
        Write-Host "Profile Path: $profilePath" -ForegroundColor White
        
        # Get additional SID properties if available
        if (Test-Path $sidPath) {
            $stateFlags = (Get-ItemProperty -Path $sidPath -Name "State" -ErrorAction SilentlyContinue).State
            Write-Host "State Flags: $stateFlags" -ForegroundColor White
            
            # Try to get profile load time if available
            $loadTimeHigh = (Get-ItemProperty -Path $sidPath -Name "ProfileLoadTimeHigh" -ErrorAction SilentlyContinue).ProfileLoadTimeHigh
            $loadTimeLow = (Get-ItemProperty -Path $sidPath -Name "ProfileLoadTimeLow" -ErrorAction SilentlyContinue).ProfileLoadTimeLow
            
            if ($null -ne $loadTimeHigh -and $null -ne $loadTimeLow) {
                $fileTime = [math]::Pow(2, 32) * $loadTimeHigh + $loadTimeLow
                $loadTime = [DateTime]::FromFileTime($fileTime)
                Write-Host "Profile Load Time: $loadTime" -ForegroundColor White
            }
        }
        
        return $sid
    } catch {
        Write-Host "Error getting current user SID: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# Function to backup a SID
function Backup-SID {
    param (
        [string]$sidPath
    )
    
    if (-not (Test-Path $sidPath)) {
        Write-Host "Error: The specified SID path does not exist." -ForegroundColor Red
        return $false
    }
    
    # Create backup directory if it doesn't exist
    if (-not (Test-Path $backupDir)) {
        New-Item -ItemType Directory -Path $backupDir | Out-Null
    }
    
    # Extract SID from path
    $sid = $sidPath.Split('\')[-1]
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupFile = "$backupDir\${sid}_$timestamp.reg"
    
    # Export registry key to backup file
    try {
        $exportCmd = "reg export 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid' '$backupFile' /y"
        Invoke-Expression $exportCmd | Out-Null
        
        if (Test-Path $backupFile) {
            Write-Host "SID backup created successfully at: $backupFile" -ForegroundColor Green
            return $true
        } else {
            Write-Host "Failed to create backup file." -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "Error creating backup: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Function to restore a SID from backup
function Restore-SID {
    # List available backups
    $backups = Get-ChildItem -Path $backupDir -Filter "*.reg" | Sort-Object LastWriteTime -Descending
    
    if ($backups.Count -eq 0) {
        Write-Host "No backups found in $backupDir" -ForegroundColor Yellow
        return
    }
    
    Write-Host "Available SID backups:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $backups.Count; $i++) {
        $backupInfo = $backups[$i].Name -replace '.reg$', ''
        Write-Host "[$i] $backupInfo ($(Get-Date $backups[$i].LastWriteTime -Format 'yyyy-MM-dd HH:mm:ss'))"
    }
    
    $selection = Read-Host "Enter the number of the backup to restore, or 'C' to cancel"
    
    if ($selection -eq 'C' -or $selection -eq 'c') {
        return
    }
    
    if ($selection -match '^\d+$' -and [int]$selection -ge 0 -and [int]$selection -lt $backups.Count) {
        $selectedBackup = $backups[[int]$selection]
        
        # Confirm restore
        $confirm = Read-Host "Are you sure you want to restore from $($selectedBackup.Name)? (Y/N)"
        
        if ($confirm -eq 'Y' -or $confirm -eq 'y') {
            try {
                # Import the registry file
                $importCmd = "reg import '$($selectedBackup.FullName)'"
                Invoke-Expression $importCmd | Out-Null
                
                Write-Host "SID restored successfully from: $($selectedBackup.Name)" -ForegroundColor Green
            } catch {
                Write-Host "Error restoring SID: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "Invalid selection." -ForegroundColor Red
    }
}

# Function to generate random SID information
function Get-RandomSIDInfo {
    # Generate a random SID
    $randomSID = "S-1-5-21-"
    # Generate three random components for the domain identifier
    for ($i = 0; $i -lt 3; $i++) {
        $randomComponent = Get-Random -Minimum 100000000 -Maximum 2147483647
        $randomSID += "$randomComponent"
        if ($i -lt 2) { $randomSID += "-" }
    }
    # Add a random RID (Relative ID)
    $randomRID = Get-Random -Minimum 1000 -Maximum 9999
    $randomSID += "-$randomRID"
    
    # Generate a random username
    $usernames = @("User", "Admin", "Guest", "Developer", "Tester", "Manager", "Support", "Analyst")
    $randomUsername = $usernames[(Get-Random -Minimum 0 -Maximum $usernames.Count)]
    $randomUsername += (Get-Random -Minimum 100 -Maximum 999)
    
    # Generate a random profile path
    $randomDrive = "C:"
    $randomProfilePath = "$randomDrive\Users\$randomUsername"
    
    # Generate random state flags (common values are 0, 256, 512, 8192, 32768)
    $stateFlags = @(0, 256, 512, 8192, 32768)
    $randomStateFlag = $stateFlags[(Get-Random -Minimum 0 -Maximum $stateFlags.Count)]
    
    # Generate a random profile load time (within the last 30 days)
    $randomDays = Get-Random -Minimum 0 -Maximum 30
    $randomHours = Get-Random -Minimum 0 -Maximum 24
    $randomMinutes = Get-Random -Minimum 0 -Maximum 60
    $randomLoadTime = (Get-Date).AddDays(-$randomDays).AddHours(-$randomHours).AddMinutes(-$randomMinutes)
    
    # Display the random SID information
    Write-Host "\nRandom SID Information:" -ForegroundColor Magenta
    Write-Host "SID: $randomSID" -ForegroundColor White
    Write-Host "Username: $randomUsername" -ForegroundColor White
    Write-Host "Profile Path: $randomProfilePath" -ForegroundColor White
    Write-Host "State Flags: $randomStateFlag" -ForegroundColor White
    Write-Host "Profile Load Time: $randomLoadTime" -ForegroundColor White
    
    # Explain what each state flag means
    Write-Host "\nState Flag Meanings:" -ForegroundColor Yellow
    switch ($randomStateFlag) {
        0 { Write-Host "0: Normal profile status" -ForegroundColor White }
        256 { Write-Host "256 (0x100): Profile is mandatory" -ForegroundColor White }
        512 { Write-Host "512 (0x200): Profile is temporary" -ForegroundColor White }
        8192 { Write-Host "8192 (0x2000): Profile is a roaming profile" -ForegroundColor White }
        32768 { Write-Host "32768 (0x8000): Profile is corrupted" -ForegroundColor White }
        default { Write-Host "$($randomStateFlag): Custom state flag" -ForegroundColor White }
    }
    
    # Generate random SID attributes
    Write-Host "\nRandom SID Attributes:" -ForegroundColor Yellow
    $attributes = @(
        "ProfileImagePath", 
        "Flags", 
        "State", 
        "RefCount", 
        "Sid", 
        "ProfileLoadTimeHigh", 
        "ProfileLoadTimeLow", 
        "RunLogonScriptSync", 
        "LocalProfileLoadTimeHigh", 
        "LocalProfileLoadTimeLow", 
        "ProfileAttemptedProfileDownloadTimeHigh", 
        "ProfileAttemptedProfileDownloadTimeLow", 
        "ProfileLoadTimeEx", 
        "ProfileUnloadTimeEx", 
        "FullProfile", 
        "LastUseTime", 
        "LastDownloadTime", 
        "LastUploadTime", 
        "CentralProfile", 
        "AppDataRoaming", 
        "AppDataLocal", 
        "AppDataLocalLow"
    )
    
    # Select 5 random attributes and assign random values
    $selectedAttributes = @()
    for ($i = 0; $i -lt 5; $i++) {
        $randomIndex = Get-Random -Minimum 0 -Maximum $attributes.Count
        $selectedAttributes += $attributes[$randomIndex]
        $attributes = $attributes | Where-Object { $_ -ne $attributes[$randomIndex] }
        if ($attributes.Count -eq 0) { break }
    }
    
    foreach ($attr in $selectedAttributes) {
        $randomValue = switch -Regex ($attr) {
            "Time|Date" { Get-Date (Get-Random -Minimum ([DateTime]::Now.AddDays(-365).Ticks) -Maximum ([DateTime]::Now.Ticks)) -Format "yyyy-MM-dd HH:mm:ss" }
            "Path|Profile" { "C:\Users\$randomUsername\$(Get-Random -Minimum 100 -Maximum 999)" }
            "Count|Flags|State" { Get-Random -Minimum 0 -Maximum 65535 }
            default { "0x" + (Get-Random -Minimum 0 -Maximum 4294967295).ToString("X8") }
        }
        
        Write-Host "$($attr): $randomValue" -ForegroundColor White
    }
    
    # Generate random security identifiers that might be associated with this SID
    Write-Host "\nRelated Security Principals:" -ForegroundColor Yellow
    $groups = @(
        "Administrators", 
        "Users", 
        "Backup Operators", 
        "Power Users", 
        "Remote Desktop Users", 
        "Network Configuration Operators", 
        "Distributed COM Users", 
        "Performance Log Users", 
        "Performance Monitor Users"
    )
    
    $selectedGroups = @()
    $numGroups = Get-Random -Minimum 2 -Maximum 5
    for ($i = 0; $i -lt $numGroups; $i++) {
        $randomIndex = Get-Random -Minimum 0 -Maximum $groups.Count
        $selectedGroups += $groups[$randomIndex]
        $groups = $groups | Where-Object { $_ -ne $groups[$randomIndex] }
        if ($groups.Count -eq 0) { break }
    }
    
    foreach ($group in $selectedGroups) {
        $groupSID = switch ($group) {
            "Administrators" { "S-1-5-32-544" }
            "Users" { "S-1-5-32-545" }
            "Backup Operators" { "S-1-5-32-551" }
            "Power Users" { "S-1-5-32-547" }
            "Remote Desktop Users" { "S-1-5-32-555" }
            "Network Configuration Operators" { "S-1-5-32-556" }
            "Distributed COM Users" { "S-1-5-32-562" }
            "Performance Log Users" { "S-1-5-32-559" }
            "Performance Monitor Users" { "S-1-5-32-558" }
            default { "S-1-5-32-" + (Get-Random -Minimum 500 -Maximum 999) }
        }
        
        Write-Host "$($group): $groupSID" -ForegroundColor White
    }
}

# Function to change SID properties
function Change-SID {
    param (
        [string]$sidPath
    )
    
    if (-not (Test-Path $sidPath)) {
        Write-Host "Error: The specified SID path does not exist." -ForegroundColor Red
        return
    }
    
    # Get current values
    $sid = $sidPath.Split('\')[-1]
    $profilePath = (Get-ItemProperty -Path $sidPath -Name "ProfileImagePath" -ErrorAction SilentlyContinue).ProfileImagePath
    
    Write-Host "Current SID: $sid" -ForegroundColor Cyan
    Write-Host "Current Profile Path: $profilePath" -ForegroundColor Cyan
    
    # Menu for modifications
    Write-Host "\nWhat would you like to modify?" -ForegroundColor Yellow
    Write-Host "[1] Profile Image Path"
    Write-Host "[2] State Flags"
    Write-Host "[3] Profile Load Time"
    Write-Host "[4] Apply Random Values to All Properties"
    Write-Host "[5] Change Computer Name"
    Write-Host "[6] Change Current User Profile Path"
    Write-Host "[C] Cancel"
    
    $choice = Read-Host "Enter your choice"
    
    switch ($choice) {
        "1" {
            $newPath = Read-Host "Enter new Profile Image Path"
            if ($newPath) {
                try {
                    Set-ItemProperty -Path $sidPath -Name "ProfileImagePath" -Value $newPath -Type String
                    Write-Host "Profile Image Path updated successfully." -ForegroundColor Green
                } catch {
                    Write-Host "Error updating Profile Image Path: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
        "2" {
            $currentFlags = (Get-ItemProperty -Path $sidPath -Name "State" -ErrorAction SilentlyContinue).State
            Write-Host "Current State Flags: $currentFlags" -ForegroundColor Cyan
            $newFlags = Read-Host "Enter new State Flags value (decimal)"
            
            if ($newFlags -match '^\d+$') {
                try {
                    Set-ItemProperty -Path $sidPath -Name "State" -Value ([int]$newFlags) -Type DWord
                    Write-Host "State Flags updated successfully." -ForegroundColor Green
                } catch {
                    Write-Host "Error updating State Flags: $($_.Exception.Message)" -ForegroundColor Red
                }
            } else {
                Write-Host "Invalid input. State Flags must be a decimal number." -ForegroundColor Red
            }
        }
        "3" {
            Write-Host "Setting current time as Profile Load Time"
            try {
                $currentTime = [DateTime]::Now
                $fileTime = $currentTime.ToFileTime()
                Set-ItemProperty -Path $sidPath -Name "ProfileLoadTimeHigh" -Value ([math]::Floor($fileTime / [math]::Pow(2, 32))) -Type DWord
                Set-ItemProperty -Path $sidPath -Name "ProfileLoadTimeLow" -Value ($fileTime % [math]::Pow(2, 32)) -Type DWord
                Write-Host "Profile Load Time updated successfully." -ForegroundColor Green
            } catch {
                Write-Host "Error updating Profile Load Time: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        "4" {
            # Apply random values to all properties
            Write-Host "\nApplying random values to SID properties..." -ForegroundColor Yellow
            $confirm = Read-Host "This will modify multiple registry values. Are you sure? (Y/N)"
            
            if ($confirm -eq 'Y' -or $confirm -eq 'y') {
                try {
                    # Generate random username
                    $usernames = @("User", "Admin", "Guest", "Developer", "Tester", "Manager", "Support", "Analyst")
                    $randomUsername = $usernames[(Get-Random -Minimum 0 -Maximum $usernames.Count)]
                    $randomUsername += (Get-Random -Minimum 100 -Maximum 999)
                    
                    # Generate random profile path
                    $randomDrive = "C:"
                    $randomProfilePath = "$randomDrive\Users\$randomUsername"
                    
                    # Update ProfileImagePath
                    Set-ItemProperty -Path $sidPath -Name "ProfileImagePath" -Value $randomProfilePath -Type String
                    Write-Host "Profile Image Path updated to: $randomProfilePath" -ForegroundColor Green
                    
                    # Generate random state flags (common values are 0, 256, 512, 8192, 32768)
                    $stateFlags = @(0, 256, 512, 8192, 32768)
                    $randomStateFlag = $stateFlags[(Get-Random -Minimum 0 -Maximum $stateFlags.Count)]
                    Set-ItemProperty -Path $sidPath -Name "State" -Value $randomStateFlag -Type DWord
                    Write-Host "State Flags updated to: $randomStateFlag" -ForegroundColor Green
                    
                    # Explain what the state flag means
                    Write-Host "State Flag Meaning:" -ForegroundColor Yellow
                    switch ($randomStateFlag) {
                        0 { Write-Host "0: Normal profile status" -ForegroundColor White }
                        256 { Write-Host "256 (0x100): Profile is mandatory" -ForegroundColor White }
                        512 { Write-Host "512 (0x200): Profile is temporary" -ForegroundColor White }
                        8192 { Write-Host "8192 (0x2000): Profile is a roaming profile" -ForegroundColor White }
                        32768 { Write-Host "32768 (0x8000): Profile is corrupted" -ForegroundColor White }
                        default { Write-Host "$($randomStateFlag): Custom state flag" -ForegroundColor White }
                    }
                    
                    # Update profile load time
                    $randomDays = Get-Random -Minimum 0 -Maximum 30
                    $randomHours = Get-Random -Minimum 0 -Maximum 24
                    $randomMinutes = Get-Random -Minimum 0 -Maximum 60
                    $randomLoadTime = (Get-Date).AddDays(-$randomDays).AddHours(-$randomHours).AddMinutes(-$randomMinutes)
                    $fileTime = $randomLoadTime.ToFileTime()
                    
                    Set-ItemProperty -Path $sidPath -Name "ProfileLoadTimeHigh" -Value ([math]::Floor($fileTime / [math]::Pow(2, 32))) -Type DWord
                    Set-ItemProperty -Path $sidPath -Name "ProfileLoadTimeLow" -Value ($fileTime % [math]::Pow(2, 32)) -Type DWord
                    Write-Host "Profile Load Time updated to: $randomLoadTime" -ForegroundColor Green
                    
                    # Additional random registry values
                    $additionalProperties = @(
                        @{Name = "RefCount"; Value = Get-Random -Minimum 0 -Maximum 10; Type = "DWord"},
                        @{Name = "Flags"; Value = Get-Random -Minimum 0 -Maximum 65535; Type = "DWord"},
                        @{Name = "FullProfile"; Value = Get-Random -Minimum 0 -Maximum 1; Type = "DWord"}
                    )
                    
                    # Apply additional random properties if they exist
                    foreach ($prop in $additionalProperties) {
                        # Check if property exists before setting it
                        $existingValue = Get-ItemProperty -Path $sidPath -Name $prop.Name -ErrorAction SilentlyContinue
                        if ($null -ne $existingValue -or $existingValue.$($prop.Name) -ne $null) {
                            Set-ItemProperty -Path $sidPath -Name $prop.Name -Value $prop.Value -Type $prop.Type
                            Write-Host "$($prop.Name) updated to: $($prop.Value)" -ForegroundColor Green
                        }
                    }
                    
                    Write-Host "\nAll SID properties have been updated with random values." -ForegroundColor Green
                } catch {
                    Write-Host "Error applying random values: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
        "5" {
            # Change Computer Name
            Write-Host "Current Computer Name: $env:COMPUTERNAME" -ForegroundColor Cyan
            $newName = Read-Host "Enter new computer name (or press Enter to cancel)"
            
            if ([string]::IsNullOrWhiteSpace($newName)) {
                Write-Host "Operation cancelled." -ForegroundColor Yellow
                return
            }
            
            # Validate the computer name
            if ($newName -match '^[a-zA-Z0-9-]{1,15}$') {
                $confirm = Read-Host "Are you sure you want to change the computer name to '$newName'? This will require a system restart (Y/N)"
                
                if ($confirm -eq 'Y' -or $confirm -eq 'y') {
                    try {
                        Rename-Computer -NewName $newName -Force
                        Write-Host "Computer name has been changed to '$newName'. The change will take effect after restart." -ForegroundColor Green
                        
                        $restartNow = Read-Host "Do you want to restart now? (Y/N)"
                        if ($restartNow -eq 'Y' -or $restartNow -eq 'y') {
                            Restart-Computer -Force
                        }
                    } catch {
                        Write-Host "Error changing computer name: $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            } else {
                Write-Host "Invalid computer name. The name must be 1-15 characters long and can contain only letters, numbers, and hyphens." -ForegroundColor Red
            }
        }
        "6" {
            # Change Current User Profile Path
            $currentUserSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            $currentUserSidPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$currentUserSID"
            
            if (-not (Test-Path $currentUserSidPath)) {
                Write-Host "Error: Cannot find current user SID registry path." -ForegroundColor Red
                return
            }
            
            $currentPath = (Get-ItemProperty -Path $currentUserSidPath -Name "ProfileImagePath" -ErrorAction SilentlyContinue).ProfileImagePath
            Write-Host "Current User Profile Path: $currentPath" -ForegroundColor Cyan
            
            $newPath = Read-Host "Enter new profile path (or press Enter to cancel)"
            
            if ([string]::IsNullOrWhiteSpace($newPath)) {
                Write-Host "Operation cancelled." -ForegroundColor Yellow
                return
            }
            
            $confirm = Read-Host "Are you sure you want to change the profile path to '$newPath'? This is a sensitive operation that might affect system stability (Y/N)"
            
            if ($confirm -eq 'Y' -or $confirm -eq 'y') {
                # Backup first
                $backupSuccess = Backup-SID -sidPath $currentUserSidPath
                
                if ($backupSuccess) {
                    try {
                        # Update the profile path
                        Set-ItemProperty -Path $currentUserSidPath -Name "ProfileImagePath" -Value $newPath -Type String
                        Write-Host "Profile path has been changed to '$newPath'." -ForegroundColor Green
                        Write-Host "Warning: You may need to manually move user data to the new location or create proper directory structure." -ForegroundColor Yellow
                        Write-Host "A system restart is recommended for changes to take full effect." -ForegroundColor Yellow
                        
                        $restartNow = Read-Host "Do you want to restart now? (Y/N)"
                        if ($restartNow -eq 'Y' -or $restartNow -eq 'y') {
                            Restart-Computer -Force
                        }
                    } catch {
                        Write-Host "Error changing profile path: $($_.Exception.Message)" -ForegroundColor Red
                    }
                } else {
                    Write-Host "Cannot proceed without successful backup." -ForegroundColor Red
                }
            }
        }
        "C" { return }
        "c" { return }
        default { Write-Host "Invalid choice." -ForegroundColor Red }
    }
}

# Function to list all SIDs
function List-SIDs {
    $sids = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | 
           Where-Object { $_.PSChildName -like "S-1-5-*" }
    
    if ($sids.Count -eq 0) {
        Write-Host "No SIDs found." -ForegroundColor Yellow
        return @()
    }
    
    Write-Host "Available SIDs:" -ForegroundColor Cyan
    $sidList = @()
    
    for ($i = 0; $i -lt $sids.Count; $i++) {
        $sid = $sids[$i].PSChildName
        $profilePath = (Get-ItemProperty -Path $sids[$i].PSPath -Name "ProfileImagePath" -ErrorAction SilentlyContinue).ProfileImagePath
        $sidList += $sids[$i].PSPath
        
        # Try to get username from profile path
        $username = "Unknown"
        if ($profilePath -match "\\Users\\([^\\]+)") {
            $username = $matches[1]
        } elseif ($profilePath -match "\\Documents and Settings\\([^\\]+)") {
            $username = $matches[1]
        }
        
        Write-Host "[$i] $sid - $username ($profilePath)"
    }
    
    return $sidList
}

# Function to modify system identification in one go
function Modify-SystemIdentification {
    # Get current values
    $currentUserSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $currentSidPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$currentUserSID"
    $currentProfilePath = (Get-ItemProperty -Path $currentSidPath -Name "ProfileImagePath" -ErrorAction SilentlyContinue).ProfileImagePath
    $currentComputerName = $env:COMPUTERNAME
    $currentUsername = $env:USERNAME
    
    Write-Host "===== Current System Identification =====" -ForegroundColor Cyan
    Write-Host "Current SID: $currentUserSID" -ForegroundColor White
    Write-Host "Current Profile Path: $currentProfilePath" -ForegroundColor White
    Write-Host "Current Computer Name: $currentComputerName" -ForegroundColor White
    Write-Host "Current Username: $currentUsername" -ForegroundColor White
    
    $confirm = Read-Host "Do you want to generate and apply random system identification? (Y/N)"
    if ($confirm -ne 'Y' -and $confirm -ne 'y') {
        return
    }
    
    # Create backup first
    Write-Host "Creating backup of current SID..." -ForegroundColor Yellow
    $backupSuccess = Backup-SID -sidPath $currentSidPath
    
    if (-not $backupSuccess) {
        Write-Host "Cannot proceed without successful backup." -ForegroundColor Red
        return
    }
    
    try {
        # Generate random values
        Write-Host "Generating random system identification..." -ForegroundColor Yellow
        
        # Extract current directory structure
        $currentProfileRoot = Split-Path -Parent $currentProfilePath
        
        # Random computer name
        $computerNamePrefixes = @("DESKTOP", "LAPTOP", "PC", "WORKSTATION", "DEV", "TEST", "SRV")
        $randomComputerName = $computerNamePrefixes[(Get-Random -Minimum 0 -Maximum $computerNamePrefixes.Count)]
        $randomComputerName += "-" + (Get-Random -Minimum 100 -Maximum 999)
        
        # Random state flags
        $stateFlags = @(0, 256, 512, 8192)
        $randomStateFlag = $stateFlags[(Get-Random -Minimum 0 -Maximum $stateFlags.Count)]
        
        # Random profile load time
        $randomDays = Get-Random -Minimum 0 -Maximum 30
        $randomHours = Get-Random -Minimum 0 -Maximum 24
        $randomMinutes = Get-Random -Minimum 0 -Maximum 60
        $randomLoadTime = (Get-Date).AddDays(-$randomDays).AddHours(-$randomHours).AddMinutes(-$randomMinutes)
        $fileTime = $randomLoadTime.ToFileTime()
        
        # Display the random values
        Write-Host "`n===== New System Identification =====" -ForegroundColor Magenta
        Write-Host "Current Profile Path (unchanged): $currentProfilePath" -ForegroundColor White
        Write-Host "New Computer Name: $randomComputerName" -ForegroundColor White
        Write-Host "New State Flags: $randomStateFlag" -ForegroundColor White
        Write-Host "New Profile Load Time: $randomLoadTime" -ForegroundColor White
        
        # Confirm the changes
        $applyConfirm = Read-Host "Do you want to apply these changes? This will require a system restart (Y/N)"
        if ($applyConfirm -ne 'Y' -and $applyConfirm -ne 'y') {
            Write-Host "Operation cancelled." -ForegroundColor Yellow
            return
        }
        
        # Apply changes to SID properties
        Write-Host "`nApplying changes..." -ForegroundColor Yellow
        
        # Change state flags
        Set-ItemProperty -Path $currentSidPath -Name "State" -Value $randomStateFlag -Type DWord
        Write-Host "State flags updated to: $randomStateFlag" -ForegroundColor Green
        
        # Change profile load time
        Set-ItemProperty -Path $currentSidPath -Name "ProfileLoadTimeHigh" -Value ([math]::Floor($fileTime / [math]::Pow(2, 32))) -Type DWord
        Set-ItemProperty -Path $currentSidPath -Name "ProfileLoadTimeLow" -Value ($fileTime % [math]::Pow(2, 32)) -Type DWord
        Write-Host "Profile load time updated to: $randomLoadTime" -ForegroundColor Green
        
        # Additional random registry values
        $additionalProperties = @(
            @{Name = "RefCount"; Value = Get-Random -Minimum 0 -Maximum 10; Type = "DWord"},
            @{Name = "Flags"; Value = Get-Random -Minimum 0 -Maximum 65535; Type = "DWord"},
            @{Name = "FullProfile"; Value = Get-Random -Minimum 0 -Maximum 1; Type = "DWord"}
        )
        
        # Apply additional random properties if they exist
        foreach ($prop in $additionalProperties) {
            # Check if property exists before setting it
            $existingValue = Get-ItemProperty -Path $currentSidPath -Name $prop.Name -ErrorAction SilentlyContinue
            if ($null -ne $existingValue -or $existingValue.$($prop.Name) -ne $null) {
                Set-ItemProperty -Path $currentSidPath -Name $prop.Name -Value $prop.Value -Type $prop.Type
                Write-Host "$($prop.Name) updated to: $($prop.Value)" -ForegroundColor Green
            }
        }
        
        # Change computer name
        Rename-Computer -NewName $randomComputerName -Force
        Write-Host "Computer name changed to: $randomComputerName" -ForegroundColor Green
        
        Write-Host "`nAll system identification has been updated successfully!" -ForegroundColor Green
        Write-Host "NOTE: The profile path was kept the same to ensure you can still log in." -ForegroundColor Yellow
        
        # Prompt for restart
        $restartNow = Read-Host "A system restart is required for changes to take effect. Restart now? (Y/N)"
        if ($restartNow -eq 'Y' -or $restartNow -eq 'y') {
            Restart-Computer -Force
        } else {
            Write-Host "Please restart your computer for the changes to take effect." -ForegroundColor Yellow
        }
        
    } catch {
        Write-Host "Error modifying system identification: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# If not running as administrator, display message and exit
if (-not (Test-Admin)) {
    Write-Host "This application needs to be run as Administrator." -ForegroundColor Red
    Write-Host "Please run the application again with Administrator privileges."
    Write-Host "Press Enter to exit..."
    Read-Host
    exit
}

# Main menu
function Show-Menu {
    Clear-Host
    Write-Host "===== LappySID - SID Management Tool =====" -ForegroundColor Cyan
    Write-Host "1. Read Current User SID"
    Write-Host "2. Generate Random SID Information"
    Write-Host "3. Backup SID"
    Write-Host "4. Restore SID from backup"
    Write-Host "5. Change SID properties"
    Write-Host "6. One-Click Random Identity"
    Write-Host "7. Exit"
    Write-Host "=========================================" -ForegroundColor Cyan
}

# Main program loop
$running = $true
while ($running) {
    Show-Menu
    $choice = Read-Host "Enter your choice"
    
    switch ($choice) {
        "1" {
            # Read Current User SID
            Get-CurrentUserSID
            Write-Host "`nPress Enter to continue..."
            Read-Host
        }
        "2" {
            # Generate Random SID Information
            Get-RandomSIDInfo
            Write-Host "`nPress Enter to continue..."
            Read-Host
        }
        "3" {
            # Backup SID
            $sidList = List-SIDs
            if ($sidList.Count -gt 0) {
                $selection = Read-Host "Enter the number of the SID to backup, or 'C' to cancel"
                
                if ($selection -ne 'C' -and $selection -ne 'c' -and 
                    $selection -match '^\d+$' -and [int]$selection -ge 0 -and [int]$selection -lt $sidList.Count) {
                    Backup-SID -sidPath $sidList[[int]$selection]
                }
            }
            Write-Host "Press Enter to continue..."
            Read-Host
        }
        "4" {
            # Restore SID
            Restore-SID
            Write-Host "Press Enter to continue..."
            Read-Host
        }
        "5" {
            # Change SID
            $sidList = List-SIDs
            if ($sidList.Count -gt 0) {
                $selection = Read-Host "Enter the number of the SID to modify, or 'C' to cancel"
                
                if ($selection -ne 'C' -and $selection -ne 'c' -and 
                    $selection -match '^\d+$' -and [int]$selection -ge 0 -and [int]$selection -lt $sidList.Count) {
                    Change-SID -sidPath $sidList[[int]$selection]
                }
            }
            Write-Host "Press Enter to continue..."
            Read-Host
        }
        "6" {
            # One-Click Random Identity
            Modify-SystemIdentification
            Write-Host "Press Enter to continue..."
            Read-Host
        }
        "7" {
            # Exit
            $running = $false
        }
        default {
            Write-Host "Invalid choice. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
}
