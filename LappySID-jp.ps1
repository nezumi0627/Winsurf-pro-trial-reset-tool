# Define the backup directory
$backupDir = "$env:USERPROFILE\Documents\SID_Backups"

# 管理者として実行されているか確認する
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# 現在のユーザーSIDを取得する関数
function Get-CurrentUserSID {
    try {
        # 現在のユーザーのSIDを取得
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $sid = $currentUser.User.Value
        
        # レジストリからプロファイルパスを取得
        $sidPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
        $profilePath = ""
        
        if (Test-Path $sidPath) {
            $profilePath = (Get-ItemProperty -Path $sidPath -Name "ProfileImagePath" -ErrorAction SilentlyContinue).ProfileImagePath
        }
        
        # ユーザー名を取得
        $username = $currentUser.Name
        
        # SID情報を表示
        Write-Host "\n現在のユーザーSID情報:" -ForegroundColor Cyan
        Write-Host "ユーザー名: $username" -ForegroundColor White
        Write-Host "SID: $sid" -ForegroundColor White
        Write-Host "プロファイルパス: $profilePath" -ForegroundColor White
        
        # 利用可能であれば追加のSIDプロパティを取得
        if (Test-Path $sidPath) {
            $stateFlags = (Get-ItemProperty -Path $sidPath -Name "State" -ErrorAction SilentlyContinue).State
            Write-Host "状態フラグ: $stateFlags" -ForegroundColor White
            
            # 利用可能であればプロファイル読み込み時刻を取得
            $loadTimeHigh = (Get-ItemProperty -Path $sidPath -Name "ProfileLoadTimeHigh" -ErrorAction SilentlyContinue).ProfileLoadTimeHigh
            $loadTimeLow = (Get-ItemProperty -Path $sidPath -Name "ProfileLoadTimeLow" -ErrorAction SilentlyContinue).ProfileLoadTimeLow
            
            if ($null -ne $loadTimeHigh -and $null -ne $loadTimeLow) {
                $fileTime = [math]::Pow(2, 32) * $loadTimeHigh + $loadTimeLow
                $loadTime = [DateTime]::FromFileTime($fileTime)
                Write-Host "プロファイル読み込み時刻: $loadTime" -ForegroundColor White
            }
        }
        
        return $sid
    } catch {
        Write-Host "現在のユーザーSIDの取得中にエラーが発生しました: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# SIDをバックアップする関数
function Backup-SID {
    param (
        [string]$sidPath
    )
    
    if (-not (Test-Path $sidPath)) {
        Write-Host "エラー: 指定されたSIDパスが存在しません" -ForegroundColor Red
        return $false
    }
    
    # バックアップ用ディレクトリが存在しない場合は作成
    if (-not (Test-Path $backupDir)) {
        New-Item -ItemType Directory -Path $backupDir | Out-Null
    }
    
    # パスからSIDを抽出
    $sid = $sidPath.Split('\')[-1]
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupFile = "$backupDir\${sid}_$timestamp.reg"
    
    # レジストリキーをバックアップファイルにエクスポート
    try {
        $exportCmd = "reg export 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid' '$backupFile' /y"
        Invoke-Expression $exportCmd | Out-Null
        
        if (Test-Path $backupFile) {
            Write-Host "SIDのバックアップが正常に作成されました: $backupFile" -ForegroundColor Green
            return $true
        } else {
            Write-Host "バックアップファイルの作成に失敗しました" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "バックアップ作成中にエラーが発生しました: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# バックアップからSIDを復元する関数
function Restore-SID {
    # 利用可能なバックアップを一覧表示
    $backups = Get-ChildItem -Path $backupDir -Filter "*.reg" | Sort-Object LastWriteTime -Descending
    
    if ($backups.Count -eq 0) {
        Write-Host "$backupDir にバックアップが見つかりません" -ForegroundColor Yellow
        return
    }
    
    Write-Host "利用可能なSIDバックアップ一覧:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $backups.Count; $i++) {
        $backupInfo = $backups[$i].Name -replace '.reg$', ''
        Write-Host "[$i] $backupInfo ($(Get-Date $backups[$i].LastWriteTime -Format 'yyyy-MM-dd HH:mm:ss'))"
    }
    
    $selection = Read-Host "復元するバックアップの番号を入力してください。キャンセルするには 'C' を入力"
    
    if ($selection -eq 'C' -or $selection -eq 'c') {
        return
    }
    
    if ($selection -match '^\d+$' -and [int]$selection -ge 0 -and [int]$selection -lt $backups.Count) {
        $selectedBackup = $backups[[int]$selection]
        
        # 復元の確認
        $confirm = Read-Host "$($selectedBackup.Name) から復元してもよろしいですか？ (Y/N)"
        
        if ($confirm -eq 'Y' -or $confirm -eq 'y') {
            try {
                # レジストリファイルをインポート
                $importCmd = "reg import '$($selectedBackup.FullName)'"
                Invoke-Expression $importCmd | Out-Null
                
                Write-Host "SIDは正常に復元されました: $($selectedBackup.Name)" -ForegroundColor Green
            } catch {
                Write-Host "SIDの復元中にエラーが発生しました: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "無効な選択です" -ForegroundColor Red
    }
}

# ランダムなSID情報を生成する関数
function Get-RandomSIDInfo {
    # ランダムなSIDを生成
    $randomSID = "S-1-5-21-"
    # ドメイン識別子の3つのランダム成分を生成
    for ($i = 0; $i -lt 3; $i++) {
        $randomComponent = Get-Random -Minimum 100000000 -Maximum 2147483647
        $randomSID += "$randomComponent"
        if ($i -lt 2) { $randomSID += "-" }
    }
    # RID（相対識別子）を追加
    $randomRID = Get-Random -Minimum 1000 -Maximum 9999
    $randomSID += "-$randomRID"
    
    # ランダムなユーザー名を生成
    $usernames = @("User", "Admin", "Guest", "Developer", "Tester", "Manager", "Support", "Analyst")
    $randomUsername = $usernames[(Get-Random -Minimum 0 -Maximum $usernames.Count)]
    $randomUsername += (Get-Random -Minimum 100 -Maximum 999)
    
    # ランダムなプロファイルパスを生成
    $randomDrive = "C:"
    $randomProfilePath = "$randomDrive\Users\$randomUsername"
    
    # ランダムな状態フラグを生成（一般的な値: 0, 256, 512, 8192, 32768）
    $stateFlags = @(0, 256, 512, 8192, 32768)
    $randomStateFlag = $stateFlags[(Get-Random -Minimum 0 -Maximum $stateFlags.Count)]
    
    # ランダムなプロファイル読み込み時間（過去30日以内）
    $randomDays = Get-Random -Minimum 0 -Maximum 30
    $randomHours = Get-Random -Minimum 0 -Maximum 24
    $randomMinutes = Get-Random -Minimum 0 -Maximum 60
    $randomLoadTime = (Get-Date).AddDays(-$randomDays).AddHours(-$randomHours).AddMinutes(-$randomMinutes)
    
    # ランダムSID情報を表示
    Write-Host "\nランダムなSID情報:" -ForegroundColor Magenta
    Write-Host "SID: $randomSID" -ForegroundColor White
    Write-Host "ユーザー名: $randomUsername" -ForegroundColor White
    Write-Host "プロファイルパス: $randomProfilePath" -ForegroundColor White
    Write-Host "状態フラグ: $randomStateFlag" -ForegroundColor White
    Write-Host "プロファイル読み込み時刻: $randomLoadTime" -ForegroundColor White
    
    # 状態フラグの意味を説明
    Write-Host "\n状態フラグの意味:" -ForegroundColor Yellow
    switch ($randomStateFlag) {
        0 { Write-Host "0: 通常のプロファイル状態" -ForegroundColor White }
        256 { Write-Host "256 (0x100): 必須プロファイル" -ForegroundColor White }
        512 { Write-Host "512 (0x200): 一時プロファイル" -ForegroundColor White }
        8192 { Write-Host "8192 (0x2000): ローミングプロファイル" -ForegroundColor White }
        32768 { Write-Host "32768 (0x8000): プロファイルが破損している" -ForegroundColor White }
        default { Write-Host "$($randomStateFlag): カスタム状態フラグ" -ForegroundColor White }
    }
    
    # ランダムなSID属性を生成
    Write-Host "\nランダムなSID属性:" -ForegroundColor Yellow
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
    
    # 属性から5つをランダムに選んでランダムな値を割り当て
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
    
    # このSIDに関連付けられる可能性のあるセキュリティ識別子を生成
    Write-Host "\n関連するセキュリティプリンシパル:" -ForegroundColor Yellow
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

# SIDのプロパティを変更する関数
function Change-SID {
    param (
        [string]$sidPath
    )
    
    if (-not (Test-Path $sidPath)) {
        Write-Host "エラー: 指定されたSIDパスが存在しません" -ForegroundColor Red
        return
    }
    
    # 現在の値を取得
    $sid = $sidPath.Split('\')[-1]
    $profilePath = (Get-ItemProperty -Path $sidPath -Name "ProfileImagePath" -ErrorAction SilentlyContinue).ProfileImagePath
    
    Write-Host "現在のSID: $sid" -ForegroundColor Cyan
    Write-Host "現在のプロファイルパス: $profilePath" -ForegroundColor Cyan
    
    # 変更メニュー
    Write-Host "`n何を変更しますか？" -ForegroundColor Yellow
    Write-Host "[1] プロファイル画像パス"
    Write-Host "[2] 状態フラグ"
    Write-Host "[3] プロファイル読み込み時間"
    Write-Host "[4] すべてのプロパティにランダム値を適用"
    Write-Host "[5] コンピューター名を変更"
    Write-Host "[6] 現在のユーザープロファイルパスを変更"
    Write-Host "[C] キャンセル"
    
    $choice = Read-Host "選択肢を入力してください"
    
    switch ($choice) {
        "1" {
            $newPath = Read-Host "新しいプロファイル画像パスを入力してください"
            if ($newPath) {
                try {
                    Set-ItemProperty -Path $sidPath -Name "ProfileImagePath" -Value $newPath -Type String
                    Write-Host "プロファイルパスを更新しました" -ForegroundColor Green
                } catch {
                    Write-Host "プロファイルパスの更新中にエラーが発生しました: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
        "2" {
            $currentFlags = (Get-ItemProperty -Path $sidPath -Name "State" -ErrorAction SilentlyContinue).State
            Write-Host "現在の状態フラグ: $currentFlags" -ForegroundColor Cyan
            $newFlags = Read-Host "新しい状態フラグの値を入力してください（10進数）"
            
            if ($newFlags -match '^\d+$') {
                try {
                    Set-ItemProperty -Path $sidPath -Name "State" -Value ([int]$newFlags) -Type DWord
                    Write-Host "状態フラグを更新しました" -ForegroundColor Green
                } catch {
                    Write-Host "状態フラグの更新中にエラーが発生しました: $($_.Exception.Message)" -ForegroundColor Red
                }
            } else {
                Write-Host "無効な入力です。状態フラグは10進数で入力してください" -ForegroundColor Red
            }
        }
        "3" {
            Write-Host "現在時刻をプロファイル読み込み時間として設定します"
            try {
                $currentTime = [DateTime]::Now
                $fileTime = $currentTime.ToFileTime()
                Set-ItemProperty -Path $sidPath -Name "ProfileLoadTimeHigh" -Value ([math]::Floor($fileTime / [math]::Pow(2, 32))) -Type DWord
                Set-ItemProperty -Path $sidPath -Name "ProfileLoadTimeLow" -Value ($fileTime % [math]::Pow(2, 32)) -Type DWord
                Write-Host "プロファイル読み込み時間を更新しました" -ForegroundColor Green
            } catch {
                Write-Host "プロファイル読み込み時間の更新中にエラーが発生しました: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        "4" {
            # すべてのプロパティにランダム値を適用
            Write-Host "`nSIDプロパティにランダム値を適用中..." -ForegroundColor Yellow
            $confirm = Read-Host "複数のレジストリ値が変更されます。実行しますか？ (Y/N)"
            
            if ($confirm -eq 'Y' -or $confirm -eq 'y') {
                try {
                    # ランダムなユーザー名生成
                    $usernames = @("User", "Admin", "Guest", "Developer", "Tester", "Manager", "Support", "Analyst")
                    $randomUsername = $usernames[(Get-Random -Minimum 0 -Maximum $usernames.Count)]
                    $randomUsername += (Get-Random -Minimum 100 -Maximum 999)
                    
                    # プロファイルパス生成と更新
                    $randomDrive = "C:"
                    $randomProfilePath = "$randomDrive\Users\$randomUsername"
                    Set-ItemProperty -Path $sidPath -Name "ProfileImagePath" -Value $randomProfilePath -Type String
                    Write-Host "プロファイルパスを更新しました: $randomProfilePath" -ForegroundColor Green
                    
                    # 状態フラグ生成と更新
                    $stateFlags = @(0, 256, 512, 8192, 32768)
                    $randomStateFlag = $stateFlags[(Get-Random -Minimum 0 -Maximum $stateFlags.Count)]
                    Set-ItemProperty -Path $sidPath -Name "State" -Value $randomStateFlag -Type DWord
                    Write-Host "状態フラグを更新しました: $randomStateFlag" -ForegroundColor Green
                    
                    # 状態フラグの意味表示
                    Write-Host "状態フラグの意味:" -ForegroundColor Yellow
                    switch ($randomStateFlag) {
                        0 { Write-Host "0: 通常プロファイル" -ForegroundColor White }
                        256 { Write-Host "256 (0x100): 必須プロファイル" -ForegroundColor White }
                        512 { Write-Host "512 (0x200): 一時プロファイル" -ForegroundColor White }
                        8192 { Write-Host "8192 (0x2000): ローミングプロファイル" -ForegroundColor White }
                        32768 { Write-Host "32768 (0x8000): 破損プロファイル" -ForegroundColor White }
                        default { Write-Host "$($randomStateFlag): カスタム状態" -ForegroundColor White }
                    }
                    
                    # プロファイル読み込み時間生成と更新
                    $randomDays = Get-Random -Minimum 0 -Maximum 30
                    $randomHours = Get-Random -Minimum 0 -Maximum 24
                    $randomMinutes = Get-Random -Minimum 0 -Maximum 60
                    $randomLoadTime = (Get-Date).AddDays(-$randomDays).AddHours(-$randomHours).AddMinutes(-$randomMinutes)
                    $fileTime = $randomLoadTime.ToFileTime()
                    Set-ItemProperty -Path $sidPath -Name "ProfileLoadTimeHigh" -Value ([math]::Floor($fileTime / [math]::Pow(2, 32))) -Type DWord
                    Set-ItemProperty -Path $sidPath -Name "ProfileLoadTimeLow" -Value ($fileTime % [math]::Pow(2, 32)) -Type DWord
                    Write-Host "読み込み時間を更新しました: $randomLoadTime" -ForegroundColor Green
                    
                    # 追加のランダム値を設定
                    $additionalProperties = @(
                        @{Name = "RefCount"; Value = Get-Random -Minimum 0 -Maximum 10; Type = "DWord"},
                        @{Name = "Flags"; Value = Get-Random -Minimum 0 -Maximum 65535; Type = "DWord"},
                        @{Name = "FullProfile"; Value = Get-Random -Minimum 0 -Maximum 1; Type = "DWord"}
                    )
                    foreach ($prop in $additionalProperties) {
                        $existingValue = Get-ItemProperty -Path $sidPath -Name $prop.Name -ErrorAction SilentlyContinue
                        if ($null -ne $existingValue -or $existingValue.$($prop.Name) -ne $null) {
                            Set-ItemProperty -Path $sidPath -Name $prop.Name -Value $prop.Value -Type $prop.Type
                            Write-Host "$($prop.Name) を更新しました: $($prop.Value)" -ForegroundColor Green
                        }
                    }
                    
                    Write-Host "`nすべてのSIDプロパティをランダムに更新しました" -ForegroundColor Green
                } catch {
                    Write-Host "ランダム値の適用中にエラーが発生しました: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
        "5" {
            # コンピューター名を変更
            Write-Host "現在のコンピューター名: $env:COMPUTERNAME" -ForegroundColor Cyan
            $newName = Read-Host "新しいコンピューター名を入力（キャンセルはEnter）"
            
            if ([string]::IsNullOrWhiteSpace($newName)) {
                Write-Host "操作をキャンセルしました" -ForegroundColor Yellow
                return
            }
            
            if ($newName -match '^[a-zA-Z0-9-]{1,15}$') {
                $confirm = Read-Host "'$newName' に変更しますか？（再起動が必要） (Y/N)"
                if ($confirm -eq 'Y' -or $confirm -eq 'y') {
                    try {
                        Rename-Computer -NewName $newName -Force
                        Write-Host "コンピューター名を '$newName' に変更しました。再起動後に反映されます" -ForegroundColor Green
                        $restartNow = Read-Host "今すぐ再起動しますか？ (Y/N)"
                        if ($restartNow -eq 'Y' -or $restartNow -eq 'y') {
                            Restart-Computer -Force
                        }
                    } catch {
                        Write-Host "コンピューター名の変更中にエラーが発生しました: $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            } else {
                Write-Host "無効なコンピューター名です。1〜15文字の英数字とハイフンのみ使用可能です" -ForegroundColor Red
            }
        }
        "6" {
            # 現在のユーザープロファイルパスを変更
            $currentUserSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            $currentUserSidPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$currentUserSID"
            
            if (-not (Test-Path $currentUserSidPath)) {
                Write-Host "エラー: 現在のユーザーSIDのレジストリパスが見つかりません" -ForegroundColor Red
                return
            }
            
            $currentPath = (Get-ItemProperty -Path $currentUserSidPath -Name "ProfileImagePath" -ErrorAction SilentlyContinue).ProfileImagePath
            Write-Host "現在のプロファイルパス: $currentPath" -ForegroundColor Cyan
            
            $newPath = Read-Host "新しいプロファイルパスを入力（キャンセルはEnter）"
            
            if ([string]::IsNullOrWhiteSpace($newPath)) {
                Write-Host "操作をキャンセルしました" -ForegroundColor Yellow
                return
            }
            
            $confirm = Read-Host "'$newPath' に変更してもよろしいですか？これはシステムに影響する可能性があります (Y/N)"
            
            if ($confirm -eq 'Y' -or $confirm -eq 'y') {
                $backupSuccess = Backup-SID -sidPath $currentUserSidPath
                if ($backupSuccess) {
                    try {
                        Set-ItemProperty -Path $currentUserSidPath -Name "ProfileImagePath" -Value $newPath -Type String
                        Write-Host "プロファイルパスを '$newPath' に変更しました" -ForegroundColor Green
                        Write-Host "注意: ユーザーデータを新しい場所に移動する必要があります" -ForegroundColor Yellow
                        Write-Host "変更を完全に反映させるには再起動が必要です" -ForegroundColor Yellow
                        $restartNow = Read-Host "今すぐ再起動しますか？ (Y/N)"
                        if ($restartNow -eq 'Y' -or $restartNow -eq 'y') {
                            Restart-Computer -Force
                        }
                    } catch {
                        Write-Host "プロファイルパスの変更中にエラーが発生しました: $($_.Exception.Message)" -ForegroundColor Red
                    }
                } else {
                    Write-Host "バックアップが成功しなかったため処理を中止しました" -ForegroundColor Red
                }
            }
        }
        "C" { return }
        "c" { return }
        default { Write-Host "無効な選択です" -ForegroundColor Red }
    }
}
# すべてのSIDを一覧表示する関数
function List-SIDs {
    $sids = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | 
           Where-Object { $_.PSChildName -like "S-1-5-*" }
    
    if ($sids.Count -eq 0) {
        Write-Host "SIDが見つかりませんでした。" -ForegroundColor Yellow
        return @()
    }
    
    Write-Host "利用可能なSID:" -ForegroundColor Cyan
    $sidList = @()
    
    for ($i = 0; $i -lt $sids.Count; $i++) {
        $sid = $sids[$i].PSChildName
        $profilePath = (Get-ItemProperty -Path $sids[$i].PSPath -Name "ProfileImagePath" -ErrorAction SilentlyContinue).ProfileImagePath
        $sidList += $sids[$i].PSPath
        
        # プロファイルパスからユーザー名を取得しようとする
        $username = "不明"
        if ($profilePath -match "\\Users\\([^\\]+)") {
            $username = $matches[1]
        } elseif ($profilePath -match "\\Documents and Settings\\([^\\]+)") {
            $username = $matches[1]
        }
        
        Write-Host "[$i] $sid - $username ($profilePath)"
    }
    
    return $sidList
}

# システム識別情報をまとめて変更する関数
function Modify-SystemIdentification {
    # 現在の値を取得
    $currentUserSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $currentSidPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$currentUserSID"
    $currentProfilePath = (Get-ItemProperty -Path $currentSidPath -Name "ProfileImagePath" -ErrorAction SilentlyContinue).ProfileImagePath
    $currentComputerName = $env:COMPUTERNAME
    $currentUsername = $env:USERNAME
    
    Write-Host "===== 現在のシステム識別情報 =====" -ForegroundColor Cyan
    Write-Host "現在のSID: $currentUserSID" -ForegroundColor White
    Write-Host "現在のプロファイルパス: $currentProfilePath" -ForegroundColor White
    Write-Host "現在のコンピューター名: $currentComputerName" -ForegroundColor White
    Write-Host "現在のユーザー名: $currentUsername" -ForegroundColor White
    
    $confirm = Read-Host "ランダムなシステム識別情報を生成して適用しますか？ (Y/N)"
    if ($confirm -ne 'Y' -and $confirm -ne 'y') {
        return
    }
    
    # まずバックアップを作成
    Write-Host "現在のSIDのバックアップを作成しています..." -ForegroundColor Yellow
    $backupSuccess = Backup-SID -sidPath $currentSidPath
    
    if (-not $backupSuccess) {
        Write-Host "バックアップに失敗したため、処理を続行できません。" -ForegroundColor Red
        return
    }
    
    try {
        # ランダム値を生成
        Write-Host "ランダムなシステム識別情報を生成しています..." -ForegroundColor Yellow
        
        # 現在のディレクトリ構造を抽出
        $currentProfileRoot = Split-Path -Parent $currentProfilePath
        
        # ランダムなコンピューター名
        $computerNamePrefixes = @("DESKTOP", "LAPTOP", "PC", "WORKSTATION", "DEV", "TEST", "SRV")
        $randomComputerName = $computerNamePrefixes[(Get-Random -Minimum 0 -Maximum $computerNamePrefixes.Count)]
        $randomComputerName += "-" + (Get-Random -Minimum 100 -Maximum 999)
        
        # ランダムな状態フラグ
        $stateFlags = @(0, 256, 512, 8192)
        $randomStateFlag = $stateFlags[(Get-Random -Minimum 0 -Maximum $stateFlags.Count)]
        
        # ランダムなプロファイル読み込み時間
        $randomDays = Get-Random -Minimum 0 -Maximum 30
        $randomHours = Get-Random -Minimum 0 -Maximum 24
        $randomMinutes = Get-Random -Minimum 0 -Maximum 60
        $randomLoadTime = (Get-Date).AddDays(-$randomDays).AddHours(-$randomHours).AddMinutes(-$randomMinutes)
        $fileTime = $randomLoadTime.ToFileTime()
        
        # ランダム値を表示
        Write-Host "`n===== 新しいシステム識別情報 =====" -ForegroundColor Magenta
        Write-Host "現在のプロファイルパス（変更なし）: $currentProfilePath" -ForegroundColor White
        Write-Host "新しいコンピューター名: $randomComputerName" -ForegroundColor White
        Write-Host "新しい状態フラグ: $randomStateFlag" -ForegroundColor White
        Write-Host "新しいプロファイル読み込み時間: $randomLoadTime" -ForegroundColor White
        
        # 変更を適用するか確認
        $applyConfirm = Read-Host "これらの変更を適用しますか？ システム再起動が必要です (Y/N)"
        if ($applyConfirm -ne 'Y' -and $applyConfirm -ne 'y') {
            Write-Host "操作をキャンセルしました。" -ForegroundColor Yellow
            return
        }
        
        # SIDプロパティに変更を適用
        Write-Host "`n変更を適用しています..." -ForegroundColor Yellow
        
        # 状態フラグ変更
        Set-ItemProperty -Path $currentSidPath -Name "State" -Value $randomStateFlag -Type DWord
        Write-Host "状態フラグを更新しました: $randomStateFlag" -ForegroundColor Green
        
        # プロファイル読み込み時間変更
        Set-ItemProperty -Path $currentSidPath -Name "ProfileLoadTimeHigh" -Value ([math]::Floor($fileTime / [math]::Pow(2, 32))) -Type DWord
        Set-ItemProperty -Path $currentSidPath -Name "ProfileLoadTimeLow" -Value ($fileTime % [math]::Pow(2, 32)) -Type DWord
        Write-Host "プロファイル読み込み時間を更新しました: $randomLoadTime" -ForegroundColor Green
        
        # 追加のランダムレジストリ値
        $additionalProperties = @(
            @{Name = "RefCount"; Value = Get-Random -Minimum 0 -Maximum 10; Type = "DWord"},
            @{Name = "Flags"; Value = Get-Random -Minimum 0 -Maximum 65535; Type = "DWord"},
            @{Name = "FullProfile"; Value = Get-Random -Minimum 0 -Maximum 1; Type = "DWord"}
        )
        
        # 存在する場合、追加の値を設定
        foreach ($prop in $additionalProperties) {
            $existingValue = Get-ItemProperty -Path $currentSidPath -Name $prop.Name -ErrorAction SilentlyContinue
            if ($null -ne $existingValue -or $existingValue.$($prop.Name) -ne $null) {
                Set-ItemProperty -Path $currentSidPath -Name $prop.Name -Value $prop.Value -Type $prop.Type
                Write-Host "$($prop.Name) を更新しました: $($prop.Value)" -ForegroundColor Green
            }
        }
        
        # コンピューター名を変更
        Rename-Computer -NewName $randomComputerName -Force
        Write-Host "コンピューター名を変更しました: $randomComputerName" -ForegroundColor Green
        
        Write-Host "`nシステム識別情報のすべての変更が正常に完了しました！" -ForegroundColor Green
        Write-Host "注意: プロファイルパスはログイン継続のため変更しませんでした。" -ForegroundColor Yellow
        
        # 再起動を促す
        $restartNow = Read-Host "変更を反映するには再起動が必要です。今すぐ再起動しますか？ (Y/N)"
        if ($restartNow -eq 'Y' -or $restartNow -eq 'y') {
            Restart-Computer -Force
        } else {
            Write-Host "変更を反映するためにコンピューターを再起動してください。" -ForegroundColor Yellow
        }
        
    } catch {
        Write-Host "システム識別情報の変更中にエラーが発生しました: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 管理者権限で実行されていなければメッセージを表示して終了
if (-not (Test-Admin)) {
    Write-Host "このアプリケーションは管理者として実行する必要があります。" -ForegroundColor Red
    Write-Host "管理者権限で再度実行してください。"
    Write-Host "終了するにはEnterキーを押してください..."
    Read-Host
    exit
}

# メインメニュー表示関数
function Show-Menu {
    Clear-Host
    Write-Host "===== LappySID - SID管理ツール =====" -ForegroundColor Cyan
    Write-Host "1. 現在のユーザーSIDを表示"
    Write-Host "2. ランダムSID情報を生成"
    Write-Host "3. SIDのバックアップ"
    Write-Host "4. バックアップからSIDを復元"
    Write-Host "5. SIDのプロパティを変更"
    Write-Host "6. ワンクリックでランダムなIDに変更"
    Write-Host "7. 終了"
    Write-Host "=========================================" -ForegroundColor Cyan
}

# メイン処理ループ
$running = $true
while ($running) {
    Show-Menu
    $choice = Read-Host "選択肢を入力してください"
    
    switch ($choice) {
        "1" {
            # 現在のユーザーSID表示
            Get-CurrentUserSID
            Write-Host "`n続行するにはEnterキーを押してください..."
            Read-Host
        }
        "2" {
            # ランダムSID情報生成
            Get-RandomSIDInfo
            Write-Host "`n続行するにはEnterキーを押してください..."
            Read-Host
        }
        "3" {
            # SIDバックアップ
            $sidList = List-SIDs
            if ($sidList.Count -gt 0) {
                $selection = Read-Host "バックアップするSIDの番号を入力、または 'C' でキャンセル"
                
                if ($selection -ne 'C' -and $selection -ne 'c' -and 
                    $selection -match '^\d+$' -and [int]$selection -ge 0 -and [int]$selection -lt $sidList.Count) {
                    Backup-SID -sidPath $sidList[[int]$selection]
                }
            }
            Write-Host "続行するにはEnterキーを押してください..."
            Read-Host
        }
        "4" {
            # SID復元
            Restore-SID
            Write-Host "続行するにはEnterキーを押してください..."
            Read-Host
        }
        "5" {
            # SID変更
            $sidList = List-SIDs
            if ($sidList.Count -gt 0) {
                $selection = Read-Host "変更するSIDの番号を入力、または 'C' でキャンセル"
                
                if ($selection -ne 'C' -and $selection -ne 'c' -and 
                    $selection -match '^\d+$' -and [int]$selection -ge 0 -and [int]$selection -lt $sidList.Count) {
                    Change-SID -sidPath $sidList[[int]$selection]
                }
            }
            Write-Host "続行するにはEnterキーを押してください..."
            Read-Host
        }
        "6" {
            # ワンクリックでランダムID変更
            Modify-SystemIdentification
            Write-Host "続行するにはEnterキーを押してください..."
            Read-Host
        }
        "7" {
            # 終了
            $running = $false
        }
        default {
            Write-Host "無効な選択肢です。もう一度入力してください。" -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
}
