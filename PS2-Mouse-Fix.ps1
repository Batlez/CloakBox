function Set-VMMouseFix {
    param(
        [Parameter(Mandatory=$true)]
        [string]$VMName,
        
        [string]$VBoxPath = "$env:USERPROFILE\VirtualBox VMs"
    )
    
    Write-Host "`n  # ==================== PS/2 MOUSE FIX ===================" -ForegroundColor Magenta
    
    Write-Host "`n  # [WHAT THIS SCRIPT DOES]" -ForegroundColor Cyan
    Write-Host "  #" -ForegroundColor Gray
    Write-Host "  #   This script fixes the PS/2 Mouse issue for Proctoring compatibility." -ForegroundColor Gray
    Write-Host "  #   It modifies your VM's .vbox file to enable proper mouse capture." -ForegroundColor Gray
    Write-Host "  #" -ForegroundColor Gray
    Write-Host "  #   Before:" -ForegroundColor Yellow
    Write-Host "  #     <HID Keyboard=`"USBKeyboard`"/>" -ForegroundColor Gray
    Write-Host "  #" -ForegroundColor Gray
    Write-Host "  #   After:" -ForegroundColor Green
    Write-Host "  #     <HID Pointing=`"USBMouse`" Keyboard=`"USBKeyboard`"/>" -ForegroundColor Gray
    Write-Host "  #" -ForegroundColor Gray
    Write-Host "  #   This allows the Host key (Right Ctrl) to capture/release the mouse" -ForegroundColor Gray
    Write-Host "  #" -ForegroundColor Gray
    
    Write-Host "`n  # [PREREQUISITES]" -ForegroundColor Yellow
    Write-Host "  #   1. Mouse MUST be set to 'PS/2 Mouse' in VM settings FIRST" -ForegroundColor Gray
    Write-Host "  #   2. All VirtualBox processes will be closed automatically" -ForegroundColor Gray
    Write-Host "  #   3. A backup of your .vbox file will be created" -ForegroundColor Gray
    
    Write-Host "`n  # [PROCESSES THAT WILL BE CLOSED]" -ForegroundColor Yellow
    Write-Host "  #   - VirtualBoxVM.exe" -ForegroundColor Gray
    Write-Host "  #   - VirtualBox.exe" -ForegroundColor Gray
    Write-Host "  #   - VBoxSVC.exe" -ForegroundColor Gray
    Write-Host "  #   - VBoxSDS.exe" -ForegroundColor Gray
    
    Write-Host "`n  # [IMPORTANT]" -ForegroundColor Red
    Write-Host "  #   Do NOT change mouse settings in VirtualBox GUI after applying this fix!" -ForegroundColor Red
    Write-Host "  #   The GUI will show 'USB Mouse' but it will actually work as PS/2 Mouse." -ForegroundColor Red
    
    Write-Host ""
    $continue = Read-Host "  # Do you want to continue? (Y/N) [Y]"
    
    if (-not [string]::IsNullOrWhiteSpace($continue) -and $continue.ToUpper() -eq "N") {
        Write-Host "`n  # [INFO] Operation cancelled by user." -ForegroundColor Yellow
        return $false
    }
    
    Write-Host "`n  # [INFO] Proceeding with PS/2 Mouse fix..." -ForegroundColor Green
    
    Write-Host "`n  # [STEP 1] Checking for VirtualBox processes..." -ForegroundColor Yellow
    
    $requiredProcesses = @("VirtualBoxVM", "VirtualBox", "VBoxSVC", "VBoxSDS")
    $runningProcesses = @()
    
    foreach ($procName in $requiredProcesses) {
        $proc = Get-Process -Name $procName -ErrorAction SilentlyContinue
        if ($proc) {
            $runningProcesses += $procName
        }
    }
    
    if ($runningProcesses.Count -gt 0) {
        Write-Host "  # [WARNING] The following VirtualBox processes are running:" -ForegroundColor Yellow
        foreach ($proc in $runningProcesses) {
            Write-Host "  #   - $proc.exe" -ForegroundColor Red
        }
        
        Write-Host "`n  # [!] ALL of these must be closed for the fix to work!" -ForegroundColor Red
        $closeProcesses = Read-Host "`n  # Close all VirtualBox processes now? (Y/N) [Y]"
        
        if ([string]::IsNullOrWhiteSpace($closeProcesses) -or $closeProcesses.ToUpper() -eq "Y") {
            Write-Host "`n  # [INFO] Closing VirtualBox processes..." -ForegroundColor Yellow
            
            foreach ($procName in $requiredProcesses) {
                $proc = Get-Process -Name $procName -ErrorAction SilentlyContinue
                if ($proc) {
                    Write-Host "  #   Stopping $procName.exe..." -ForegroundColor Gray
                    Stop-Process -Name $procName -Force -ErrorAction SilentlyContinue
                }
            }
            
            Start-Sleep -Seconds 3
            
            $stillRunning = @()
            foreach ($procName in $requiredProcesses) {
                $proc = Get-Process -Name $procName -ErrorAction SilentlyContinue
                if ($proc) {
                    $stillRunning += $procName
                }
            }
            
            if ($stillRunning.Count -gt 0) {
                Write-Host "  # [ERROR] Could not close: $($stillRunning -join ', ')" -ForegroundColor Red
                Write-Host "  # [WARNING] Some processes require administrator privileges to terminate." -ForegroundColor Yellow
                
                $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                
                if (-not $isAdmin) {
                    Write-Host "`n  # [INFO] This script is NOT running as Administrator." -ForegroundColor Yellow
                    $runAsAdmin = Read-Host "  # Restart script as Administrator? (Y/N) [Y]"
                    
                    if ([string]::IsNullOrWhiteSpace($runAsAdmin) -or $runAsAdmin.ToUpper() -eq "Y") {
                        Write-Host "`n  # [INFO] Restarting with Administrator privileges..." -ForegroundColor Yellow
                        
                        $scriptPath = $PSCommandPath
                        $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -VMName `"$VMName`""
                        
                        try {
                            Start-Process powershell.exe -ArgumentList $arguments -Verb RunAs
                            Write-Host "  # [OK] Script restarted as Administrator. Exiting this instance..." -ForegroundColor Green
                            return $null  # Special return to exit without error
                        }
                        catch {
                            Write-Host "  # [ERROR] Failed to restart as Administrator: $($_.Exception.Message)" -ForegroundColor Red
                            return $false
                        }
                    }
                    else {
                        Write-Host "  # [ERROR] Cannot proceed without closing VirtualBox processes." -ForegroundColor Red
                        return $false
                    }
                }
                else {
                    Write-Host "  # [ERROR] Already running as Administrator but still cannot close processes." -ForegroundColor Red
                    Write-Host "  # Please manually close VirtualBox and try again." -ForegroundColor Yellow
                    return $false
                }
            }
            
            Write-Host "  # [OK] All VirtualBox processes closed." -ForegroundColor Green
        } else {
            Write-Host "  # [ERROR] Cannot apply fix while VirtualBox is running." -ForegroundColor Red
            return $false
        }
    } else {
        Write-Host "  # [OK] No VirtualBox processes running." -ForegroundColor Green
    }
    
    Write-Host "`n  # [STEP 2] Locating VM file..." -ForegroundColor Yellow
    
    $vboxFile = "$VBoxPath\$VMName\$VMName.vbox"
    
    if (-not (Test-Path $vboxFile)) {
        Write-Host "  # [WARNING] Could not find: $vboxFile" -ForegroundColor Yellow
        $manualPath = Read-Host "  # Enter full path to .vbox file (or press Enter to cancel)"
        
        if ([string]::IsNullOrWhiteSpace($manualPath)) {
            Write-Host "  # [ERROR] Cancelled by user." -ForegroundColor Red
            return $false
        }
        
        $vboxFile = $manualPath
        
        if (-not (Test-Path $vboxFile)) {
            Write-Host "  # [ERROR] File not found: $vboxFile" -ForegroundColor Red
            return $false
        }
    }
    
    Write-Host "  # [OK] Found: $vboxFile" -ForegroundColor Green
    
    Write-Host "`n  # [STEP 3] Creating backup..." -ForegroundColor Yellow
    
    $backupFile = "$vboxFile.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Copy-Item -Path $vboxFile -Destination $backupFile -Force
    Write-Host "  # [OK] Backup saved: $backupFile" -ForegroundColor Green
    
    Write-Host "`n  # [STEP 4] Applying PS/2 Mouse fix..." -ForegroundColor Yellow
    
    $content = Get-Content -Path $vboxFile -Raw
    
    if ($content -match '<HID Pointing="USBMouse" Keyboard="USBKeyboard"/>') {
        Write-Host "  # [OK] PS/2 Mouse fix is already applied!" -ForegroundColor Green
        return $true
    }
    
    if ($content -match '<HID Keyboard="USBKeyboard"/>') {
        Write-Host "  # [INFO] Found: <HID Keyboard=`"USBKeyboard`"/>" -ForegroundColor Gray
        $newContent = $content -replace '<HID Keyboard="USBKeyboard"/>', '<HID Pointing="USBMouse" Keyboard="USBKeyboard"/>'
    }
    elseif ($content -match '<HID[^/>]*Pointing="[^"]*"[^/>]*/>') {
        $match = [regex]::Match($content, '<HID[^/>]*/>')
        Write-Host "  # [INFO] Found: $($match.Value)" -ForegroundColor Gray
        $newContent = $content -replace '<HID[^/>]*/>', '<HID Pointing="USBMouse" Keyboard="USBKeyboard"/>'
    }
    elseif ($content -match '<HID[^/>]*/>') {
        $match = [regex]::Match($content, '<HID[^/>]*/>')
        Write-Host "  # [INFO] Found: $($match.Value)" -ForegroundColor Gray
        $newContent = $content -replace '<HID[^/>]*/>', '<HID Pointing="USBMouse" Keyboard="USBKeyboard"/>'
    }
    elseif ($content -notmatch '<HID') {
        Write-Host "  # [WARNING] No <HID> line found in .vbox file!" -ForegroundColor Yellow
        Write-Host "  #" -ForegroundColor Gray
        Write-Host "  # This usually happens when VBoxManage --mouse ps2 command fails." -ForegroundColor Gray
        Write-Host "  # The script can automatically insert the HID line for you." -ForegroundColor Gray
        Write-Host "  #" -ForegroundColor Gray
        Write-Host "  # The following line will be added after <Memory RAMSize=.../>:" -ForegroundColor Cyan
        Write-Host "  #   <HID Pointing=`"USBMouse`" Keyboard=`"USBKeyboard`"/>" -ForegroundColor Green
        
        $insertHID = Read-Host "`n  # Do you want to insert the HID line automatically? (Y/N) [Y]"
        
        if ([string]::IsNullOrWhiteSpace($insertHID) -or $insertHID.ToUpper() -eq "Y") {
            Write-Host "`n  # [INFO] Inserting HID line..." -ForegroundColor Yellow
            
            if ($content -match '<Memory RAMSize="\d+"/>') {
                $newLine = [System.Environment]::NewLine
                $newContent = $content -replace '(<Memory RAMSize="\d+"/>)', "`$1$newLine      <HID Pointing=`"USBMouse`" Keyboard=`"USBKeyboard`"/>"
                Write-Host "  # [OK] HID line will be inserted after Memory tag" -ForegroundColor Green
            }
            elseif ($content -match '<Hardware>') {
                $newLine = [System.Environment]::NewLine
                $newContent = $content -replace '(<Hardware>)', "`$1$newLine      <HID Pointing=`"USBMouse`" Keyboard=`"USBKeyboard`"/>"
                Write-Host "  # [OK] HID line will be inserted after Hardware tag" -ForegroundColor Green
            }
            else {
                Write-Host "  # [ERROR] Could not find suitable location to insert HID line" -ForegroundColor Red
                Write-Host "  # [INFO] Your .vbox file structure is unusual" -ForegroundColor Yellow
                Write-Host "  # [TIP] Try setting mouse to PS/2 in VirtualBox GUI first" -ForegroundColor Yellow
                return $false
            }
        }
        else {
            Write-Host "  # [ERROR] Cannot proceed without HID configuration" -ForegroundColor Red
            Write-Host "  # [TIP] Try one of these solutions:" -ForegroundColor Yellow
            Write-Host "  #   1. Set mouse to PS/2 in VirtualBox GUI" -ForegroundColor Gray
            Write-Host "  #   2. Run: VBoxManage modifyvm $VMName --mouse ps2" -ForegroundColor Gray
            Write-Host "  #   3. Manually add HID line to .vbox file" -ForegroundColor Gray
            return $false
        }
    }
    else {
        Write-Host "  # [ERROR] Could not find HID configuration in .vbox file" -ForegroundColor Red
        Write-Host "  # [TIP] Make sure PS/2 Mouse is selected in VM settings first!" -ForegroundColor Yellow
        return $false
    }
    
    Write-Host "`n  # [STEP 5] Saving changes..." -ForegroundColor Yellow
    
    try {
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($vboxFile, $newContent, $utf8NoBom)
        Write-Host "  # [OK] File updated successfully!" -ForegroundColor Green
    }
    catch {
        Write-Host "  # [ERROR] Failed to write file: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  # [INFO] Restoring backup..." -ForegroundColor Yellow
        Copy-Item -Path $backupFile -Destination $vboxFile -Force
        return $false
    }
    
    Write-Host "`n  # ==================== SUCCESS ===================" -ForegroundColor Green
    Write-Host "  # PS/2 Mouse fix has been applied!" -ForegroundColor Green
    Write-Host "`n  # [REMEMBER]" -ForegroundColor Yellow
    Write-Host "  #   - VirtualBox GUI will show 'USB Mouse' - IGNORE THIS" -ForegroundColor Cyan
    Write-Host "  #   - Do NOT change mouse settings in VirtualBox GUI" -ForegroundColor Cyan
    Write-Host "  #   - Host key (Right Ctrl) will capture/release the mouse" -ForegroundColor Cyan
    Write-Host "  #   - If you change settings, run this script again" -ForegroundColor Cyan
    Write-Host "  # =================================================" -ForegroundColor Green
    
    return $true
}

param([string]$VMName = "")

Clear-Host
Write-Host "`n  ###################################################" -ForegroundColor Magenta
Write-Host "  #                                                 #" -ForegroundColor Magenta
Write-Host "  #          PS/2 MOUSE FIX FOR CLOAKBOX            #" -ForegroundColor Magenta
Write-Host "  #                                                 #" -ForegroundColor Magenta
Write-Host "  ###################################################" -ForegroundColor Magenta

if ([string]::IsNullOrWhiteSpace($VMName)) {
    $VMName = Read-Host "`n  # Enter the VM Name (or press Enter to cancel)"
}

if ([string]::IsNullOrWhiteSpace($VMName)) {
    Write-Host "`n  # [INFO] No VM name entered. Exiting." -ForegroundColor Yellow
} else {
    $result = Set-VMMouseFix -VMName $VMName
    
    if ($result -eq $true) {
        Write-Host "`n  # You can now launch your VM!" -ForegroundColor Green
    }
    elseif ($result -eq $null) {
        exit 0
    }
}

Write-Host "`n  # Press any key to exit..." -ForegroundColor Magenta
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")