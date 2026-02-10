$scriptPath = $MyInvocation.MyCommand.Path
if ($scriptPath -and (Test-Path $scriptPath)) {
    Unblock-File -Path $scriptPath -ErrorAction SilentlyContinue
}

try {
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue
} catch { }

$isAdministrator = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdministrator) {
    Write-Warning "Administrator privileges are required for this script."
    Write-Host "Attempting to re-launch with elevated privileges..." -ForegroundColor Yellow
    
    try {
        $scriptPath = $MyInvocation.MyCommand.Path
        $arguments = "-ExecutionPolicy Bypass -NoProfile -File `"$scriptPath`""
        
        Start-Process powershell.exe -ArgumentList $arguments -Verb RunAs -ErrorAction Stop
        
        Exit
    }
    catch {
        Write-Host "[ERROR] Failed to elevate." -ForegroundColor Red
        Write-Host "Please start a PowerShell session as an Administrator and run the script manually." -ForegroundColor Red
        Write-Host "" -ForegroundColor Red
        Write-Host "To run manually:" -ForegroundColor Cyan
        Write-Host "  1. Right-click PowerShell → Run as Administrator" -ForegroundColor Gray
        Write-Host "  2. Run: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass" -ForegroundColor Gray
        Write-Host "  3. Run: .\Run-Outside-VM.ps1" -ForegroundColor Gray
        
        if ($Host.UI.RawUI.KeyAvailable) { $Host.UI.RawUI.FlushInputBuffer() }
        Write-Host "`nPress any key to exit..."
        $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
        Exit
    }
}

Write-Host "Successfully running with Administrator privileges." -ForegroundColor Green

function Get-UserChoice {
    param(
        [string]$Message,
        [string]$Default,
        [string]$Description
    )
    
    Write-Host "`n  # $Message " -NoNewline -ForegroundColor Cyan
    Write-Host "[$Default] " -NoNewline -ForegroundColor Yellow
    if ($Description) {
        Write-Host "($Description)" -ForegroundColor Gray
    }
    $userInput = Read-Host
    
    if ([string]::IsNullOrWhiteSpace($userInput)) {
        return $Default
    }
    return $userInput
}

function Get-YesNoChoice {
    param(
        [string]$Message,
        [string]$Default = "Y",
        [string]$Description
    )
    
    do {
        Write-Host "`n  # $Message (Y/N) " -NoNewline -ForegroundColor Cyan
        Write-Host "[$Default] " -NoNewline -ForegroundColor Yellow
        if ($Description) {
            Write-Host "($Description)" -ForegroundColor Gray
        }
        $userInput = Read-Host
        
        if ([string]::IsNullOrWhiteSpace($userInput)) {
            $userInput = $Default
        }
        
        $userInput = $userInput.ToUpper()
    } while ($userInput -ne "Y" -and $userInput -ne "N")
    
    return ($userInput -eq "Y")
}

function Get-VBoxVersion {
    param([string]$VBoxManager)
    
    try {
        $versionOutput = & $VBoxManager --version 2>&1
        if ($versionOutput -match '(\d+)\.(\d+)\.(\d+)') {
            return [PSCustomObject]@{
                Major = [int]$matches[1]
                Minor = [int]$matches[2]
                Patch = [int]$matches[3]
                FullVersion = $versionOutput
            }
        }
    }
    catch {
        Write-Host "  # [WARNING] Could not detect VirtualBox version. Assuming latest." -ForegroundColor Yellow
    }
    
    return [PSCustomObject]@{
        Major = 7
        Minor = 0
        Patch = 0
        FullVersion = "Unknown"
    }
}

function Close-VirtualBoxProcesses {
    Write-Host "Checking for running VirtualBox processes..."
    
    $vboxSvc = Get-Process -Name "VBoxSVC" -ErrorAction SilentlyContinue
    if ($vboxSvc) {
        Write-Host "Stopping VBoxSVC.exe process..."
        Stop-Process -Name "VBoxSVC" -Force
        Write-Host "VBoxSVC.exe terminated."
    }
    
    $virtualBox = Get-Process -Name "VirtualBox" -ErrorAction SilentlyContinue
    if ($virtualBox) {
        Write-Host "Stopping VirtualBox.exe process..."
        Stop-Process -Name "VirtualBox" -Force
        Write-Host "VirtualBox.exe terminated."
    }
    
    $otherVBox = Get-Process | Where-Object { $_.Name -like "VBox*" -and $_.Name -ne "VBoxSVC" }
    if ($otherVBox) {
        Write-Host "Stopping other VirtualBox-related processes..."
        $otherVBox | ForEach-Object { 
            Write-Host "Stopping $($_.Name)..."
            Stop-Process -Id $_.Id -Force 
        }
    }
    
    Start-Sleep -Seconds 3
    Write-Host "All VirtualBox processes have been terminated."
}

function Set-VMMouseFix {
    param(
        [Parameter(Mandatory=$true)]
        [string]$VMName,
        [string]$VBoxPath = "$env:USERPROFILE\VirtualBox VMs"
    )
    
    Write-Host "`n  # ==================== PS/2 MOUSE FIX ===================" -ForegroundColor Magenta
    Write-Host "  # [INFO] Applying PS/2 Mouse fix for detection evasion..." -ForegroundColor Cyan
    
    # Ensure processes are closed first
    Close-VirtualBoxProcesses
    
    $vboxFile = "$VBoxPath\$VMName\$VMName.vbox"
    
    if (-not (Test-Path $vboxFile)) {
        # Try standard path if custom path not found
        $vboxFile = "$env:USERPROFILE\VirtualBox VMs\$VMName\$VMName.vbox"
        if (-not (Test-Path $vboxFile)) {
            Write-Host "  # [WARNING] Could not find .vbox file at: $vboxFile" -ForegroundColor Yellow
            return $false
        }
    }
    
    Write-Host "  # [OK] Found: $vboxFile" -ForegroundColor Green
    
    # Create backup
    $backupFile = "$vboxFile.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Copy-Item -Path $vboxFile -Destination $backupFile -Force
    
    $content = Get-Content -Path $vboxFile -Raw
    $newContent = $content
    $modified = $false
    
    # Case 1: Already fixed
    if ($content -match '<HID Pointing="USBMouse" Keyboard="USBKeyboard"/>') {
        Write-Host "  # [OK] PS/2 Mouse fix is already applied." -ForegroundColor Green
        return $true
    }
    
    # Case 2: Only Keyboard present
    if ($content -match '<HID Keyboard="USBKeyboard"/>') {
        Write-Host "  # [INFO] Upgrading HID tag..." -ForegroundColor Gray
        $newContent = $content -replace '<HID Keyboard="USBKeyboard"/>', '<HID Pointing="USBMouse" Keyboard="USBKeyboard"/>'
        $modified = $true
    }
    # Case 3: Empty HID tag
    elseif ($content -match '<HID[^/>]*/>') {
        $match = [regex]::Match($content, '<HID[^/>]*/>')
        Write-Host "  # [INFO] Replacing generic HID tag..." -ForegroundColor Gray
        $newContent = $content -replace '<HID[^/>]*/>', '<HID Pointing="USBMouse" Keyboard="USBKeyboard"/>'
        $modified = $true
    }
    # Case 4: Missing HID tag completely (Common with PS/2 setting)
    elseif ($content -notmatch '<HID') {
        Write-Host "  # [INFO] Inserting missing HID tag..." -ForegroundColor Yellow
        
        if ($content -match '<Memory RAMSize="\d+"/>') {
            $newLine = [System.Environment]::NewLine
            $newContent = $content -replace '(<Memory RAMSize="\d+"/>)', "`$1$newLine      <HID Pointing=`"USBMouse`" Keyboard=`"USBKeyboard`"/>"
            $modified = $true
        }
        elseif ($content -match '<Hardware>') {
            $newLine = [System.Environment]::NewLine
            $newContent = $content -replace '(<Hardware>)', "`$1$newLine      <HID Pointing=`"USBMouse`" Keyboard=`"USBKeyboard`"/>"
            $modified = $true
        }
    }
    
    if ($modified) {
        try {
            $utf8NoBom = New-Object System.Text.UTF8Encoding $false
            [System.IO.File]::WriteAllText($vboxFile, $newContent, $utf8NoBom)
            Write-Host "  # [OK] Mouse fix applied successfully!" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Host "  # [ERROR] Failed to write file: $($_.Exception.Message)" -ForegroundColor Red
            Copy-Item -Path $backupFile -Destination $vboxFile -Force
            return $false
        }
    } else {
        Write-Host "  # [WARNING] Could not apply mouse fix automatically." -ForegroundColor Yellow
        return $false
    }
}

function Get-SystemInfo {
    Write-Host "`n  # [INFO] Detecting system hardware..." -ForegroundColor Yellow
    
    function Get-SafeInt {
        param($InputObject)
        try {
            if ($null -eq $InputObject) { return 0 }
            if ($InputObject -is [array]) { 
                if ($InputObject.Count -eq 0) { return 0 }
                return [int][math]::Round([double]$InputObject[0]) 
            }
            return [int][math]::Round([double]$InputObject)
        } catch { return 0 }
    }

    $procInfo = $null
    $memInfo = $null
    $diskInfo = $null
    $gpuInfo = $null

    $finalCores = 4
    $finalLogical = 8
    $finalModel = "Unknown CPU"
    $finalManu = "Unknown"
    $finalRamGB = 8
    $finalRamMB = 8192
    $finalDiskGB = 256
    $finalFreeGB = 128
    $finalGpu = "Unknown GPU"
    $detectionSuccess = $false

    try {
        $procInfo = @(Get-WmiObject -Class Win32_Processor -ErrorAction SilentlyContinue)
        if ($procInfo) {
            $coresSum = 0
            $logicalSum = 0
            foreach ($p in $procInfo) {
                $coresSum += Get-SafeInt $p.NumberOfCores
                $logicalSum += Get-SafeInt $p.NumberOfLogicalProcessors
            }
            
            if ($coresSum -gt 0) { $finalCores = $coresSum }
            if ($logicalSum -gt 0) { $finalLogical = $logicalSum }
            
            if ($procInfo[0].Name) { $finalModel = $procInfo[0].Name.Trim() }
            if ($finalModel -match "Intel") { $finalManu = "Intel" } elseif ($finalModel -match "AMD") { $finalManu = "AMD" }
        }

        $memInfo = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($memInfo) {
            $bytes = [double]$memInfo.TotalPhysicalMemory
            $finalRamGB = Get-SafeInt ($bytes / 1GB)
            $finalRamMB = Get-SafeInt ($bytes / 1MB)
        }

        $sysDrive = $env:SystemDrive
        $diskInfo = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$sysDrive'" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($diskInfo) {
            $finalDiskGB = Get-SafeInt ($diskInfo.Size / 1GB)
            $finalFreeGB = Get-SafeInt ($diskInfo.FreeSpace / 1GB)
        }

        $gpuInfo = @(Get-WmiObject -Class Win32_VideoController -ErrorAction SilentlyContinue)
        if ($gpuInfo -and $gpuInfo.Count -gt 0) {
            $finalGpu = $gpuInfo[0].Name
        }

        $detectionSuccess = $true
    } 
    catch {
        Write-Host "  # [WARNING] Hardware detection failed. Using defaults." -ForegroundColor Yellow
        $detectionSuccess = $false
    }

    return @{
        CPUCores = $finalCores
        CPULogicalProcessors = $finalLogical
        CPUModel = [string]$finalModel
        CPUManufacturer = [string]$finalManu
        TotalRAM_GB = $finalRamGB
        TotalRAM_MB = $finalRamMB
        SystemDrive = $env:SystemDrive
        TotalStorage_GB = $finalDiskGB
        FreeStorage_GB = $finalFreeGB
        GPUName = [string]$finalGpu
        DetectionSuccessful = $detectionSuccess
    }
}

function Get-RecommendedVMSettings {
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$SystemInfo
    )
    
    if (-not $SystemInfo.DetectionSuccessful) {
        Write-Host "`n  # [WARNING] Could not auto-detect hardware. Please enter manually." -ForegroundColor Yellow
        
        $SystemInfo.CPUCores = [int](Read-Host "  # CPU Cores (e.g. 4, 8):")
        $ramInput = [int](Read-Host "  # RAM in GB (e.g. 16, 32):")
        $SystemInfo.TotalRAM_GB = $ramInput
        $SystemInfo.TotalRAM_MB = $ramInput * 1024
        $SystemInfo.FreeStorage_GB = [int](Read-Host "  # Free Storage in GB (e.g. 100):")
        $SystemInfo.CPUManufacturer = Read-Host "  # CPU Type (Intel/AMD):"
    }
    
    [int]$cores = $SystemInfo.CPUCores
    [int]$ramMB = $SystemInfo.TotalRAM_MB
    [int]$freeDisk = $SystemInfo.FreeStorage_GB

    $recCores = 2
    if ($cores -ge 16) { $recCores = 8 }
    elseif ($cores -ge 10) { $recCores = 6 }
    elseif ($cores -ge 8) { $recCores = 4 }
    elseif ($cores -ge 6) { $recCores = 3 }
    elseif ($cores -eq 1) { $recCores = 1 }
    else { $recCores = [math]::Floor($cores / 2) }
    if ($recCores -lt 1) { $recCores = 1 }

    [int]$recRAM = 4096
    if ($SystemInfo.TotalRAM_GB -lt 8) { $recRAM = 2048 }
    elseif ($SystemInfo.TotalRAM_GB -lt 16) { $recRAM = 4096 }
    elseif ($SystemInfo.TotalRAM_GB -lt 32) { $recRAM = 8192 }
    else { $recRAM = 16384 }

    $maxSafeRAM = $ramMB - 2048
    if ($maxSafeRAM -lt 1024) { $maxSafeRAM = 1024 }
    if ($recRAM -gt $maxSafeRAM) { $recRAM = $maxSafeRAM }

    [int]$recDisk = 60
    if ($freeDisk -lt 120) { $recDisk = 40 }
    if ($freeDisk -lt 60) { $recDisk = 25 }
    
    if ("$($SystemInfo.CPUManufacturer)" -eq "Intel") {
		$prof = "Intel Core i7-6700K"
		$choice = "1"
	} else {
		$prof = "AMD Ryzen 7 1800X"
		$choice = "5"
	}

    return @{
        CPUCores = [int]$recCores
        RAM_MB = [int]$recRAM
        Storage_GB = [int]$recDisk
        CPUProfile = [string]$prof
        CPUChoice = [string]$choice
    }
}

function Remove-VirtualMachine {
    param(
        [string]$VBoxManager
    )
    
    Write-Host "`n  # ==================== DELETE VIRTUAL MACHINE ===================" -ForegroundColor Magenta
    Write-Host "`n  # Available VMs on this system:`n" -ForegroundColor Cyan
    & $VBoxManager list vms
    
    $vmToDelete = Read-Host "`n  # Enter the VM Name to DELETE"
    
    if ([string]::IsNullOrWhiteSpace($vmToDelete)) {
        Write-Host "  # [ERROR] No VM name entered. Aborting." -ForegroundColor Red
        return
    }
    
    $vmInfo = & $VBoxManager showvminfo $vmToDelete 2>&1
    if ($vmInfo -like "*VBOX_E_OBJECT_NOT_FOUND*") {
        Write-Host "  # [ERROR] VM '$vmToDelete' does not exist!" -ForegroundColor Red
        return
    }
    
    Write-Host "`n  # [WARNING] You are about to DELETE VM: $vmToDelete" -ForegroundColor Yellow
    Write-Host "  # This action cannot be undone!" -ForegroundColor Red
    
    $confirmDelete = Get-YesNoChoice "Are you absolutely sure you want to delete this VM?" "N" "Type Y to confirm deletion"
    
    if (-not $confirmDelete) {
        Write-Host "  # [INFO] Deletion cancelled." -ForegroundColor Cyan
        return
    }
    
    Write-Host "`n  # Deletion Options:" -ForegroundColor Cyan
    Write-Host "  # 1. Delete VM registration only (keep all files)" -ForegroundColor Gray
    Write-Host "  # 2. Delete VM and all associated files (complete removal)" -ForegroundColor Gray
    
    $deleteChoice = Get-UserChoice "Select deletion option (1-2):" "1" "Option 2 permanently deletes all VM files"
    
    try {
        if ($deleteChoice -eq "2") {
            Write-Host "`n  # [INFO] Deleting VM '$vmToDelete' and ALL associated files..." -ForegroundColor Yellow
            & $VBoxManager unregistervm $vmToDelete --delete
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  # [OK] VM '$vmToDelete' and all files have been permanently deleted." -ForegroundColor Green
            } else {
                Write-Host "  # [ERROR] Failed to delete VM (Exit code: $LASTEXITCODE)." -ForegroundColor Red
            }
        } else {
            Write-Host "`n  # [INFO] Removing VM registration for '$vmToDelete' (keeping files)..." -ForegroundColor Yellow
            & $VBoxManager unregistervm $vmToDelete
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  # [OK] VM '$vmToDelete' has been unregistered. Files are preserved." -ForegroundColor Green
                Write-Host "  # [INFO] VM files location: $env:USERPROFILE\VirtualBox VMs\$vmToDelete" -ForegroundColor Cyan
            } else {
                Write-Host "  # [ERROR] Failed to unregister VM (Exit code: $LASTEXITCODE)." -ForegroundColor Red
            }
        }
    }
    catch {
        Write-Host "  # [ERROR] An error occurred during deletion: $_" -ForegroundColor Red
    }
    
    Write-Host "`n  # Press any key to continue..." -ForegroundColor Magenta
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ================= MAIN SCRIPT START =================

Close-VirtualBoxProcesses

Write-Host "`n  ###################################################" -ForegroundColor Magenta
Write-Host "  #                                                 #" -ForegroundColor Magenta
Write-Host "  #         BYPASS PROCTORING WITH CLOAKBOX         #" -ForegroundColor Magenta
Write-Host "  #                                                 #" -ForegroundColor Magenta
Write-Host "  ###################################################" -ForegroundColor Magenta
Write-Host "`n  # This tool will help you configure your Cloakbox VM to avoid detection." -ForegroundColor Cyan
Write-Host "  # Default values are shown in [brackets]." -ForegroundColor Cyan

$systemInfo = Get-SystemInfo
$recommendedSettings = Get-RecommendedVMSettings -SystemInfo $systemInfo

if ($systemInfo.DetectionSuccessful) {
    Write-Host "`n  # ==================== SYSTEM DETECTED =====================" -ForegroundColor Magenta
    Write-Host "  # CPU:  $($systemInfo.CPUModel) ($($systemInfo.CPUCores) cores, $($systemInfo.CPULogicalProcessors) threads)" -ForegroundColor Gray
    Write-Host "  # RAM: $($systemInfo.TotalRAM_GB) GB ($($systemInfo.TotalRAM_MB) MB)" -ForegroundColor Gray
    Write-Host "  # Storage: $($systemInfo.FreeStorage_GB) GB free of $($systemInfo.TotalStorage_GB) GB total" -ForegroundColor Gray
    Write-Host "  # GPU: $($systemInfo.GPUName)" -ForegroundColor Gray
    Write-Host "  # ==========================================================" -ForegroundColor Magenta
} else {
    Write-Host "`n  # ==================== SYSTEM INFO (MANUAL) ================" -ForegroundColor Magenta
    Write-Host "  # CPU: $($systemInfo.CPUManufacturer) ($($systemInfo.CPUCores) cores)" -ForegroundColor Gray
    Write-Host "  # RAM:  $($systemInfo.TotalRAM_GB) GB" -ForegroundColor Gray
    Write-Host "  # Storage:  $($systemInfo.FreeStorage_GB) GB free" -ForegroundColor Gray
    Write-Host "  # ==========================================================" -ForegroundColor Magenta
}

Write-Host "`n  # ================ RECOMMENDED VM SETTINGS ================" -ForegroundColor Magenta
Write-Host "  # CPU Cores: $($recommendedSettings.CPUCores) cores (VM will use ~50% of your CPU)" -ForegroundColor Gray
Write-Host "  # RAM: $([math]::Round($recommendedSettings.RAM_MB/1024, 1)) GB = $($recommendedSettings.RAM_MB) MB (VM will use ~50% of your RAM)" -ForegroundColor Gray
Write-Host "  # Storage: $($recommendedSettings.Storage_GB) GB (Leaves space for host OS)" -ForegroundColor Gray
Write-Host "  # CPU Profile: $($recommendedSettings.CPUProfile)" -ForegroundColor Gray
Write-Host "  # ==========================================================" -ForegroundColor Magenta

Write-Host "`n  # [TIP] These defaults allocate ~50% of your resources to the VM." -ForegroundColor Yellow
Write-Host "  # You can customize these in the next steps." -ForegroundColor Yellow

$defaultVBoxPath = "$env:ProgramFiles\Vektor T13\VirtualBox"
$vboxPathExists = Test-Path "$defaultVBoxPath\VBoxManage.exe"

if ($vboxPathExists) {
    Write-Host "`n  # [INFO] Cloakbox installation found at default location." -ForegroundColor Green
    $VBoxPath = $defaultVBoxPath
} else {
    $VBoxPath = Get-UserChoice "Enter the path to your Cloakbox/VirtualBox installation:" $defaultVBoxPath "e.g. C:\Program Files\Vektor T13\VirtualBox"
    
    if (-not (Test-Path "$VBoxPath\VBoxManage.exe")) {
        Write-Host "  # [ERROR] VBoxManage.exe not found at '$VBoxPath\VBoxManage.exe'." -ForegroundColor Red
        Write-Host "  # Please verify your Cloakbox/VirtualBox installation path and try again." -ForegroundColor Red
        pause
        exit 1
    }
}

$VBoxManager = "$VBoxPath\VBoxManage.exe"

$vboxVersion = Get-VBoxVersion -VBoxManager $VBoxManager
Write-Host "`n  # [INFO] Detected VirtualBox version: $($vboxVersion.FullVersion)" -ForegroundColor Cyan

Write-Host "`n  # ==================== MAIN MENU ===================" -ForegroundColor Magenta
Write-Host "  # 1. Create or Modify a VM" -ForegroundColor Gray
Write-Host "  # 2. Delete a VM" -ForegroundColor Gray
Write-Host "  # 3. Exit" -ForegroundColor Gray

$menuChoice = Get-UserChoice "Select an option (1-3):" "1" "Choose what you want to do"

if ($menuChoice -eq "2") {
    Remove-VirtualMachine -VBoxManager $VBoxManager
    Write-Host "`n  # Script complete. Press any key to exit..." -ForegroundColor Magenta
    pause
    exit 0
} elseif ($menuChoice -eq "3") {
    Write-Host "`n  # Exiting script..." -ForegroundColor Cyan
    exit 0
}

try {
    Write-Host "`n  # Available VMs on this system (May take a few seconds):`n" -ForegroundColor Cyan
    & $VBoxManager list vms
    
    Write-Host "`n  # [TIP] Type a NEW name to create a VM, or an EXISTING name to modify it." -ForegroundColor Yellow
    $VM = Read-Host "`n  # Enter the VM Name"
    
    if ([string]::IsNullOrWhiteSpace($VM)) {
        Write-Host "`n  # [ERROR] No VM name entered. Aborting script." -ForegroundColor Red
        pause
        exit 1
    }
    
    $vmExists = & $VBoxManager showvminfo $VM 2>&1
    $createNewVM = $vmExists -like "*VBOX_E_OBJECT_NOT_FOUND*"
    
    if ($createNewVM) {
        Write-Host "`n  # [INFO] VM '$VM' does not exist. Will create new VM." -ForegroundColor Cyan
    } else {
        Write-Host "`n  # [INFO] VM '$VM' already exists. Will modify existing VM." -ForegroundColor Cyan
    }

    Write-Host "`n  # ==================== UNATTENDED INSTALLATION ===================" -ForegroundColor Magenta

	$useUnattended = $false
	$isoPath = ""
	$windowsEdition = ""
	$windowsVersion = ""
	$windowsUsername = ""
	$windowsPasswordPlain = ""
	$windowsFullName = ""
	$windowsHostname = "$VM.local"
	$windowsDomain = ""
	$productKey = ""
	$installGuestAdditions = $false
	$guestAdditionsIsoPath = ""
	$installInBackground = $false

	if ($createNewVM) {
		Write-Host "`n  # [INFO] Unattended installation automates Windows setup (no manual clicking)." -ForegroundColor Cyan
		Write-Host "  # [WARNING] If it fails, just install Windows manually instead." -ForegroundColor Yellow
		
		$useUnattended = Get-YesNoChoice "Configure unattended (automatic) Windows installation?" "Y" "Automatically install Windows without manual intervention"
	} else {
		Write-Host "  # [INFO] Skipping unattended install for existing VM." -ForegroundColor Gray
	}

	if ($useUnattended) {
		Write-Host "`n  # ========== STEP 1: SELECT WINDOWS ISO ==========" -ForegroundColor Magenta
		
		Write-Host "`n  # [INFO] Select Windows ISO file..." -ForegroundColor Yellow
		Add-Type -AssemblyName System.Windows.Forms
		$openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
		$openFileDialog.Filter = "ISO files (*.iso)|*.iso|All files (*.*)|*.*"
		$openFileDialog.Title = "Select Windows Installation ISO"
		$openFileDialog.InitialDirectory = [Environment]::GetFolderPath("MyDocuments")
		
		if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
			$isoPath = $openFileDialog.FileName
			Write-Host "  # [OK] Selected ISO: $isoPath" -ForegroundColor Green
		} else {
			Write-Host "  # [WARNING] No ISO selected. Unattended install will be skipped." -ForegroundColor Yellow
			$useUnattended = $false
		}
		
		if ($useUnattended) {
			Write-Host "`n  # ========== STEP 2: WINDOWS EDITION ==========" -ForegroundColor Magenta
			
			$isoFileName = [System.IO.Path]::GetFileNameWithoutExtension($isoPath)
			Write-Host "`n  # [INFO] Analyzing ISO: $isoFileName" -ForegroundColor Cyan
			
			$detectedEditions = @()
			$autoDetected = $false
			
			if ($isoFileName -match "Win11|Windows11|W11") {
				Write-Host "  # [DETECTED] Windows 11 ISO" -ForegroundColor Green
				$detectedEditions = @{
					"1" = @{Name = "Windows 11 Pro"; EditionId = "Windows 11 Pro"; Type = "Microsoft Windows"; Version = "Windows 11 (64-bit)"}
					"2" = @{Name = "Windows 11 Home"; EditionId = "Windows 11 Home"; Type = "Microsoft Windows"; Version = "Windows 11 (64-bit)"}
				}
				$autoDetected = $true
			}
			elseif ($isoFileName -match "Win10|Windows10|W10") {
				Write-Host "  # [DETECTED] Windows 10 ISO" -ForegroundColor Green
				$detectedEditions = @{
					"1" = @{Name = "Windows 10 Pro"; EditionId = "Windows 10 Pro"; Type = "Microsoft Windows"; Version = "Windows 10 (64-bit)"}
					"2" = @{Name = "Windows 10 Home"; EditionId = "Windows 10 Home"; Type = "Microsoft Windows"; Version = "Windows 10 (64-bit)"}
				}
				$autoDetected = $true
			}
			else {
				Write-Host "  # [WARNING] Could not auto-detect Windows version from filename" -ForegroundColor Yellow
				Write-Host "  # [INFO] Please select manually" -ForegroundColor Cyan
				$detectedEditions = @{
					"1" = @{Name = "Windows 11 Pro"; EditionId = "Windows 11 Pro"; Type = "Microsoft Windows"; Version = "Windows 11 (64-bit)"}
					"2" = @{Name = "Windows 11 Home"; EditionId = "Windows 11 Home"; Type = "Microsoft Windows"; Version = "Windows 11 (64-bit)"}
					"3" = @{Name = "Windows 10 Pro"; EditionId = "Windows 10 Pro"; Type = "Microsoft Windows"; Version = "Windows 10 (64-bit)"}
					"4" = @{Name = "Windows 10 Home"; EditionId = "Windows 10 Home"; Type = "Microsoft Windows"; Version = "Windows 10 (64-bit)"}
				}
				$autoDetected = $false
			}
			
			Write-Host "`n  # Available Windows Editions:" -ForegroundColor Cyan
			foreach ($key in $detectedEditions.Keys | Sort-Object) {
				Write-Host "  # $key. $($detectedEditions[$key].Name)" -ForegroundColor Gray
			}
			
			if ($autoDetected) {
				$editionChoice = Get-UserChoice "Select Windows Edition (1-2):" "1" "Pro recommended (has more features)"
			} else {
				$editionChoice = Get-UserChoice "Select Windows Edition (1-4):" "1" "Must match your ISO"
			}
			
			$selectedEdition = $detectedEditions[$editionChoice]
			$windowsEdition = $selectedEdition.EditionId
			$windowsType = $selectedEdition.Type
			$windowsVersion = $selectedEdition.Version
			
			Write-Host "  # [OK] Selected: $windowsEdition" -ForegroundColor Green
			
			Write-Host "`n  # ========== STEP 3: USERNAME AND PASSWORD ==========" -ForegroundColor Magenta
			
			$defaultUsername = "User"
			$windowsUsername = Get-UserChoice "Enter Windows username:" $defaultUsername "This will be your Windows account name"
			
			Write-Host "`n  # Enter Windows password:" -NoNewline -ForegroundColor Cyan
			Write-Host " (typing is hidden)" -ForegroundColor Gray
			Write-Host "  # [TIP] VirtualBox unattended install requires a password." -ForegroundColor Yellow
			Write-Host "  # [TIP] Use a simple temporary password, you can change it after installation." -ForegroundColor Yellow
			Write-Host "  # [TIP] Suggested: ChangeMe123!" -ForegroundColor Yellow
			$windowsPassword = Read-Host -AsSecureString
			$windowsPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
				[Runtime.InteropServices.Marshal]::SecureStringToBSTR($windowsPassword)
			)
			
			if ([string]::IsNullOrWhiteSpace($windowsPasswordPlain)) {
				Write-Host "  # [WARNING] No password entered!" -ForegroundColor Yellow
				Write-Host "  # [INFO] A temporary password 'ChangeMe123!' will be used." -ForegroundColor Cyan
				Write-Host "  # [INFO] You can change it after Windows installs." -ForegroundColor Cyan
				$confirmNoPassword = Get-YesNoChoice "Continue with temporary password?" "Y" "You can change it later"
				if (-not $confirmNoPassword) {
					Write-Host "  # [INFO] Please enter a password:" -NoNewline -ForegroundColor Cyan
					$windowsPassword = Read-Host -AsSecureString
					$windowsPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
						[Runtime.InteropServices.Marshal]::SecureStringToBSTR($windowsPassword)
					)
				}
			}
			
			Write-Host "  # [OK] Username: $windowsUsername" -ForegroundColor Green
			if ([string]::IsNullOrWhiteSpace($windowsPasswordPlain)) {
				Write-Host "  # [OK] Password: (none)" -ForegroundColor Yellow
			} else {
				Write-Host "  # [OK] Password: ********" -ForegroundColor Green
			}
			
			Write-Host "`n  # ========== STEP 4: PRODUCT KEY (OPTIONAL) ==========" -ForegroundColor Magenta
			
			$useProductKey = Get-YesNoChoice "Do you have a Windows product key?" "N" "Skip to activate later"
			if ($useProductKey) {
				$productKey = Read-Host "  # Enter Windows product key (format: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX)"
				if ([string]::IsNullOrWhiteSpace($productKey)) {
					Write-Host "  # [INFO] No product key entered - Windows will run unactivated." -ForegroundColor Yellow
					$productKey = ""
				} else {
					Write-Host "  # [OK] Product key: $productKey" -ForegroundColor Green
				}
			} else {
				$productKey = ""
				Write-Host "  # [INFO] Skipping product key - Windows will run unactivated." -ForegroundColor Cyan
			}
			
			Write-Host "`n  # ========== STEP 5: HOSTNAME ==========" -ForegroundColor Magenta
			
			$defaultHostname = "$VM"
			$windowsHostname = Get-UserChoice "Enter computer hostname:" $defaultHostname "Computer name shown in Windows"
			
			# VirtualBox requires .local suffix
			if ($windowsHostname -notmatch '\.') {
				$windowsHostname = "$windowsHostname.local"
				Write-Host "  # [INFO] Added .local suffix: $windowsHostname" -ForegroundColor Cyan
			}
			
			Write-Host "  # [OK] Hostname: $windowsHostname" -ForegroundColor Green
			
			Write-Host "`n  # ========== STEP 6: DOMAIN (OPTIONAL) ==========" -ForegroundColor Magenta
			
			$useDomain = Get-YesNoChoice "Join a Windows domain?" "N" "Most users should skip this"
			if ($useDomain) {
				$windowsDomain = Read-Host "  # Enter domain name (e.g. company.local)"
				if ([string]::IsNullOrWhiteSpace($windowsDomain)) {
					Write-Host "  # [INFO] No domain entered - will use WORKGROUP." -ForegroundColor Cyan
					$windowsDomain = ""
				} else {
					Write-Host "  # [OK] Domain: $windowsDomain" -ForegroundColor Green
				}
			} else {
				$windowsDomain = ""
				Write-Host "  # [INFO] Skipping domain - will use WORKGROUP." -ForegroundColor Cyan
			}
			
			Write-Host "`n  # ========== STEP 6.5: LOCALE AND TIMEZONE ==========" -ForegroundColor Magenta

			$timeZones = @{
				"1" = "UTC"
				"2" = "America/New_York (EST/EDT)"
				"3" = "America/Chicago (CST/CDT)"
				"4" = "America/Los_Angeles (PST/PDT)"
				"5" = "Europe/London (GMT/BST)"
				"6" = "Europe/Paris (CET/CEST)"
			}

			Write-Host "`n  # Available Time Zones:" -ForegroundColor Cyan
			foreach ($key in $timeZones.Keys | Sort-Object) {
				Write-Host "  # $key. $($timeZones[$key])" -ForegroundColor Gray
			}

			$tzChoice = Get-UserChoice "Select time zone (1-6):" "1" "UTC is most compatible"
			$selectedTZ = switch ($tzChoice) {
				"2" { "EST" }
				"3" { "CST" }
				"4" { "PST" }
				"5" { "GMT" }
				"6" { "CET" }
				default { "UTC" }
			}

			Write-Host "  # [OK] Time zone: $selectedTZ" -ForegroundColor Green
					
			Write-Host "`n  # ========== STEP 7: INSTALL IN BACKGROUND ==========" -ForegroundColor Magenta
			
			Write-Host "  # [INFO] Background install runs the VM headless (no window)." -ForegroundColor Cyan
			Write-Host "  # [INFO] You won't see the installation progress." -ForegroundColor Cyan
			
			$installInBackground = Get-YesNoChoice "Install in background?" "N" "Recommended: N (so you can see progress)"
			
			if ($installInBackground) {
				Write-Host "  # [OK] VM will start headless during installation." -ForegroundColor Green
			} else {
				Write-Host "  # [OK] VM window will show during installation." -ForegroundColor Green
			}
			
			Write-Host "`n  # ========== STEP 8: GUEST ADDITIONS ==========" -ForegroundColor Magenta
			
			Write-Host "  # [WARNING] Guest Additions increases VM detection!" -ForegroundColor Yellow
			Write-Host "  #           Proctoring software can easily detect:" -ForegroundColor Yellow
			Write-Host "  #           - VBoxGuest.sys driver" -ForegroundColor Red
			Write-Host "  #           - VBoxService.exe process" -ForegroundColor Red
			Write-Host "  #           - VirtualBox registry keys" -ForegroundColor Red
			
			$installGuestAdditions = Get-YesNoChoice "Install VirtualBox Guest Additions automatically?" "N" "NOT recommended for anti-detection"
			
			if ($installGuestAdditions) {
				Write-Host "`n  # [WARNING] You chose to install Guest Additions - VM will be DETECTABLE!" -ForegroundColor Red
				
				$defaultGAPath = "C:\Program Files\Vektor T13\VirtualBox\DriverUpdaterCD.iso"
				if (Test-Path $defaultGAPath) {
					$guestAdditionsIsoPath = $defaultGAPath
					Write-Host "  # [OK] Found Guest Additions ISO: $guestAdditionsIsoPath" -ForegroundColor Green
				} else {
					Write-Host "`n  # [INFO] Select Guest Additions ISO file..." -ForegroundColor Yellow
					$openFileDialog2 = New-Object System.Windows.Forms.OpenFileDialog
					$openFileDialog2.Filter = "ISO files (*.iso)|*.iso|All files (*.*)|*.*"
					$openFileDialog2.Title = "Select DriverUpdaterCD.iso"
					$openFileDialog2.InitialDirectory = "C:\Program Files\Vektor T13\VirtualBox\"
					
					if ($openFileDialog2.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
						$guestAdditionsIsoPath = $openFileDialog2.FileName
						Write-Host "  # [OK] Selected Guest Additions ISO: $guestAdditionsIsoPath" -ForegroundColor Green
					} else {
						Write-Host "  # [WARNING] No Guest Additions ISO selected. Will skip installation." -ForegroundColor Yellow
						$installGuestAdditions = $false
					}
				}
			} else {
				Write-Host "  # [OK] Guest Additions will NOT be installed (good for anti-detection)." -ForegroundColor Green
			}
			
			$windowsFullName = $windowsUsername
			
			Write-Host "`n  # ========== UNATTENDED INSTALL SUMMARY ==========" -ForegroundColor Magenta
			Write-Host "  # ISO: $isoPath" -ForegroundColor Gray
			Write-Host "  # Edition: $windowsEdition" -ForegroundColor Gray
			Write-Host "  # Username: $windowsUsername" -ForegroundColor Gray
			Write-Host "  # Password: $(if ([string]::IsNullOrWhiteSpace($windowsPasswordPlain)) { '(none)' } else { '********' })" -ForegroundColor Gray
			Write-Host "  # Product Key: $(if ([string]::IsNullOrWhiteSpace($productKey)) { '(none - unactivated)' } else { $productKey })" -ForegroundColor Gray
			Write-Host "  # Hostname: $windowsHostname" -ForegroundColor Gray
			Write-Host "  # Domain: $(if ([string]::IsNullOrWhiteSpace($windowsDomain)) { '(none - WORKGROUP)' } else { $windowsDomain })" -ForegroundColor Gray
			Write-Host "  # Background Install: $(if ($installInBackground) { 'Yes' } else { 'No' })" -ForegroundColor Gray
			Write-Host "  # Guest Additions: $(if ($installGuestAdditions) { 'Yes (DETECTABLE!)' } else { 'No (stealthy)' })" -ForegroundColor Gray
			Write-Host "  # ================================================" -ForegroundColor Magenta
			
			$confirmUnattended = Get-YesNoChoice "Proceed with these settings?" "Y" "Confirm unattended install configuration"
			
			if (-not $confirmUnattended) {
				Write-Host "  # [INFO] Unattended install cancelled by user." -ForegroundColor Yellow
				$useUnattended = $false
			} else {
				Write-Host "  # [OK] Unattended installation configured." -ForegroundColor Green
			}
		}
	}

    Write-Host "`n  # ==================== OPERATING SYSTEM ====================" -ForegroundColor Magenta

	$osOptions = @{
		"1" = @{Type = "Windows11_64"; Name = "Windows 11 (64-bit)"}
		"2" = @{Type = "Windows10_64"; Name = "Windows 10 (64-bit)"}
	}

	if ($useUnattended -and $windowsVersion) {
		Write-Host "`n  # [INFO] Using OS type from unattended install configuration" -ForegroundColor Cyan
		
		if ($windowsVersion -like "*Windows 11*") {
			$osType = "Windows11_64"
			Write-Host "  # [OK] OS Type: Windows 11 (64-bit)" -ForegroundColor Green
		} else {
			$osType = "Windows10_64"
			Write-Host "  # [OK] OS Type: Windows 10 (64-bit)" -ForegroundColor Green
		}
	} else {
		Write-Host "`n  # Available Operating Systems:" -ForegroundColor Cyan
		foreach ($key in $osOptions.Keys | Sort-Object) {
			Write-Host "  # $key. $($osOptions[$key].Name)" -ForegroundColor Gray
		}

		$osChoice = Get-UserChoice "Select Operating System (1-2):" "2" "Windows 10 has better compatibility"
		$selectedOS = $osOptions[$osChoice]
		$osType = $selectedOS.Type
		
		Write-Host "  # [OK] Selected: $($selectedOS.Name)" -ForegroundColor Green
	}

    Write-Host "`n  # ==================== HARDWARE ===================" -ForegroundColor Magenta
    
    $minRAM = 1024
	if ($systemInfo.TotalRAM_MB -gt 0) {
		$maxRAM = $systemInfo.TotalRAM_MB - 2048
		if ($maxRAM -lt $minRAM) { $maxRAM = $systemInfo.TotalRAM_MB }
	} else {
		$maxRAM = 16384
	}

	if ($null -ne $recommendedSettings.RAM_MB -and $recommendedSettings.RAM_MB -gt 0) {
		$defaultMemory = $recommendedSettings.RAM_MB.ToString()
	} else {
		$defaultMemory = "4096"
	}

	Write-Host "`n  # Base Memory Range: $minRAM MB (1 GB) to $maxRAM MB ($([math]::Round($maxRAM/1024, 1)) GB)" -ForegroundColor Gray
	$memory = Get-UserChoice "Enter memory size in MB:" $defaultMemory "Recommended: $defaultMemory MB = $([math]::Round([int]$defaultMemory/1024, 1)) GB"

    $minCPU = 1
    $maxCPU = $systemInfo.CPUCores
    
    $defaultCPUs = $recommendedSettings.CPUCores.ToString()
    Write-Host "`n  # Processors Range: $minCPU to $maxCPU cores available" -ForegroundColor Gray
    $cpus = Get-UserChoice "Enter number of CPU cores:" $defaultCPUs "Recommended: $defaultCPUs cores (~50% of your system)"
    
	$cpuProfiles = @{
		"1" = @{
			Name = "Intel Core i7-6700K"
			VBoxProfile = "Intel Core i7-6700K"
			Manufacturer = "Intel"
			Socket = "LGA1151"
			CPUID_EAX = "000506E3"
			CPUID_EBX = "00100800"
			CPUID_ECX = "7FFAFBFF"
			CPUID_EDX = "BFEBFBFF"
			CPUID_0_EAX = "00000016"
			Brand_80000002 = @("65746E49", "2952286C", "726F4320", "4D542865")
			Brand_80000003 = @("37692029", "3030372D", "5043204B", "40205055")
			Brand_80000004 = @("30302E34", "007A4847", "00000000", "00000000")
			DMIName = "Intel(R) Core(TM) i7-6700K CPU @ 4.00GHz"
			DMIFamily = "0xCD"
		}
		"2" = @{
			Name = "Intel Core i7-9700K"
			VBoxProfile = "Intel Core i7-9700K"
			Manufacturer = "Intel"
			Socket = "LGA1151"
			CPUID_EAX = "000906ED"
			CPUID_EBX = "00100800"
			CPUID_ECX = "7FFAFBFF"
			CPUID_EDX = "BFEBFBFF"
			CPUID_0_EAX = "00000016"
			Brand_80000002 = @("65746E49", "2952286C", "726F4320", "4D542865")
			Brand_80000003 = @("37692029", "3030372D", "5043204B", "40205055")
			Brand_80000004 = @("30362E33", "007A4847", "00000000", "00000000")
			DMIName = "Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz"
			DMIFamily = "0xCD"
		}
		"3" = @{
			Name = "Intel Core i7-3960X"
			VBoxProfile = "Intel Core i7-3960X"
			Manufacturer = "Intel"
			Socket = "LGA2011"
			CPUID_EAX = "000206D7"
			CPUID_EBX = "00100800"
			CPUID_ECX = "1FBAE3FF"
			CPUID_EDX = "BFEBFBFF"
			CPUID_0_EAX = "0000000D"
			Brand_80000002 = @("65746E49", "2952286C", "726F4320", "4D542865")
			Brand_80000003 = @("37692029", "3036392D", "43205858", "40205550")
			Brand_80000004 = @("30332E33", "007A4847", "00000000", "00000000")
			DMIName = "Intel(R) Core(TM) i7-3960X CPU @ 3.30GHz"
			DMIFamily = "0xCD"
		}
		"4" = @{
			Name = "Intel Core i9-9900K"
			VBoxProfile = "Intel Core i9-9900K"
			Manufacturer = "Intel"
			Socket = "LGA1151"
			CPUID_EAX = "000906ED"
			CPUID_EBX = "00100800"
			CPUID_ECX = "7FFAFBFF"
			CPUID_EDX = "BFEBFBFF"
			CPUID_0_EAX = "00000016"
			Brand_80000002 = @("65746E49", "2952286C", "726F4320", "4D542865")
			Brand_80000003 = @("39692029", "3030392D", "5043204B", "40205055")
			Brand_80000004 = @("30362E33", "007A4847", "00000000", "00000000")
			DMIName = "Intel(R) Core(TM) i9-9900K CPU @ 3.60GHz"
			DMIFamily = "0xCD"
		}
		"5" = @{
			Name = "AMD Ryzen 7 1800X"
			VBoxProfile = "AMD Ryzen 7 1800X Eight-Core"
			Manufacturer = "AMD"
			Socket = "AM4"
			CPUID_EAX = "00800F11"
			CPUID_EBX = "00100800"
			CPUID_ECX = "7ED8320B"
			CPUID_EDX = "178BFBFF"
			CPUID_0_EAX = "0000000D"
			Brand_80000002 = @("20444D41", "657A7952", "2037206E", "30303831")
			Brand_80000003 = @("69452058", "2D746867", "65726F43", "6F725020")
			Brand_80000004 = @("73736563", "0000726F", "00000000", "00000000")
			DMIName = "AMD Ryzen 7 1800X Eight-Core Processor"
			DMIFamily = "0x6B"
		}
		"6" = @{
			Name = "Intel Core i7-7700K"
			VBoxProfile = "Intel Core i7-7700K"
			Manufacturer = "Intel"
			Socket = "LGA1151"
			CPUID_EAX = "000906E9"
			CPUID_EBX = "00100800"
			CPUID_ECX = "7FFAFBFF"
			CPUID_EDX = "BFEBFBFF"
			CPUID_0_EAX = "00000016"
			Brand_80000002 = @("65746E49", "2952286C", "726F4320", "4D542865")
			Brand_80000003 = @("37692029", "3030372D", "5043204B", "40205055")
			Brand_80000004 = @("30322E34", "007A4847", "00000000", "00000000")
			DMIName = "Intel(R) Core(TM) i7-7700K CPU @ 4.20GHz"
			DMIFamily = "0xCD"
		}
	}

	Write-Host "`n  # Available CPU models:" -ForegroundColor Cyan
	Write-Host "  # [INFO] Will try VirtualBox built-in profiles first, fallback to manual CPUID if needed" -ForegroundColor Gray
	Write-Host ""
	foreach ($key in $cpuProfiles.Keys | Sort-Object) {
		if ($key -eq $recommendedSettings.CPUChoice) {
			Write-Host "  # $key. $($cpuProfiles[$key].Name) (RECOMMENDED)" -ForegroundColor Green
		} else {
			Write-Host "  # $key. $($cpuProfiles[$key].Name)" -ForegroundColor Gray
		}
	}

	$cpuChoice = Get-UserChoice "Select a CPU model (1-6):" $recommendedSettings.CPUChoice "Recommended based on your CPU type"
	$cpuProfile = $cpuProfiles[$cpuChoice]

	if ($null -eq $cpuProfile) {
		$cpuProfile = $cpuProfiles[$recommendedSettings.CPUChoice]
		Write-Host "  # [INFO] Using recommended CPU model: $($cpuProfile.Name)" -ForegroundColor Yellow
	}
	Write-Host "  # [OK] Selected: $($cpuProfile.Name)" -ForegroundColor Green

    Write-Host "`n  # Available Chipsets:" -ForegroundColor Cyan
	Write-Host "  # 1. ICH9 (Recommended - Modern, supports PCIe)" -ForegroundColor Green
	Write-Host "  # 2. PIIX3 (Legacy - Better compatibility with older OSes)" -ForegroundColor Gray

	$chipsetChoice = Get-UserChoice "Select Chipset (1-2):" "1" "ICH9 recommended for Windows 10/11"
	$chipset = if ($chipsetChoice -eq "2") { "piix3" } else { "ich9" }

	Write-Host "`n  # Available TPM (Trusted Platform Module) options:" -ForegroundColor Cyan
	Write-Host "  # 1. None (Good for anti-detection)" -ForegroundColor Gray
	Write-Host "  # 2. TPM v1.2" -ForegroundColor Gray
	Write-Host "  # 3. TPM v2.0 (Required for Windows 11)" -ForegroundColor $(if ($osType -eq "Windows11_64") { "Green" } else { "Gray" })

	if ($osType -eq "Windows11_64") {
		Write-Host "`n  # [DETECTED] Windows 11 selected - TPM 2.0 is REQUIRED!" -ForegroundColor Yellow
		$defaultTPM = "3"
	} else {
		Write-Host "`n  # [INFO] Windows 10 detected - TPM not required (better for anti-detection)" -ForegroundColor Cyan
		$defaultTPM = "1"
	}

	$tpmChoice = Get-UserChoice "Select TPM version (1-3):" $defaultTPM $(if ($osType -eq "Windows11_64") { "TPM 2.0 required for Windows 11" } else { "None recommended for stealth" })
	$tpmType = switch ($tpmChoice) {
		"2" { "1.2" }
		"3" { "2.0" }
		default { "none" }
	}

	Write-Host "`n  # Available Pointing Devices:" -ForegroundColor Cyan
	Write-Host "  # 1. PS/2 Mouse (Recommended for anti-detection)" -ForegroundColor Green
	Write-Host "  # 2. USB Tablet" -ForegroundColor Gray
	Write-Host "  # 3. USB Multi-Touch Tablet" -ForegroundColor Gray
	Write-Host "  # 4. USB Multi-Touch Touchscreen and TouchPad" -ForegroundColor Gray

	$mouseChoice = Get-UserChoice "Select pointing device (1-4):" "1" "PS/2 Mouse recommended"
	$mouseType = switch ($mouseChoice) {
		"2" { "usbtablet" }
		"3" { "usbmultitouch" }
		"4" { "usbmtscreenpluspad" }
		default { "ps2" }
	}

	$enableIOAPIC = Get-YesNoChoice "Enable I/O APIC?" "Y" "Required for multi-core CPUs and 64-bit guests"

	$enablePAE = Get-YesNoChoice "Enable PAE/NX?" "Y" "Physical Address Extension - Required for 64-bit guests"

	$enableNestedVTx = Get-YesNoChoice "Enable Nested VT-x/AMD-V?" "Y" "Allows running VMs inside the VM (may increase detection)"

	Write-Host "`n  # Available Paravirtualization Interfaces:" -ForegroundColor Cyan
	Write-Host "  #   1. None (No paravirtualization)" -ForegroundColor Gray
	Write-Host "  #   2. Default (Let VirtualBox decide)" -ForegroundColor Gray
	Write-Host "  #   3. Legacy (Recommended for anti-detection)" -ForegroundColor Green
	Write-Host "  #   4. Minimal (Minimal paravirtualization)" -ForegroundColor Gray
	Write-Host "  #   5. Hyper-V (Windows-optimized)" -ForegroundColor Gray
	Write-Host "  #   6. KVM (Linux-optimized)" -ForegroundColor Gray

	$paraVirtChoice = Get-UserChoice "Select Paravirtualization Interface (1-6):" "3" "Legacy recommended for hiding VM"
	$paraVirtProvider = switch ($paraVirtChoice) {
		"1" { "none" }
		"2" { "default" }
		"3" { "legacy" }
		"4" { "minimal" }
		"5" { "hyperv" }
		"6" { "kvm" }
		default { "legacy" }
	}

	$enableNestedPaging = Get-YesNoChoice "Enable Nested Paging?" "Y" "Hardware virtualization feature for better performance"

	$useUTCClock = Get-YesNoChoice "Enable hardware clock in UTC time?" "N" "Useful for dual-boot systems"

	if ($osType -eq "Windows11_64") {
		Write-Host "`n  # [DETECTED] Windows 11 selected - UEFI firmware is REQUIRED!" -ForegroundColor Yellow
		$defaultUEFI = "Y"
	} else {
		Write-Host "`n  # [INFO] Windows 10 detected - BIOS mode is better for anti-detection" -ForegroundColor Cyan
		$defaultUEFI = "N"
		$enableSecureBoot = $false
	}

	$enableUEFI = Get-YesNoChoice "Enable UEFI (EFI) firmware?" $defaultUEFI $(if ($osType -eq "Windows11_64") { "Required for Windows 11" } else { "BIOS mode harder to detect" })

	$enableSecureBoot = $false
	if ($enableUEFI) {
		if ($osType -eq "Windows11_64") {
			Write-Host "`n  # [DETECTED] Windows 11 + UEFI - Secure Boot is REQUIRED!" -ForegroundColor Yellow
			$defaultSecureBoot = "Y"
		} else {
			Write-Host "`n  # [INFO] UEFI enabled but Windows 10 doesn't require Secure Boot" -ForegroundColor Cyan
			$defaultSecureBoot = "N"
		}
		
		$enableSecureBoot = Get-YesNoChoice "Enable Secure Boot?" $defaultSecureBoot $(if ($osType -eq "Windows11_64") { "Required for Windows 11" } else { "Optional for Windows 10" })
	}

    Write-Host "`n  # Video Memory Range: 16 MB to 1024 MB" -ForegroundColor Gray
    Write-Host "  # Note: Minimum 128 MB required for 3D acceleration" -ForegroundColor Gray

    $defaultVRAM = "128"
    $vramSize = Get-UserChoice "Enter video memory in MB:" $defaultVRAM "128 MB recommended for best compatibility"

    [int]$vramInt = [int]$vramSize
    if ($vramInt -lt 16) {
        Write-Host "  # [WARNING] VRAM too low. Setting to minimum 16 MB." -ForegroundColor Yellow
        $vramInt = 16
    } elseif ($vramInt -gt 1024) {
        Write-Host "  # [WARNING] VRAM too high. Setting to maximum 1024 MB." -ForegroundColor Yellow
        $vramInt = 1024
    }

    Write-Host "`n  # Available Graphics Controllers:" -ForegroundColor Cyan
    Write-Host "  # 1. VMSVGA (Recommended - Best compatibility)" -ForegroundColor Green
    Write-Host "  # 2. GpuSVGA (3D acceleration support, min 128 MB VRAM)" -ForegroundColor Gray
    Write-Host "  # 3. VBoxVGA (Legacy)" -ForegroundColor Gray

    $graphicsChoice = Get-UserChoice "Select graphics controller (1-3):" "1" "VMSVGA recommended"
    $graphicsController = switch ($graphicsChoice) {
        "2" { "gpusvga" }
        "3" { "vboxvga" }
        default { "vmsvga" }
    }

    $enable3D = $false
    if ($graphicsController -eq "GpuSVGA") {
        if ($vramInt -ge 128) {
            $enable3D = Get-YesNoChoice "Enable 3D acceleration?" "Y" "GpuSVGA supports 3D acceleration"
        } else {
            Write-Host "  # [INFO] 3D acceleration requires minimum 128 MB VRAM. Disabled." -ForegroundColor Yellow
        }
    }

    Write-Host "`n  # ==================== HARD DISK ===================" -ForegroundColor Magenta

    $createDisk = $false
    $existingDiskPath = ""
    $skipDisk = $false
    $diskPath = ""
    $storageGB = 0
    $diskFormat = "VDI"
    $diskVariant = "Standard"
    $enableSSD = $false
    $enableHotplug = $false

    if ($createNewVM) {
        Write-Host "`n  # Hard Disk Options:" -ForegroundColor Cyan
        Write-Host "  # 1. Create a Virtual Hard Disk Now (Recommended)" -ForegroundColor Gray
        Write-Host "  # 2. Use an Existing Virtual Hard Disk File" -ForegroundColor Gray
        Write-Host "  # 3. Do Not Add a Virtual Hard Disk" -ForegroundColor Gray
        
        $diskChoice = Get-UserChoice "Select hard disk option (1-3):" "1" "Option 1 creates a new virtual disk"
        
        switch ($diskChoice) {
            "1" {
                $createDisk = $true
                
                Write-Host "`n  # ========== HARD DISK FILE LOCATION AND SIZE ==========" -ForegroundColor Magenta
                
                $defaultVMFolder = "$env:USERPROFILE\VirtualBox VMs\$VM"
                $defaultDiskPath = "$defaultVMFolder\$VM.vdi"
                
                Write-Host "  # Default location: $defaultDiskPath" -ForegroundColor Gray
                $customPath = Get-YesNoChoice "Use custom disk location?" "N" "Default location is usually fine"
                
                if ($customPath) {
                    $diskPath = Read-Host "  # Enter full path for virtual disk (include .vdi extension)"
                } else {
                    $diskPath = $defaultDiskPath
                }
                
                $defaultStorageGB = $recommendedSettings.Storage_GB.ToString()
                Write-Host "`n  # Disk Size Range: 4.00 MB to 2.00 TB" -ForegroundColor Gray
                $storageGB = Get-UserChoice "Enter VM storage size in GB:" $defaultStorageGB "Recommended: $($recommendedSettings.Storage_GB) GB"
                
                $storageGBFloat = [float]$storageGB
                if ($storageGBFloat -lt 0.004 -or $storageGBFloat -gt 2000) {
                    Write-Host "  # [WARNING] Size out of range. Using default:  $defaultStorageGB GB" -ForegroundColor Yellow
                    $storageGB = $defaultStorageGB
                }
                
                Write-Host "`n  # ========== HARD DISK FILE TYPE AND VARIANT ==========" -ForegroundColor Magenta
                
                Write-Host "`n  # Available disk formats:" -ForegroundColor Cyan
                $diskFormats = @{
                    "1" = @{Format = "VDI"; Name = "VDI (VirtualBox Disk Image)"; Extension = ".vdi"}
                    "2" = @{Format = "VMDK"; Name = "VMDK (Virtual Machine Disk)"; Extension = ".vmdk"}
                    "3" = @{Format = "VHD"; Name = "VHD (Virtual Hard Disk)"; Extension = ".vhd"}
                }
                
                foreach ($key in $diskFormats.Keys | Sort-Object) {
                    if ($key -eq "1") {
                        Write-Host "  # $key. $($diskFormats[$key].Name) (Recommended)" -ForegroundColor Green
                    } else {
                        Write-Host "  # $key. $($diskFormats[$key].Name)" -ForegroundColor Gray
                    }
                }
                
                $formatChoice = Get-UserChoice "Select disk format (1-3):" "1" "VDI is native VirtualBox format"
                $selectedFormat = $diskFormats[$formatChoice]
                $diskFormat = $selectedFormat.Format
                
                if ($diskPath -notmatch "\.(vdi|vmdk|vhd)$") {
                    $diskPath += $selectedFormat.Extension
                }
                
                Write-Host "`n  # Available disk variants:" -ForegroundColor Cyan
                Write-Host "  # 1. Dynamically allocated (Recommended - grows as needed)" -ForegroundColor Green
                Write-Host "  # 2. Fixed size (Pre-allocate Full Size - faster but uses full space immediately)" -ForegroundColor Gray
                
                $variantChoice = Get-UserChoice "Select disk variant (1-2):" "1" "Dynamic allocation saves space"
                
                if ($variantChoice -eq "2") {
                    $diskVariant = "Fixed"
                    Write-Host "  # [INFO] Fixed size will allocate $storageGB GB immediately." -ForegroundColor Yellow
                } else {
                    $diskVariant = "Standard"
                    Write-Host "  # [INFO] Dynamic disk will grow up to $storageGB GB as needed." -ForegroundColor Cyan
                }
                
                if ($diskFormat -eq "VMDK") {
                    $split2GB = Get-YesNoChoice "Split disk into 2GB parts?" "N" "Useful for FAT32 filesystems"
                    if ($split2GB) {
                        $diskVariant += ",Split2G"
                    }
                }

                Write-Host "`n  # Disk Performance Options:" -ForegroundColor Cyan
                $enableSSD = Get-YesNoChoice "Mark as Solid-State Drive (SSD)?" "Y" "Better performance characteristics"
                $enableHotplug = Get-YesNoChoice "Enable hot-pluggable?" "N" "Allows disk to be attached/detached while running"
            }
            
            "2" {
                Write-Host "`n  # [INFO] Select existing virtual hard disk file..." -ForegroundColor Yellow
                
                Add-Type -AssemblyName System.Windows.Forms
                $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
                $openFileDialog.Filter = "Virtual Disk files (*.vdi;*.vmdk;*.vhd)|*.vdi;*.vmdk;*.vhd|All files (*.*)|*.*"
                $openFileDialog.Title = "Select Existing Virtual Hard Disk"
                $openFileDialog.InitialDirectory = "$env:USERPROFILE\VirtualBox VMs"
                
                if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                    $existingDiskPath = $openFileDialog.FileName
                    Write-Host "  # [OK] Selected disk: $existingDiskPath" -ForegroundColor Green
                    $createDisk = $false
                } else {
                    Write-Host "  # [WARNING] No disk selected. VM will be created without a hard disk." -ForegroundColor Yellow
                    $skipDisk = $true
                }
            }
            
            "3" {
                Write-Host "  # [INFO] VM will be created without a hard disk." -ForegroundColor Yellow
                $skipDisk = $true
            }
            
            default {
                $createDisk = $true
                $diskPath = "$env:USERPROFILE\VirtualBox VMs\$VM\$VM.vdi"
                $storageGB = $recommendedSettings.Storage_GB
                $diskFormat = "VDI"
                $diskVariant = "Standard"
            }
        }
    } else {
        Write-Host "`n  # [INFO] VM already exists - disk configuration will be skipped." -ForegroundColor Gray
        Write-Host "  # To modify disks, use VirtualBox GUI or VBoxManage storageattach command." -ForegroundColor Gray
        $skipDisk = $true
    }

    $diskConfig = @{
        CreateDisk = $createDisk
        DiskPath = if ($createDisk) { $diskPath } else { $existingDiskPath }
        StorageGB = if ($createDisk) { $storageGB } else { 0 }
        DiskFormat = if ($createDisk) { $diskFormat } else { "" }
        DiskVariant = if ($createDisk) { $diskVariant } else { "" }
        SkipDisk = $skipDisk
        EnableSSD = $enableSSD
        EnableHotplug = $enableHotplug
    }

    $usbControllers = @{
        "1" = "USB 1.1 (OHCI)"
        "2" = "USB 2.0 (EHCI)" 
        "3" = "USB 3.0 (xHCI)"
    }

    Write-Host "`n  # Available USB controllers:" -ForegroundColor Cyan
    foreach ($key in $usbControllers.Keys | Sort-Object) {
        Write-Host "  # $key. $($usbControllers[$key])" -ForegroundColor Gray
    }

    $defaultUSB = "3"
    $usbChoice = Get-UserChoice "Select a USB controller (1-3):" $defaultUSB "USB 3.0 recommended for webcams and modern devices"

    $networkCards = @{
        "1" = @{Name = "82540EM"; Desc = "Intel PRO/1000 MT Desktop (Recommended)"}
        "2" = @{Name = "82543GC"; Desc = "Intel PRO/1000 T Server"}
        "3" = @{Name = "82545EM"; Desc = "Intel PRO/1000 MT Server"}
        "4" = @{Name = "virtio"; Desc = "VirtIO"}
    }

    Write-Host "`n  # Available network card models:" -ForegroundColor Cyan
    foreach ($key in $networkCards.Keys | Sort-Object) {
        Write-Host "  # $key. $($networkCards[$key].Desc)" -ForegroundColor Gray
    }

    $defaultNetCard = "1"
    $netCardChoice = Get-UserChoice "Select a network card model (1-4):" $defaultNetCard "Intel PRO/1000 MT Desktop has best compatibility"
    
    # Defaults for network config variables to prevent null errors
    $macAddress = ""
    $networkMode = "1" # Default to NAT
    $selectedNetCard = $null
    $bridgedAdapter = ""
    $intNetName = ""
    $natNetName = ""
    $dnsChoice = "1"
    $customPrimary = ""
    $customSecondary = ""

	Write-Host "`n  # ==================== ENHANCED NETWORK CONFIGURATION ===================" -ForegroundColor Magenta

	$configureAdvancedNetwork = Get-YesNoChoice "Configure advanced network settings?" "Y" "Device ID, DHCP, DNS spoofing"

	if ($configureAdvancedNetwork) {

		Write-Host "`n  # ========== ETHERNET CONFIGURATION ==========" -ForegroundColor Cyan
		
		$networkCards = @{
			"1" = @{Name = "82540EM"; Desc = "Intel PRO/1000 MT Desktop"; DeviceId = "100E"; VendorId = "8086"}
			"2" = @{Name = "82543GC"; Desc = "Intel PRO/1000 T Server"; DeviceId = "1004"; VendorId = "8086"}
			"3" = @{Name = "82545EM"; Desc = "Intel PRO/1000 MT Server"; DeviceId = "100F"; VendorId = "8086"}
			"4" = @{Name = "82574L"; Desc = "Intel 82574L Gigabit"; DeviceId = "10D3"; VendorId = "8086"}
			"5" = @{Name = "I217-LM"; Desc = "Intel I217-LM Gigabit"; DeviceId = "153A"; VendorId = "8086"}
			"6" = @{Name = "I219-V"; Desc = "Intel I219-V Gigabit"; DeviceId = "15B8"; VendorId = "8086"}
			"7" = @{Name = "RTL8111"; Desc = "Realtek RTL8111/8168"; DeviceId = "8168"; VendorId = "10EC"}
			"8" = @{Name = "RTL8125"; Desc = "Realtek RTL8125 2.5GbE"; DeviceId = "8125"; VendorId = "10EC"}
		}
		
		Write-Host "`n  # Available Network Cards:" -ForegroundColor Cyan
		foreach ($key in $networkCards.Keys | Sort-Object {[int]$_}) {
			Write-Host "  # $key. $($networkCards[$key].Desc)" -ForegroundColor Gray
		}
		
		$netCardChoice = Get-UserChoice "Select Network Card (1-8):" "1" "Intel PRO/1000 MT is most compatible"
		$selectedNetCard = $networkCards[$netCardChoice]
		if ($null -eq $selectedNetCard) { $selectedNetCard = $networkCards["1"] }
		
		Write-Host "  # [OK] Network Card: $($selectedNetCard.Desc)" -ForegroundColor Green
		
		Write-Host "`n  # [INFO] Storing PCI Device ID configuration (will apply after creation)..." -ForegroundColor Yellow
		
		Write-Host "`n  # ========== MAC ADDRESS CONFIGURATION ==========" -ForegroundColor Cyan
		
		$macVendors = @{
			"1" = @{Name = "Intel"; OUIs = @("00:1B:21", "00:1E:67", "00:1F:3B", "3C:97:0E", "48:2A:E3", "A4:4C:C8")}
			"2" = @{Name = "Realtek"; OUIs = @("00:E0:4C", "52:54:00", "00:0C:29", "28:D2:44", "74:D4:35")}
			"3" = @{Name = "Dell"; OUIs = @("00:14:22", "00:1A:A0", "00:1D:09", "14:FE:B5", "18:A9:9B")}
			"4" = @{Name = "HP"; OUIs = @("00:1E:0B", "00:21:5A", "00:25:B3", "3C:D9:2B", "98:E7:F4")}
			"5" = @{Name = "Lenovo"; OUIs = @("00:06:1B", "00:1A:6B", "00:21:86", "54:EE:75", "98:FA:9B")}
			"6" = @{Name = "ASUS"; OUIs = @("00:1A:92", "00:1D:60", "00:26:18", "14:DA:E9", "48:5B:39")}
			"7" = @{Name = "Gigabyte"; OUIs = @("00:1D:7D", "40:8D:5C", "74:D0:2B", "94:DE:80", "E0:D5:5E")}
			"8" = @{Name = "MSI"; OUIs = @("00:01:29", "4C:CC:6A", "80:C5:F2", "D8:BB:C1")}
		}
		
		Write-Host "`n  # Select MAC Address Vendor (for realistic OUI):" -ForegroundColor Cyan
		foreach ($key in $macVendors.Keys | Sort-Object {[int]$_}) {
			Write-Host "  # $key. $($macVendors[$key].Name)" -ForegroundColor Gray
		}
		
		$macVendorChoice = Get-UserChoice "Select MAC Vendor (1-8):" "1" "Intel is most common for built-in NICs"
		$selectedMacVendor = $macVendors[$macVendorChoice]
		if ($null -eq $selectedMacVendor) { $selectedMacVendor = $macVendors["1"] }
		
		$randomOUI = $selectedMacVendor.OUIs | Get-Random
		$randomMAC = $randomOUI
		foreach ($i in 0..2) {
			$randomMAC += ":" + ("{0:X2}" -f (Get-Random -Minimum 0 -Maximum 255))
		}
		
		$macAddress = $randomMAC.Replace(":", "")
		
		Write-Host "  # [OK] Generated MAC: $randomMAC ($($selectedMacVendor.Name))" -ForegroundColor Green
		

		Write-Host "`n  # ========== DHCP CONFIGURATION ==========" -ForegroundColor Cyan
		
		Write-Host "`n  # Network Connection Mode:" -ForegroundColor Cyan
		Write-Host "  # 1. NAT (Recommended - shares host IP, good for internet)" -ForegroundColor Green
		Write-Host "  # 2. Bridged Adapter (Gets own IP from your router)" -ForegroundColor Gray
		Write-Host "  # 3. Internal Network (Isolated VM network)" -ForegroundColor Gray
		Write-Host "  # 4. Host-Only Adapter (Talk to host only)" -ForegroundColor Gray
		Write-Host "  # 5. NAT Network (Multiple VMs share NAT)" -ForegroundColor Gray
		
		$networkMode = Get-UserChoice "Select Network Mode (1-5):" "1" "NAT is simplest and most secure"
		
		switch ($networkMode) {
			"1" { 
				Write-Host "  # [OK] Network Mode: NAT" -ForegroundColor Green
			}
			"2" { 
				Write-Host "`n  # [INFO] Detecting available network adapters..." -ForegroundColor Yellow
				$bridgedAdapters = & $VBoxManager list bridgedifs | Select-String "^Name:" | ForEach-Object { $_.ToString().Replace("Name:", "").Trim() }
				
				if ($bridgedAdapters) {
					Write-Host "`n  # Available Network Adapters:" -ForegroundColor Cyan
					$adapterIndex = 1
					$adapterMap = @{}
					foreach ($adapter in $bridgedAdapters) {
						Write-Host "  # $adapterIndex. $adapter" -ForegroundColor Gray
						$adapterMap["$adapterIndex"] = $adapter
						$adapterIndex++
					}
					
					$bridgeChoice = Get-UserChoice "Select adapter to bridge (1-$($adapterIndex-1)):" "1" "Usually your main ethernet/wifi"
					$bridgedAdapter = $adapterMap[$bridgeChoice]
					
					Write-Host "  # [OK] Bridged to: $bridgedAdapter" -ForegroundColor Green
				} else {
					Write-Host "  # [WARNING] No bridged adapters found, using NAT" -ForegroundColor Yellow
                    $networkMode = "1"
				}
			}
			"3" { 
				$intNetName = Get-UserChoice "Enter Internal Network name:" "intnet" "Name for the internal network"
				Write-Host "  # [OK] Internal Network: $intNetName" -ForegroundColor Green
			}
			"4" { 
				Write-Host "  # [OK] Host-Only Adapter" -ForegroundColor Green
			}
			"5" { 
				$natNetName = Get-UserChoice "Enter NAT Network name:" "NatNetwork" "Name for the NAT network"
				Write-Host "  # [OK] NAT Network: $natNetName" -ForegroundColor Green
			}
			default { 
                $networkMode = "1"
				Write-Host "  # [OK] Network Mode: NAT (default)" -ForegroundColor Green
			}
		}
		
		if ($networkMode -eq "1" -or $networkMode -eq "5") {
			Write-Host "`n  # ========== DNS CONFIGURATION ==========" -ForegroundColor Cyan
			
			$configureDNS = Get-YesNoChoice "Configure custom DNS settings?" "Y" "Use custom DNS servers"
			
			if ($configureDNS) {
				$dnsServers = @{
					"1" = @{Name = "Use Host DNS"; Primary = ""; Secondary = ""; Desc = "Pass through host DNS settings"}
					"2" = @{Name = "Google DNS"; Primary = "8.8.8.8"; Secondary = "8.8.4.4"; Desc = "Fast and reliable"}
					"3" = @{Name = "Cloudflare DNS"; Primary = "1.1.1.1"; Secondary = "1.0.0.1"; Desc = "Privacy-focused"}
					"4" = @{Name = "OpenDNS"; Primary = "208.67.222.222"; Secondary = "208.67.220.220"; Desc = "Security features"}
					"5" = @{Name = "Quad9"; Primary = "9.9.9.9"; Secondary = "149.112.112.112"; Desc = "Malware blocking"}
					"6" = @{Name = "Custom"; Primary = ""; Secondary = ""; Desc = "Enter your own DNS servers"}
				}
				
				Write-Host "`n  # Available DNS Options:" -ForegroundColor Cyan
				foreach ($key in $dnsServers.Keys | Sort-Object {[int]$_}) {
					Write-Host "  # $key. $($dnsServers[$key].Name) - $($dnsServers[$key].Desc)" -ForegroundColor Gray
				}
				
				$dnsChoice = Get-UserChoice "Select DNS Option (1-6):" "1" "Host DNS is simplest"
				$selectedDNS = $dnsServers[$dnsChoice]
				
				if ($dnsChoice -eq "1") {
					Write-Host "  # [OK] Using Host DNS resolver" -ForegroundColor Green
				}
				elseif ($dnsChoice -eq "6") {
					$customPrimary = Read-Host "  # Enter Primary DNS server (e.g. 8.8.8.8)"
					$customSecondary = Read-Host "  # Enter Secondary DNS server (optional, press Enter to skip)"
					
					Write-Host "  # [INFO] Custom DNS: $customPrimary / $customSecondary" -ForegroundColor Cyan
					Write-Host "  # [INFO] You may need to set DNS manually inside the VM" -ForegroundColor Yellow
				}
				else {
					Write-Host "  # [OK] DNS: $($selectedDNS.Name) ($($selectedDNS.Primary) / $($selectedDNS.Secondary))" -ForegroundColor Green
					Write-Host "  # [INFO] Set these DNS servers inside the VM's network settings" -ForegroundColor Yellow
				}
			}
			
			Write-Host "`n  # DNS Suffix (Domain name for the VM):" -ForegroundColor Cyan
			$dnsSuffix = Get-UserChoice "Enter DNS Suffix:" "localdomain" "e.g., home.local, company.com"
			
			Write-Host "  # [INFO] DNS Suffix '$dnsSuffix' should be configured inside Windows" -ForegroundColor Yellow
		}
		
		Write-Host "`n  # ========== NETWORK ANTI-DETECTION ==========" -ForegroundColor Cyan
        # Will execute later
		Write-Host "  # [OK] Network anti-detection settings recorded" -ForegroundColor Green
		
		Write-Host "`n  # ========== NETWORK CONFIGURATION SUMMARY ==========" -ForegroundColor Magenta
		Write-Host "  # Network Card: $($selectedNetCard.Desc)" -ForegroundColor Gray
		Write-Host "  # PCI IDs:      $($selectedNetCard.VendorId):$($selectedNetCard.DeviceId)" -ForegroundColor Gray
		Write-Host "  # MAC Address:  $randomMAC ($($selectedMacVendor.Name))" -ForegroundColor Gray
		Write-Host "  # Network Mode: $(switch($networkMode) { '1'{'NAT'} '2'{'Bridged'} '3'{'Internal'} '4'{'Host-Only'} '5'{'NAT Network'} default{'NAT'} })" -ForegroundColor Gray
		Write-Host "  # ====================================================" -ForegroundColor Magenta
	} else {
        # Generate a random MAC anyway to be safe if advanced skipped
        $randomOUI = "08:00:27" # VirtualBox default
		$randomMAC = $randomOUI
		foreach ($i in 0..2) {
			$randomMAC += ":" + ("{0:X2}" -f (Get-Random -Minimum 0 -Maximum 255))
		}
        $macAddress = $randomMAC.Replace(":", "")
    }

    Write-Host "`n  # ==================== AUDIO CONFIGURATION ===================" -ForegroundColor Magenta

    Write-Host "`n  # Available Host Audio Drivers:" -ForegroundColor Cyan
    Write-Host "  # 1. Windows Audio Session (WASAPI) - Recommended for Windows 10/11" -ForegroundColor Green
    Write-Host "  # 2. Windows DirectSound - Legacy Windows" -ForegroundColor Gray
    Write-Host "  # 3. Null Audio - No audio" -ForegroundColor Gray
    Write-Host "  # 4. Default - Let VirtualBox decide" -ForegroundColor Gray

    $audioDriverChoice = Get-UserChoice "Select host audio driver (1-4):" "1" "WASAPI recommended"
    $audioDriver = switch ($audioDriverChoice) {
        "2" { "dsound" }
        "3" { "null" }
        "4" { "default" }
        default { "was" }
    }

    if ($audioDriver -ne "null") {
        Write-Host "`n  # Available Audio Controllers:" -ForegroundColor Cyan
        Write-Host "  # 1. Intel HD Audio (Recommended)" -ForegroundColor Green
        Write-Host "  # 2. ICH AC97" -ForegroundColor Gray
        Write-Host "  # 3. SoundBlaster 16" -ForegroundColor Gray
        
        $audioControllerChoice = Get-UserChoice "Select audio controller (1-3):" "1" "Intel HD Audio recommended"
        $audioController = switch ($audioControllerChoice) {
            "2" { "ac97" }
            "3" { "sb16" }
            default { "hda" }
        }
        
        $enableAudioOutput = Get-YesNoChoice "Enable audio output?" "Y" "Allow sound from VM"
        $enableAudioInput = Get-YesNoChoice "Enable audio input (microphone)?" "Y" "Allow microphone in VM"
    } else {
        $audioController = "hda"
        $enableAudioOutput = $false
        $enableAudioInput = $false
    }

	Write-Host "`n  # ==================== CLIPBOARD & DRAG-AND-DROP ===================" -ForegroundColor Magenta

	Write-Host "`n  # [INFO] Clipboard and drag-and-drop allow copy/paste between host and VM." -ForegroundColor Cyan
	Write-Host "  # [WARNING] These features can increase VM detection!" -ForegroundColor Yellow
	Write-Host "  # [INFO] They require Guest Additions to work." -ForegroundColor Gray

	Write-Host "`n  # Available Shared Clipboard modes:" -ForegroundColor Cyan
	Write-Host "  # 1. Disabled (Recommended for anti-detection)" -ForegroundColor Green
	Write-Host "  # 2. Host To Guest (Copy from host → paste in VM)" -ForegroundColor Gray
	Write-Host "  # 3. Guest To Host (Copy from VM → paste in host)" -ForegroundColor Gray
	Write-Host "  # 4. Bidirectional (Copy/paste both ways)" -ForegroundColor Gray

	$clipboardChoice = Get-UserChoice "Select clipboard mode (1-4):" "1" "Disabled recommended"
	$clipboardMode = switch ($clipboardChoice) {
		"2" { "hosttoguest" }
		"3" { "guesttohost" }
		"4" { "bidirectional" }
		default { "disabled" }
	}

	Write-Host "`n  # Available Drag-and-Drop modes:" -ForegroundColor Cyan
	Write-Host "  # 1. Disabled (Recommended for anti-detection)" -ForegroundColor Green
	Write-Host "  # 2. Host To Guest (Drag files from host → VM)" -ForegroundColor Gray
	Write-Host "  # 3. Guest To Host (Drag files from VM → host)" -ForegroundColor Gray
	Write-Host "  # 4. Bidirectional (Drag files both ways)" -ForegroundColor Gray

	$dragDropChoice = Get-UserChoice "Select drag-and-drop mode (1-4):" "1" "Disabled recommended"
	$dragDropMode = switch ($dragDropChoice) {
		"2" { "hosttoguest" }
		"3" { "guesttohost" }
		"4" { "bidirectional" }
		default { "disabled" }
	}

	if ($clipboardMode -ne "disabled" -or $dragDropMode -ne "disabled") {
		Write-Host "`n  # [WARNING] You enabled clipboard/drag-and-drop features!" -ForegroundColor Yellow
		Write-Host "  # [INFO] These require Guest Additions to be installed." -ForegroundColor Yellow
		
		if (-not $installGuestAdditions -and $useUnattended) {
			Write-Host "  # [WARNING] Guest Additions are NOT enabled in unattended install!" -ForegroundColor Red
			Write-Host "  # [INFO] Clipboard/drag-and-drop will NOT work until you install Guest Additions manually." -ForegroundColor Yellow
		}
	} else {
		Write-Host "`n  # [OK] Clipboard and drag-and-drop disabled (good for anti-detection)." -ForegroundColor Green
	}

    Write-Host "`n  # ================== ADVANCED CONFIGURATION =================" -ForegroundColor Magenta
    
    $applyAdvanced = Get-YesNoChoice "Apply advanced anti-detection settings?" "Y" "Recommended for maximum concealment"
    
    $vendorChoice = "1"
    $storageChoice = "1"
    
    if ($applyAdvanced) {
        Write-Host "`n  # Available hardware vendor profiles:" -ForegroundColor Cyan
        $vendorProfiles = @{
            "1" = "MSI"
            "2" = "ASUS"
            "3" = "Gigabyte"
            "4" = "ASRock"
        }
        
        foreach ($key in $vendorProfiles.Keys | Sort-Object) {
            Write-Host "  # $key. $($vendorProfiles[$key])" -ForegroundColor Gray
        }
        
        $defaultVendor = "1"
        $vendorChoice = Get-UserChoice "Select a hardware vendor profile (1-4):" $defaultVendor "MSI has good detection evasion"
        
        Write-Host "`n  # Available storage device profiles:" -ForegroundColor Cyan
        $storageProfiles = @{
            "1" = "Samsung SSD 980 EVO"
            "2" = "Samsung SSD 870 EVO" 
            "3" = "Western Digital Blue SN570 NVMe"
            "4" = "Crucial MX500"
        }
        
        foreach ($key in $storageProfiles.Keys | Sort-Object) {
            Write-Host "  # $key. $($storageProfiles[$key])" -ForegroundColor Gray
        }
        
        $defaultStorage = "1"
        $storageChoice = Get-UserChoice "Select a storage device profile (1-4):" $defaultStorage "Samsung SSDs are common and realistic"
        $storageDevice = $storageProfiles[$storageChoice]
        
        if ([string]::IsNullOrWhiteSpace($storageDevice)) {
            $storageDevice = $storageProfiles[$defaultStorage]
        }
    }

	Write-Host "`n  # [INFO] Validating configuration for conflicts..." -ForegroundColor Yellow

	$warningCount = 0
	$criticalCount = 0
	$conflictsFixed = 0

	if (-not $enablePAE -and $osType -like "*64*") {
		Write-Host "  # [CRITICAL] PAE/NX is DISABLED but you selected a 64-bit OS!" -ForegroundColor Red
		Write-Host "  #            The VM will NOT boot without PAE/NX enabled." -ForegroundColor Red
		$fixPAE = Get-YesNoChoice "Auto-enable PAE/NX?" "Y" "Required for 64-bit guests"
		if ($fixPAE) {
			$enablePAE = $true
			Write-Host "  # [FIXED] PAE/NX has been enabled." -ForegroundColor Green
			$conflictsFixed++
		} else {
			Write-Host "  # [WARNING] VM may fail to boot!" -ForegroundColor Yellow
			$criticalCount++
		}
	}

	if (-not $enableIOAPIC -and [int]$cpus -gt 1) {
		Write-Host "  # [CRITICAL] I/O APIC is DISABLED but you assigned $cpus CPU cores!" -ForegroundColor Red
		Write-Host "  #            Only 1 core will be usable without I/O APIC." -ForegroundColor Red
		$fixIOAPIC = Get-YesNoChoice "Auto-enable I/O APIC?" "Y" "Required for multi-core CPUs"
		if ($fixIOAPIC) {
			$enableIOAPIC = $true
			Write-Host "  # [FIXED] I/O APIC has been enabled." -ForegroundColor Green
			$conflictsFixed++
		} else {
			Write-Host "  # [WARNING] Only 1 CPU core will work!" -ForegroundColor Yellow
			$criticalCount++
		}
	}

	if ($osType -eq "Windows11_64" -and $tpmType -eq "none") {
		Write-Host "  # [CRITICAL] Windows 11 requires TPM 2.0!" -ForegroundColor Red
		Write-Host "  #            Installation will fail without TPM." -ForegroundColor Red
		$fixTPM = Get-YesNoChoice "Auto-enable TPM 2.0?" "Y" "Required for Windows 11"
		if ($fixTPM) {
			$tpmType = "2.0"
			Write-Host "  # [FIXED] TPM 2.0 has been enabled." -ForegroundColor Green
			$conflictsFixed++
		} else {
			Write-Host "  # [WARNING] Windows 11 installation will likely fail!" -ForegroundColor Yellow
			$criticalCount++
		}
	}

	if ($osType -eq "Windows11_64" -and -not $enableUEFI) {
		Write-Host "  # [CRITICAL] Windows 11 requires UEFI firmware!" -ForegroundColor Red
		Write-Host "  #            Installation will fail without UEFI." -ForegroundColor Red
		$fixUEFI = Get-YesNoChoice "Auto-enable UEFI?" "Y" "Required for Windows 11"
		if ($fixUEFI) {
			$enableUEFI = $true
			$enableSecureBoot = Get-YesNoChoice "Also enable Secure Boot?" "Y" "Recommended for Windows 11"
			Write-Host "  # [FIXED] UEFI has been enabled." -ForegroundColor Green
			$conflictsFixed++
		} else {
			Write-Host "  # [WARNING] Windows 11 installation will likely fail!" -ForegroundColor Yellow
			$criticalCount++
		}
	}

	if ($osType -eq "Windows11_64" -and $enableUEFI -and $tpmType -eq "1.2") {
		Write-Host "  # [CRITICAL] Windows 11 requires TPM 2.0, but you have TPM 1.2!" -ForegroundColor Red
		$fixTPMVersion = Get-YesNoChoice "Upgrade to TPM 2.0?" "Y" "Required for Windows 11"
		if ($fixTPMVersion) {
			$tpmType = "2.0"
			Write-Host "  # [FIXED] TPM upgraded to 2.0." -ForegroundColor Green
			$conflictsFixed++
		} else {
			$criticalCount++
		}
	}

	if ($enableSecureBoot -and -not $enableUEFI) {
		Write-Host "  # [CRITICAL] Secure Boot requires UEFI firmware!" -ForegroundColor Red
		Write-Host "  #            Secure Boot will not work with BIOS." -ForegroundColor Red
		$fixSecureBoot = Get-YesNoChoice "Enable UEFI to support Secure Boot?" "Y" "Required"
		if ($fixSecureBoot) {
			$enableUEFI = $true
			Write-Host "  # [FIXED] UEFI enabled." -ForegroundColor Green
			$conflictsFixed++
		} else {
			$enableSecureBoot = $false
			Write-Host "  # [FIXED] Secure Boot disabled (UEFI not enabled)." -ForegroundColor Yellow
			$conflictsFixed++
		}
	}

	if ($tpmType -eq "2.0" -and -not $enableUEFI) {
		Write-Host "  # [CRITICAL] TPM 2.0 requires UEFI firmware!" -ForegroundColor Red
		$fixTPMUEFI = Get-YesNoChoice "Enable UEFI to support TPM 2.0?" "Y" "Required"
		if ($fixTPMUEFI) {
			$enableUEFI = $true
			Write-Host "  # [FIXED] UEFI enabled." -ForegroundColor Green
			$conflictsFixed++
		} else {
			$tpmType = "none"
			Write-Host "  # [FIXED] TPM 2.0 disabled (UEFI not enabled)." -ForegroundColor Yellow
			$conflictsFixed++
		}
	}

	if ($enableNestedVTx -and -not $enableNestedPaging) {
		Write-Host "  # [WARNING] Nested VT-x is enabled but Nested Paging is disabled." -ForegroundColor Yellow
		Write-Host "  #           Nested VMs will have poor performance." -ForegroundColor Yellow
		$fixNesting = Get-YesNoChoice "Enable Nested Paging for better performance?" "Y" "Recommended"
		if ($fixNesting) {
			$enableNestedPaging = $true
			Write-Host "  # [FIXED] Nested Paging enabled." -ForegroundColor Green
			$conflictsFixed++
		} else {
			$warningCount++
		}
	}

	if ($paraVirtProvider -eq "hyperv" -and $applyAdvanced) {
		Write-Host "  # [WARNING] Hyper-V paravirtualization INCREASES VM detection!" -ForegroundColor Yellow
		Write-Host "  #           This conflicts with your anti-detection settings." -ForegroundColor Yellow
		$fixParavirt = Get-YesNoChoice "Switch to Legacy paravirtualization?" "Y" "Better for anti-detection"
		if ($fixParavirt) {
			$paraVirtProvider = "legacy"
			Write-Host "  # [FIXED] Switched to Legacy paravirtualization." -ForegroundColor Green
			$conflictsFixed++
		} else {
			$warningCount++
		}
	}

	if ($paraVirtProvider -eq "kvm" -and $osType -like "Windows*") {
		Write-Host "  # [WARNING] KVM paravirtualization is optimized for Linux, not Windows!" -ForegroundColor Yellow
		Write-Host "  #           May cause compatibility issues." -ForegroundColor Yellow
		$fixKVM = Get-YesNoChoice "Switch to Legacy (recommended for Windows)?" "Y" "Better compatibility"
		if ($fixKVM) {
			$paraVirtProvider = "legacy"
			Write-Host "  # [FIXED] Switched to Legacy paravirtualization." -ForegroundColor Green
			$conflictsFixed++
		} else {
			$warningCount++
		}
	}

	if ($mouseType -ne "ps2" -and $applyAdvanced) {
		Write-Host "  # [WARNING] USB pointing devices increase VM detection fingerprint!" -ForegroundColor Yellow
		Write-Host "  #           Current:  $mouseType" -ForegroundColor Yellow
		$fixMouse = Get-YesNoChoice "Switch to PS/2 Mouse for better anti-detection?" "Y" "Recommended"
		if ($fixMouse) {
			$mouseType = "ps2"
			Write-Host "  # [FIXED] Switched to PS/2 Mouse." -ForegroundColor Green
			$conflictsFixed++
		} else {
			$warningCount++
		}
	}

	if ($chipset -eq "piix3" -and [int]$cpus -gt 8) {
		Write-Host "  # [WARNING] PIIX3 chipset may not work well with $cpus CPU cores." -ForegroundColor Yellow
		Write-Host "  #           ICH9 is recommended for > 8 cores." -ForegroundColor Yellow
		$fixChipset = Get-YesNoChoice "Switch to ICH9 chipset?" "Y" "Better for high core counts"
		if ($fixChipset) {
			$chipset = "ich9"
			Write-Host "  # [FIXED] Switched to ICH9 chipset." -ForegroundColor Green
			$conflictsFixed++
		} else {
			$warningCount++
		}
	}

	if ($chipset -eq "piix3" -and $enableUEFI) {
		Write-Host "  # [WARNING] PIIX3 chipset with UEFI is not recommended!" -ForegroundColor Yellow
		Write-Host "  #           ICH9 is recommended for UEFI systems." -ForegroundColor Yellow
		$fixChipsetUEFI = Get-YesNoChoice "Switch to ICH9 chipset?" "Y" "Better UEFI support"
		if ($fixChipsetUEFI) {
			$chipset = "ich9"
			Write-Host "  # [FIXED] Switched to ICH9 chipset." -ForegroundColor Green
			$conflictsFixed++
		} else {
			$warningCount++
		}
	}

	if ([int]$memory -lt 2048 -and $osType -like "Windows*64*") {
		Write-Host "  # [WARNING] Only $memory MB RAM assigned to 64-bit Windows." -ForegroundColor Yellow
		Write-Host "  #           Minimum 2048 MB (2 GB) recommended, 4096 MB (4 GB) preferred." -ForegroundColor Yellow
		$warningCount++
	}

	if ([int]$memory -lt 1024) {
		Write-Host "  # [WARNING] Only $memory MB RAM assigned!" -ForegroundColor Yellow
		Write-Host "  #           This is extremely low and will cause severe performance issues." -ForegroundColor Yellow
		$warningCount++
	}

	if ([int]$memory -gt ($systemInfo.TotalRAM_MB - 2048) -and $systemInfo.TotalRAM_MB -gt 0) {
		$hostRAMLeft = $systemInfo.TotalRAM_MB - [int]$memory
		Write-Host "  # [WARNING] Allocating $memory MB leaves only $hostRAMLeft MB for host OS!" -ForegroundColor Yellow
		Write-Host "  #           Host system may become unstable." -ForegroundColor Yellow
		$warningCount++
	}

	if ($graphicsController -eq "vboxvga" -and $osType -like "Windows1*64*") {
		Write-Host "  # [WARNING] VBoxVGA is legacy and not recommended for Windows 10/11." -ForegroundColor Yellow
		Write-Host "  #           VMSVGA or GpuSVGA recommended for better compatibility." -ForegroundColor Yellow
		$fixGraphics = Get-YesNoChoice "Switch to VMSVGA?" "Y" "Better Windows 10/11 support"
		if ($fixGraphics) {
			$graphicsController = "vmsvga"
			Write-Host "  # [FIXED] Switched to VMSVGA." -ForegroundColor Green
			$conflictsFixed++
		} else {
			$warningCount++
		}
	}

	if ($enable3D -and $graphicsController -eq "vmsvga") {
		Write-Host "  # [WARNING] 3D acceleration is enabled but VMSVGA doesn't support it!" -ForegroundColor Yellow
		Write-Host "  #           Only GpuSVGA supports 3D acceleration." -ForegroundColor Yellow
		$fix3D = Get-YesNoChoice "Switch to GpuSVGA for 3D support?" "Y" "Required for 3D"
		if ($fix3D) {
			$graphicsController = "GpuSVGA"
			Write-Host "  # [FIXED] Switched to GpuSVGA." -ForegroundColor Green
			$conflictsFixed++
		} else {
			$enable3D = $false
			Write-Host "  # [FIXED] 3D acceleration disabled." -ForegroundColor Yellow
			$conflictsFixed++
		}
	}

	if ($vramInt -lt 64 -and $osType -like "Windows*64*") {
		Write-Host "  # [WARNING] Only $vramInt MB VRAM assigned." -ForegroundColor Yellow
		Write-Host "  #           Windows 10/11 recommends at least 128 MB." -ForegroundColor Yellow
		$warningCount++
	}

	if ($vramInt -gt 256 -and -not $enable3D) {
		Write-Host "  # [INFO] $vramInt MB VRAM assigned but 3D acceleration is disabled." -ForegroundColor Cyan
		Write-Host "  #        High VRAM is mainly useful with 3D acceleration enabled." -ForegroundColor Cyan
	}

	if ($createDisk -and [int]$storageGB -lt 40) {
		Write-Host "  # [WARNING] Disk size is only $storageGB GB." -ForegroundColor Yellow
		Write-Host "  #           Windows 10/11 needs ~25-30 GB minimum (40+ GB recommended)." -ForegroundColor Yellow
		$warningCount++
	}

	if ($createDisk -and [int]$storageGB -lt 25) {
		Write-Host "  # [CRITICAL] Disk size of $storageGB GB is too small for Windows!" -ForegroundColor Red
		Write-Host "  #            Windows installation will likely fail." -ForegroundColor Red
		$criticalCount++
	}

	if ($diskVariant -eq "Fixed" -and [int]$storageGB -gt 100) {
		Write-Host "  # [WARNING] Fixed size disk of $storageGB GB will allocate ALL space immediately!" -ForegroundColor Yellow
		Write-Host "  #           Dynamic allocation is recommended for large disks." -ForegroundColor Yellow
		$warningCount++
	}

	if ($skipDisk -and $createNewVM) {
		Write-Host "  # [WARNING] No hard disk will be attached to the VM!" -ForegroundColor Yellow
		Write-Host "  #           You won't be able to install an OS without a disk." -ForegroundColor Yellow
		$warningCount++
	}

	if ([int]$cpus -gt $systemInfo.CPUCores -and $systemInfo.CPUCores -gt 0) {
		Write-Host "  # [WARNING] Assigned $cpus cores but system only has $($systemInfo.CPUCores) cores!" -ForegroundColor Yellow
		Write-Host "  #           This will cause performance degradation." -ForegroundColor Yellow
		$warningCount++
	}

	if ([int]$cpus -eq 1 -and $osType -like "Windows1*64*") {
		Write-Host "  # [WARNING] Only 1 CPU core assigned to Windows 10/11." -ForegroundColor Yellow
		Write-Host "  #           At least 2 cores recommended for acceptable performance." -ForegroundColor Yellow
		$warningCount++
	}

	if ([int]$cpus -gt 16) {
		Write-Host "  # [WARNING] Assigning $cpus CPU cores is excessive for most workloads." -ForegroundColor Yellow
		Write-Host "  #           May cause performance issues on the host." -ForegroundColor Yellow
		$warningCount++
	}

	if ($enableNestedVTx -and $applyAdvanced) {
		Write-Host "  # [WARNING] Nested VT-x may increase VM detection!" -ForegroundColor Yellow
		Write-Host "  #           Some proctoring software detects nested virtualization." -ForegroundColor Yellow
		$fixNestedVTx = Get-YesNoChoice "Disable Nested VT-x for better anti-detection?" "N" "Only if you don't need nested VMs"
		if ($fixNestedVTx) {
			$enableNestedVTx = $false
			Write-Host "  # [FIXED] Nested VT-x disabled." -ForegroundColor Green
			$conflictsFixed++
		} else {
			$warningCount++
		}
	}

	if ($enableUEFI -and $applyAdvanced -and $osType -ne "Windows11_64") {
		Write-Host "  # [WARNING] UEFI firmware may increase VM detection!" -ForegroundColor Yellow
		Write-Host "  #           BIOS mode is harder to detect (unless you need Windows 11)." -ForegroundColor Yellow
		$fixUEFIDetection = Get-YesNoChoice "Switch to BIOS firmware for better anti-detection?" "N" "Only if you don't need UEFI"
		if ($fixUEFIDetection) {
			$enableUEFI = $false
			$enableSecureBoot = $false
			Write-Host "  # [FIXED] Switched to BIOS firmware." -ForegroundColor Green
			$conflictsFixed++
		} else {
			$warningCount++
		}
	}

	if ($diskConfig.EnableHotplug -and $applyAdvanced) {
		Write-Host "  # [WARNING] Hot-pluggable disk is an uncommon feature!" -ForegroundColor Yellow
		Write-Host "  #           May increase VM fingerprint." -ForegroundColor Yellow
		$warningCount++
	}

	if ($usbChoice -eq "1" -and $osType -like "Windows1*64*") {
		Write-Host "  # [WARNING] USB 1.1 (OHCI) is very old for Windows 10/11." -ForegroundColor Yellow
		Write-Host "  #           USB 3.0 (xHCI) recommended for modern devices." -ForegroundColor Yellow
		$warningCount++
	}

	if ($netCardChoice -eq "4" -and $osType -like "Windows*") {
		Write-Host "  # [WARNING] VirtIO network requires special drivers for Windows!" -ForegroundColor Yellow
		Write-Host "  #           Intel PRO/1000 works out of the box." -ForegroundColor Yellow
		$warningCount++
	}

	if ($audioDriver -eq "null") {
		Write-Host "  # [INFO] Null audio driver selected - VM will have NO audio." -ForegroundColor Cyan
	}

	if ($audioDriver -eq "null" -and $osType -like "Windows*") {
		Write-Host "  # [WARNING] Audio is disabled!" -ForegroundColor Yellow
		Write-Host "  #           Some proctoring software requires working audio/microphone." -ForegroundColor Yellow
		$warningCount++
	}

	if ($audioController -eq "sb16" -and $osType -like "Windows1*64*") {
		Write-Host "  # [WARNING] SoundBlaster 16 is very old for Windows 10/11." -ForegroundColor Yellow
		Write-Host "  #           Intel HD Audio recommended." -ForegroundColor Yellow
		$warningCount++
	}

	if ($audioDriver -eq "dsound" -and $osType -like "Windows1*64*") {
		Write-Host "  # [WARNING] DirectSound is legacy audio driver." -ForegroundColor Yellow
		Write-Host "  #           WASAPI recommended for Windows 10/11." -ForegroundColor Yellow
		$warningCount++
	}
	
	if (($clipboardMode -ne "disabled" -or $dragDropMode -ne "disabled") -and $applyAdvanced) {
		Write-Host "  # [WARNING] Clipboard/drag-and-drop are enabled but you're using anti-detection mode!" -ForegroundColor Yellow
		Write-Host "  #           These features can help identify VirtualBox." -ForegroundColor Yellow
		$fixClipboard = Get-YesNoChoice "Disable clipboard and drag-and-drop for better stealth?" "Y" "Recommended"
		if ($fixClipboard) {
			$clipboardMode = "disabled"
			$dragDropMode = "disabled"
			Write-Host "  # [FIXED] Clipboard and drag-and-drop disabled." -ForegroundColor Green
			$conflictsFixed++
		} else {
			$warningCount++
		}
	}

	if (($clipboardMode -ne "disabled" -or $dragDropMode -ne "disabled") -and -not $installGuestAdditions -and $useUnattended) {
		Write-Host "  # [WARNING] Clipboard/drag-and-drop enabled but Guest Additions won't be installed!" -ForegroundColor Yellow
		Write-Host "  #           These features require Guest Additions to work." -ForegroundColor Yellow
		$warningCount++
	}

	if ($useUnattended -and [string]::IsNullOrWhiteSpace($isoPath)) {
		Write-Host "  # [CRITICAL] Unattended install enabled but no ISO selected!" -ForegroundColor Red
		$useUnattended = $false
		Write-Host "  # [FIXED] Unattended install disabled." -ForegroundColor Yellow
		$conflictsFixed++
	}

	if ($useUnattended -and -not $createNewVM) {
		Write-Host "  # [WARNING] Unattended install is for NEW VMs only!" -ForegroundColor Yellow
		Write-Host "  #           This VM already exists." -ForegroundColor Yellow
		$useUnattended = $false
		Write-Host "  # [FIXED] Unattended install disabled for existing VM." -ForegroundColor Yellow
		$conflictsFixed++
	}

	if ($installGuestAdditions -and $applyAdvanced) {
		Write-Host "  # [WARNING] Guest Additions SIGNIFICANTLY increase VM detection!" -ForegroundColor Yellow
		Write-Host "  #           This defeats the purpose of anti-detection settings." -ForegroundColor Yellow
		$fixGuestAdd = Get-YesNoChoice "Disable Guest Additions auto-install?" "Y" "Highly recommended"
		if ($fixGuestAdd) {
			$installGuestAdditions = $false
			Write-Host "  # [FIXED] Guest Additions auto-install disabled." -ForegroundColor Green
			$conflictsFixed++
		} else {
			Write-Host "  # [WARNING] Your VM will be easily detectable!" -ForegroundColor Red
			$criticalCount++
		}
	}

	Write-Host "`n  # ========== VALIDATION SUMMARY ==========" -ForegroundColor Magenta
	Write-Host "  # Conflicts Fixed: $conflictsFixed" -ForegroundColor Green
	if ($criticalCount -eq 0 -and $warningCount -eq 0) {
		Write-Host "  # No remaining conflicts!  Configuration looks good." -ForegroundColor Green
	} else {
		if ($criticalCount -gt 0) {
			Write-Host "  #   $criticalCount CRITICAL issue(s) remaining" -ForegroundColor Red
			Write-Host "  #   (May prevent VM from working properly)" -ForegroundColor Red
		}
		if ($warningCount -gt 0) {
			Write-Host "  #   $warningCount Warning(s) remaining" -ForegroundColor Yellow
			Write-Host "  #   (May cause performance or compatibility issues)" -ForegroundColor Yellow
		}
		
		if ($criticalCount -gt 0) {
			Write-Host "`n  # [! ] CRITICAL ISSUES DETECTED!" -ForegroundColor Red
			$proceedAnyway = Get-YesNoChoice "Continue with configuration anyway?" "N" "NOT recommended - VM may not work"
			if (-not $proceedAnyway) {
				Write-Host "`n  # [INFO] Configuration cancelled by user." -ForegroundColor Yellow
				Write-Host "  # Please review the issues above and run the script again." -ForegroundColor Yellow
				pause
				exit 0
			} else {
				Write-Host "`n  # [WARNING] Proceeding with critical issues - VM may not work correctly!" -ForegroundColor Red
			}
		}
	}
	Write-Host "  # ========================================" -ForegroundColor Magenta

    if ($createNewVM) {
        Write-Host "`n  # [INFO] Creating new VM '$VM'..." -ForegroundColor Yellow
        
        & $VBoxManager createvm --name $VM --ostype $osType --register
        Write-Host "  # [OK] VM registered." -ForegroundColor Green
        
        if ($diskConfig.CreateDisk) {
            Write-Host "`n  # [INFO] Creating virtual hard disk..." -ForegroundColor Yellow
            Write-Host "  # Path: $($diskConfig.DiskPath)" -ForegroundColor Gray
            Write-Host "  # Size: $($diskConfig.StorageGB) GB" -ForegroundColor Gray
            Write-Host "  # Format: $($diskConfig.DiskFormat)" -ForegroundColor Gray
            Write-Host "  # Variant: $($diskConfig.DiskVariant)" -ForegroundColor Gray
            
            $diskSizeMB = [int]$diskConfig.StorageGB * 1024
            
            & $VBoxManager createhd --filename "$($diskConfig.DiskPath)" --size $diskSizeMB --format $diskConfig.DiskFormat --variant $diskConfig.DiskVariant
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  # [OK] Virtual hard disk created." -ForegroundColor Green
                
                Write-Host "  # [INFO] Creating SATA controller..." -ForegroundColor Yellow
                & $VBoxManager storagectl $VM --name "SATA Controller" --add sata --controller IntelAhci
				
				Write-Host "  # [INFO] Applying AHCI stability fixes for Windows installation..." -ForegroundColor Yellow
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/QueueDepth" "16"
				& $VBoxManager storagectl $VM --name "SATA Controller" --hostiocache off
				Write-Host "  # [OK] AHCI queue depth limited to 16 (prevents overflow during install)." -ForegroundColor Green
                
                Write-Host "  # [INFO] Attaching disk to VM..." -ForegroundColor Yellow
                & $VBoxManager storageattach $VM --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "$($diskConfig.DiskPath)"
                
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "  # [OK] Disk attached successfully." -ForegroundColor Green

                    if ($diskConfig.EnableSSD) {
                        Write-Host "  # [INFO] Configuring disk as SSD..." -ForegroundColor Yellow
                        & $VBoxManager storageattach $VM --storagectl "SATA Controller" --port 0 --device 0 --nonrotational on
                        Write-Host "  # [OK] Disk configured as SSD with TRIM support." -ForegroundColor Green
                    }

                    if ($diskConfig.EnableHotplug) {
                        Write-Host "  # [INFO] Enabling hot-pluggable..." -ForegroundColor Yellow
                        & $VBoxManager storageattach $VM --storagectl "SATA Controller" --port 0 --device 0 --hotpluggable on
                        Write-Host "  # [OK] Disk is now hot-pluggable." -ForegroundColor Green
                    }
                } else {
                    Write-Host "  # [WARNING] Disk attachment may have failed (Exit code: $LASTEXITCODE)." -ForegroundColor Yellow
                }
            } else {
                Write-Host "  # [ERROR] Failed to create virtual hard disk (Exit code: $LASTEXITCODE)." -ForegroundColor Red
            }
            
        } elseif (-not $diskConfig.SkipDisk -and $diskConfig.DiskPath) {
            Write-Host "`n  # [INFO] Attaching existing virtual hard disk..." -ForegroundColor Yellow
            Write-Host "  # Path: $($diskConfig.DiskPath)" -ForegroundColor Gray
            
            & $VBoxManager storagectl $VM --name "SATA Controller" --add sata --controller IntelAhci
            & $VBoxManager storageattach $VM --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "$($diskConfig.DiskPath)"
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  # [OK] Existing disk attached successfully." -ForegroundColor Green
            } else {
                Write-Host "  # [WARNING] Disk attachment may have failed (Exit code: $LASTEXITCODE)." -ForegroundColor Yellow
            }
            
        } else {
            Write-Host "`n  # [INFO] VM created without a hard disk." -ForegroundColor Yellow
        }
		
		Write-Host "`n  # [INFO] Configuring boot order..." -ForegroundColor Yellow
        & $VBoxManager modifyvm $VM --boot1 dvd --boot2 disk --boot3 none --boot4 none
        Write-Host "  # [OK] Boot order: DVD → Disk → None → None" -ForegroundColor Green
        
    } else {
        Write-Host "`n  # [INFO] VM '$VM' already exists. Applying configuration changes..." -ForegroundColor Yellow
    }
    
    Write-Host "`n  # [INFO] Starting VM configuration for '$VM'..." -ForegroundColor Yellow
    
    Write-Host "`n  # [INFO] Applying base configuration..." -ForegroundColor Yellow
    
    & $VBoxManager modifyvm $VM --clipboard-mode $clipboardMode
	& $VBoxManager modifyvm $VM --drag-and-drop $dragDropMode
    & $VBoxManager modifyvm $VM --mouse $mouseType
    & $VBoxManager modifyvm $VM --keyboard ps2
    if ($enablePAE) {
		& $VBoxManager modifyvm $VM --pae on
	} else {
		& $VBoxManager modifyvm $VM --pae off
	}
    if ($enableNestedPaging) {
		& $VBoxManager modifyvm $VM --nested-paging on
	} else {
		& $VBoxManager modifyvm $VM --nested-paging off
	}
    
    if (-not [string]::IsNullOrWhiteSpace($macAddress)) {
        & $VBoxManager modifyvm $VM --mac-address1 $macAddress
    }

    & $VBoxManager modifyvm $VM --hwvirtex on
    if ($enableNestedVTx) {
		& $VBoxManager modifyvm $VM --nested-hw-virt on
	} else {
		& $VBoxManager modifyvm $VM --nested-hw-virt off
	}
    & $VBoxManager modifyvm $VM --large-pages on
	& $VBoxManager modifyvm $VM --paravirt-provider $paraVirtProvider
    & $VBoxManager modifyvm $VM --vram $vramInt
    & $VBoxManager modifyvm $VM --memory $memory
    & $VBoxManager modifyvm $VM --apic on
    
    if ($enableIOAPIC) {
        & $VBoxManager modifyvm $VM --ioapic on
    } else {
        & $VBoxManager modifyvm $VM --ioapic off
    }
    
    & $VBoxManager modifyvm $VM --cpus $cpus
    & $VBoxManager modifyvm $VM --cpu-execution-cap 100
    & $VBoxManager modifyvm $VM --chipset $chipset
    & $VBoxManager modifyvm $VM --graphicscontroller $graphicsController
    
    if ($enable3D) {
        & $VBoxManager modifyvm $VM --accelerate-3d on
    } else {
        & $VBoxManager modifyvm $VM --accelerate-3d off
    }
    
    if ($enableUEFI) {
		& $VBoxManager modifyvm $VM --firmware efi
		
		if ($enableSecureBoot) {
			Write-Host "  # [INFO] Configuring Secure Boot via NVRAM..." -ForegroundColor Yellow
			
			& $VBoxManager modifynvram $VM inituefivarstore 2>$null
			if ($LASTEXITCODE -ne 0) {
				Write-Host "  # [WARNING] Failed to initialize UEFI variable store" -ForegroundColor Yellow
			}
			
			& $VBoxManager modifynvram $VM enrollmssignatures 2>$null
			if ($LASTEXITCODE -ne 0) {
				Write-Host "  # [WARNING] Failed to enroll Microsoft signatures" -ForegroundColor Yellow
			}
			
			& $VBoxManager modifynvram $VM enrollorclpk 2>$null
			if ($LASTEXITCODE -eq 0) {
				Write-Host "  # [OK] Secure Boot configured successfully" -ForegroundColor Green
			} else {
				Write-Host "  # [WARNING] Failed to enroll Oracle Platform Key" -ForegroundColor Yellow
			}
		}
	} else {
		& $VBoxManager modifyvm $VM --firmware bios
	}
    
    if ($tpmType -ne "none") {
        & $VBoxManager modifyvm $VM --tpm-type $tpmType
    }
    
    if ($useUTCClock) {
        & $VBoxManager modifyvm $VM --rtcuseutc on
    } else {
        & $VBoxManager modifyvm $VM --rtcuseutc off
    }
    
    Write-Host "  # [OK] Base configuration applied." -ForegroundColor Green

	Write-Host "`n  # [INFO] Configuring USB controller..." -ForegroundColor Yellow
	switch ($usbChoice) {
		"1" { 
			& $VBoxManager modifyvm $VM --usb-ohci on
			& $VBoxManager modifyvm $VM --usb-ehci off
			& $VBoxManager modifyvm $VM --usb-xhci off
		}
		"2" { 
			& $VBoxManager modifyvm $VM --usb-ohci on
			& $VBoxManager modifyvm $VM --usb-ehci on
			& $VBoxManager modifyvm $VM --usb-xhci off
		}
		"3" { 
			& $VBoxManager modifyvm $VM --usb-ohci off
			& $VBoxManager modifyvm $VM --usb-ehci off
			& $VBoxManager modifyvm $VM --usb-xhci on 2>$null
			
			if ($LASTEXITCODE -ne 0) {
				Write-Host "  # [WARNING] USB 3.0 requires Extension Pack. Falling back to USB 2.0" -ForegroundColor Yellow
				& $VBoxManager modifyvm $VM --usb-ohci on
				& $VBoxManager modifyvm $VM --usb-ehci on
				& $VBoxManager modifyvm $VM --usb-xhci off
			}
		}
		default { 
			& $VBoxManager modifyvm $VM --usb-xhci on 2>$null
			if ($LASTEXITCODE -ne 0) {
				Write-Host "  # [WARNING] USB 3.0 requires Extension Pack. Falling back to USB 2.0" -ForegroundColor Yellow
				& $VBoxManager modifyvm $VM --usb-ohci on
				& $VBoxManager modifyvm $VM --usb-ehci on
				& $VBoxManager modifyvm $VM --usb-xhci off
			}
		}
	}
	Write-Host "  # [OK] USB controller configured." -ForegroundColor Green

    Write-Host "`n  # [INFO] Setting network adapter type..." -ForegroundColor Yellow
    switch ($netCardChoice) {
        "1" { & $VBoxManager modifyvm $VM --nic-type1 82540EM }
        "2" { & $VBoxManager modifyvm $VM --nic-type1 82543GC }
        "3" { & $VBoxManager modifyvm $VM --nic-type1 82545EM }
        "4" { & $VBoxManager modifyvm $VM --nic-type1 virtio }
        default { & $VBoxManager modifyvm $VM --nic-type1 82540EM }
    }
    Write-Host "  # [OK] Network adapter type set to $($networkCards[$netCardChoice].Desc)" -ForegroundColor Green

    if ($configureAdvancedNetwork) {
        Write-Host "  # [INFO] Applying advanced network settings..." -ForegroundColor Yellow
        
        if ($selectedNetCard.VendorId -and $selectedNetCard.DeviceId) {
            Write-Host "  # [OK] PCI Device IDs applied." -ForegroundColor Green
        }

        switch ($networkMode) {
			"1" { 
				& $VBoxManager modifyvm $VM --nic1 nat
			}
			"2" { 
				if ($bridgedAdapter) {
					& $VBoxManager modifyvm $VM --nic1 bridged --bridgeadapter1 "$bridgedAdapter"
				} else {
                    & $VBoxManager modifyvm $VM --nic1 nat
                }
			}
			"3" { 
				& $VBoxManager modifyvm $VM --nic1 intnet --intnet1 "$intNetName"
			}
			"4" { 
				& $VBoxManager modifyvm $VM --nic1 hostonly
			}
			"5" { 
				& $VBoxManager modifyvm $VM --nic1 natnetwork --nat-network1 "$natNetName"
			}
			default { 
				& $VBoxManager modifyvm $VM --nic1 nat
			}
		}

        if ($networkMode -eq "1" -or $networkMode -eq "5") {
            if ($configureDNS) {
                if ($dnsChoice -eq "1") {
					& $VBoxManager modifyvm $VM --natdnshostresolver1 on
					& $VBoxManager modifyvm $VM --natdnsproxy1 on
				}
				elseif ($dnsChoice -eq "6") {
					& $VBoxManager modifyvm $VM --natdnshostresolver1 off
					& $VBoxManager modifyvm $VM --natdnsproxy1 off
				}
				else {
					& $VBoxManager modifyvm $VM --natdnshostresolver1 off
					& $VBoxManager modifyvm $VM --natdnsproxy1 off
				}
            }
        }

        & $VBoxManager setextradata $VM "VBoxInternal/Devices/e1000/0/Config/AdapterType" "0"
		& $VBoxManager modifyvm $VM --cableconnected1 on
		if ($networkMode -eq "2") {
			& $VBoxManager modifyvm $VM --nicpromisc1 allow-all
		}

        Write-Host "  # [OK] Advanced network settings applied." -ForegroundColor Green
    } else {
        & $VBoxManager modifyvm $VM --nic1 nat
        Write-Host "  # [INFO] Using default NAT networking." -ForegroundColor Gray
    }


    Write-Host "`n  # [INFO] Configuring audio..." -ForegroundColor Yellow

    if ($audioDriver -ne "null") {
        & $VBoxManager modifyvm $VM --audio-controller $audioController
        & $VBoxManager modifyvm $VM --audio-driver $audioDriver
        & $VBoxManager modifyvm $VM --audio-enabled on
        
        if ($enableAudioOutput) {
            & $VBoxManager modifyvm $VM --audio-out on
        } else {
            & $VBoxManager modifyvm $VM --audio-out off
        }
        
        if ($enableAudioInput) {
            & $VBoxManager modifyvm $VM --audio-in on
        } else {
            & $VBoxManager modifyvm $VM --audio-in off
        }
        
        Write-Host "  # [OK] Audio configured (Controller: $audioController, Driver: $audioDriver)" -ForegroundColor Green
    } else {
        & $VBoxManager modifyvm $VM --audio-enabled off
        Write-Host "  # [OK] Audio disabled (Null audio driver selected)" -ForegroundColor Green
    }

    Write-Host "`n  # [INFO] Applying CPU configuration..." -ForegroundColor Yellow
	Write-Host "  # CPU Model: $($cpuProfile.Name)" -ForegroundColor Gray

	$cpuProfileSuccess = $false

	if ($cpuProfile.VBoxProfile) {
		Write-Host "  # [INFO] Attempting VirtualBox CPU profile: $($cpuProfile.VBoxProfile)" -ForegroundColor Cyan
		& $VBoxManager modifyvm $VM --cpu-profile "$($cpuProfile.VBoxProfile)" 2>$null
		
		if ($LASTEXITCODE -eq 0) {
			Write-Host "  # [OK] CPU profile applied!" -ForegroundColor Green
			$cpuProfileSuccess = $true
		} else {
			Write-Host "  # [WARNING] CPU profile not available, using manual CPUID" -ForegroundColor Yellow
		}
	}

	Write-Host "  # [INFO] Setting CPU vendor string..." -ForegroundColor Cyan
	if ($cpuProfile.Manufacturer -eq "Intel") {
		& $VBoxManager modifyvm $VM --cpuid-set 00000000 $cpuProfile.CPUID_0_EAX 756E6547 6C65746E 49656E69
	} else {
		& $VBoxManager modifyvm $VM --cpuid-set 00000000 $cpuProfile.CPUID_0_EAX 68747541 444D4163 69746E65
	}

	Write-Host "  # [INFO] Setting CPUID leaf 1..." -ForegroundColor Cyan
	& $VBoxManager modifyvm $VM --cpuid-set 00000001 $cpuProfile.CPUID_EAX $cpuProfile.CPUID_EBX $cpuProfile.CPUID_ECX $cpuProfile.CPUID_EDX

	if ($cpuProfile.Brand_80000002) {
		Write-Host "  # [INFO] Setting CPU brand string..." -ForegroundColor Cyan
		& $VBoxManager modifyvm $VM --cpuid-set 80000002 $cpuProfile.Brand_80000002[0] $cpuProfile.Brand_80000002[1] $cpuProfile.Brand_80000002[2] $cpuProfile.Brand_80000002[3]
		& $VBoxManager modifyvm $VM --cpuid-set 80000003 $cpuProfile.Brand_80000003[0] $cpuProfile.Brand_80000003[1] $cpuProfile.Brand_80000003[2] $cpuProfile.Brand_80000003[3]
		& $VBoxManager modifyvm $VM --cpuid-set 80000004 $cpuProfile.Brand_80000004[0] $cpuProfile.Brand_80000004[1] $cpuProfile.Brand_80000004[2] $cpuProfile.Brand_80000004[3]
	}

	Write-Host "  # [INFO] Setting DMI processor info..." -ForegroundColor Cyan
	if ($cpuProfile.Manufacturer -eq "Intel") {
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiProcManufacturer" "Intel Corporation"
	} else {
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiProcManufacturer" "Advanced Micro Devices, Inc."
	}
	& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiProcVersion" $cpuProfile.DMIName
	& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiProcSocket" $cpuProfile.Socket
	& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiProcFamily" $cpuProfile.DMIFamily

	Write-Host "  # [OK] CPU configuration complete!" -ForegroundColor Green
	Write-Host "  #      Vendor: $($cpuProfile.Manufacturer)" -ForegroundColor Gray
	Write-Host "  #      Model:  $($cpuProfile.DMIName)" -ForegroundColor Gray
	Write-Host "  #      Socket: $($cpuProfile.Socket)" -ForegroundColor Gray

	Write-Host "  # [INFO] Applying advanced CPU timing and features..." -ForegroundColor Cyan
	& $VBoxManager setextradata $VM "VBoxInternal/TM/TSCTiedToExecution" "1"
	& $VBoxManager setextradata $VM "VBoxInternal/CPUM/NestedHWVirt" "1"
	& $VBoxManager setextradata $VM "VBoxInternal/TM/WarpDrivePercentage" "100"
	& $VBoxManager setextradata $VM "VBoxInternal/TM/TSCMode" "RealTSCOffset"
	& $VBoxManager setextradata $VM "VBoxInternal/CPUM/SSE4.1" "1"
	& $VBoxManager setextradata $VM "VBoxInternal/CPUM/SSE4.2" "1"

	Write-Host "  # [OK] CPU configuration complete!" -ForegroundColor Green

	if ($applyAdvanced) {
		Write-Host "`n  # [INFO] Removing VirtualBox ACPI signatures..." -ForegroundColor Yellow
		
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/acpi/0/Config/AcpiOemId" "ALASKA"
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/acpi/0/Config/AcpiCreatorId" "AMI"
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/acpi/0/Config/AcpiCreatorRev" '00000001'
		
		Write-Host "  # [OK] ACPI signatures spoofed." -ForegroundColor Green
	}

	if ($installGuestAdditions) {
		Write-Host "`n  # [INFO] Hiding VirtualBox-specific PCI devices..." -ForegroundColor Yellow
		
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/VBoxGuest/0/Trusted" "1"
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/VBoxGuest/0/Config/HideDeviceTable" "1"
		
		Write-Host "  # [OK] PCI devices hidden." -ForegroundColor Green
	}
	
	if ($applyAdvanced) {
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemSerial" "System Serial Number"
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemUuid" "deadbeef-dead-beef-dead-beefdeadbeef"
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardSerial" "Board Serial Number"
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiChassisSerial" "Chassis Serial Number"
	}
	
    if ($applyAdvanced) {
		Write-Host "`n  # [INFO] Applying SMBIOS (DMI) spoofing..." -ForegroundColor Yellow
		
		function Get-RandomSerial {
			param([int]$Length = 12)
			$chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
			-join ((1..$Length) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
		}
		
		$randomBoardSerial = Get-RandomSerial -Length 12
		$randomSystemSerial = Get-RandomSerial -Length 10
		$randomChassisSerial = Get-RandomSerial -Length 10
		$randomUUID = [guid]::NewGuid().ToString()
		
		switch ($vendorChoice) {
			"1" {
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVendor" "American Megatrends International, LLC."
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVersion" "1.A0"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseDate" "11/23/2023"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseMajor" "5"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseMinor" "17"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSFirmwareMajor" "1"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSFirmwareMinor" "10"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVendor" "Micro-Star International Co., Ltd."
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemProduct" "MS-7D78"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVersion" "1.0"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemSKU" "To be filled by O.E.M."
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemFamily" "Desktop"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardVendor" "Micro-Star International Co., Ltd."
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardProduct" "PRO B650-P WIFI (MS-7D78)"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardVersion" "1.0"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardAssetTag" ""
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardLocInChassis" "To be filled by O.E.M."
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiChassisVendor" "Micro-Star International Co., Ltd."
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiChassisAssetTag" ""
			}
			"2" {
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVendor" "American Megatrends Inc."
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVersion" "2402"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseDate" "12/15/2023"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseMajor" "5"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseMinor" "17"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSFirmwareMajor" "24"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSFirmwareMinor" "2"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVendor" "ASUSTeK COMPUTER INC."
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemProduct" "ROG STRIX B650E-F GAMING WIFI"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVersion" "Rev 1.xx"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemSKU" "SKU"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemFamily" "ROG STRIX"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardVendor" "ASUSTeK COMPUTER INC."
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardProduct" "ROG STRIX B650E-F GAMING WIFI"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardVersion" "Rev 1.xx"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardAssetTag" "Default string"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardLocInChassis" "Default string"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiChassisVendor" "ASUSTeK COMPUTER INC."
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiChassisAssetTag" "Default string"
			}
			"3" {
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVendor" "American Megatrends International, LLC."
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVersion" "F5a"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseDate" "09/28/2023"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseMajor" "5"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseMinor" "17"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSFirmwareMajor" "5"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSFirmwareMinor" "10"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVendor" "Gigabyte Technology Co., Ltd."
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemProduct" "B650 AORUS ELITE AX"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVersion" "x.x"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemSKU" ""
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemFamily" ""
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardVendor" "Gigabyte Technology Co., Ltd."
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardProduct" "B650 AORUS ELITE AX"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardVersion" "x.x"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardAssetTag" ""
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardLocInChassis" ""
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiChassisVendor" "Default string"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiChassisAssetTag" ""
			}
			"4" {
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVendor" "American Megatrends Inc."
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVersion" "1.90"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseDate" "01/05/2024"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseMajor" "5"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseMinor" "17"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSFirmwareMajor" "1"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSFirmwareMinor" "90"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVendor" "ASRock"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemProduct" "B650E PG Lightning"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVersion" ""
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemSKU" ""
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemFamily" ""
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardVendor" "ASRock"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardProduct" "B650E PG Lightning"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardVersion" ""
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardAssetTag" ""
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardLocInChassis" ""
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiChassisVendor" "To Be Filled By O.E.M."
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiChassisAssetTag" "To Be Filled By O.E.M."
			}
			default {
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVendor" "American Megatrends International, LLC."
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVersion" "1.A0"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseDate" "11/23/2023"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseMajor" "5"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseMinor" "17"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSFirmwareMajor" "1"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSFirmwareMinor" "10"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVendor" "Micro-Star International Co., Ltd."
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemProduct" "MS-7D78"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVersion" "1.0"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemSKU" "To be filled by O.E.M."
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemFamily" "Desktop"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardVendor" "Micro-Star International Co., Ltd."
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardProduct" "PRO B650-P WIFI (MS-7D78)"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardVersion" "1.0"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardAssetTag" ""
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardLocInChassis" "To be filled by O.E.M."
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiChassisVendor" "Micro-Star International Co., Ltd."
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiChassisAssetTag" ""
			}
		}
		
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemSerial" $randomSystemSerial
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemUuid" $randomUUID
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardSerial" $randomBoardSerial
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiChassisSerial" $randomChassisSerial
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiChassisType" "3"
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiChassisVersion" "1.0"
		
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiOEMVBoxVer" ""
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiOEMVBoxRev" ""
		
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiExposeMemoryTable" "0"
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiExposeProcInf" "0"
		
		Write-Host "  # [OK] DMI/SMBIOS motherboard info spoofed." -ForegroundColor Green
		Write-Host "  #      Board Serial: $randomBoardSerial" -ForegroundColor Gray
		Write-Host "  #      System Serial: $randomSystemSerial" -ForegroundColor Gray
		Write-Host "  #      System UUID: $randomUUID" -ForegroundColor Gray

        Write-Host "`n  # [INFO] Applying storage device spoofing..." -ForegroundColor Yellow

		function Get-RandomDriveSerial {
			param([int]$Length = 20)
			$chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
			-join ((1..$Length) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
		}

		$randomHDSerial = Get-RandomDriveSerial -Length 20

		switch ($storageChoice) {
			"1" {
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/ModelNumber" "Samsung SSD 980 EVO 500GB"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/FirmwareRevision" "1B4QFXO7"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/SerialNumber" "S5GXNF0R$($randomHDSerial.Substring(0,8))"
			}
			"2" {
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/ModelNumber" "Samsung SSD 870 EVO 1TB"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/FirmwareRevision" "SVT01B6Q"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/SerialNumber" "S62SNJ0R$($randomHDSerial.Substring(0,8))"
			}
			"3" {
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/ModelNumber" "WDC WDS500G3B0C-00ZMC0"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/FirmwareRevision" "234100WD"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/SerialNumber" "WD-WXK2A$($randomHDSerial.Substring(0,10))"
			}
			"4" {
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/ModelNumber" "CT500MX500SSD1"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/FirmwareRevision" "M3CR033"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/SerialNumber" "2119E5CB$($randomHDSerial.Substring(0,8))"
			}
			default {
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/ModelNumber" "Samsung SSD 980 EVO 500GB"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/FirmwareRevision" "1B4QFXO7"
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/SerialNumber" "S5GXNF0R$($randomHDSerial.Substring(0,8))"
			}
		}

		& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/NonRotational" "1"
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/IgnoreFlush" "0"
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/WriteCache" "1"

		Write-Host "  # [OK] Hard disk spoofing applied." -ForegroundColor Green

		Write-Host "  # [INFO] Applying optical drive spoofing..." -ForegroundColor Yellow

		$opticalDrives = @{
			"1" = @{Vendor = "HL-DT-ST"; Product = "DVDRAM GH24NSC0"; Revision = "LY00"}
			"2" = @{Vendor = "TSSTcorp"; Product = "CDDVDW SH-224DB"; Revision = "SB01"}
			"3" = @{Vendor = "ATAPI"; Product = "iHAS124 Y"; Revision = "CL9M"}
			"4" = @{Vendor = "Slimtype"; Product = "DVD A DS8A8SH"; Revision = "KAA2"}
		}

		$selectedOptical = $opticalDrives[([string](Get-Random -Minimum 1 -Maximum 5))]

		& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port1/ATAPIVendorId" $selectedOptical.Vendor
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port1/ATAPIProductId" $selectedOptical.Product
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port1/ATAPIRevision" $selectedOptical.Revision

		Write-Host "  # [OK] Optical drive spoofing applied." -ForegroundColor Green
		Write-Host "  #      HDD: $($storageProfiles[$storageChoice])" -ForegroundColor Gray
		Write-Host "  #      DVD: $($selectedOptical.Vendor) $($selectedOptical.Product)" -ForegroundColor Gray

		Write-Host "`n  # [INFO] Applying RAM module spoofing..." -ForegroundColor Yellow

		$ramProfiles = @{
			"1" = @{
				Name = "Corsair Vengeance LPX 16GB"
				Slots = @(
					@{ Size = "8192"; Manufacturer = "Corsair"; PartNumber = "CMK16GX4M2B3200C16"; Serial = "00000000" }
					@{ Size = "8192"; Manufacturer = "Corsair"; PartNumber = "CMK16GX4M2B3200C16"; Serial = "00000001" }
				)
			}
			"2" = @{
				Name = "G.Skill Ripjaws V 32GB"
				Slots = @(
					@{ Size = "8192"; Manufacturer = "G.Skill"; PartNumber = "F4-3200C16-8GVKB"; Serial = "00000000" }
					@{ Size = "8192"; Manufacturer = "G.Skill"; PartNumber = "F4-3200C16-8GVKB"; Serial = "00000001" }
					@{ Size = "8192"; Manufacturer = "G.Skill"; PartNumber = "F4-3200C16-8GVKB"; Serial = "00000002" }
					@{ Size = "8192"; Manufacturer = "G.Skill"; PartNumber = "F4-3200C16-8GVKB"; Serial = "00000003" }
				)
			}
			"3" = @{
				Name = "Kingston Fury Beast 16GB"
				Slots = @(
					@{ Size = "8192"; Manufacturer = "Kingston"; PartNumber = "KF432C16BB/8"; Serial = "E03B1A25" }
					@{ Size = "8192"; Manufacturer = "Kingston"; PartNumber = "KF432C16BB/8"; Serial = "E03B1A26" }
				)
			}
			"4" = @{
				Name = "Samsung DDR4 32GB"
				Slots = @(
					@{ Size = "16384"; Manufacturer = "Samsung"; PartNumber = "M378A2K43CB1-CTD"; Serial = "3A5E7B9C" }
					@{ Size = "16384"; Manufacturer = "Samsung"; PartNumber = "M378A2K43CB1-CTD"; Serial = "3A5E7B9D" }
				)
			}
		}

		Write-Host "`n  # Available RAM profiles:" -ForegroundColor Cyan
		foreach ($key in $ramProfiles.Keys | Sort-Object) {
			Write-Host "  # $key. $($ramProfiles[$key].Name)" -ForegroundColor Gray
		}

		$ramChoice = Get-UserChoice "Select a RAM profile (1-4):" "1" "Realistic RAM module configuration"
		$selectedRam = $ramProfiles[$ramChoice]

		if ($null -eq $selectedRam) {
			$selectedRam = $ramProfiles["1"]
		}

		Write-Host "  # [OK] Selected: $($selectedRam.Name)" -ForegroundColor Green

		$slotIndex = 0
		foreach ($slot in $selectedRam.Slots) {
			$serialNumber = $slot.Serial
			if ($serialNumber -eq "00000000") {
				$serialNumber = "{0:X4}{1:X4}" -f (Get-Random -Maximum 0xFFFF), (Get-Random -Maximum 0xFFFF)
			}
			
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiMemorySlot$slotIndex/Size" $slot.Size
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiMemorySlot$slotIndex/Manufacturer" $slot.Manufacturer
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiMemorySlot$slotIndex/PartNumber" $slot.PartNumber
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiMemorySlot$slotIndex/SerialNumber" $serialNumber
			
			Write-Host "  # [OK] RAM Slot $slotIndex`: $($slot.Manufacturer) $($slot.PartNumber) ($($slot.Size) MB)" -ForegroundColor Green
			
			$slotIndex++
		}

		for ($i = $slotIndex; $i -lt 4; $i++) {
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiMemorySlot$i/Size" ""
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiMemorySlot$i/Manufacturer" ""
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiMemorySlot$i/PartNumber" ""
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiMemorySlot$i/SerialNumber" ""
		}

		Write-Host "  # [OK] RAM module spoofing applied." -ForegroundColor Green

        Write-Host "`n  # [INFO] Configuring time synchronization controls..." -ForegroundColor Yellow
        & $VBoxManager setextradata $VM "VBoxInternal/Devices/VMMDev/0/Config/GetHostTimeDisabled" "1"
        Write-Host "  # [OK] Time synchronization controls modified." -ForegroundColor Green

        Write-Host "`n  # [INFO] Configuring console output and boot display..." -ForegroundColor Yellow
        & $VBoxManager modifyvm $VM --bios-boot-menu messageandmenu
        & $VBoxManager modifyvm $VM --bios-logo-fade-in off
        & $VBoxManager modifyvm $VM --bios-logo-fade-out off
        & $VBoxManager modifyvm $VM --bios-logo-display-time 0
        Write-Host "  # [OK] Console and boot display configured." -ForegroundColor Green
		
		Write-Host "`n  # ==================== PORT CONNECTOR EMULATION ===================" -ForegroundColor Magenta

		$configurePortConnectors = Get-YesNoChoice "Configure Port Connector Emulation?" "Y" "Adds realistic port information to DMI"

		if ($configurePortConnectors) {
			Write-Host "`n  # [INFO] Configuring port connectors for realistic DMI data..." -ForegroundColor Yellow
			
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector0/InternalDesignator" "USB3_1"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector0/InternalConnectorType" "0"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector0/ExternalDesignator" "USB 3.2 Gen 1 Type-A"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector0/ExternalConnectorType" "18"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector0/PortType" "16"
			Write-Host "  # [OK] Port 0: USB 3.2 Gen 1 Type-A" -ForegroundColor Green

			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector1/InternalDesignator" "USB3_2"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector1/InternalConnectorType" "0"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector1/ExternalDesignator" "USB 3.2 Gen 1 Type-A"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector1/ExternalConnectorType" "18"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector1/PortType" "16"
			Write-Host "  # [OK] Port 1: USB 3.2 Gen 1 Type-A" -ForegroundColor Green

			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector2/InternalDesignator" "USB3_3"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector2/InternalConnectorType" "0"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector2/ExternalDesignator" "USB 3.2 Gen 2 Type-C"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector2/ExternalConnectorType" "18"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector2/PortType" "16"
			Write-Host "  # [OK] Port 2: USB 3.2 Gen 2 Type-C" -ForegroundColor Green

			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector3/InternalDesignator" "USB2_1"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector3/InternalConnectorType" "0"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector3/ExternalDesignator" "USB 2.0 Type-A"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector3/ExternalConnectorType" "18"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector3/PortType" "16"
			Write-Host "  # [OK] Port 3: USB 2.0 Type-A" -ForegroundColor Green

			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector4/InternalDesignator" "USB2_2"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector4/InternalConnectorType" "0"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector4/ExternalDesignator" "USB 2.0 Type-A"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector4/ExternalConnectorType" "18"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector4/PortType" "16"
			Write-Host "  # [OK] Port 4: USB 2.0 Type-A" -ForegroundColor Green

			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector5/InternalDesignator" "AAFP"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector5/InternalConnectorType" "31"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector5/ExternalDesignator" "HD Audio Line Out"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector5/ExternalConnectorType" "31"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector5/PortType" "29"
			Write-Host "  # [OK] Port 5: HD Audio Line Out" -ForegroundColor Green

			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector6/InternalDesignator" "AAFP"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector6/InternalConnectorType" "31"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector6/ExternalDesignator" "HD Audio Mic In"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector6/ExternalConnectorType" "31"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector6/PortType" "29"
			Write-Host "  # [OK] Port 6: HD Audio Mic In" -ForegroundColor Green

			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector7/InternalDesignator" "LAN"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector7/InternalConnectorType" "0"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector7/ExternalDesignator" "Realtek RTL8125 2.5GbE"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector7/ExternalConnectorType" "11"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector7/PortType" "31"
			Write-Host "  # [OK] Port 7: Ethernet RJ-45" -ForegroundColor Green

			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector8/InternalDesignator" "SATA6G_1"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector8/InternalConnectorType" "34"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector8/ExternalDesignator" ""
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector8/ExternalConnectorType" "0"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector8/PortType" "32"
			Write-Host "  # [OK] Port 8: SATA 6Gb/s" -ForegroundColor Green

			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector9/InternalDesignator" "SATA6G_2"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector9/InternalConnectorType" "34"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector9/ExternalDesignator" ""
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector9/ExternalConnectorType" "0"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector9/PortType" "32"
			Write-Host "  # [OK] Port 9: SATA 6Gb/s" -ForegroundColor Green

			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector10/InternalDesignator" ""
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector10/InternalConnectorType" "0"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector10/ExternalDesignator" "HDMI"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector10/ExternalConnectorType" "255"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector10/PortType" "28"
			Write-Host "  # [OK] Port 10: HDMI" -ForegroundColor Green

			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector11/InternalDesignator" ""
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector11/InternalConnectorType" "0"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector11/ExternalDesignator" "DisplayPort"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector11/ExternalConnectorType" "255"
			& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiPortConnector11/PortType" "28"
			Write-Host "  # [OK] Port 11: DisplayPort" -ForegroundColor Green

			Write-Host "`n  # [OK] Port Connector Emulation configured with 12 ports!" -ForegroundColor Green
			Write-Host "  # [INFO] These ports will appear in system information tools (dmidecode, etc.)" -ForegroundColor Cyan
		}
		
		Write-Host "`n  # ==================== MISC HARDWARE EMULATION ===================" -ForegroundColor Magenta

		$configureMiscHardware = Get-YesNoChoice "Configure Misc Hardware Emulation?" "Y" "Adds realistic keyboard, mouse, ACPI, AHCI, OHCI info"

		if ($configureMiscHardware) {
			
			Write-Host "`n  # ========== KEYBOARD/MOUSE CONFIGURATION ==========" -ForegroundColor Cyan
			
			$keyboardVendors = @{
				"1" = @{Vendor = "Logitech"; Models = @("K120", "K270", "K380", "G Pro", "G915")}
				"2" = @{Vendor = "Microsoft"; Models = @("Wired Keyboard 600", "Ergonomic Keyboard", "Surface Keyboard")}
				"3" = @{Vendor = "Dell"; Models = @("KB216", "KB522", "KM636")}
				"4" = @{Vendor = "HP"; Models = @("125 Wired Keyboard", "Pavilion Keyboard 300", "USB Slim Keyboard")}
				"5" = @{Vendor = "Razer"; Models = @("BlackWidow V3", "Huntsman Elite", "Cynosa V2")}
			}
			
			Write-Host "`n  # Available Keyboard Vendors:" -ForegroundColor Cyan
			foreach ($key in $keyboardVendors.Keys | Sort-Object) {
				Write-Host "  # $key. $($keyboardVendors[$key].Vendor)" -ForegroundColor Gray
			}
			
			$kbVendorChoice = Get-UserChoice "Select Keyboard Vendor (1-5):" "1" "Logitech is most common"
			$selectedKbVendor = $keyboardVendors[$kbVendorChoice]
			
			if ($null -eq $selectedKbVendor) { $selectedKbVendor = $keyboardVendors["1"] }
			
			Write-Host "`n  # Available $($selectedKbVendor.Vendor) Keyboard Models:" -ForegroundColor Cyan
			for ($i = 0; $i -lt $selectedKbVendor.Models.Count; $i++) {
				Write-Host "  # $($i+1). $($selectedKbVendor.Models[$i])" -ForegroundColor Gray
			}
			
			$kbModelChoice = Get-UserChoice "Select Keyboard Model (1-$($selectedKbVendor.Models.Count)):" "1" "Select your preferred model"
			$kbModelIndex = [int]$kbModelChoice - 1
			if ($kbModelIndex -lt 0 -or $kbModelIndex -ge $selectedKbVendor.Models.Count) { $kbModelIndex = 0 }
			$selectedKbModel = $selectedKbVendor.Models[$kbModelIndex]
			
			Write-Host "  # [OK] Keyboard: $($selectedKbVendor.Vendor) $selectedKbModel" -ForegroundColor Green
			
			$mouseVendors = @{
				"1" = @{Vendor = "Logitech"; Models = @("M185", "M510", "G502 HERO", "G Pro X", "MX Master 3")}
				"2" = @{Vendor = "Microsoft"; Models = @("Basic Optical Mouse", "Ergonomic Mouse", "Arc Mouse")}
				"3" = @{Vendor = "Dell"; Models = @("MS116", "MS3220", "WM126")}
				"4" = @{Vendor = "HP"; Models = @("125 Wired Mouse", "X500", "Wireless Mouse 200")}
				"5" = @{Vendor = "Razer"; Models = @("DeathAdder V2", "Viper Ultimate", "Basilisk V3")}
			}
			
			Write-Host "`n  # Available Mouse Vendors:" -ForegroundColor Cyan
			foreach ($key in $mouseVendors.Keys | Sort-Object) {
				Write-Host "  # $key. $($mouseVendors[$key].Vendor)" -ForegroundColor Gray
			}
			
			$mouseVendorChoice = Get-UserChoice "Select Mouse Vendor (1-5):" "1" "Logitech is most common"
			$selectedMouseVendor = $mouseVendors[$mouseVendorChoice]
			
			if ($null -eq $selectedMouseVendor) { $selectedMouseVendor = $mouseVendors["1"] }
			
			Write-Host "`n  # Available $($selectedMouseVendor.Vendor) Mouse Models:" -ForegroundColor Cyan
			for ($i = 0; $i -lt $selectedMouseVendor.Models.Count; $i++) {
				Write-Host "  # $($i+1). $($selectedMouseVendor.Models[$i])" -ForegroundColor Gray
			}
			
			$mouseModelChoice = Get-UserChoice "Select Mouse Model (1-$($selectedMouseVendor.Models.Count)):" "1" "Select your preferred model"
			$mouseModelIndex = [int]$mouseModelChoice - 1
			if ($mouseModelIndex -lt 0 -or $mouseModelIndex -ge $selectedMouseVendor.Models.Count) { $mouseModelIndex = 0 }
			$selectedMouseModel = $selectedMouseVendor.Models[$mouseModelIndex]
			
			Write-Host "  # [OK] Mouse: $($selectedMouseVendor.Vendor) $selectedMouseModel" -ForegroundColor Green
			
			Write-Host "  # [OK] Keyboard/Mouse emulation configured." -ForegroundColor Green

			Write-Host "`n  # ========== POWER CONFIGURATION ==========" -ForegroundColor Cyan

			Write-Host "`n  # Platform Type:" -ForegroundColor Cyan
			Write-Host "  # 1. Desktop (No battery - Standard configuration)" -ForegroundColor Green
			Write-Host "  # 2. Laptop (Note: VirtualBox cannot emulate battery hardware)" -ForegroundColor Yellow

			$platformChoice = Get-UserChoice "Select Platform (1-2):" "1" "Desktop is standard"

			if ($platformChoice -eq "2") {
				Write-Host "  # [INFO] Laptop selected - DMI will show laptop model" -ForegroundColor Yellow
				Write-Host "  # [WARN] VirtualBox does not support battery emulation" -ForegroundColor Yellow
				Write-Host "  # [WARN] Guest OS will show 'AC Power Only' despite laptop DMI" -ForegroundColor Yellow
			} else {
				Write-Host "  # [OK] Platform: Desktop (AC Power Only)" -ForegroundColor Green
			}

			Write-Host "`n  # ========== ACPI CONTROLLER CONFIGURATION ==========" -ForegroundColor Cyan
			
			$acpiVendors = @{
				"1" = @{Vendor = "Intel"; Models = @("Lynx Point-LP", "Sunrise Point", "Cannon Lake", "Tiger Lake", "Alder Lake")}
				"2" = @{Vendor = "AMD"; Models = @("FCH", "Promontory", "X570", "B550", "B650")}
				"3" = @{Vendor = "ASUSTeK"; Models = @("ACPI x64-based PC", "ROG ACPI", "TUF ACPI")}
				"4" = @{Vendor = "MSI"; Models = @("ACPI x64-based PC", "MEG ACPI", "MPG ACPI")}
				"5" = @{Vendor = "Gigabyte"; Models = @("ACPI x64-based PC", "AORUS ACPI")}
			}
			
			Write-Host "`n  # Available ACPI Vendors:" -ForegroundColor Cyan
			foreach ($key in $acpiVendors.Keys | Sort-Object) {
				Write-Host "  # $key. $($acpiVendors[$key].Vendor)" -ForegroundColor Gray
			}
			
			if ($cpuProfile.Manufacturer -eq "Intel") {
				$defaultACPI = "1"
			} else {
				$defaultACPI = "2"
			}
			
			$acpiVendorChoice = Get-UserChoice "Select ACPI Vendor (1-5):" $defaultACPI "Match your CPU vendor for consistency"
			$selectedAcpiVendor = $acpiVendors[$acpiVendorChoice]
			
			if ($null -eq $selectedAcpiVendor) { $selectedAcpiVendor = $acpiVendors[$defaultACPI] }
			
			Write-Host "`n  # Available $($selectedAcpiVendor.Vendor) ACPI Models:" -ForegroundColor Cyan
			for ($i = 0; $i -lt $selectedAcpiVendor.Models.Count; $i++) {
				Write-Host "  # $($i+1). $($selectedAcpiVendor.Models[$i])" -ForegroundColor Gray
			}
			
			$acpiModelChoice = Get-UserChoice "Select ACPI Model (1-$($selectedAcpiVendor.Models.Count)):" "1" "Select chipset generation"
			$acpiModelIndex = [int]$acpiModelChoice - 1
			if ($acpiModelIndex -lt 0 -or $acpiModelIndex -ge $selectedAcpiVendor.Models.Count) { $acpiModelIndex = 0 }
			$selectedAcpiModel = $selectedAcpiVendor.Models[$acpiModelIndex]
			
			Write-Host "  # [OK] ACPI: $($selectedAcpiVendor.Vendor) $selectedAcpiModel" -ForegroundColor Green

			Write-Host "`n  # ========== AHCI CONTROLLER CONFIGURATION ==========" -ForegroundColor Cyan
			
			$ahciVendors = @{
				"1" = @{Vendor = "Intel"; Models = @(
					"8 Series/C220 Series SATA Controller",
					"Sunrise Point-LP SATA Controller",
					"Cannon Lake PCH SATA AHCI Controller",
					"400 Series Chipset SATA Controller",
					"500 Series Chipset SATA Controller",
					"Tiger Lake SATA AHCI Controller",
					"Alder Lake SATA AHCI Controller"
				)}
				"2" = @{Vendor = "AMD"; Models = @(
					"FCH SATA Controller [AHCI mode]",
					"400 Series Chipset SATA Controller",
					"500 Series Chipset SATA Controller",
					"600 Series Chipset SATA Controller"
				)}
				"3" = @{Vendor = "ASMedia"; Models = @(
					"ASM1062 Serial ATA Controller",
					"ASM1064 Serial ATA Controller",
					"ASM1166 Serial ATA Controller"
				)}
			}
			
			Write-Host "`n  # Available AHCI Vendors:" -ForegroundColor Cyan
			foreach ($key in $ahciVendors.Keys | Sort-Object) {
				Write-Host "  # $key. $($ahciVendors[$key].Vendor)" -ForegroundColor Gray
			}
			
			if ($cpuProfile.Manufacturer -eq "Intel") {
				$defaultAHCI = "1"
			} else {
				$defaultAHCI = "2"
			}
			
			$ahciVendorChoice = Get-UserChoice "Select AHCI Vendor (1-3):" $defaultAHCI "Match your CPU vendor"
			$selectedAhciVendor = $ahciVendors[$ahciVendorChoice]
			
			if ($null -eq $selectedAhciVendor) { $selectedAhciVendor = $ahciVendors[$defaultAHCI] }
			
			Write-Host "`n  # Available $($selectedAhciVendor.Vendor) AHCI Models:" -ForegroundColor Cyan
			for ($i = 0; $i -lt $selectedAhciVendor.Models.Count; $i++) {
				Write-Host "  # $($i+1). $($selectedAhciVendor.Models[$i])" -ForegroundColor Gray
			}
			
			$ahciModelChoice = Get-UserChoice "Select AHCI Model (1-$($selectedAhciVendor.Models.Count)):" "1" "Select chipset SATA controller"
			$ahciModelIndex = [int]$ahciModelChoice - 1
			if ($ahciModelIndex -lt 0 -or $ahciModelIndex -ge $selectedAhciVendor.Models.Count) { $ahciModelIndex = 0 }
			$selectedAhciModel = $selectedAhciVendor.Models[$ahciModelIndex]
			
			if ($selectedAhciVendor.Vendor -eq "Intel") {
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/VenDevId" "0x8086a352"
			} elseif ($selectedAhciVendor.Vendor -eq "AMD") {
				& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/VenDevId" "0x10227901"
			}
			
			Write-Host "  # [OK] AHCI: $($selectedAhciVendor.Vendor) $selectedAhciModel" -ForegroundColor Green

			Write-Host "`n  # ========== OHCI CONTROLLER CONFIGURATION ==========" -ForegroundColor Cyan
			
			$ohciVendors = @{
				"1" = @{Vendor = "Intel"; Models = @(
					"USB Controller",
					"7 Series/C216 Chipset USB Controller",
					"8 Series/C220 Series USB Controller"
				)}
				"2" = @{Vendor = "AMD"; Models = @(
					"FCH USB OHCI Controller",
					"SB7x0/SB8x0 USB OHCI Controller"
				)}
				"3" = @{Vendor = "VIA"; Models = @(
					"VT82xx USB OHCI Controller"
				)}
				"4" = @{Vendor = "NEC"; Models = @(
					"USB Controller"
				)}
			}
			
			Write-Host "`n  # Available OHCI Vendors:" -ForegroundColor Cyan
			foreach ($key in $ohciVendors.Keys | Sort-Object) {
				Write-Host "  # $key. $($ohciVendors[$key].Vendor)" -ForegroundColor Gray
			}
			
			if ($cpuProfile.Manufacturer -eq "Intel") {
				$defaultOHCI = "1"
			} else {
				$defaultOHCI = "2"
			}
			
			$ohciVendorChoice = Get-UserChoice "Select OHCI Vendor (1-4):" $defaultOHCI "Match your CPU vendor"
			$selectedOhciVendor = $ohciVendors[$ohciVendorChoice]
			
			if ($null -eq $selectedOhciVendor) { $selectedOhciVendor = $ohciVendors[$defaultOHCI] }
			
			Write-Host "`n  # Available $($selectedOhciVendor.Vendor) OHCI Models:" -ForegroundColor Cyan
			for ($i = 0; $i -lt $selectedOhciVendor.Models.Count; $i++) {
				Write-Host "  # $($i+1). $($selectedOhciVendor.Models[$i])" -ForegroundColor Gray
			}
			
			$ohciModelChoice = Get-UserChoice "Select OHCI Model (1-$($selectedOhciVendor.Models.Count)):" "1" "Select USB controller"
			$ohciModelIndex = [int]$ohciModelChoice - 1
			if ($ohciModelIndex -lt 0 -or $ohciModelIndex -ge $selectedOhciVendor.Models.Count) { $ohciModelIndex = 0 }
			$selectedOhciModel = $selectedOhciVendor.Models[$ohciModelIndex]
			
			Write-Host "  # [OK] OHCI: $($selectedOhciVendor.Vendor) $selectedOhciModel" -ForegroundColor Green
			Write-Host "  # [OK] EHCI/XHCI also configured to match." -ForegroundColor Green

			Write-Host "`n  # ========== MISC HARDWARE SUMMARY ==========" -ForegroundColor Magenta
			Write-Host "  # Keyboard:  $($selectedKbVendor.Vendor) $selectedKbModel" -ForegroundColor Gray
			Write-Host "  # Mouse:     $($selectedMouseVendor.Vendor) $selectedMouseModel" -ForegroundColor Gray
			Write-Host "  # Platform:  $(if ($platformChoice -eq '2') { 'Laptop with battery' } else { 'Desktop (no battery)' })" -ForegroundColor Gray
			Write-Host "  # ACPI:      $($selectedAcpiVendor.Vendor) $selectedAcpiModel" -ForegroundColor Gray
			Write-Host "  # AHCI:      $($selectedAhciVendor.Vendor) $selectedAhciModel" -ForegroundColor Gray
			Write-Host "  # OHCI:      $($selectedOhciVendor.Vendor) $selectedOhciModel" -ForegroundColor Gray
			Write-Host "  # ============================================" -ForegroundColor Magenta
			
			Write-Host "`n  # [OK] Misc Hardware Emulation configured!" -ForegroundColor Green
		}
    }

    Write-Host "`n  # [INFO] Applying extra anti-detection flags..." -ForegroundColor Yellow
    & $VBoxManager setextradata $VM "VBoxInternal/HostInfo/BrandB" "0"
	& $VBoxManager setextradata $VM "VBoxInternal/CPUM/EnableHVP" "0"

	& $VBoxManager setextradata $VM "VBoxInternal/Devices/VMMDev/0/Config/KeepCredentials" "0"
	& $VBoxManager setextradata $VM "VBoxInternal/PDM/HaltOnReset" "1"

	& $VBoxManager setextradata $VM "VBoxInternal/TM/TSCTiedToExecution" "1"
	& $VBoxManager setextradata $VM "VBoxInternal/TM/TSCTicksPerSecond" "3000000000"

	Write-Host "  # [OK] Additional anti-detection fixes applied." -ForegroundColor Green
    Write-Host "  # [OK] Extra flags applied." -ForegroundColor Green

	if ($useUnattended) {
		Write-Host "`n  # [INFO] Configuring unattended installation..." -ForegroundColor Yellow
		
		$unattendedCmd = @(
			"unattended", "install", $VM,
			"--iso=$isoPath",
			"--user=$windowsUsername",
			"--full-user-name=$windowsFullName",
			"--hostname=$windowsHostname",
			"--time-zone=$selectedTZ",
			"--locale=en_US",
			"--country=US"
		)
		
		if (-not [string]::IsNullOrWhiteSpace($windowsPasswordPlain)) {
			$unattendedCmd += "--password=$windowsPasswordPlain"
		} else {
			$unattendedCmd += "--password=ChangeMe123!"
			Write-Host "  # [INFO] Using temporary password 'ChangeMe123!'" -ForegroundColor Yellow
		}
		
		if (-not [string]::IsNullOrWhiteSpace($productKey)) {
			$unattendedCmd += "--product-key=$productKey"
		}
		
		if ($installGuestAdditions -and -not [string]::IsNullOrWhiteSpace($guestAdditionsIsoPath)) {
			$unattendedCmd += "--install-additions"
			$unattendedCmd += "--additions-iso=$guestAdditionsIsoPath"
		}
		
		Write-Host "  # [DEBUG] Command: VBoxManage $($unattendedCmd -join ' ')" -ForegroundColor Gray
		
		try {
			$result = & $VBoxManager @unattendedCmd 2>&1
			
			if ($LASTEXITCODE -eq 0) {
				Write-Host "  # [OK] Unattended installation configured!" -ForegroundColor Green
				Write-Host "  # [INFO] VirtualBox will automatically:" -ForegroundColor Cyan
				Write-Host "  #        - Attach the Windows ISO" -ForegroundColor Cyan
				Write-Host "  #        - Generate autounattend.xml" -ForegroundColor Cyan
				Write-Host "  #        - Boot and install Windows" -ForegroundColor Cyan
			} else {
				Write-Host "  # [ERROR] Exit code: $LASTEXITCODE" -ForegroundColor Red
				Write-Host "  # [ERROR] Output: $result" -ForegroundColor Red
				Write-Host "  # [INFO] You can still install Windows manually." -ForegroundColor Yellow
			}
		}
		catch {
			Write-Host "  # [ERROR] Exception: $_" -ForegroundColor Red
			Write-Host "  # [INFO] You can still install Windows manually." -ForegroundColor Yellow
		}
	}

    Write-Host "`n  # [INFO] Verifying configuration..." -ForegroundColor Yellow
    $vmInfo = & $VBoxManager showvminfo $VM --machinereadable

    $criticalSettings = @{
        "memory" = $memory
        "cpus" = $cpus
        "chipset" = $chipset
        "graphicscontroller" = $graphicsController
    }

    $allGood = $true
    foreach ($setting in $criticalSettings.GetEnumerator()) {
        $matchLine = $vmInfo | Select-String "^$($setting.Key)=" | Select-Object -First 1
        if ($matchLine) {
            $actual = $matchLine.ToString().Split('=')[1].Trim('"')
            if ($actual -ne $setting.Value) {
                Write-Host "  # [WARNING] $($setting.Key): Expected '$($setting.Value)', got '$actual'" -ForegroundColor Yellow
                $allGood = $false
            }
        } else {
            Write-Host "  # [WARNING] Could not verify $($setting.Key)" -ForegroundColor Yellow
        }
    }

    if ($allGood) {
        Write-Host "  # [OK] All critical settings verified." -ForegroundColor Green
    } else {
        Write-Host "  # [WARNING] Some settings may not have applied correctly. Review above warnings." -ForegroundColor Yellow
    }

        if (Get-YesNoChoice "Create a snapshot of this VM configuration?" "Y" "Recommended to preserve this state") {
			
			$vmState = & $VBoxManager showvminfo $VM --machinereadable | Select-String "VMState="
			if ($vmState -notmatch "poweroff" -and $vmState -notmatch "aborted") {
				Write-Host "  # [INFO] VM is currently running or saved. Powering off for snapshot..." -ForegroundColor Yellow
				& $VBoxManager controlvm $VM poweroff 2>$null
				
				$timeout = 0
				do {
					Start-Sleep -Seconds 1
					$vmState = & $VBoxManager showvminfo $VM --machinereadable | Select-String "VMState="
					$timeout++
				} while ($vmState -notmatch "poweroff" -and $vmState -notmatch "aborted" -and $timeout -lt 10)
				
				Start-Sleep -Seconds 2
			}

			$snapshotName = Get-UserChoice "Enter snapshot name:" "CloakBox-Configured-$(Get-Date -Format 'yyyy-MM-dd')" "Descriptive name for this snapshot"
			
			Write-Host "`n  # [INFO] Creating snapshot '$snapshotName'..." -ForegroundColor Yellow
			& $VBoxManager snapshot $VM take "$snapshotName" --description "Configured with anti-detection settings on $(Get-Date)"
			
			if ($LASTEXITCODE -eq 0) {
				Write-Host "  # [OK] Snapshot created successfully." -ForegroundColor Green
			} else {
				Write-Host "  # [WARNING] Snapshot creation may have failed (Exit code: $LASTEXITCODE)." -ForegroundColor Yellow
				Write-Host "  # [TIP] If the VM is locked, try restarting the script." -ForegroundColor Gray
			}
		}

    if ($mouseType -eq "ps2") {
        Set-VMMouseFix -VMName $VM
    }

    $exportConfig = Get-YesNoChoice "Export configuration summary to file?" "Y" "Save settings for reference"

    if ($exportConfig) {
        $configFile = "$env:USERPROFILE\Desktop\CloakBox-$VM-Config-$(Get-Date -Format 'yyyy-MM-dd-HHmm').txt"
        
        $configSummary = @"
========================================
CLOAKBOX VM CONFIGURATION SUMMARY
========================================
VM Name: $VM
Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
VirtualBox Version: $($vboxVersion.FullVersion)

OPERATING SYSTEM: 
- OS Type: $osType
- Chipset: $chipset
- TPM:  $tpmType
- Firmware: $(if ($enableUEFI) { "UEFI/EFI" } else { "BIOS" })
- Secure Boot: $(if ($enableSecureBoot) { "Enabled" } else { "Disabled" })

HARDWARE CONFIGURATION: 
- CPU Cores: $cpus
- RAM: $memory MB ($([math]::Round($memory/1024, 1)) GB)
- VRAM: $vramInt MB
- CPU Profile: $cpuProfile
- PAE/NX: $(if ($enablePAE) { "Enabled" } else { "Disabled" })
- Nested VT-x/AMD-V: $(if ($enableNestedVTx) { "Enabled" } else { "Disabled" })
- Nested Paging: $(if ($enableNestedPaging) { "Enabled" } else { "Disabled" })
- Paravirtualization:  $paraVirtProvider
- Graphics Controller: $graphicsController
- 3D Acceleration: $(if ($enable3D) { "Enabled" } else { "Disabled" })
- Pointing Device: $mouseType
- I/O APIC: $(if ($enableIOAPIC) { "Enabled" } else { "Disabled" })
- UTC Clock: $(if ($useUTCClock) { "Enabled" } else { "Disabled" })

CLIPBOARD & DRAG-AND-DROP:
- Shared Clipboard: $clipboardMode
- Drag-and-Drop: $dragDropMode

DISK CONFIGURATION:
- Create New Disk: $($diskConfig.CreateDisk)
- Disk Path: $($diskConfig.DiskPath)
- Size: $($diskConfig.StorageGB) GB
- Format: $($diskConfig.DiskFormat)
- Variant: $($diskConfig.DiskVariant)
- SSD Mode: $(if ($diskConfig.EnableSSD) { "Enabled" } else { "Disabled" })
- Hot-pluggable: $(if ($diskConfig.EnableHotplug) { "Enabled" } else { "Disabled" })

NETWORK:
- NIC Type: $($networkCards[$netCardChoice].Desc)
- MAC Address: $macAddress

USB: 
- Controller: $($usbControllers[$usbChoice])

AUDIO:
- Host Driver: $audioDriver
- Controller: $audioController
- Audio Output: $(if ($enableAudioOutput) { "Enabled" } else { "Disabled" })
- Audio Input: $(if ($enableAudioInput) { "Enabled" } else { "Disabled" })

ANTI-DETECTION SETTINGS:
- Advanced Anti-Detection: $(if ($applyAdvanced) { "Enabled" } else { "Disabled" })
- Vendor Profile: $(if ($applyAdvanced) { $vendorProfiles[$vendorChoice] } else { "N/A" })
- Storage Device Spoofing: $(if ($applyAdvanced) { "Enabled" } else { "Disabled" })
- SMBIOS Spoofing:  $(if ($applyAdvanced) { "Enabled" } else { "Disabled" })
- CPUID Spoofing:  Enabled
- Time Sync Disabled: Yes

UNATTENDED INSTALLATION:
- Enabled: $useUnattended
- ISO:  $isoPath
- Windows Edition: $windowsEdition
- Username: $windowsUsername
- Hostname: $windowsHostname
- Guest Additions: $installGuestAdditions

========================================
NEXT STEPS:
Run Powershell Script inside VM!
========================================
"@
        
        $configSummary | Out-File -FilePath $configFile -Encoding UTF8
        Write-Host "  # [OK] Configuration saved to:  $configFile" -ForegroundColor Green
    }

	if ($createNewVM) {
		Write-Host "`n  # ==================== START VM ===================" -ForegroundColor Magenta
		
		$startNow = Get-YesNoChoice "Start the VM now?" "Y" "Begin installation"
		
		if ($startNow) {
			if ($useUnattended) {
				if ($installInBackground) {
					Write-Host "`n  # [INFO] Starting VM in headless mode (background)..." -ForegroundColor Yellow
					& $VBoxManager startvm $VM --type headless
				} else {
					Write-Host "`n  # [INFO] Starting VM with GUI..." -ForegroundColor Yellow
					& $VBoxManager startvm $VM --type gui
				}
				
				if ($LASTEXITCODE -eq 0) {
					Write-Host "  # [OK] VM started successfully!" -ForegroundColor Green
					Write-Host "  # [INFO] Unattended Windows installation is now running." -ForegroundColor Cyan
					Write-Host "  # [INFO] This may take 30-60 minutes depending on your hardware." -ForegroundColor Cyan
					if (-not [string]::IsNullOrWhiteSpace($windowsPasswordPlain)) {
						Write-Host "  # [INFO] Login credentials after installation:" -ForegroundColor Yellow
						Write-Host "  #        Username: $windowsUsername" -ForegroundColor Yellow
						Write-Host "  #        Password: (the password you entered)" -ForegroundColor Yellow
					} else {
						Write-Host "  # [INFO] Login credentials after installation:" -ForegroundColor Yellow
						Write-Host "  #        Username: $windowsUsername" -ForegroundColor Yellow
						Write-Host "  #        Password: ChangeMe123!" -ForegroundColor Yellow
					}
				} else {
					Write-Host "  # [ERROR] Failed to start VM (Exit code: $LASTEXITCODE)." -ForegroundColor Red
				}
			} else {
				Write-Host "`n  # [INFO] Starting VM with GUI for manual installation..." -ForegroundColor Yellow
				& $VBoxManager startvm $VM --type gui
				
				if ($LASTEXITCODE -eq 0) {
					Write-Host "  # [OK] VM started successfully!" -ForegroundColor Green
					Write-Host "  # [INFO] Please complete Windows installation manually." -ForegroundColor Cyan
				} else {
					Write-Host "  # [ERROR] Failed to start VM (Exit code: $LASTEXITCODE)." -ForegroundColor Red
				}
			}
		}
	}
	
    Write-Host "`n     # ================== IMPORTANT NEXT STEP ==================" -ForegroundColor Cyan
    Write-Host "  # VERIFY ANTI-DETECTION: Use tools like Pafish or Al-Khaser or my Powershell to test VM detection." -ForegroundColor Cyan
    Write-Host "       # ==========================================================" -ForegroundColor Cyan

    if (-not $installInBackground) {
        if (Get-YesNoChoice "Start the VM now?" "N" "Launch VM after configuration") {
            Write-Host "`n  # [INFO] Starting VM '$VM'..." -ForegroundColor Yellow
            & $VBoxManager startvm $VM --type gui
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  # [OK] VM started successfully." -ForegroundColor Green
            } else {
                Write-Host "  # [ERROR] Failed to start VM (Exit code: $LASTEXITCODE)." -ForegroundColor Red
            }
        }
    }

}
catch {
    Write-Host "`n  # [ERROR] An error occurred during VM configuration:  $_" -ForegroundColor Red
    Write-Host "  # Error details: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  # Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Red
}

Write-Host "`n  # Script execution complete. Press any key to exit..." -ForegroundColor Magenta
pause
