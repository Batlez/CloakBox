$isAdministrator = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdministrator) {
    Write-Warning "Administrator privileges are required for this script."
    Write-Host "Attempting to re-launch with elevated privileges..." -ForegroundColor Yellow
    
    try {
        $scriptPath = $MyInvocation.MyCommand.Path
        $arguments = "& '$scriptPath' $args"
        
        Start-Process powershell.exe -ArgumentList $arguments -Verb RunAs -ErrorAction Stop
        
        Exit
    }
    catch {
        Write-Host "[ERROR] Failed to elevate." -ForegroundColor Red
        Write-Host "Please start a PowerShell session as an Administrator and run the script manually." -ForegroundColor Red
        
        if ($Host.UI.RawUI.KeyAvailable) { $Host.UI.RawUI.FlushInputBuffer() }
        Write-Host "Press any key to exit..."
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

Close-VirtualBoxProcesses

function Get-SystemInfo {
    $cpuInfo = Get-WmiObject -Class Win32_Processor
    $totalCores = 0
    foreach ($cpu in $cpuInfo) {
        $totalCores += $cpu.NumberOfCores
    }
    $cpuModel = $cpuInfo[0].Name
    $cpuManufacturer = if ($cpuModel -like "*Intel*") { "Intel" } else { "AMD" }
    
    $ramInfo = Get-WmiObject -Class Win32_ComputerSystem
    $totalRamGB = [math]::Round($ramInfo.TotalPhysicalMemory / 1GB)
    
    $systemDrive = $env:SystemDrive
    $driveInfo = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$systemDrive'"
    $totalStorageGB = [math]::Round($driveInfo.Size / 1GB)
    $freeStorageGB = [math]::Round($driveInfo.FreeSpace / 1GB)
    
    $gpuInfo = Get-WmiObject -Class Win32_VideoController
    $gpuName = $gpuInfo[0].Name
    
    return @{
        CPUCores = $totalCores
        CPUModel = $cpuModel
        CPUManufacturer = $cpuManufacturer
        TotalRAM_GB = $totalRamGB
        SystemDrive = $systemDrive
        TotalStorage_GB = $totalStorageGB
        FreeStorage_GB = $freeStorageGB
        GPUName = $gpuName
    }
}

function Get-RecommendedVMSettings {
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$SystemInfo
    )
    
    $recommendedCores = switch ($SystemInfo.CPUCores) {
        {$_ -le 2} { 1 }
        {$_ -le 4} { 2 }
        {$_ -le 6} { 3 }
        {$_ -le 8} { 4 }
        {$_ -le 10} { 6 }
        default { [math]::Floor($SystemInfo.CPUCores * 0.5) }
    }
    
    $recommendedRAM_MB = switch ($SystemInfo.TotalRAM_GB) {
        {$_ -lt 4} { 1024 }
        {$_ -lt 6} { 1536 }
        {$_ -lt 8} { 2048 }
        {$_ -lt 10} { 4096 }
        {$_ -lt 12} { 6144 }
        {$_ -lt 16} { 8192 }
        default { 8192 }
    }
    
    $recommendedStorage_GB = switch ($SystemInfo.TotalStorage_GB) {
        {$_ -lt 128} { 40 }
        {$_ -lt 256} { 65 }
        {$_ -lt 512} { 80 }
        default { 85 }
    }
    
    if ($recommendedStorage_GB -gt ($SystemInfo.FreeStorage_GB - 15)) {
        $recommendedStorage_GB = [math]::Max(20, $SystemInfo.FreeStorage_GB - 15)
    }
    
    if ($SystemInfo.CPUManufacturer -eq "Intel") {
        $recommendedCPUProfile = "Intel Core i7-8700"
        $recommendedCPUChoice = "2"
    } else {
        $recommendedCPUProfile = "AMD Ryzen 7 1800X Eight-Core" 
        $recommendedCPUChoice = "4"
    }
    
    return @{
        CPUCores = $recommendedCores
        RAM_MB = $recommendedRAM_MB
        Storage_GB = $recommendedStorage_GB
        CPUProfile = $recommendedCPUProfile
        CPUChoice = $recommendedCPUChoice
    }
}

Write-Host "`n  ###################################################" -ForegroundColor Magenta
Write-Host "  #                                                 #" -ForegroundColor Magenta
Write-Host "  #         BYPASS PROCTORING WITH CLOAKBOX         #" -ForegroundColor Magenta
Write-Host "  #                                                 #" -ForegroundColor Magenta
Write-Host "  ###################################################" -ForegroundColor Magenta
Write-Host "`n  # This tool will help you configure your Cloakbox VM to avoid detection." -ForegroundColor Cyan
Write-Host "  # Default values are shown in [brackets]." -ForegroundColor Cyan

Write-Host "`n  # [INFO] Analyzing your system hardware to recommend optimal VM settings..." -ForegroundColor Yellow
$systemInfo = Get-SystemInfo
$recommendedSettings = Get-RecommendedVMSettings -SystemInfo $systemInfo

Write-Host "`n  # ==================== SYSTEM DETECTED =====================" -ForegroundColor Magenta
Write-Host "  # CPU: $($systemInfo.CPUModel) ($($systemInfo.CPUCores) cores)" -ForegroundColor Gray
Write-Host "  # RAM: $($systemInfo.TotalRAM_GB) GB" -ForegroundColor Gray
Write-Host "  # Storage: $($systemInfo.FreeStorage_GB) GB free of $($systemInfo.TotalStorage_GB) GB total" -ForegroundColor Gray
Write-Host "  # GPU: $($systemInfo.GPUName)" -ForegroundColor Gray
Write-Host "  # ==========================================================" -ForegroundColor Magenta

Write-Host "`n  # ================ RECOMMENDED VM SETTINGS ================" -ForegroundColor Magenta
Write-Host "  # CPU Cores: $($recommendedSettings.CPUCores) cores" -ForegroundColor Gray
Write-Host "  # RAM: $([math]::Round($recommendedSettings.RAM_MB/1024, 1)) GB ($($recommendedSettings.RAM_MB) MB)" -ForegroundColor Gray
Write-Host "  # Storage: $($recommendedSettings.Storage_GB) GB" -ForegroundColor Gray
Write-Host "  # CPU Profile: $($recommendedSettings.CPUProfile)" -ForegroundColor Gray
Write-Host "  # ==========================================================" -ForegroundColor Magenta

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

try {
    Write-Host "`n  # Available VMs on this system (May take a few seconds):`n" -ForegroundColor Cyan
    & $VBoxManager list vms
    $VM = Read-Host "`n  # Enter the exact VM Name from the list above"
    
    if ([string]::IsNullOrWhiteSpace($VM)) {
        Write-Host "`n  # [ERROR] No VM name entered. Aborting script." -ForegroundColor Red
        pause
        exit 1
    }
    
    $VDI = "$env:USERPROFILE\VirtualBox VMs\$VM\$VM.vdi"

    Write-Host "`n  # ==================== BASE CONFIGURATION ===================" -ForegroundColor Magenta
    
    $defaultMemory = $recommendedSettings.RAM_MB.ToString()
    $memory = Get-UserChoice "Enter memory size in MB:" $defaultMemory "Recommended based on your system ($([math]::Round($recommendedSettings.RAM_MB/1024, 1)) GB)"
    
    $defaultCPUs = $recommendedSettings.CPUCores.ToString()
    $cpus = Get-UserChoice "Enter number of CPU cores:" $defaultCPUs "Recommended based on your system ($($recommendedSettings.CPUCores) cores)"
    
    $cpuProfiles = @{
        "1" = "Intel Core i7-6700"
        "2" = "Intel Core i7-8700"
        "3" = "AMD Ryzen 5 3600"
        "4" = "AMD Ryzen 7 1800X Eight-Core"
    }
    
    Write-Host "`n  # Available CPU profiles:" -ForegroundColor Cyan
    foreach ($key in $cpuProfiles.Keys | Sort-Object) {
        if ($key -eq $recommendedSettings.CPUChoice) {
            Write-Host "  #   $key. $($cpuProfiles[$key]) (RECOMMENDED)" -ForegroundColor Green
        } else {
            Write-Host "  #   $key. $($cpuProfiles[$key])" -ForegroundColor Gray
        }
    }
    
    $cpuChoice = Get-UserChoice "Select a CPU profile (1-4):" $recommendedSettings.CPUChoice "Recommended based on your CPU type"
    $cpuProfile = $cpuProfiles[$cpuChoice]
    
    if ([string]::IsNullOrWhiteSpace($cpuProfile)) {
        $cpuProfile = $cpuProfiles[$recommendedSettings.CPUChoice]
        Write-Host "  # [INFO] Using recommended CPU profile: $cpuProfile" -ForegroundColor Yellow
    }

	$usbControllers = @{
		"1" = "USB 1.1 (OHCI)"
		"2" = "USB 2.0 (EHCI)" 
		"3" = "USB 3.0 (xHCI)"
	}

	Write-Host "`n  # Available USB controllers:" -ForegroundColor Cyan
	foreach ($key in $usbControllers.Keys | Sort-Object) {
		Write-Host "  #   $key. $($usbControllers[$key])" -ForegroundColor Gray
	}

	$defaultUSB = "3"
	$usbChoice = Get-UserChoice "Select a USB controller (1-3):" $defaultUSB "USB 3.0 recommended for webcams and modern devices"

	switch ($usbChoice) {
		"1" { 
			& $VBoxManager modifyvm $VM --usb on
			& $VBoxManager modifyvm $VM --usbehci off 
			& $VBoxManager modifyvm $VM --usbxhci off 
		}
		"2" { 
			& $VBoxManager modifyvm $VM --usb on
			& $VBoxManager modifyvm $VM --usbehci on 
			& $VBoxManager modifyvm $VM --usbxhci off 
		}
		"3" { 
			& $VBoxManager modifyvm $VM --usb on
			& $VBoxManager modifyvm $VM --usbehci off 
			& $VBoxManager modifyvm $VM --usbxhci on 
		}
		default { 
			& $VBoxManager modifyvm $VM --usb on
			& $VBoxManager modifyvm $VM --usbehci off 
			& $VBoxManager modifyvm $VM --usbxhci on 
		}
	}	

	$networkCards = @{
		"1" = @{Name = "82540EM"; Desc = "Intel PRO/1000 MT Desktop (Recommended)"}
		"2" = @{Name = "82543GC"; Desc = "Intel PRO/1000 T Server"}
		"3" = @{Name = "82545EM"; Desc = "Intel PRO/1000 MT Server"}
		"4" = @{Name = "virtio";   Desc = "VirtIO"}
	}

	Write-Host "`n  # Available network card models:" -ForegroundColor Cyan
	foreach ($key in $networkCards.Keys | Sort-Object) {
		Write-Host "  #   $key. $($networkCards[$key].Desc)" -ForegroundColor Gray
	}

	$defaultNetCard = "1"
	$netCardChoice = Get-UserChoice "Select a network card model (1-4):" $defaultNetCard "Intel PRO/1000 MT Desktop has best compatibility"

	try {
		Write-Host "  # [INFO] Setting network adapter type..." -ForegroundColor Yellow
    
		switch ($netCardChoice) {
			"1" { & $VBoxManager modifyvm $VM --nictype1 82540EM }
			"2" { & $VBoxManager modifyvm $VM --nictype1 82543GC }
			"3" { & $VBoxManager modifyvm $VM --nictype1 82545EM }
			"4" { & $VBoxManager modifyvm $VM --nictype1 virtio }
			default { & $VBoxManager modifyvm $VM --nictype1 82540EM }
		}
    
		Write-Host "  # [OK] Network adapter type set to $($networkCards[$netCardChoice].Desc)" -ForegroundColor Green
	}
	catch {
		Write-Host "  # [ERROR] Failed to set network adapter: $($_.Exception.Message)" -ForegroundColor Red
	}

    $generateRandomMAC = Get-YesNoChoice "Generate a random realistic MAC address?" "Y" "Recommended for anti-detection"
    
    if ($generateRandomMAC) {
        $validOUIs = @("00:1A:A0", "14:5A:05", "48:82:44", "D4:81:D7", "C8:5B:76")
        $randomOUI = $validOUIs | Get-Random
        $randomMAC = $randomOUI
        foreach ($i in 0..2) {
            $randomMAC += ":" + ("{0:X2}" -f (Get-Random -Minimum 0 -Maximum 255))
        }
        Write-Host "  # [INFO] Generated MAC address: $randomMAC" -ForegroundColor Yellow
        $macAddress = $randomMAC.Replace(":", "")
    } else {
        $defaultMAC = "BC4A68D3F871"
        $macAddress = Get-UserChoice "Enter MAC address (without colons):" $defaultMAC "Example: BC4A68D3F871"
    }

    $defaultStorageGB = $recommendedSettings.Storage_GB.ToString()
    $storageGB = Get-UserChoice "Enter VM storage size in GB:" $defaultStorageGB "Recommended based on your system ($($recommendedSettings.Storage_GB) GB)"

    Write-Host "`n  # ================== ADVANCED CONFIGURATION =================" -ForegroundColor Magenta
    
    $applyAdvanced = Get-YesNoChoice "Apply advanced anti-detection settings?" "Y" "Recommended for maximum concealment"
    
    if ($applyAdvanced) {
        Write-Host "`n  # Available hardware vendor profiles:" -ForegroundColor Cyan
        $vendorProfiles = @{
            "1" = "MSI"
            "2" = "ASUS"
            "3" = "Gigabyte"
            "4" = "ASRock"
        }
        
        foreach ($key in $vendorProfiles.Keys | Sort-Object) {
            Write-Host "  #   $key. $($vendorProfiles[$key])" -ForegroundColor Gray
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
            Write-Host "  #   $key. $($storageProfiles[$key])" -ForegroundColor Gray
        }
        
        $defaultStorage = "1"
        $storageChoice = Get-UserChoice "Select a storage device profile (1-4):" $defaultStorage "Samsung SSDs are common and realistic"
        $storageDevice = $storageProfiles[$storageChoice]
        
        if ([string]::IsNullOrWhiteSpace($storageDevice)) {
            $storageDevice = $storageProfiles[$defaultStorage]
        }
        
        $audioControllers = @{
            "1" = "ac97"   # Legacy Sound Blaster
            "2" = "hda"    # Intel HD Audio
            "3" = "sb16"   # Sound Blaster 16
        }
        
        Write-Host "`n  # Available audio controller types:" -ForegroundColor Cyan
        foreach ($key in $audioControllers.Keys | Sort-Object) {
            Write-Host "  #   $key. $($audioControllers[$key])" -ForegroundColor Gray
        }
        
        $defaultAudio = "2"
        $audioChoice = Get-UserChoice "Select an audio controller (1-3):" $defaultAudio "Intel HD Audio is most common"
        $audioController = $audioControllers[$audioChoice]
        
        if ([string]::IsNullOrWhiteSpace($audioController)) {
            $audioController = $audioControllers[$defaultAudio]
        }
    }

    $vmExists = & $VBoxManager showvminfo $VM 2>&1
    $createNewVM = $vmExists -like "*VBOX_E_OBJECT_NOT_FOUND*"
    
    if ($createNewVM) {
        Write-Host "`n  # [INFO] VM '$VM' does not exist. Creating new VM..." -ForegroundColor Yellow
        
        & $VBoxManager createvm --name $VM --ostype "Windows10_64" --register
        
        $vmFolder = "$env:USERPROFILE\VirtualBox VMs\$VM"
        $vdiPath = "$vmFolder\$VM.vdi"
        & $VBoxManager createhd --filename $vdiPath --size (([int]$storageGB) * 1024) --variant Standard
        
        & $VBoxManager storagectl $VM --name "SATA Controller" --add sata --controller IntelAhci
        
        & $VBoxManager storageattach $VM --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium $vdiPath
        
        Write-Host "  # [OK] VM created with $storageGB GB storage space." -ForegroundColor Green
    } else {
        Write-Host "`n  # [INFO] VM '$VM' already exists. Applying configuration changes..." -ForegroundColor Yellow
    }
    
    Write-Host "`n  # [INFO] Starting VM configuration for '$VM'..." -ForegroundColor Yellow
    
    Write-Host "`n  # [INFO] Applying base configuration..." -ForegroundColor Yellow
    & $VBoxManager modifyvm $VM --clipboard "bidirectional" --draganddrop "bidirectional"
    & $VBoxManager modifyvm $VM --mouse "ps2" --keyboard "ps2"
    & $VBoxManager modifyvm $VM --pae "on"
    & $VBoxManager modifyvm $VM --nestedpaging "on"
    & $VBoxManager modifyvm $VM --audioout "on" --audioin "on"
    & $VBoxManager modifyvm $VM --macaddress1 $macAddress
    & $VBoxManager modifyvm $VM --hwvirtex "on" --vtxux "on"
    & $VBoxManager modifyvm $VM --largepages "on"
    & $VBoxManager modifyvm $VM --vram "256" --memory $memory
    & $VBoxManager modifyvm $VM --apic "on"
    & $VBoxManager modifyvm $VM --cpus $cpus
    & $VBoxManager modifyvm $VM --cpuexecutioncap "100"
    & $VBoxManager modifyvm $VM --paravirtprovider "legacy"
    & $VBoxManager modifyvm $VM --chipset "piix3"
    & $VBoxManager modifyvm $VM --usb "on"
    & $VBoxManager modifyvm $VM --accelerate3d "on" --accelerate2dvideo "on"
    Write-Host "  # [OK] Base configuration applied." -ForegroundColor Green

    Write-Host "`n  # [INFO] Applying CPU profile and deep CPUID spoofing..." -ForegroundColor Yellow
    & $VBoxManager modifyvm $VM --cpu-profile $cpuProfile
	& $VBoxManager setextradata $VM "VBoxInternal/TM/TSCTiedToExecution" "1"
	& $VBoxManager setextradata $VM "VBoxInternal/CPUM/NestedHWVirt" "1"
	& $VBoxManager setextradata $VM "VBoxInternal/TM/WarpDrivePercentage" "100"
    & $VBoxManager setextradata $VM "VBoxInternal/TM/TSCMode" "RealTSCOffset"
    & $VBoxManager setextradata $VM "VBoxInternal/CPUM/SSE4.1" "1"
    & $VBoxManager setextradata $VM "VBoxInternal/CPUM/SSE4.2" "1"
    
    if ($cpuProfile -like "*Intel*") {
        & $VBoxManager modifyvm $VM --cpuid-set "00000001" "000906e9" "05100800" "7ed8320b" "bfebfbff"
    } else {
        & $VBoxManager modifyvm $VM --cpuid-set "00000001" "00a60f12" "02100800" "7ed8320b" "178bfbff"
    }
    Write-Host "  # [OK] CPU profile, timing, and raw CPUID values applied." -ForegroundColor Green

    if ($applyAdvanced) {
        Write-Host "`n  # [INFO] Applying SMBIOS (DMI) spoofing..." -ForegroundColor Yellow
        
        switch ($vendorChoice) {
            # MSI
            "1" {
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVendor" "American Megatrends International, LLC."
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVersion" "1.A0"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseDate" "11/23/2023"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVendor" "Micro-Star International Co., Ltd."
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemProduct" "MS-7D78"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVersion" "1.0"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardVendor" "Micro-Star International Co., Ltd."
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardProduct" "PRO B650-P WIFI (MS-7D78)"
            }
            # ASUS
            "2" {
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVendor" "American Megatrends Inc."
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVersion" "2402"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseDate" "12/15/2023"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVendor" "ASUSTeK COMPUTER INC."
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemProduct" "ROG STRIX B650E-F GAMING WIFI"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVersion" "Rev 1.xx"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardVendor" "ASUSTeK COMPUTER INC."
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardProduct" "ROG STRIX B650E-F GAMING WIFI"
            }
            # Gigabyte
            "3" {
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVendor" "American Megatrends International, LLC."
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVersion" "F5a"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseDate" "09/28/2023"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVendor" "Gigabyte Technology Co., Ltd."
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemProduct" "B650 AORUS ELITE AX"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVersion" "x.x"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardVendor" "Gigabyte Technology Co., Ltd."
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardProduct" "B650 AORUS ELITE AX"
            }
            # ASRock
            "4" {
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVendor" "American Megatrends Inc."
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVersion" "1.90"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseDate" "01/05/2024"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVendor" "ASRock"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemProduct" "B650E PG Lightning"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVersion" "1.0"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardVendor" "ASRock"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardProduct" "B650E PG Lightning"
            }
            default {
                # MSI
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVendor" "American Megatrends International, LLC."
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVersion" "1.A0"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseDate" "11/23/2023"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVendor" "Micro-Star International Co., Ltd."
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemProduct" "MS-7D78"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVersion" "1.0"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardVendor" "Micro-Star International Co., Ltd."
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardProduct" "PRO B650-P WIFI (MS-7D78)"
            }
        }
        
        & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemSerial" "To be filled by O.E.M."
        & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemFamily" "To be filled by O.E.M."
        & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardVersion" "1.0"
        & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardSerial" "To be filled by O.E.M."
        & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiChassisVendor" "Default string"
        & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiChassisType" 3
        & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiChassisVersion" "1.0"
        & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiChassisSerial" "To be filled by O.E.M."
        & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiProcManufacturer" "Advanced Micro Devices, Inc."
        & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiProcVersion" $cpuProfile
        & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiOEMVBoxVer" "<EMPTY>"
        & $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiOEMVBoxRev" "<EMPTY>"
        Write-Host "  # [OK] DMI strings set to mimic a real motherboard." -ForegroundColor Green

        Write-Host "`n  # [INFO] Applying storage device spoofing..." -ForegroundColor Yellow
        switch ($storageChoice) {
            "1" {
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/ModelNumber" "Samsung SSD 980 EVO"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/FirmwareRevision" "L4Q8G9Y1"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/SerialNumber" "J8R9H3P5N4Q7W0X2Y9A5"
            }
            "2" {
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/ModelNumber" "Samsung SSD 870 EVO"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/FirmwareRevision" "SVT01B6Q"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/SerialNumber" "S62SNJ0R853409K"
            }
            "3" {
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/ModelNumber" "WD Blue SN570 NVMe SSD"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/FirmwareRevision" "234100WD"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/SerialNumber" "WD-WXK2A36559MK"
            }
            "4" {
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/ModelNumber" "Crucial MX500 SSD"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/FirmwareRevision" "M3CR023"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/SerialNumber" "2119E5CB2CAB"
            }
            default {
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/ModelNumber" "Samsung SSD 980 EVO"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/FirmwareRevision" "L4Q8G9Y1"
                & $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/SerialNumber" "J8R9H3P5N4Q7W0X2Y9A5"
            }
        }
        
        & $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/NonRotational" "1" # SSD
        & $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/IgnoreFlush" "0"
        & $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/WriteCache" "1"
        & $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port1/ATAPIProductId" "DVD A DS8A8SH"
        & $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port1/ATAPIRevision" "KAA2"
        & $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port1/ATAPIVendorId" "Slimtype"
        Write-Host "  # [OK] Storage device strings have been spoofed." -ForegroundColor Green

        Write-Host "`n  # [INFO] Applying audio device spoofing..." -ForegroundColor Yellow
        & $VBoxManager modifyvm $VM --audiocontroller $audioController
        
		if ($audioController -eq "hda") {
			& $VBoxManager modifyvm $VM --audiocontroller hda
		}
		elseif ($audioController -eq "ac97") {
			& $VBoxManager modifyvm $VM --audiocontroller ac97
		}
		elseif ($audioController -eq "sb16") {
			& $VBoxManager modifyvm $VM --audiocontroller sb16
		}
        Write-Host "  # [OK] Audio device configured." -ForegroundColor Green

        Write-Host "`n  # [INFO] Configuring time synchronization controls..." -ForegroundColor Yellow
        & $VBoxManager setextradata $VM "VBoxInternal/Devices/VMMDev/0/Config/GetHostTimeDisabled" "1"
        Write-Host "  # [OK] Time synchronization controls modified." -ForegroundColor Green

        Write-Host "`n  # [INFO] Configuring console output and boot display..." -ForegroundColor Yellow
        & $VBoxManager modifyvm $VM --biosbootmenu "messageandmenu"
        & $VBoxManager modifyvm $VM --bioslogofadein "off" --bioslogofadeout "off"
        & $VBoxManager modifyvm $VM --bioslogodisplaytime 0
        Write-Host "  # [OK] Console and boot display configured." -ForegroundColor Green
    }

    Write-Host "`n  # [INFO] Applying extra anti-detection flags..." -ForegroundColor Yellow
    & $VBoxManager setextradata $VM "VBoxInternal/HostInfo/BrandB" "0"
    Write-Host "  # [OK] Extra flags applied." -ForegroundColor Green
    
    Write-Host "`n  # [SUCCESS] All VM configurations have been applied successfully to '$VM'." -ForegroundColor Green

    Write-Host "`n  # ================== IMPORTANT NEXT STEPS ==================" -ForegroundColor Cyan
    Write-Host "  # The following steps MUST be performed INSIDE the guest OS for maximum undetectability:" -ForegroundColor Cyan
    Write-Host "  #" -ForegroundColor Cyan
    Write-Host "  # 1. CHECK DEVICE MANAGER: Manually look for any remaining devices that mention 'VirtualBox' or 'VBox'." -ForegroundColor Cyan
    Write-Host "  #" -ForegroundColor Cyan
    Write-Host "  # 2. REGISTRY CLEANUP: After OS installation, carefully search the registry for the strings" -ForegroundColor Cyan
    Write-Host "  #    'VirtualBox', 'VBox', and 'Oracle' and remove or rename them." -ForegroundColor Cyan
    Write-Host "  #" -ForegroundColor Cyan
    Write-Host "  # 3. INSTALL GUEST ADDITIONS CAREFULLY: If needed, install them but remove detection fingerprints." -ForegroundColor Cyan
    Write-Host "  # ===========================================================" -ForegroundColor Cyan

}
catch {
    Write-Host "`n  # [ERROR] An error occurred during VM configuration: $_" -ForegroundColor Red
    Write-Host "  # Error details: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  # Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Red
}

Write-Host "`n  # Script execution complete. Press any key to exit..." -ForegroundColor Magenta
pause