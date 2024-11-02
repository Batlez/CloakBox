#################################################
## RUN IN VM.ps1: A script that attempts to hide the VirtualBox hypervisor from malware by modifying registry keys, killing associated processes, and removing uneeded driver/system files.
## Written and tested on Windows 7 and Windows 10. Should work for Windows 11 as well!
## Many thanks to pafish for some of the ideas - https://github.com/a0rtega/pafish
##################################################
## Author: d4rksystem & Scrut1ny
## Version: 1
##################################################

# Define command line parameters
param (
    [switch]$all = $true,
    [switch]$reg = $false,
    [switch]$procs = $false,
    [switch]$files = $false,
	[switch]$extra = $false
)

if ($all) {
    $reg = $true
    $procs = $true
    $files = $true
	$extra = $true
}
if ($extra) {
# ==================================================
# Admin Check
# ==================================================


if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$($PWD.Path)' ; & '$($myInvocation.InvocationName)'`"" -Verb RunAs
    Exit
}

# -------------------------------------------------------------------------------------------------------
# Define random string generator function

function Get-RandomString {

    $charSet = "abcdefghijklmnopqrstuvwxyz0123456789".ToCharArray()
    
    for ($i = 0; $i -lt 10; $i++ ) {
        $randomString += $charSet | Get-Random
    }

    return $randomString
 }
}
# -------------------------------------------------------------------------------------------------------
# Stop VBox Processes

$process_list = "VBoxTray", "VBoxService", "VBoxControl"

if ($procs) {

    Write-Output "[*] Attempting to kill VirtualBox processes..."

    foreach ($p in $process_list) {

        $process = Get-Process "$p" -ErrorAction SilentlyContinue

        if ($process) {
            $process | Stop-Process -Force
            Write-Output "[+] $p process killed!"
        }

        if (!$process) {
            Write-Output "[!] $p process does not exist!"
        }
     }        
}

# ==================================================
# Host and NetBIOS name Spoof
# ==================================================


$RandomString = -join ((48..57) + (65..90) | Get-Random -Count '7' | % {[char]$_})

# Local Computer Name (Device Name) & Network Computer Name (NetBIOS Name)
Rename-Computer -NewName "DESKTOP-$RandomString" -Force *>$null

# ==================================================
# Legit Install Date & Time Spoof
# ==================================================


# Generating a random date between Jan 1, 2011, and Dec 31, 2022
$start = [datetime]::new(2011, 1, 1)
$end = [datetime]::new(2022, 12, 31)
$randomDate = $start.AddSeconds((Get-Random -Maximum (($end - $start).TotalSeconds)))

# Converting the DateTime object to Unix timestamp
$unixTimestamp = [int][double]::Parse(($randomDate.ToUniversalTime() - [datetime]'1970-01-01T00:00:00').TotalSeconds)

# Calculating LDAP/FILETIME timestamp directly
$LDAP_FILETIME_timestamp = ($unixTimestamp + 11644473600) * 10000000

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "InstallDate" -Value "$unixTimestamp" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "InstallTime" -Value "$LDAP_FILETIME_timestamp" -Force

if ((Get-Service w32time).Status -eq 'Stopped') {
	Start-Service -Name w32time
}

w32tm /config /syncfromflags:manual /manualpeerlist:"0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org" /update
Restart-Service -Name w32time -Force ; w32tm /resync

# ==================================================
# Device Manager: 'Friendly name' Spoof
# ==================================================


$deviceIDs = (Get-CimInstance Win32_PnPEntity | Where-Object { $_.Name -like '*VBOX*' -or $_.Name -like '*VMware*' -or $_.PNPDeviceID -like '*VBOX*' -or $_.PNPDeviceID -like '*VMware*' }).DeviceID

foreach ($deviceID in $deviceIDs) {
	$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\$deviceID"
	Set-ItemProperty -Path "$registryPath" -Name "FriendlyName" -Value "Samsung SSD 980 500GB" -Force
}

# -------------------------------------------------------------------------------------------------------
# Modify VBox registry keys

if ($reg) {

    # Modify system BIOS version

    if (Get-ItemProperty -Path "HKLM:\HARDWARE\Description\System" -Name "SystemBiosVersion" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Modifying Reg Key HKLM:\HARDWARE\Description\System\SystemBiosVersion..."
	    Set-ItemProperty -Path "HKLM:\HARDWARE\Description\System" -Name "SystemBiosVersion" -Value $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\HARDWARE\Description\System\SystemBiosVersion does not seem to exist! Skipping this one..."
    }

	# HardwareConfig
	
	$lastConfig = Get-ItemProperty -Path "HKLM:\SYSTEM\HardwareConfig" -Name "LastConfig"
	$guidValue = $lastConfig.LastConfig
	Set-ItemProperty -Path "HKLM:\SYSTEM\HardwareConfig\$guidValue" -Name "SystemBiosVersion" -Value "ALASKA - 1072009", "1.C0", "American Megatrends - 50020" -Force
	Set-ItemProperty -Path "HKLM:\SYSTEM\HardwareConfig\$guidValue" -Name "SystemFamily" -Value "To be filled by O.E.M." -Force
	
	
	# Monitor
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "DriverDesc" -Value "NVIDIA GeForce RTX 3050" -Force
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "HardwareInformation.AdapterString" -Value "NVIDIA GeForce RTX 3050" -Force
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "HardwareInformation.BiosString" -Value "Version94.6.37.0.40" -Force
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "HardwareInformation.ChipType" -Value "NVIDIA GeForce RTX 3050" -Force
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "HardwareInformation.DacType" -Value "Integrated RAMDAC" -Force
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "ProviderName" -Value "NVIDIA" -Force
	
    # Modify CurrentControlSet BIOS info

    if (Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Modifying Reg Key Values in HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation..."
	    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -Name "BIOSVersion" -Value $(Get-RandomString)
	    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -Name "BIOSReleaseDate" -Value $(Get-RandomString)
	    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -Name "BIOSProductName" -Value $(Get-RandomString)
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -Name "SystemManufacturer" -Value "Micro-Star International Co., Ltd." -Force

    } Else {

        Write-Output "[!] Reg Key HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation does not seem to exist! Skipping this one..."
    }

    # Modify system BIOS date

    if (Get-ItemProperty -Path "HKLM:\HARDWARE\Description\System" -Name "SystemBiosDate" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Modifying Reg Key HKLM:\HARDWARE\Description\System\SystemBiosDate"
	    Set-ItemProperty -Path "HKLM:\HARDWARE\Description\System" -Name "SystemBiosDate" -Value $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\HARDWARE\Description\System\SystemBiosDate does not seem to exist! Skipping this one..."
    }

    # Modify system BIOS Video Version

    if (Get-ItemProperty -Path "HKLM:\HARDWARE\Description\System" -Name "VideoBiosVersion" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Modifying Reg Key HKLM:\HARDWARE\Description\System\VideoBiosVersion"
	    Set-ItemProperty -Path "HKLM:\HARDWARE\Description\System" -Name "VideoBiosVersion" -Value $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\HARDWARE\Description\System\VideoBiosVersion does not seem to exist! Skipping this one..."
    }

    # Rename Guest Additions Reg Key

    if (Get-Item -Path "HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Renaming Reg Key HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions"
	    Rename-Item -Path "HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions" -NewName $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions does not seem to exist, or has already been renamed! Skipping this one..."
    }

	# Remove VBox services
	Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*VBox*" } | ForEach-Object {
		Remove-Item $_.PSPath -Recurse -Force
	}

	# Remove VBox drivers
	Get-ChildItem "$env:windir\System32\drivers\VBox*" -ErrorAction SilentlyContinue | ForEach-Object {
		Remove-Item $_.FullName -Recurse -Force
	}
	
    # Rename ACPI DSDT Reg Key

    if (Get-Item -Path "HKLM:\HARDWARE\ACPI\DSDT\VBOX__" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Renaming Reg Key HKLM:\HARDWARE\ACPI\DSDT\VBOX__"
	    Rename-Item -Path "HKLM:\HARDWARE\ACPI\DSDT\VBOX__" -NewName $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\HARDWARE\ACPI\DSDT\VBOX__ does not seem to exist, or has already been renamed! Skipping this one..."
    }

    # Rename ACPI FADT Reg Key

    if (Get-Item -Path "HKLM:\HARDWARE\ACPI\FADT\VBOX__" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Renaming Reg Key HKLM:\HARDWARE\ACPI\FADT\VBOX__"
	    Rename-Item -Path "HKLM:\HARDWARE\ACPI\FADT\VBOX__" -NewName $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\HARDWARE\ACPI\FADT\VBOX__ does not seem to exist, or has already been renamed! Skipping this one..."
    }

    # Rename ACPI RSDT Reg Key

    if (Get-Item -Path "HKLM:\HARDWARE\ACPI\RSDT\VBOX__" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Renaming Reg Key HKLM:\HARDWARE\ACPI\RSDT\VBOX__"
	    Rename-Item -Path "HKLM:\HARDWARE\ACPI\RSDT\VBOX__" -NewName $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\HARDWARE\ACPI\RSDT\VBOX__ does not seem to exist, or has already been renamed! Skipping this one..."
    }

	# Rename ACPI SSDT Reg Key
	
    if (Get-Item -Path "HKLM:\HARDWARE\ACPI\SSDT\VBOX__" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Renaming Reg Key HKLM:\HARDWARE\ACPI\SSDT\VBOX__"
	    Rename-Item -Path "HKLM:\HARDWARE\ACPI\SSDT\VBOX__" -NewName $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\HARDWARE\ACPI\SSDT\VBOX__ does not seem to exist, or has already been renamed! Skipping this one..."
    }
	
    # Rename VBoxMouse Reg Key

    if (Get-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxMouse" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Renaming Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxMouse"
	    Rename-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxMouse" -NewName $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxMouse does not seem to exist, or has already been renamed! Skipping this one..."
    }

    # Rename VBoxService Reg Key

    if (Get-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxService" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Renaming Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxService"
	    Rename-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxService" -NewName $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxService does not seem to exist, or has already been renamed! Skipping this one..."
    }

    # Rename VBoxSF Reg Key

    if (Get-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxSF" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Renaming Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxSF"
	    Write-Output "[!] Warning: This will disconnect VM shared folders. You will need to reconnect them later..."
	    Rename-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxSF" -NewName $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxSF does not seem to exist, or has already been renamed! Skipping this one..."
    }

    # Rename VBoxVideo Reg Key

    if (Get-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxVideo" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Renaming Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxVideo"
	    Rename-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxVideo" -NewName $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxVideo does not seem to exist, or has already been renamed! Skipping this one..."
    }

    # Rename VBoxGuest Reg Key

    if (Get-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxGuest" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Renaming Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxGuest"
	    Rename-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxGuest" -NewName $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxGuest does not seem to exist, or has already been renamed! Skipping this one..."
    }

    # Rename VBoxTray Reg Key

    if (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "VBoxTray" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Renaming Reg Key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\VBoxTray"
	    Rename-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "VBoxTray" -NewName $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\VBoxTray does not seem to exist, or has already been renamed! Skipping this one..."
    }

    # Rename VBox Uninstaller Reg Key

    if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Oracle VM VirtualBox Guest Additions" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Renaming Reg Key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Oracle VM VirtualBox Guest Additions"
	    Rename-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Oracle VM VirtualBox Guest Additions" -NewName $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Oracle VM VirtualBox Guest Additions does not seem to exist, or has already been renamed! Skipping this one..."
    }
	
}

# ==================================================
# HKLM:\HARDWARE\DEVICEMAP\Scsi
# ==================================================


function Get-UpperRandomString {
    $Identifier = -join (1..20 | ForEach {[char]((65..90) + (48..57) | Get-Random)})
    return $Identifier
}

# Physical Drives (SATA/NVMe)
foreach ($PortNumber in 0..9) {
    foreach ($BusNumber in 0..9) {
	foreach ($LogicalUnitIdNumber in 0..9) {
		$registryPath = "HKLM:\HARDWARE\DEVICEMAP\Scsi\Scsi Port $PortNumber\Scsi Bus $BusNumber\Target Id 0\Logical Unit Id $LogicalUnitIdNumber"

		if (Test-Path -Path $registryPath) {
			$NewString = Get-UpperRandomString
			Set-ItemProperty -Path "$registryPath" -Name 'Identifier' -Type String -Value "NVMe    Samsung SSD 980 FXO7" -Force
			Set-ItemProperty -Path "$registryPath" -Name 'SerialNumber' -Type String -Value "$NewString" -Force
		}
	}
    }
}

# ==================================================
# Custom DNS
# ==================================================


# Quad9 DNS servers
$Ipv4PrimaryDns = '9.9.9.9'
$Ipv4BackupDns = '149.112.112.112'
$Ipv6PrimaryDns = '2620:fe::fe'
$Ipv6BackupDns = '2620:fe::9'

Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {
    Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses $Ipv4PrimaryDns, $Ipv4BackupDns, $Ipv6PrimaryDns, $Ipv6BackupDns
}

Clear-DnsClientCache

# -------------------------------------------------------------------------------------------------------
# Rename VBox Files

if ($files) {
	
	# Rename driver files
	
	$file_list = "VBoxMouse.sys", "VBoxSF.sys", "VBoxWddm.sys", "VBoxGuest.sys"

	Write-Output "[*] Attempting to rename VirtualBox driver files..."

    foreach ($f in $file_list) {

		Write-Output "[+] Attempting to rename $f..."
		
		try {
			Rename-Item "C:\Windows\System32\drivers\$f" "C:\Windows\System32\drivers\$(Get-RandomString).sys" -ErrorAction Stop
		}
		
		catch {
			Write-Output "[!] File does not seem to exist! Skipping..."
		}
	}

	# Rename system32 executable files
	
	Write-Output "[*] Attempting to rename System32 VirtualBox executable files..."
	
	$file_list = "VBoxTray.exe", "VBoxControl.exe", "VBoxService.exe", "VBoxMRXNP.dll", "VBoxSVGA.dll", "VBoxHook.dll", "VBoxNine.dll", "VBoxGL.dll", "VBoxDispD3D.dll", "VBoxICD.dll"

    foreach ($f in $file_list) {

    	Write-Output "[+] Attempting to rename $f..."
		
		try {
			Rename-Item "C:\Windows\System32\$f" "C:\Windows\System32\$(Get-RandomString).sys" -ErrorAction Stop
		}
		
		catch {
			Write-Output "[!] File does not seem to exist! Skipping..."
		}
	}
	
	# Rename SysWOW64 executable files
	
	Write-Output "[*] Attempting to rename SysWOW64 VirtualBox executable files..."
	
	$file_list = "VBoxGL-x86.dll", "VBoxMRXNP.dll", "VBoxDispD3D-x86.dll", "VBoxICD-x86.dll", "VBoxSVGA-x86.dll", "VBoxNine-x86.dll"

    foreach ($f in $file_list) {

    	Write-Output "[+] Attempting to rename $f..."
		
		try {
			Rename-Item "C:\Windows\SysWOW64\$f" "C:\Windows\SysWOW64\$(Get-RandomString).sys" -ErrorAction Stop
		}
		
		catch {
			Write-Output "[!] File does not seem to exist! Skipping..."
		}
	}

	# Rename program directory

	Write-Output "[+] Attempting to rename VirtualBox program directory..."

	# First check if the path exists
	$vboxPath = "C:\Program Files\Oracle\VirtualBox"
	$vboxDir = $null

	# Try to get the directory with error handling
	try {
		$vboxDir = Get-ChildItem $vboxPath -ErrorAction Stop
	} catch {
		Write-Output "[!] Directory does not appear to exist! Skipping..."
	}

	# Check for existence of files
	if ($vboxDir) {
		try {
			Rename-Item "C:\Program Files\Oracle\VirtualBox Guest Additions" "C:\Program Files\Oracle\$(Get-Random)" -ErrorAction Stop
			Write-Output "[+] Successfully renamed directory"
		} catch {
			Write-Output "[!] Failed to rename directory: $($_.Exception.Message)"
		}
	}
}
Write-Output ""
Write-Output "== All Done! Make sure you run it as Admin"
Write-Output "== Spot any bugs or issues? Message me on Discord: Croakq"
Write-Output "== Please restart your computer now!"
Write-Output ""
pause