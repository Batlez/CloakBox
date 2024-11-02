# ==================================================
# Admin Check
# ==================================================


if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$($PWD.Path)' ; & '$($myInvocation.InvocationName)'`"" -Verb RunAs
    Exit
}


# ==================================================
# External Modifiers
# ==================================================


$Hypervisor = Read-Host "`n  # Enter a hypervisor 'vmware' or 'vbox'"
$CPUID_String = Read-Host "`n  # Enter a CPUID string 'GenuineIntel' or 'AuthenticAMD'"

if ($Hypervisor -eq "vbox") {
    $VBoxManager = "$env:ProgramFiles\Vektor T13\VirtualBox\VBoxManage.exe"
    Write-Host "`n  # Available VMs:`n"
    & $VBoxManager list vms

    $VM = Read-Host "`n  # Enter VM Name"
	$VDI = "$env:USERPROFILE\VirtualBox VMs\$VM\$VM.vdi"

    if (-not (Test-Path $VBoxManager)) {
        Write-Host "  # VirtualBox is not installed." -ForegroundColor Red
        exit 1
    }

    try {
		# ===== Misc. =====
		& $VBoxManager modifyvm $VM --clipboard "bidirectional" --draganddrop "bidirectional"
		Write-Host "`n  # Clipboard sharing set to bidirectional, allowing copy-paste between host and VM."
		Write-Host "`n  # Drag-and-drop also set to bidirectional for easy file transfer between host and VM."
		& $VBoxManager modifyvm $VM --mouse "ps2" --keyboard "ps2"
		Write-Host "`n  # Mouse and keyboard configured as PS/2 devices for compatibility with most guest OSes."
		& $VBoxManager modifyvm $VM --pae "on"
		Write-Host "`n  # PAE (Physical Address Extension) enabled to allow 32-bit guest OSes to access more than 4 GB of memory."
		& $VBoxManager modifyvm $VM --paravirtprovider "none" --nestedpaging "on"
		Write-Host "`n  # Paravirtualization provider set to 'none', using basic virtualization. Nested paging enabled for memory management."
		& $VBoxManager modifyvm $VM --audioout "on" --audioin "on"
		Write-Host "`n  # Audio input and output enabled for both playback and recording support in the VM."
		& $VBoxManager modifyvm $VM --macaddress1 "428D5C257A8B"
		Write-Host "`n  # MAC address manually set for compatibility or identification needs."
		& $VBoxManager modifyvm $VM --hwvirtex "on" --vtxux "on"
		Write-Host "`n  # Hardware virtualization enabled for performance improvement. Intel VT-x/AMD-V feature enabled for the VM."
		& $VBoxManager modifyvm $VM --largepages "on"
		Write-Host "`n  # Large pages enabled for memory optimization, reducing memory fragmentation and improving performance."
		& $VBoxManager modifyvm $VM --vram "128" --memory "4096"
		Write-Host "`n  # Video memory set to 128 MB, allowing for higher resolution displays in the VM."
		Write-Host "`n  # Main memory allocated to 4096 MB (4 GB) for smooth multitasking within the VM."
		& $VBoxManager modifyvm $VM --apic "on"
		Write-Host "`n  # APIC enabled to support SMP and improve performance for multi-core CPUs."
		& $VBoxManager modifyvm $VM --cpus "4"
		Write-Host "`n  # VM configured to use 4 CPUs, enhancing processing power and performance."
		& $VBoxManager modifyvm $VM --cpuexecutioncap "100"
		Write-Host "`n  # CPU execution cap set to 100%, allowing the VM to fully utilize the assigned CPU resources."
		& $VBoxManager modifyvm $VM --paravirtprovider "legacy"
		Write-Host "`n  # Paravirtualization provider switched to 'legacy' for better compatibility with older OSes."
		& $VBoxManager modifyvm $VM --hwvirtex "on"
		Write-Host "`n  # Confirmed hardware virtualization enabled for consistent VM performance."
		& $VBoxManager modifyvm $VM --chipset "piix3"
		Write-Host "`n  # Chipset set to 'PIIX3', ensuring broad compatibility, especially with legacy guest operating systems."
		& $VBoxManager modifyvm $VM --accelerate3d  "on" --accelerate2dvideo "on"
		Write-Host "`n  # 3D and 2D acceleration enabled, providing enhanced graphics performance within the VM."
		& $VBoxManager modifyvm $VM --usb "on"
		Write-Host "`n  # USB support enabled, allowing the VM to recognize USB devices."
		
		# ===== Storage Config [SATA > NVMe] =====
		# Important: Must install Windows on the .vdi attachment before switching to a NVMe Controller.
		# & $VBoxManager storagectl $VM --name "NVMe" --add "pcie" --controller "NVMe" --bootable "on"
		# & $VBoxManager storageattach $VM --storagectl "SATA" --port "0" --device "0" --medium "none"
		# & $VBoxManager storageattach $VM --storagectl "NVMe" --port "0" --device "0" --type "hdd" --medium "$VDI" --nonrotational "on"
		# NVMe Fix
		# & $VBoxManager setextradata $VM "VBoxInternal/Devices/nvme/0/Config/MsiXSupported" "0"
		# & $VBoxManager setextradata $VM "VBoxInternal/Devices/nvme/0/Config/CtrlMemBufSize" "0"
		
		# ===== CPU =====
		# CPUID
		& $VBoxManager modifyvm $VM --cpu-profile "AMD Ryzen 7 1800X Eight-Core"
		# RDTSC (Read Time-Stamp Counter)
		& $VBoxManager setextradata $VM "VBoxInternal/TM/TSCMode" "RealTSCOffset"
		& $VBoxManager setextradata $VM "VBoxInternal/CPUM/SSE4.1" "1"
		& $VBoxManager setextradata $VM "VBoxInternal/CPUM/SSE4.2" "1"
		# RDTSC VM Exit (Read Time-Stamp Counter)
		

		# ===== SMBIOS DMI =====
		# DMI BIOS Information (type 0)
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVendor" "American Megatrends International, LLC."
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVersion" "1.A0"
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseDate" "11/23/2023"
		# DMI System Information (type 1)
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVendor" "Micro-Star International Co., Ltd."
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemProduct" "MS-7D78"
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVersion" "1.0"
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemSerial" "To be filled by O.E.M."
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiSystemFamily" "To be filled by O.E.M."
		# DMI Base Board/Module Information (type 2)
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardVendor" "Micro-Star International Co., Ltd."
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardProduct" "PRO B650-P WIFI (MS-7D78)"
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardVersion" "1.0"
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiBoardSerial" "To be filled by O.E.M."
		# DMI System Enclosure or Chassis (type 3)
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiChassisVendor" "Micro-Star International Co., Ltd."
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiChassisType" "03"
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiChassisVersion" "1.0"
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiChassisSerial" "To be filled by O.E.M."
		# DMI Processor Information (type 4)
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiProcManufacturer" "Advanced Micro Devices, Inc."
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiProcVersion" "AMD Ryzen 7 1800X Eight-Core Processor"
		# DMI OEM strings (type 11)
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiOEMVBoxVer" "<EMPTY>"
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/pcbios/0/Config/DmiOEMVBoxRev" "<EMPTY>"
		# Configuring the Hard Disk Vendor Product Data (VPD)
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/ModelNumber" "Samsung SSD 980 EVO"
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/FirmwareRevision" "L4Q8G9Y1"
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port0/SerialNumber" "J8R9H3P5N4Q7W0X2Y9A5"
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port1/ModelNumber" "HL-DT-ST BD-RE WH16NS60"
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port1/FirmwareRevision" "P2K9W6X5"
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port1/SerialNumber" "Q2W3E4R5T6Y7U8I9O0PA"
		# CD/DVD drives
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port1/ATAPIProductId" "DVD A DS8A8SH"
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port1/ATAPIRevision" "KAA2"
		& $VBoxManager setextradata $VM "VBoxInternal/Devices/ahci/0/Config/Port1/ATAPIVendorId" "Slimtype"

		# & $VBoxManager startvm $VM
        Write-Host "`n  # Success" -ForegroundColor Green
    }
    catch {
        Write-Host "`n  # An error occurred: $_" -ForegroundColor Red
    }
}
elseif ($Hypervisor -eq "vmware") {
	# vmware-kvm.exe [OPTIONS] vmx-file.vmx
	# acpi.passthru.slic = "TRUE"
	# acpi.passthru.slicvendor = "TRUE"
	
}
else {
    Write-Host "`n  # Invalid hypervisor selected. Please choose 'vmware' or 'vbox'." -ForegroundColor Red
}


# https://en.wikipedia.org/wiki/CPUID
# "%ProgramFiles%\Oracle\VirtualBox\VBoxManage.exe" list cpu-profiles
# "%ProgramFiles%\Oracle\VirtualBox\VBoxManage.exe" list hostcpuids

# & $VBoxManager modifyvm $VM --cpuid-set "00000001", "00a60f12", "02100800", "7ed8320b", "178bfbff"
# & $VBoxManager modifyvm $VM --paravirtdebug "enabled=1,vendor=AuthenticAMD"
# & $VBoxManager modifyvm $VM --paravirtdebug "enabled=1,vendor=GenuineIntel"

# --long-mode "off"
# --vtx-vpid "off"
pause