if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$($PWD.Path)' ; & '$($myInvocation.InvocationName)'`"" -Verb RunAs
    Exit
}

function Check-RegistryArtifacts {

    $category = "Registry Keys"

    $detected = @()

    $paths = @(
      "HKLM:\\SOFTWARE\\Oracle\\VirtualBox Guest Additions",
      "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
      "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\VBoxMouse",
      "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\VBoxService",
      "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\VBoxSF",
      "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\VBoxVideo",
      "HKLM:\\SOFTWARE\\VMware, Inc.\\VMware Tools",
      "HKLM:\\SOFTWARE\\Wine",
      "HKLM:\\SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters"
    )
    foreach ($p in $paths) {
        if (Test-Path $p) { $detected += $p }
    }

    $acpi = @(
      "HKLM:\\HARDWARE\\ACPI\\DSDT\\VBOX__",
      "HKLM:\\HARDWARE\\ACPI\\FADT\\VBOX__",
      "HKLM:\\HARDWARE\\ACPI\\RSDT\\VBOX__"
    )
    foreach ($p in $acpi) {
        if (Test-Path $p) { $detected += $p }
    }

    try {
        Get-ChildItem "HKLM:\\HARDWARE\\DEVICEMAP\\Scsi" -Recurse -ErrorAction Stop |
          ForEach-Object {
            $id = (Get-ItemProperty -Path $_.PSPath -Name Identifier -ErrorAction Stop).Identifier
            if ($id -match "VBOX|VMWARE|QEMU") { $detected += "Scsi Identifier = $id" }
          }
    } catch { }

    $diskKey = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum"
    if (Test-Path $diskKey) {
        try {
            (Get-ItemProperty $diskKey).PSObject.Properties |
              Where-Object { $_.Name -match '^\d+$' } |
              ForEach-Object {
                  if ($_.Value -match "VMware|VBOX|Virtual") {
                      $detected += "Disk Enum -> $($_.Value)"
                  }
              }
        } catch { }
    }

    $isBad = $detected.Count -gt 0
    if ($isBad) {
        $detail = "BAD: Detected virtualization registry artifacts:`n" +
                  ($detected -join "`n")
    } else {
        $detail = "GOOD: No virtualization or sandbox registry artifacts found."
    }

    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = $detail
    }
}


function Check-SleepHook {
    $category = "Timing Check"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Start-Sleep -Milliseconds 1000   
    $sw.Stop()
    $actualMs = $sw.ElapsedMilliseconds

    $expectedMs = 1000
    $thresholdMs = 900               
    $suspicious = $actualMs -lt $thresholdMs

    return [PSCustomObject]@{
        Category = $category
        IsBad    = $suspicious
        Detail   = if ($suspicious) {
            "Sleep(1000ms) returned too fast (actual ${actualMs}ms)"
        } else {
            "Sleep timing is normal (${actualMs}ms)"
        }
    }
}

function Check-Hypervisor {
    $category = "HypervisorCheck"
    $hypervisorFlag = $null
    try {
        $hypervisorFlag = (Get-CimInstance Win32_ComputerSystem).HypervisorPresent
    } catch {
        $hypervisorFlag = $false
    }
    $isHypervisor = ($hypervisorFlag -eq $true)
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isHypervisor
        Detail   = if ($isHypervisor) {
            "Hypervisor is present (WMI HypervisorPresent = True)"
        } else {
            "No hypervisor flag detected (HypervisorPresent = False)"
        }
    }
}

function Check-CPUFeatures {
    $category = "CPUFeatureCheck"
    if (-not ([System.Management.Automation.PSTypeName]'Win32.NativeMethods').Type) {
        Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition @"
        [DllImport("kernel32.dll")]
        public static extern bool IsProcessorFeaturePresent(uint feature);
"@ -PassThru | Out-Null
    }
    $nxSupported   = [Win32.NativeMethods]::IsProcessorFeaturePresent(12)  
    $sse2Supported = [Win32.NativeMethods]::IsProcessorFeaturePresent(10)  
    $sse3Supported = [Win32.NativeMethods]::IsProcessorFeaturePresent(13)  
    $rdtscSupported= [Win32.NativeMethods]::IsProcessorFeaturePresent(8)  

    $missing = @()
    if (-not $nxSupported)   { $missing += "NX/DEP" }
    if (-not $sse2Supported) { $missing += "SSE2" }
    if (-not $sse3Supported) { $missing += "SSE3" }
    if (-not $rdtscSupported) { $missing += "RDTSC" }

    $isAnomalous = ($missing.Count -gt 0)
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isAnomalous
        Detail   = if ($isAnomalous) {
            "Missing CPU features: " + ($missing -join ", ")
        } else {
            "All expected CPU features (NX, SSE2/3, RDTSC) are present"
        }
    }
}

function Check-VideoAdapter {
    $category = "VideoAdapterCheck"
    $virtualKeywords = @("VMWARE", "VirtualBox", "Virtual VGA", "Virtual", 
                          "SVGA", "S3 Trio", "Basic Display", "Remote Display",
                          "Hyper-V", "Microsoft Hyper-V", "QXL", "Red Hat", "Parallels")
    $virtualFound = @()

    foreach ($gpu in Get-CimInstance Win32_VideoController) {
        $name = $gpu.Name
        $descr= $gpu.Description
        $adapterText = ($name + " " + $descr).ToUpper()  
        foreach ($kw in $virtualKeywords) {
            if ($adapterText -like "*$kw.ToUpper()*") {
                $virtualFound += $gpu.Name 
                break
            }
        }
    }

    $isVirtualGPU = ($virtualFound.Count -gt 0)
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isVirtualGPU
        Detail   = if ($isVirtualGPU) {
            "Unusual GPU driver detected: " + ($virtualFound -join "; ")
        } else {
            "Graphics adapters appear normal (no known virtual GPU drivers)"
        }
    }
}

function Check-OSArtifacts {
    $category = "OSArtifactCheck"
    $os = Get-CimInstance Win32_OperatingSystem

    $regUser   = $os.RegisteredUser
    $org       = $os.Organization
    $caption   = $os.Caption       
    $installDateStr = $os.InstallDate  
    $installDate = try {
        [System.Management.ManagementDateTimeConverter]::ToDateTime($installDateStr)
    } catch { $null }

    $flags = @()
    if ([string]::IsNullOrWhiteSpace($regUser) -or $regUser.ToLower() -match "user|admin|sandbox") {
        $flags += "RegisteredUser='$regUser'"
    }
    if ($org -and ($org.ToLower() -match "organization|orgname|contoso" -or $org.Trim().Length -eq 0)) {
        $flags += "Organization='$org'"
    }
    if ($caption -match "Evaluation") {
        $flags += "OS Edition is Evaluation Copy"
    }
    if ($installDate) {
        $daysSinceInstall = (Get-Date) - $installDate
        if ($daysSinceInstall.TotalDays -lt 30) {
            $flags += "OS installed ${[math]::Round($daysSinceInstall.TotalDays,1)} days ago"
        }
    }

    $isSuspicious = ($flags.Count -gt 0)
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isSuspicious
        Detail   = if ($isSuspicious) {
            "Suspicious OS info: " + ($flags -join "; ")
        } else {
            "No obvious sandbox artifacts in OS metadata (user, org, install date seem normal)"
        }
    }
}

function Check-Processes {

    $category = "Processes"

    $suspectNames = @(
        "vboxservice",   
        "vboxtray",      
        "vmtoolsd",     
        "vmwaretray",    
        "vmwareuser",   
        "vgauthservice",  
        "vmacthlp",      
        "vmsrvc",      
        "vmusrvc",    
        "sbiectrl",     
        "sbiesvc"      
    )

    $detected = Get-Process -ErrorAction SilentlyContinue |
                Where-Object { $suspectNames -contains $_.Name.ToLower() } |
                ForEach-Object { $_.Name + ".exe" }

    $isBad = $detected.Count -gt 0
    if ($isBad) {
        $detail = "BAD: Detected the following VM/sandbox processes:`n" + ($detected -join "`n")
    } else {
        $detail = "GOOD: No known VM or sandbox processes are running."
    }

    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = $detail
    }
}


function Check-DriversFiles {

    $systemDir = $Env:SystemRoot + "\\System32"
    $filePaths = @(
        "$systemDir\\drivers\\VBoxMouse.sys",  
		"$systemDir\\drivers\\VBoxWddm.sys", 
        "$systemDir\\drivers\\VBoxGuest.sys", 
        "$systemDir\\drivers\\VBoxSF.sys",    
        "$systemDir\\drivers\\VBoxVideo.sys",   
        "$systemDir\\drivers\\vmmouse.sys",    
        "$systemDir\\drivers\\vmhgfs.sys",  
        "$systemDir\\drivers\\vm3dmp.sys",   
        "$systemDir\\drivers\\vmci.sys",        
        "$systemDir\\drivers\\vmmemctl.sys",    
        "$systemDir\\drivers\\vmrawdsk.sys",  
        "$systemDir\\drivers\\vmusbmouse.sys", 
        "$systemDir\\vboxservice.exe",        
        "$systemDir\\vboxtray.exe"         
    )
    $detected = @()
    foreach ($file in $filePaths) {
        if (Test-Path $file) {
            $detected += ([System.IO.Path]::GetFileName($file))
        }
    }
	
    $isBad = $detected.Count -gt 0
    if ($isBad) {
        $detail = "BAD: Detected the following VM driver files:`n" + ($detected -join "`n")
    } else {
        $detail = "GOOD: No virtualization driver files were found."
    }

    return [PSCustomObject]@{
        Category = "System Files"
        IsBad    = $isBad
        Detail   = $detail
    }
}

function Check-SystemManufacturer {

    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $manufacturer = $cs.Manufacturer
    $model = $cs.Model
    $detected = @()
    $vmKeywords = @("VMware", "VirtualBox", "Virtual Machine", "Microsoft Corporation", "Xen", "QEMU", "Bochs", "Parallels", "KVM", "Innotek")
    if ($manufacturer) {
        foreach ($kw in $vmKeywords) {
            if ($manufacturer -match $kw) {
                $detected += "Manufacturer: $manufacturer"
                break
            }
        }
    }
    if ($model) {
        foreach ($kw in $vmKeywords) {
            if ($model -match $kw) {
                $detected += "Model: $model"
                break
            }
        }
    }
    $csp = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction SilentlyContinue
    if ($csp) {
        if ($csp.Vendor) {
            foreach ($kw in $vmKeywords) {
                if ($csp.Vendor -match $kw) {
                    $detected += "System Vendor: $($csp.Vendor)"
                    break
                }
            }
        }
        if ($csp.Name) {
            foreach ($kw in $vmKeywords) {
                if ($csp.Name -match $kw) {
                    $detected += "Product Name: $($csp.Name)"
                    break
                }
            }
        }
    }
    $isBad = $detected.Count -gt 0
    if ($isBad) {
        $detail = "BAD: Detected virtualization in hardware IDs:`n" + ($detected -join "`n")
    } else {
        $detail = "GOOD: No virtualization indicators in manufacturer/model/vendor/product."
    }

    return [PSCustomObject]@{
        Category = "Hardware IDs"
        IsBad    = $isBad
        Detail   = $detail
    }	
}

function Check-BIOSInfo {

    $bios = Get-CimInstance -ClassName Win32_BIOS
    $biosVendor = $bios.Manufacturer
    $biosVersion = ($bios.SMBIOSBIOSVersion -join " ")
    $detected = @()
    $vmKeywords = @("VMware", "VirtualBox", "VBox", "HVM", "Xen", "QEMU", "Virtual Machine", "Hyper-V", "Microsoft", "Bochs", "SeaBIOS", "Parallels")
    if ($biosVendor) {
        foreach ($kw in $vmKeywords) {
            if ($biosVendor -match $kw) {
                $detected += "BIOS Vendor: $biosVendor"
                break
            }
        }
    }
    if ($biosVersion) {
        foreach ($kw in $vmKeywords) {
            if ($biosVersion -match $kw) {
                $detected += "BIOS Version: $biosVersion"
                break
            }
        }
    }
    if ($bios.SerialNumber -and ($bios.SerialNumber -match "0{4,}|Default|To be filled")) {
        $detected += "BIOS Serial: $($bios.SerialNumber)"
    }
	
    $isBad = $detected.Count -gt 0
    if ($isBad) {
        $detail = "BAD: Detected virtualization in BIOS info:`n" + ($detected -join "`n")
    } else {
        $detail = "GOOD: No virtualization indicators in BIOS vendor, version, or serial."
    }

    return [PSCustomObject]@{
        Category = "BIOS Info"
        IsBad    = $isBad
        Detail   = $detail
    }
}

function Check-MAC {

    $vmMACPrefixes = @{
        "080027" = "VirtualBox"    
        "000569" = "VMware"        
        "000C29" = "VMware"        
        "001C14" = "VMware"        
        "005056" = "VMware"        
        "001C42" = "Parallels"     
        "00163E" = "Xen"           
        "0A0027" = "Sandbox"       
        "00155D" = "Hyper-V"       
        "525400" = "QEMU/KVM"      
    }
    $detected = @()
    Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "MACAddress IS NOT NULL" | ForEach-Object {
        $mac = $_.MACAddress
        if ($mac) {
            $prefix = $mac.ToUpper() -replace "[:\-]", ""
            if ($prefix.Length -ge 6) {
                $prefix6 = $prefix.Substring(0,6)
                if ($vmMACPrefixes.ContainsKey($prefix6)) {
                    $detected += ("MAC $mac (Vendor: $($vmMACPrefixes[$prefix6]))")
                }
            }
        }
    }
    $isBad = $detected.Count -gt 0
    if ($isBad) {
        $detail = "BAD: Detected VM MAC prefixes:`n" + ($detected -join "`n")
    } else {
        $detail = "GOOD: No VM-related MAC address prefixes detected."
    }

    return [PSCustomObject]@{
        Category = "MAC Address"
        IsBad    = $isBad
        Detail   = $detail
    }
}

function Check-DeviceNames {
    $detected = @()
	$vmKeywords = @("VBOX", "VMware", "Virtual", "QEMU", "Hyper-V", "Xen", "Parallels")
	
    Get-CimInstance -ClassName Win32_DiskDrive | ForEach-Object {
        if ($_.Model -match "VBOX|Virtual|VMware|QEMU") {
            $detected += "DiskDrive: $($_.Model)"
        }
    }
Get-CimInstance Win32_VideoController | ForEach-Object {
    foreach ($kw in $vmKeywords) {
        if ($_.Name -match $kw) {
            $detected += "VideoController: $($_.Name)"
            break
        }
    }
}

Get-CimInstance Win32_NetworkAdapter -Filter "MACAddress IS NOT NULL" | ForEach-Object {
    foreach ($kw in $vmKeywords) {
        if ($_.Name -match $kw) {
            $detected += "NetworkAdapter: $($_.Name)"
            break
        }
    }
}
    $isBad = $detected.Count -gt 0
    if ($isBad) {
        $detail = "BAD: Detected virtualization in device names:`n" + ($detected -join "`n")
    } else {
        $detail = "GOOD: No virtualization indicators found in device names."
    }

    return [PSCustomObject]@{
        Category = "Device Manager Names"
        IsBad    = $isBad
        Detail   = $detail
    }
}

function Check-ACPI {

    $detected = @()
    $acpiRoot = "HKLM:\\HARDWARE\\ACPI"
    $vmACPIKeywords = @("VBOX", "VMWARE", "VIRTUAL", "QEMU", "XEN", "HYPERV", "PARALLELS", "KVM", "BOCHS", "MICROSOFT")

    if (Test-Path $acpiRoot) {
        Get-ChildItem $acpiRoot -ErrorAction SilentlyContinue | ForEach-Object {
            $keyName = $_.PSChildName
            if ($vmACPIKeywords -contains $keyName.ToUpper()) {
                $detected += "ACPI Root Table: $keyName matches known VM pattern."
            }
            Get-ChildItem -Path "$acpiRoot\\$keyName" -ErrorAction SilentlyContinue | ForEach-Object {
                $subKeyName = $_.PSChildName
                foreach ($kw in $vmACPIKeywords) {
                    if ($subKeyName.ToUpper() -like "*$kw*") {
                        $detected += "ACPI Subkey: $($keyName)\$($subKeyName) matches $kw"
                        break
                    }
                }
            }
        }
    }

    function Get-OEMIDFromACPI {
        param (
            [string]$TableSignature
        )
        try {
            $bufferSize = [System.Runtime.InteropServices.Marshal]::SizeOf([byte]) * 36
            $buffer = New-Object byte[] $bufferSize
            $bytesRead = [System.Runtime.InteropServices.Marshal]::SizeOf([byte]) * $bufferSize

            $result = [System.Runtime.InteropServices.Marshal]::Copy(
                [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bufferSize),
                $buffer,
                0,
                $bufferSize
            )

            $firmwareTableProviderSignature = [System.Text.Encoding]::ASCII.GetBytes("ACPI")
            $tableSignature = [System.Text.Encoding]::ASCII.GetBytes($TableSignature)

            $oemId = [System.Text.Encoding]::ASCII.GetString($buffer, 10, 6).Trim()
            return $oemId
        } catch {
            return $null
        }
    }

    $dsdtOemId = Get-OEMIDFromACPI -TableSignature "DSDT"
    $facpOemId = Get-OEMIDFromACPI -TableSignature "FACP"

    foreach ($oemId in @($dsdtOemId, $facpOemId)) {
        if ($oemId) {
            foreach ($kw in $vmACPIKeywords) {
                if ($oemId.ToUpper() -like "*$kw*") {
                    $detected += "ACPI Table OEM ID: $oemId matches $kw"
                    break
                }
            }
        }
    }

    $isBad    = $detected.Count -gt 0
    $detail = if ($isBad) {
		"BAD: Detected ACPI VM indicators:`n" + ($detected -join "`n")
	} else {
		"GOOD: No virtualization indicators found in ACPI tables."
	}

    return [PSCustomObject]@{
        Category = "ACPI Tables"
        IsBad    = $isBad
        Detail   = $detail
    }
}

function Check-CPUIDHypervisorBit {
    $category = "CPUID Hypervisor Bit"
    
    try {
        $proc = Get-CimInstance Win32_Processor | Select-Object -First 1
        $hypervisorPresent = (Get-CimInstance Win32_ComputerSystem).HypervisorPresent
        
        $cpuHints = $proc.Name -match "Virtual|Hypervisor|QEMU|KVM"
        
        $isBad = $hypervisorPresent -or $cpuHints
        
        return [PSCustomObject]@{
            Category = $category
            IsBad    = $isBad
            Detail   = if ($isBad) {
                "CPUID indicates hypervisor present or virtual CPU detected"
            } else {
                "CPUID shows no hypervisor presence"
            }
        }
    }
    catch {
        return [PSCustomObject]@{
            Category = $category
            IsBad    = $false
            Detail   = "Could not query CPUID information"
        }
    }
}

function Check-USBDevices {
    $category = "USB Devices"
    
    $usbDevices = Get-PnpDevice -Class USB -ErrorAction SilentlyContinue
    $realDeviceCount = ($usbDevices | Where-Object {
        $_.FriendlyName -notmatch "Root Hub|Generic|Composite"
    }).Count
    
    $isBad = $realDeviceCount -eq 0
    
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) {
            "No real USB devices detected (typical of VMs)"
        } else {
            "Real USB devices detected ($realDeviceCount devices)"
        }
    }
}

function Check-BatteryPresence {
    $category = "Battery Presence"
    
    $battery = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue
    $isDesktop = (Get-CimInstance Win32_SystemEnclosure).ChassisTypes -contains 3
    
    $isSuspicious = ($null -eq $battery) -and -not $isDesktop
    
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isSuspicious
        Detail   = if ($battery) {
            "Battery detected (laptop or hybrid)"
        } elseif ($isDesktop) {
            "No battery (desktop chassis)"
        } else {
            "No battery on non-desktop system (VM indicator)"
        }
    }
}

function Check-ScreenResolution {
    $category = "Screen Resolution"
    
    Add-Type -AssemblyName System.Windows.Forms
    $screen = [System.Windows.Forms.Screen]::PrimaryScreen
    $width = $screen.Bounds.Width
    $height = $screen.Bounds.Height
    
    # Common VM default resolutions
    $vmResolutions = @(
        "800x600", "1024x768", "1280x720", "1280x800", "1366x768"
    )
    
    $currentRes = "${width}x${height}"
    $isSuspicious = $vmResolutions -contains $currentRes
    
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isSuspicious
        Detail   = if ($isSuspicious) {
            "Resolution $currentRes matches common VM default"
        } else {
            "Resolution $currentRes appears normal"
        }
    }
}

function Check-UserActivity {
    $category = "User Activity"
    
    $chromeHistory = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
    $edgeHistory = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
    
    $hasHistory = (Test-Path $chromeHistory) -or (Test-Path $edgeHistory)
    
    $recentFiles = Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" -ErrorAction SilentlyContinue
    $hasRecentActivity = $recentFiles.Count -gt 5
    
    $isSuspicious = -not $hasHistory -and -not $hasRecentActivity
    
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isSuspicious
        Detail   = if ($isSuspicious) {
            "No browser history or recent files (fresh VM indicator)"
        } else {
            "User activity detected (browser history or recent files exist)"
        }
    }
}

function Check-TemperatureSensors {
    $category = "Temperature Sensors"
    
    $wmi = Get-WmiObject -Namespace "root\wmi" -Class MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue
    
    $hasSensors = $null -ne $wmi
    
    return [PSCustomObject]@{
        Category = $category
        IsBad    = -not $hasSensors
        Detail   = if ($hasSensors) {
            "Temperature sensors detected (physical hardware)"
        } else {
            "No temperature sensors (VM indicator)"
        }
    }
}

function Check-ClipboardSharing {
    $category = "Clipboard Sharing"
    
    $clipboardProcesses = Get-Process | Where-Object {
        $_.Name -match "VBoxClient|vmware-vmblock"
    }
    
    $isBad = $clipboardProcesses.Count -gt 0
    
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) {
            "VM clipboard sharing detected"
        } else {
            "No VM clipboard sharing detected"
        }
    }
}

function Check-SystemUptime {
    $category = "System Uptime"
    
    $os = Get-CimInstance Win32_OperatingSystem
    $uptime = (Get-Date) - $os.LastBootUpTime
    
    $isSuspicious = $uptime.TotalMinutes -lt 30
    
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isSuspicious
        Detail   = if ($isSuspicious) {
            "System uptime is only $([math]::Round($uptime.TotalMinutes, 1)) minutes (fresh boot)"
        } else {
            "System uptime: $([math]::Round($uptime.TotalHours, 1)) hours"
        }
    }
}

function Check-CPUCores {

    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $numCores = $cs.NumberOfLogicalProcessors
    if (-not $numCores) {
        $numCores = (Get-CimInstance -ClassName Win32_Processor).Count
    }
    $detected = @()
    if ($numCores -le 2) {
        $detected += "$numCores core(s) detected"
    }
    $isBad = $detected.Count -gt 0
    $detail = if ($isBad) { $detected } else { @("Detected $numCores logical processor(s). This appears normal for a modern physical machine.") }

    return [PSCustomObject]@{
        Category = "CPU Cores"
        IsBad    = $isBad
        Detail   = $detail
    }
}

function Check-RAM {

    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $totalMemGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
    $detected = @()
    $thresholdGB = 6

    if ($totalMemGB -lt $thresholdGB) {
        $detected += "$totalMemGB GB RAM detected, which is below the typical threshold of $thresholdGB GB."
    } else {
        $detected += "$totalMemGB GB RAM detected, which meets or exceeds the typical threshold of $thresholdGB GB."
    }

    $isBad = $totalMemGB -lt $thresholdGB

    return [PSCustomObject]@{
        Category = "RAM Size"
        IsBad    = $isBad
        Detail   = $detected
    }
}


function Check-Disk {

    $detected = @()
    $cDrive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
    $thresholdGB = 80

    if ($cDrive -and $cDrive.Size) {
        $totalGB = [math]::Round($cDrive.Size / 1GB, 1)

        if ($totalGB -lt $thresholdGB) {
            $detected += "$totalGB GB disk size detected, which is below the threshold of $thresholdGB GB."
        } else {
            $detected += "$totalGB GB disk size detected, which exceeds the threshold of $thresholdGB GB."
        }
    } else {
        $detected += "Unable to retrieve disk size information. This may indicate a restricted or abnormal system configuration."
    }

    $isBad    = $cDrive -and $cDrive.Size -and ([math]::Round($cDrive.Size / 1GB, 1) -lt $thresholdGB)
    $detail = $detected

    return [PSCustomObject]@{
        Category = "Disk Size"
        IsBad    = $isBad
        Detail   = $detail
    }
}


function Check-MouseMovement {

    Add-Type -AssemblyName System.Windows.Forms
    $initialPos = [System.Windows.Forms.Cursor]::Position
    Start-Sleep -Milliseconds 2000
    $newPos = [System.Windows.Forms.Cursor]::Position
    $detected = @()

    if (($newPos.X -eq $initialPos.X) -and ($newPos.Y -eq $initialPos.Y)) {
        $detected += "No mouse movement detected after 2 seconds."
    } else {
        $detected += "Mouse movement detected within 2 seconds."
    }

    $isBad    = ($newPos.X -eq $initialPos.X) -and ($newPos.Y -eq $initialPos.Y)
    $detail = $detected

    return [PSCustomObject]@{
        Category = "Mouse Movement"
        IsBad    = $isBad
        Detail   = $detail
    }
}


function Check-CPUHypervisor {

    $proc = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
    $cpuName = $proc.Name
    $detected = @()

    if ($cpuName -match "Virtual CPU|Microsoft Hyper-V|Virtualbox|vbox") {
        $detected += "CPU Name indicates virtualization: '$cpuName'"
    }

    $isBad    = $detected.Count -gt 0
    $detail = if ($isBad) { $detected } else { "CPU Name appears normal: '$cpuName'. Typical of real hardware." }

    return [PSCustomObject]@{
        Category = "CPU IDs"
        IsBad    = $isBad
        Detail   = $detail
    }
}


function Check-PciVendor {

    $detected = @()
    Get-CimInstance -ClassName Win32_PnPEntity | ForEach-Object {
        if ($_.PNPDeviceID -match "VEN_80EE&DEV_CAFE") {
            $detected += "Detected VirtualBox PCI device: $($_.PNPDeviceID)"
        }
    }
    $isBad    = $detected.Count -gt 0
    $detail = if ($isBad) {
        $detected
    } else {
        "No VirtualBox-specific PCI devices detected."
    }

    return [PSCustomObject]@{
        Category = "PCI Vendor ID"
        IsBad    = $isBad
        Detail   = $detail
    }
}


function Check-BaseBoard {

    $detected = @()
    $vmKeywords = @("VirtualBox", "Oracle Corporation", "Vbox")
    $genericKeywords = @("OEM", "To Be Filled By OEM", "System Manufacturer", "System Product Name", "Default string")

    $bb = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction SilentlyContinue
    if ($bb) {
        foreach ($prop in @($bb.Manufacturer, $bb.Product)) {
            foreach ($kw in $vmKeywords + $genericKeywords) {
                if ($prop -and ($prop -match [regex]::Escape($kw))) {
                    $detected += "Suspicious baseboard entry detected: $prop"
                    break
                }
            }
        }
    }

    $isBad = $detected.Count -gt 0
    $detail = if ($isBad) {
        $detected
    } else {
        "No suspicious baseboard manufacturer or product names found."
    }

    return [PSCustomObject]@{
        Category = "BaseBoard"
        IsBad    = $isBad
        Detail   = $detail
    }
}


function Check-EventLogSources {

    $targets = @("vboxvideo", "VBoxVideoW8", "VBoxWddm")
    $detected = @()

    try {
        $events = Get-WinEvent -LogName System -ErrorAction SilentlyContinue
        foreach ($event in $events) {
            if ($targets -contains $event.ProviderName) {
                $detected += "Detected VirtualBox-related event source: $($event.ProviderName)"
            }
        }
    } catch {
        $detected += "Error accessing System event log: $_"
    }

    $isBad = $detected.Count -gt 0
    $detail = if ($isBad) {
        $detected
    } else {
        "No VirtualBox-related event sources detected in the System event log."
    }

    return [PSCustomObject]@{
        Category = "Event Log Sources"
        IsBad    = $isBad
        Detail   = $detail
    }
}


function Check-NetworkProvider {

    $dll = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("mpr.dll", CharSet=CharSet.Auto)]
    public static extern int WNetGetProviderName(int netType, System.Text.StringBuilder lpProviderName, ref int lpnLength);
}
"@
    Add-Type -TypeDefinition $dll -PassThru | Out-Null

    $sb  = New-Object System.Text.StringBuilder 1024
    $len = $sb.Capacity
    $res = [Win32]::WNetGetProviderName(0x0000001A, $sb, [ref]$len)  
    $provider = if ($res -eq 0) { $sb.ToString() } else { "" }

    $isBad = ($provider -eq "VirtualBox Shared Folders")

    if ($isBad) {
        $detail = @("Provider: `"$provider`" (VirtualBox shared-folders detected)")
    } else {
        $detail = @("No VirtualBox Shared Folders provider")
    }

    return [PSCustomObject]@{
        Category = "NetProvider"
        IsBad    = $isBad
        Detail   = $detail
    }
}

function Check-VBoxBiosData {
    $category = "VirtualBox BIOS"
    $findings = @()
    $biosKey  = "HKLM:\\HARDWARE\\DESCRIPTION\\System"

    try {
        $sysBiosVersion = (Get-ItemProperty -Path $biosKey -Name "SystemBiosVersion" -ErrorAction Stop)."SystemBiosVersion"
        if ($sysBiosVersion) {
            $sysBiosVersionText = if ($sysBiosVersion -is [System.Array]) { $sysBiosVersion -join " " } else { $sysBiosVersion }
            if ($sysBiosVersionText -match "VBOX") {
                $findings += "SystemBiosVersion contains 'VBOX'"
            }
        }
    } catch { }  

    try {
        $vidBiosVersion = (Get-ItemProperty -Path $biosKey -Name "VideoBiosVersion" -ErrorAction Stop)."VideoBiosVersion"
        if ($vidBiosVersion) {
            $vidBiosVersionText = if ($vidBiosVersion -is [System.Array]) { $vidBiosVersion -join " " } else { $vidBiosVersion }
            if ($vidBiosVersionText -match "VIRTUALBOX") {
                $findings += "VideoBiosVersion contains 'VIRTUALBOX'"
            }
        }
    } catch { }

    try {
        $biosDate = (Get-ItemProperty -Path $biosKey -Name "SystemBiosDate" -ErrorAction Stop)."SystemBiosDate"
        if ($biosDate) {
            if ($biosDate -match "^06/2[3-9]/99$") {
                $findings += "SystemBiosDate is $biosDate (matches VirtualBox default)"
            }
        }
    } catch { }

    $isBad = $findings.Count -gt 0
    $detail = if ($isBad) {
        $findings  
    } else {
        @("BIOS strings are normal (no VirtualBox signatures detected)")
    }
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = $detail
    }
}

function Check-VBoxRegistryKeys {
    $category = "VirtualBox Registry"
    $findings = @()

    $regPaths = @(
        "HKLM:\\SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
        "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\VBoxMouse",
        "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\VBoxService",
        "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\VBoxSF",
        "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\VBoxVideo",
        "HKLM:\\HARDWARE\\ACPI\\DSDT\\VBOX__",
        "HKLM:\\HARDWARE\\ACPI\\FADT\\VBOX__",
        "HKLM:\\HARDWARE\\ACPI\\RSDT\\VBOX__"
    )
    foreach ($path in $regPaths) {
        if (Test-Path $path) {
            switch -Wildcard ($path) {
                "*VirtualBox Guest Additions" {
                    $findings += "VirtualBox Guest Additions registry key exists"
                }
                "*\\Services\\VBox*" {
                    $serviceName = ($path -split '\\')[-1]
                    $findings += "Service '$serviceName' registry key exists"
                }
                "*\\ACPI\\DSDT\\VBOX__" {
                    $findings += "ACPI DSDT\\VBOX__ registry key exists"
                }
                "*\\ACPI\\FADT\\VBOX__" {
                    $findings += "ACPI FADT\\VBOX__ registry key exists"
                }
                "*\\ACPI\\RSDT\\VBOX__" {
                    $findings += "ACPI RSDT\\VBOX__ registry key exists"
                }
                default {
                    $findings += "$path exists"
                }
            }
        }
    }

    $isBad = $findings.Count -gt 0
    $detail = if ($isBad) {
        $findings 
    } else {
        @("No VirtualBox-related registry keys or values found")
    }
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = $detail
    }
}

function Check-InstructionTiming {
    $category = "CPU Instruction Timing"
    
    $deltas = @()
    for ($i = 0; $i -lt 100; $i++) {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $null = [Math]::Sqrt(12345)
        $sw.Stop()
        $deltas += $sw.Elapsed.TotalMilliseconds
    }
    
    $mean = ($deltas | Measure-Object -Average).Average
    $sumSquares = ($deltas | ForEach-Object { [Math]::Pow($_ - $mean, 2) } | Measure-Object -Sum).Sum
    $variance = $sumSquares / $deltas.Count
    $stdDev = [Math]::Sqrt($variance)
    
    $isBad = $stdDev -gt 0.15
    
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = "Timing variance: $([Math]::Round($stdDev, 4)) (VMs typically >0.15)"
    }
}

function Check-CPUBrandString {
    $category = "CPU Brand String Deep Check"
    
    $cpu = (Get-CimInstance Win32_Processor).Name
    $findings = @()
    
    if ($cpu -match "Intel" -and $cpu -notmatch "\d{4,5}[A-Z]{0,2}") {
        $findings += "Intel CPU missing generation/model number"
    }
    
    if ($cpu -match "\s{2,}") {
        $findings += "Unusual whitespace in CPU name"
    }
    
    $nominalSpeed = (Get-CimInstance Win32_Processor).MaxClockSpeed
    $currentSpeed = (Get-CimInstance Win32_Processor).CurrentClockSpeed
    
    if ([math]::Abs($nominalSpeed - $currentSpeed) -gt 500) {
        $findings += "Clock speed mismatch: Nominal=$nominalSpeed, Current=$currentSpeed"
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "CPU brand string appears legitimate" }
    }
}

function Check-CacheTopology {
    $category = "CPU Cache Topology"
    
    $caches = Get-CimInstance Win32_CacheMemory
    $findings = @()
    
    if ($caches.Count -eq 0) {
        $findings += "No CPU cache detected (VM indicator)"
    }
    
    $l2Cache = $caches | Where-Object { $_.Level -eq 3 }
    $l3Cache = $caches | Where-Object { $_.Level -eq 4 }
    
    if (-not $l2Cache -and -not $l3Cache) {
        $findings += "Missing L2/L3 cache entries"
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "Cache topology normal ($($caches.Count) levels)" }
    }
}

function Check-MemoryArtifacts {
    $category = "Memory Artifacts"
    
    $memory = Get-CimInstance Win32_PhysicalMemory
    $findings = @()
    
    foreach ($dimm in $memory) {
        $mfg = $dimm.Manufacturer
        $partNumber = $dimm.PartNumber
        
        if ([string]::IsNullOrWhiteSpace($mfg) -or $mfg -match "^0+$") {
            $findings += "Missing or null memory manufacturer"
        }
        
        if ($partNumber -match "DIMM|Module|Virtual") {
            $findings += "Generic memory part number: $partNumber"
        }
        
        if ($dimm.SerialNumber -match "^0+$|^[Ff]+$") {
            $findings += "Invalid memory serial: $($dimm.SerialNumber)"
        }
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "Memory DIMMs appear legitimate" }
    }
}

function Check-DiskIOPattern {
    $category = "Disk I/O Patterns"
    
    $tempFile = [System.IO.Path]::GetTempFileName()
    $data = New-Object byte[] (1024 * 1024)  # 1MB
    
    $times = @()
    for ($i = 0; $i -lt 10; $i++) {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        [System.IO.File]::WriteAllBytes($tempFile, $data)
        $sw.Stop()
        $times += $sw.ElapsedMilliseconds
    }
    
    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    
    $average = ($times | Measure-Object -Average).Average
    $sumSquares = ($times | ForEach-Object { [Math]::Pow($_ - $average, 2) } | Measure-Object -Sum).Sum
    $variance = $sumSquares / $times.Count
    
    $hasNVMe = Get-PhysicalDisk | Where-Object { $_.BusType -eq "NVMe" }
    
    $isBad = ($variance -lt 0.5 -and $average -lt 3 -and -not $hasNVMe)
    
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($hasNVMe) {
            "NVMe SSD detected - skipping check (Avg: $([Math]::Round($average, 2))ms)"
        } else {
            "Avg: $([Math]::Round($average, 2))ms, Variance: $([Math]::Round($variance, 2))"
        }
    }
}

function Check-NetworkInterfaceDetails {
    $category = "Network Interface Deep Scan"
    
    $findings = @()
    
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    
    foreach ($adapter in $adapters) {
        if ($adapter.InterfaceDescription -match "VirtualBox Host-Only|Hyper-V|vEthernet|Wi-Fi Direct|NordLynx|WireGuard|OpenVPN|TAP-Windows") {
            continue
        }
        
        $mac = $adapter.MacAddress -replace "-", ""
        
        if ($mac.Length -ge 6) {
            $prefix = $mac.Substring(0, 6)
            
            $vmMacs = @{
                "080027" = "VirtualBox"
                "0A0027" = "VirtualBox (Newer)"
                "000569" = "VMware"
                "000C29" = "VMware"
                "001C14" = "VMware"
                "005056" = "VMware"
                "001C42" = "Parallels"
                "00163E" = "Xen"
                "00155D" = "Hyper-V"
                "525400" = "QEMU/KVM"
                "020054" = "Novell/QEMU"
                "001DD8" = "Microsoft Loopback"
            }
            
            if ($vmMacs.ContainsKey($prefix)) {
                $findings += "$($adapter.Name): $($adapter.MacAddress) ($($vmMacs[$prefix]))"
            }
        }
        
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "Network interfaces appear legitimate" }
    }
}

function Check-VirtualizationPersistence {
    $category = "Virtualization Persistence"
    
    $findings = @()
    
    $runKeys = @(
        "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
    )
    
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            $entries = Get-ItemProperty $key -ErrorAction SilentlyContinue
            
            foreach ($prop in $entries.PSObject.Properties) {
                if ($prop.Value -match "vbox|vmware|parallels|qemu|xen|virtio") {
                    $findings += "Autorun entry: $($prop.Name) = $($prop.Value)"
                }
            }
        }
    }
    
    $services = Get-Service | Where-Object { 
        $_.Name -match "vbox|vmware|parallels|qemu" -and 
        $_.Status -eq "Running" 
    }
    
    foreach ($svc in $services) {
        $findings += "VM service running: $($svc.Name) ($($svc.DisplayName))"
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "No VM persistence mechanisms detected" }
    }
}

function Check-PCIDevices {
    $category = "PCI Device Enumeration"
    
    $findings = @()
    
    $pciDevices = Get-CimInstance Win32_PnPEntity | Where-Object {
        $_.PNPDeviceID -match "PCI\\"
    }
    
    foreach ($device in $pciDevices) {
        $deviceId = $device.PNPDeviceID
        
        if ($deviceId -match "VEN_80EE") {
            $findings += "VirtualBox PCI device: $($device.Name)"
        }
        
        if ($deviceId -match "VEN_15AD") {
            $findings += "VMware PCI device: $($device.Name)"
        }
        
        if ($deviceId -match "VEN_1234|VEN_1AF4") {
            $findings += "QEMU/KVM PCI device: $($device.Name)"
        }
        
        if ($deviceId -match "VEN_1B36") {
            $findings += "Red Hat Virtual device: $($device.Name)"
        }
        
        if ($deviceId -match "VEN_1414") {
            $findings += "Microsoft Virtual device: $($device.Name)"
        }
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "PCI devices appear to be physical hardware" }
    }
}

function Check-SystemEntropy {
    $category = "System Entropy Analysis"
    
    $findings = @()
    
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $bytes = New-Object byte[] 1000
    
    $startTime = Get-Date
    for ($i = 0; $i -lt 10; $i++) {
        $rng.GetBytes($bytes)
    }
    $duration = ((Get-Date) - $startTime).TotalMilliseconds
    
    if ($duration -gt 100) {
        $findings += "Slow entropy generation: ${duration}ms (VMs often >100ms)"
    }
    
    $rngService = Get-Service -Name "RNG" -ErrorAction SilentlyContinue
    if (-not $rngService) {
    }
    
    $rng.Dispose()
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "Entropy generation appears normal (${duration}ms)" }
    }
}

function Check-AudioDevices {
    $category = "Audio Hardware"
    
    $findings = @()
    
    $audioDevices = Get-CimInstance Win32_SoundDevice
    
    if ($audioDevices.Count -eq 0) {
        $findings += "No audio devices detected (VM indicator)"
    } else {
        foreach ($device in $audioDevices) {
            if ($device.Name -match "NVIDIA Virtual Audio|NVIDIA High Definition Audio|Intel Display Audio") {
                continue
            }
            
            if ($device.Name -match "VBox|VMware|QEMU|Microsoft Basic Display|Bochs") {
                $findings += "Virtual audio device: $($device.Name)"
            }
            
            if ($device.Manufacturer -match "Oracle.*VirtualBox|VMware|Innotek|Red Hat") {
                $findings += "Suspicious audio manufacturer: $($device.Manufacturer)"
            }
        }
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "Audio devices appear legitimate ($($audioDevices.Count) device(s))" }
    }
}

function Check-VirtualBoxPorts {
    $category = "VirtualBox Port Communication"
    
    $findings = @()
    
    $vboxPorts = @("VBoxGuest", "VBoxMouse", "VBoxSF", "VBoxVideo")
    
    Get-CimInstance Win32_PnPEntity | ForEach-Object {
        $deviceId = $_.DeviceID
        foreach ($port in $vboxPorts) {
            if ($deviceId -match $port) {
                $findings += "VirtualBox port device: $deviceId"
            }
        }
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "No VirtualBox port devices found" }
    }
}

function Check-GPUMemory {
    $category = "GPU Memory Analysis"
    
    $gpu = Get-CimInstance Win32_VideoController | Select-Object -First 1
    $vramMB = [math]::Round($gpu.AdapterRAM / 1MB, 0)
    
    $findings = @()
    
    $suspiciousSizes = @(16, 32, 64, 128, 256)
    
    if ($suspiciousSizes -contains $vramMB) {
        $findings += "GPU has exactly ${vramMB}MB VRAM (common VM allocation)"
    }
    
    if ($vramMB -eq 0 -or $gpu.AdapterRAM -eq 0) {
        $findings += "GPU reports 0 or invalid VRAM"
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "GPU VRAM appears normal (${vramMB}MB)" }
    }
}

function Check-WindowsSandbox {
    $category = "Windows Sandbox Detection"
    
    $findings = @()
    
    Get-NetAdapter | ForEach-Object {
        if ($_.InterfaceDescription -match "Hyper-V|vEthernet") {
            $findings += "Hyper-V network adapter: $($_.InterfaceDescription)"
        }
    }
    
    $hvServices = @("vmms", "vmcompute", "hvhost")
    foreach ($svc in $hvServices) {
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
            $findings += "Hyper-V service running: $svc"
        }
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "No Hyper-V/Sandbox artifacts" }
    }
}

function Check-SuspiciousPrograms {
    $category = "Installed Programs Check"
    
    $findings = @()
    $suspiciousApps = @(
        "VirtualBox Guest Additions",
        "VMware Tools",
        "Parallels Tools",
        "QEMU",
        "Sandboxie",
        "Shade Sandbox"
    )
    
    $paths = @(
        "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
        "HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*"
    )
    
    foreach ($path in $paths) {
        Get-ItemProperty $path -ErrorAction SilentlyContinue | ForEach-Object {
            $displayName = $_.DisplayName
            foreach ($app in $suspiciousApps) {
                if ($displayName -match $app) {
                    $findings += "Installed: $displayName"
                }
            }
        }
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "No suspicious programs installed" }
    }
}

function Check-SMARTData {
    $category = "SMART Disk Data"
    
    $findings = @()
    
    try {
        $disks = Get-PhysicalDisk
        foreach ($disk in $disks) {
            if ($disk.HealthStatus -eq "Unknown") {
                $findings += "Disk '$($disk.FriendlyName)' has unknown health status"
            }
            
            if ($disk.MediaType -eq "Unspecified") {
                $findings += "Disk '$($disk.FriendlyName)' has unspecified media type"
            }
        }
    } catch {
        $findings += "Unable to query SMART data (may indicate VM)"
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "SMART data appears normal" }
    }
}

function Check-VBoxFiles {
    $category = "VirtualBox Files"
    $findings = @()
    $system32 = "$Env:SystemRoot\\System32"

    $filePaths = @(
        "$system32\\drivers\\VBoxMouse.sys",
        "$system32\\drivers\\VBoxWddm.sys",
        "$system32\\drivers\\VBoxGuest.sys",
        "$system32\\drivers\\VBoxSF.sys",
        "$system32\\drivers\\VBoxVideo.sys",
        "$system32\\vboxdisp.dll",
        "$system32\\vboxhook.dll",
        "$system32\\vboxmrxnp.dll",
        "$system32\\vboxogl.dll",
        "$system32\\vboxoglarrayspu.dll",
        "$system32\\vboxoglcrutil.dll",
        "$system32\\vboxoglerrorspu.dll",
        "$system32\\vboxoglfeedbackspu.dll",
        "$system32\\vboxoglpackspu.dll",
        "$system32\\vboxoglpassthroughspu.dll",
        "$system32\\VBoxService.exe",
        "$system32\\VBoxTray.exe",
        "$system32\\VBoxControl.exe"
    )
    foreach ($file in $filePaths) {
        if (Test-Path $file) {
            $filename = [System.IO.Path]::GetFileName($file)
            $findings += "$filename found"
        }
    }

    $isBad = $findings.Count -gt 0
    $detail = if ($isBad) {
        $findings 
    } else {
        @("No VirtualBox Guest Additions files or drivers found")
    }
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = $detail
    }
}

function Check-VBoxDirectories {

    $category = "VirtualBox Directories"
    $findings = @()

    $dirPaths = @(
        "$Env:ProgramFiles\\Vektor T13\\VirtualBox Guest Additions",
        "$Env:ProgramFiles(x86)\\Vektor T13\\VirtualBox Guest Additions",
        "$Env:ProgramFiles\\Vektor T13\\VirtualBox"
    )
    foreach ($path in $dirPaths) {
        if ([string]::IsNullOrEmpty($path)) { continue }  # skip if env var not defined
        if (Test-Path $path) {
            if ($path -match "VirtualBox Guest Additions$") {
                $findings += "VirtualBox Guest Additions folder found"
            }
            elseif ($path -match "VirtualBox$") {
                $findings += "Oracle VirtualBox installation folder found"
            }
            else {
                $findings += "$path found"
            }
        }
    }

    $isBad = $findings.Count -gt 0
    $detail = if ($isBad) {
        $findings  
    } else {
        @("No VirtualBox program directories detected")
    }
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = $detail
    }
}

function Check-VBoxDLLs {
    $category = "VirtualBox DLL Injection"
    
    $findings = @()
    $vboxDlls = @(
        "VBoxHook.dll",
        "VBoxMRXNP.dll", 
        "VBoxOGL.dll",
        "VBoxOGLarrayspu.dll",
        "VBoxOGLcrutil.dll",
        "VBoxOGLerrorspu.dll",
        "VBoxOGLfeedbackspu.dll",
        "VBoxOGLpackspu.dll",
        "VBoxOGLpassthroughspu.dll",
        "VBoxDisp.dll",
        "VBoxTray.exe",
        "VBoxControl.exe"
    )
    
    $loadedModules = Get-Process -Id $PID | Select-Object -ExpandProperty Modules -ErrorAction SilentlyContinue
    
    foreach ($dll in $vboxDlls) {
        if (Test-Path "$env:SystemRoot\System32\$dll") {
            $findings += "Found in System32: $dll"
        }
        
        if (Test-Path "$env:SystemRoot\SysWOW64\$dll") {
            $findings += "Found in SysWOW64: $dll"
        }
        
        if ($loadedModules.ModuleName -contains $dll) {
            $findings += "Loaded in memory: $dll"
        }
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "No VirtualBox DLLs detected" }
    }
}

function Check-ProcessAncestry {
    $category = "Suspicious Process Ancestry"
    
    $findings = @()
    
    $currentProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $PID"
    $parentPID = $currentProcess.ParentProcessId
    
    if ($parentPID) {
        $parent = Get-Process -Id $parentPID -ErrorAction SilentlyContinue
        
        if ($parent) {
            $suspiciousParents = @("vboxservice", "vmtoolsd", "joeboxserver", "prl_tools")
            
            if ($suspiciousParents -contains $parent.Name.ToLower()) {
                $findings += "Suspicious parent process: $($parent.Name)"
            }
            
            $timeDiff = ($currentProcess.CreationDate - $parent.StartTime).TotalSeconds
            if ($timeDiff -lt 1) {
                $findings += "Process spawned suspiciously fast after parent ($timeDiff seconds)"
            }
        }
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "Process ancestry appears normal" }
    }
}

function Check-VMWindowTitles {
    $category = "VM Window Titles"
    
    $findings = @()
    
    Add-Type @"
    using System;
    using System.Runtime.InteropServices;
    using System.Text;
    
    public class WindowChecker {
        [DllImport("user32.dll")]
        static extern bool EnumWindows(EnumWindowsProc enumProc, IntPtr lParam);
        
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
        
        [DllImport("user32.dll")]
        static extern IntPtr GetForegroundWindow();
        
        delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
        
        public static string[] GetAllWindowTitles() {
            var titles = new System.Collections.Generic.List<string>();
            IntPtr foreground = GetForegroundWindow();
            
            EnumWindows((hWnd, lParam) => {
                if (hWnd == foreground) return true;
                
                StringBuilder sb = new StringBuilder(256);
                if (GetWindowText(hWnd, sb, sb.Capacity) > 0) {
                    titles.Add(sb.ToString());
                }
                return true;
            }, IntPtr.Zero);
            
            return titles.ToArray();
        }
    }
"@
    
    $windowTitles = [WindowChecker]::GetAllWindowTitles()
    
    $vmKeywords = @(
        "VBoxTray", 
        "Oracle VM VirtualBox", 
        "VMware Workstation",
        "VMware Player",
        "QEMU",
        ".*\[Running\] - Oracle VM VirtualBox",
        "Parallels Desktop"
    )
    
    foreach ($title in $windowTitles) {
        if ([string]::IsNullOrWhiteSpace($title) -or $title -match "VM.*Checker|Detection Tool") {
            continue
        }
        
        foreach ($keyword in $vmKeywords) {
            if ($title -match $keyword) {
                $findings += "Suspicious window: $title"
                break
            }
        }
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "No VM-related windows detected" }
    }
}

function Check-KernelDrivers {
    $category = "Kernel Driver Analysis"
    
    $findings = @()
    $vmDrivers = @(
        "vboxguest", "vboxmouse", "vboxsf", "vboxvideo", "vboxwddm",
        "vmci", "vmhgfs", "vmmouse", "vmmemctl", "vmrawdsk", "vmusbmouse",
        "prl_fs", "prl_eth", "prl_tg", "prl_mouf",
        "balloon", "pvscsi", "vmxnet"
    )
    
    $drivers = Get-WindowsDriver -Online -ErrorAction SilentlyContinue | 
               Select-Object -ExpandProperty Driver
    
    foreach ($driver in $drivers) {
        foreach ($vmDriver in $vmDrivers) {
            if ($driver -match $vmDriver) {
                $findings += "VM kernel driver: $driver"
                break
            }
        }
    }
    
    $runningDrivers = Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq "Running" }
    
    foreach ($driver in $runningDrivers) {
        foreach ($vmDriver in $vmDrivers) {
            if ($driver.Name -match $vmDriver) {
                $findings += "Running VM driver: $($driver.Name)"
                break
            }
        }
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "No VM kernel drivers detected" }
    }
}

function Check-ClipboardHistory {
    $category = "Clipboard Usage Analysis"
    
    Add-Type -AssemblyName System.Windows.Forms
    
    $findings = @()
    
    try {
        $clipboardProcesses = Get-Process | Where-Object {
            $_.ProcessName -match "VBoxClient|VBoxTray|vmware-vmblock|vmware-user|prl_cc"
        }
        
        if ($clipboardProcesses) {
            foreach ($proc in $clipboardProcesses) {
                $findings += "Clipboard sync process: $($proc.ProcessName)"
            }
        }
        
        $clipReg = "HKLM:\\SOFTWARE\\Oracle\\VirtualBox Guest Additions"
        if (Test-Path $clipReg) {
            $clipSettings = Get-ItemProperty $clipReg -Name "*Clipboard*" -ErrorAction SilentlyContinue
            if ($clipSettings) {
                $findings += "VirtualBox clipboard registry keys found"
            }
        }
        
    } catch {
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "No VM clipboard sync detected" }
    }
}

function Check-TLSCallbacks {
    $category = "TLS Callback Anomalies"
    
    $findings = @()
    
    try {
        $csharp = @"
using System;
using System.Runtime.InteropServices;

public class TLSCheck {
    [DllImport("ntdll.dll")]
    public static extern uint NtQueryInformationProcess(
        IntPtr ProcessHandle,
        uint ProcessInformationClass,
        IntPtr ProcessInformation,
        uint ProcessInformationLength,
        out uint ReturnLength
    );
    
    public static bool CheckTLS() {
        IntPtr hProcess = System.Diagnostics.Process.GetCurrentProcess().Handle;
        uint retLen;
        IntPtr buffer = Marshal.AllocHGlobal(8);
        
        uint result = NtQueryInformationProcess(hProcess, 7, buffer, 8, out retLen);
        
        int debugPort = Marshal.ReadInt32(buffer);
        Marshal.FreeHGlobal(buffer);
        
        return debugPort != 0;
    }
}
"@
        Add-Type -TypeDefinition $csharp
        
        $isDebugged = [TLSCheck]::CheckTLS()
        
        if ($isDebugged) {
            $findings += "Process appears to be debugged (common in analysis environments)"
        }
        
    } catch {
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "No TLS/debugging anomalies detected" }
    }
}

function Check-SharedFolders {
    $category = "VM Shared Folders"
    
    $findings = @()
    
    $vboxShares = net use 2>$null | Select-String "VBoxSvr|VBoxSharedFolders"
    if ($vboxShares) {
        $findings += "VirtualBox shared folders detected"
    }
    
    $vmwareShares = net use 2>$null | Select-String "vmware-host|hgfs"
    if ($vmwareShares) {
        $findings += "VMware shared folders detected"
    }
    
    $sharedFolderKeys = @(
        "HKLM:\\SOFTWARE\\Oracle\\VirtualBox Guest Additions\\SharedFolders",
        "HKLM:\\SOFTWARE\\VMware, Inc.\\VMware Tools\\SharedFolders"
    )
    
    foreach ($key in $sharedFolderKeys) {
        if (Test-Path $key) {
            $findings += "Shared folder registry key: $key"
        }
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "No VM shared folders detected" }
    }
}

function Check-FirmwareVM {
    
    $csp = @"
    using System;
    using System.Runtime.InteropServices;
    public static class Native {
        [DllImport("ntdll.dll")]
        public static extern int NtQuerySystemInformation(
            uint SystemInformationClass,
            IntPtr SystemInformation,
            uint SystemInformationLength,
            out uint ReturnLength);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern IntPtr VirtualAlloc(
            IntPtr lpAddress,
            UIntPtr dwSize,
            uint flAllocationType,
            uint flProtect);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool VirtualFree(
            IntPtr lpAddress,
            UIntPtr dwSize,
            uint dwFreeType);
    }
"@
    Add-Type -TypeDefinition $csp | Out-Null

    function Get-TableBytes {
        param(
            [uint32]$Signature,
            [uint32]$TableId
        )

        $class    = 76                           
        [uint32]$reqLen = 0                     
        $tmpPtr = [Native]::VirtualAlloc(
            [IntPtr]::Zero,
            [UIntPtr]::new(16),
            0x3000,                            
            0x04                                
        )
        [Native]::NtQuerySystemInformation(
            $class,
            $tmpPtr,
            [uint32]16,                        
            [ref]$reqLen
        ) | Out-Null

        if ($reqLen -le 16) {
            [Native]::VirtualFree($tmpPtr, [UIntPtr]::new(0), 0x8000) | Out-Null
            return $null
        }

        [Native]::VirtualFree($tmpPtr, [UIntPtr]::new(0), 0x8000) | Out-Null
        $bufPtr = [Native]::VirtualAlloc(
            [IntPtr]::Zero,
            [UIntPtr]::new($reqLen),
            0x3000,
            0x04
        )

        [System.Runtime.InteropServices.Marshal]::WriteInt32($bufPtr,   0, [int]$Signature)
        [System.Runtime.InteropServices.Marshal]::WriteInt32($bufPtr,   4, 1)
        [System.Runtime.InteropServices.Marshal]::WriteInt32($bufPtr,   8, [int]$TableId)
        [System.Runtime.InteropServices.Marshal]::WriteInt32($bufPtr,  12, [int]($reqLen - 16))

        [uint32]$outLen = 0                    
        [Native]::NtQuerySystemInformation(
            $class,
            $bufPtr,
            [uint32]$reqLen,                   
            [ref]$outLen
        ) | Out-Null

        if ($outLen -le 16) {
            [Native]::VirtualFree($bufPtr, [UIntPtr]::new(0), 0x8000) | Out-Null
            return $null
        }

        $payload = New-Object byte[] ($outLen - 16)
        [System.Runtime.InteropServices.Marshal]::Copy($bufPtr + 16, $payload, 0, $payload.Length)
        [Native]::VirtualFree($bufPtr, [UIntPtr]::new(0), 0x8000) | Out-Null

        return $payload
    }

    $targets = @(
      "Parallels","innotek","Oracle","VirtualBox","VMware, Inc.","VMware",
      "Qemu","vbox","BOCHS","BXPC","WAET"
    )

    $findings = @()

    foreach ($tbl in @("RSMB","FIRM")) {
        $sig = [System.BitConverter]::ToInt32([System.Text.Encoding]::ASCII.GetBytes($tbl),0)
        $ids = if ($tbl -eq "FIRM") { 0xC0000,0xE0000 } else { 0 }
        foreach ($id in $ids) {
            $bytes = Get-TableBytes -Signature $sig -TableId $id
            if ($bytes) {
                $text = [System.Text.Encoding]::ASCII.GetString($bytes)
                foreach ($t in $targets) {
                    if ($text.Contains($t)) {
                        $findings += "Found `$t` in $tbl table (ID=0x{0:X})" -f $id
                    }
                }
            }
        }
    }

    $acpiSig = [System.BitConverter]::ToInt32([System.Text.Encoding]::ASCII.GetBytes("ACPI"),0)
    $bytes = Get-TableBytes -Signature $acpiSig -TableId 0
    if ($bytes) {
        $s = [System.Text.Encoding]::ASCII.GetString($bytes)
        foreach ($t in $targets) {
            if ($s.Contains($t)) { $findings += "Found `$t` in ACPI dump" }
        }
    }

    $sn = (Get-WmiObject Win32_BIOS).SerialNumber
    if ($sn -match '^VMW' -or $sn -eq '0' -or $sn -match '^[Ff]+$') {
        $findings += "BIOS serial suggests VM: $sn"
    }

    return [PSCustomObject]@{
      Category = 'Firmware VM Signatures'
      IsBad    = ($findings.Count -gt 0)
      Detail   = if ($findings) { $findings } else { @('No firmware VM signatures detected') }
    }
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = "VM/Sandbox Detection Tool"
$form.Size = New-Object System.Drawing.Size(800, 600)
$form.StartPosition = "CenterScreen"

$startButton = New-Object System.Windows.Forms.Button
$startButton.Text = "Start Scan"
$startButton.Size = New-Object System.Drawing.Size(100, 30)
$startButton.Location = New-Object System.Drawing.Point(10, 10)

$saveButton = New-Object System.Windows.Forms.Button
$saveButton.Text = "Save Report"
$saveButton.Size = New-Object System.Drawing.Size(100, 30)
$saveButton.Location = New-Object System.Drawing.Point(120, 10)
$saveButton.Enabled = $false

$label = New-Object System.Windows.Forms.Label
$label.Text = "Detailed View:"
$label.AutoSize = $true
$label.Location = New-Object System.Drawing.Point(10, 50)

$descButton = New-Object System.Windows.Forms.Button
$descButton.Text = "Descriptions"
$descButton.Size = New-Object System.Drawing.Size(100, 30)
$descButton.Location = New-Object System.Drawing.Point(230, 10)

$descriptions = @"
Registry Keys:
- No virtualization or sandbox-related registry keys detected. Indicates no leftover or active virtual environment signatures like VBoxService or Sandboxie.
Timing Check:
- Normal sleep duration observed. Malware sandboxes often patch sleep timers to artificially speed up execution.
HypervisorCheck:
- The CPU does not report a hypervisor being present. On real hardware, the HypervisorPresent flag is false.
CPUFeatureCheck:
- All expected CPU instructions (NX, SSE2/3, RDTSC) are present. Virtual CPUs may lack or misreport these features.
VideoAdapterCheck:
- No known virtual GPU drivers (e.g., VBoxVideo, VMware SVGA) detected. Indicates likely presence of physical hardware.
OSArtifactCheck:
- System metadata (username, organization, install date) lacks sandbox defaults or artifacts.
Processes:
- No known VM-related processes (VBoxService, vboxtray, vmtoolsd) are running. Suggests this is not a virtual machine.
System Files:
- No virtualization or sandbox-related driver files found on disk (e.g., VBoxGuest.sys, VBoxSF.sys).
Hardware IDs:
- Manufacturer/model strings of hardware do not match known virtual device patterns (e.g., “VirtualBox”, “VMware”).
BIOS Info:
- BIOS vendor, version, and serial appear consistent with OEM/physical systems, not virtualization platforms.
MAC Address:
- No MAC address prefixes associated with virtualization vendors (e.g., 08:00:27 for VirtualBox) detected.
Device Manager Names:
- No device names in Device Manager indicate virtualization or emulation.
ACPI Tables:
- No virtualization indicators (e.g., “VBOX__”, “VMW__”) present in ACPI firmware tables.
CPU Cores:
- Logical CPU core count is high (16+), which matches modern real hardware. VMs often use only 1–4 cores.
RAM Size:
- Detected RAM exceeds typical VM defaults (6 GB minimum). Higher values suggest physical hardware.
Disk Size:
- Storage capacity exceeds typical VM provisioning (usually under 100 GB). A large disk (e.g., 475 GB) implies real hardware.
Mouse Movement:
- Mouse movement detected quickly. Sandboxes often lack real input simulation or have high input latency.
PCI Vendor ID:
- PCI devices do not match VirtualBox-specific vendor IDs or known emulated hardware.
BaseBoard:
- Motherboard manufacturer/product does not indicate virtualization. Values like “Oracle” or “VirtualBox” are absent.
VirtualBox BIOS:
- BIOS strings lack references to “VirtualBox” or “Oracle Corporation”.
Event Log Sources:
- No VBox-related sources (vboxvideo, VBoxWddm) found in Windows event logs.
VirtualBox Registry:
- No registry keys or values left behind by VirtualBox installation detected.
NetProvider:
- No network providers related to VirtualBox Shared Folders are present.
VirtualBox Files:
- File system lacks VBoxGuest Additions binaries (e.g., VBoxService.exe).
VirtualBox Directories:
- No program directories like “C:\Program Files\Oracle\VirtualBox” exist.
Firmware VM Signatures:
- No EFI/firmware-based identifiers for VMs were found.
CPU IDs:
- CPU name appears standard (“Intel Core i5-12500H”) without any virtual machine branding (QEMU, VMWare, etc.).
"@

$descButton.Add_Click({
    [System.Windows.Forms.MessageBox]::Show($descriptions, "Descriptions", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
})

$form.Controls.Add($descButton)

$richTextBox = New-Object System.Windows.Forms.RichTextBox
$richTextBox.Location = New-Object System.Drawing.Point(10, 70)
$richTextBox.Size = New-Object System.Drawing.Size(760, 480)
$richTextBox.ReadOnly = $true
$richTextBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$richTextBox.BackColor = [System.Drawing.Color]::Black
$richTextBox.ForeColor = [System.Drawing.Color]::White
$richTextBox.WordWrap = $false
$richTextBox.ScrollBars = "Both"

$form.Controls.Add($startButton)
$form.Controls.Add($saveButton)
$form.Controls.Add($label)
$form.Controls.Add($richTextBox)

$checks = @(
    'Check-RegistryArtifacts',
    'Check-SleepHook',
    'Check-Hypervisor',
    'Check-CPUFeatures',
    'Check-VideoAdapter',
    'Check-OSArtifacts',
    'Check-Processes',
    'Check-DriversFiles',
    'Check-SystemManufacturer',
    'Check-BIOSInfo',
    'Check-MAC',
    'Check-DeviceNames',
    'Check-ACPI',
    'Check-CPUCores',
    'Check-RAM',
    'Check-Disk',
    'Check-MouseMovement',
    'Check-PciVendor',
    'Check-BaseBoard',
    'Check-VBoxBiosData',
    'Check-EventLogSources',
    'Check-VBoxRegistryKeys',
    'Check-NetworkProvider',
    'Check-VBoxFiles',
    'Check-VBoxDirectories',
    'Check-FirmwareVM',
    'Check-CPUHypervisor',
    'Check-CPUIDHypervisorBit',
    'Check-USBDevices',
    'Check-BatteryPresence',
    'Check-TemperatureSensors',
    'Check-SystemUptime',
	'Check-InstructionTiming',
    'Check-CPUBrandString',
    'Check-CacheTopology',
    'Check-MemoryArtifacts',
    'Check-DiskIOPattern',
    'Check-VirtualBoxPorts',
    'Check-GPUMemory',
    'Check-WindowsSandbox',
    'Check-SuspiciousPrograms',
    'Check-SMARTData',
    'Check-VBoxDLLs',
    'Check-ProcessAncestry',
    'Check-VMWindowTitles',
    'Check-KernelDrivers',
    'Check-ClipboardHistory',
    'Check-TLSCallbacks',
    'Check-SharedFolders',
	'Check-NetworkInterfaceDetails',
    'Check-VirtualizationPersistence',
    'Check-PCIDevices',
    'Check-SystemEntropy',
    'Check-AudioDevices'
)

$startButton.Add_Click({
    $richTextBox.Clear()
    $results = @()

    foreach ($fn in $checks) {
        try {
            $results += & $fn
        }
        catch {
            $results += [PSCustomObject]@{
                Category = $fn
                IsBad    = $true
                Detail   = "Error running $fn`: $_"
            }
        }
    }

    $maxLen = ($results | ForEach-Object { $_.Category.Length } | Measure-Object -Maximum).Maximum
    $padLen = $maxLen + 3

    foreach ($res in $results) {
        $richTextBox.SelectionColor = [System.Drawing.Color]::White
        $richTextBox.AppendText($res.Category.PadRight($padLen))

        if ($res.IsBad) {
            $richTextBox.SelectionColor = [System.Drawing.Color]::Red
            $richTextBox.AppendText("[ BAD ]")
        } else {
            $richTextBox.SelectionColor = [System.Drawing.Color]::Lime
            $richTextBox.AppendText("[ GOOD ]")
        }

        $richTextBox.SelectionColor = [System.Drawing.Color]::White
        $richTextBox.AppendText("`r`n")

        if ($res.Detail) {
            foreach ($item in ($res.Detail -as [array])) {
                $richTextBox.SelectionColor = [System.Drawing.Color]::Gray
                $richTextBox.AppendText("    - $item`r`n")
            }
        }
    }

    $saveButton.Enabled = $true
})

$saveButton.Add_Click({
    $dialog = New-Object System.Windows.Forms.SaveFileDialog -Property @{
        Filter   = "Text Files|*.txt"
        Title    = "Save Report"
        FileName = "VMDetectionReport.txt"
    }
    if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $richTextBox.Text | Out-File -FilePath $dialog.FileName -Encoding UTF8
        [System.Windows.Forms.MessageBox]::Show("Report saved to $($dialog.FileName)", "Saved")
    }
})

[void]$form.ShowDialog()
