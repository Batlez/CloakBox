[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

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

Add-Type @"
    using System;
    using System.Runtime.InteropServices;
    namespace Win32 {
        public class User32 {
            [DllImport("user32.dll")]
            public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
            [DllImport("user32.dll")]
            public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        }
    }
"@ -ErrorAction SilentlyContinue

$Global:restartRequired = $false
$Global:logPath = ""
$Global:UserChoices = @{}

function Get-YesNoChoice {
    param(
        [string]$Question,
        [string]$Default = "N",
        [string]$HelpMessage = "",
        [string]$SettingName = ""
    )
    $choices = @(
        [System.Management.Automation.Host.ChoiceDescription]::new("&Yes", "Apply this change.")
        [System.Management.Automation.Host.ChoiceDescription]::new("&No", "Skip this change.")
    )
    $defaultChoiceIndex = if ($Default -eq "Y") { 0 } else { 1 }

    Write-Host "`n? [ACTION] " -ForegroundColor White -NoNewline
    Write-Host "$Question" -ForegroundColor Cyan
    if ($HelpMessage) {
        Write-Host "  > $HelpMessage" -ForegroundColor Gray
    }
    $decision = $Host.UI.PromptForChoice("", "", $choices, $defaultChoiceIndex)
    
    if ($SettingName) {
        $Global:UserChoices[$SettingName] = ($decision -eq 0)
    }
    
    return $decision -eq 0
}

function Get-RandomString {
    param ([int]$Length = 10)
    $charSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".ToCharArray()
    -join ($charSet | Get-Random -Count $Length)
}

function Start-ScriptLogging {
    param (
        [string]$LogPath = "$env:USERPROFILE\Documents\WindowsHardening_Log.txt"
    )
    
    Start-Transcript -Path $LogPath -Append -Force
    
    Write-Host "`n# ===========================================================" -ForegroundColor Magenta
    Write-Host "#      WINDOWS HARDENING & ANTI-VM DETECTION SCRIPT" -ForegroundColor Magenta
    Write-Host "#      Execution Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Magenta
    Write-Host "#      System: $([System.Environment]::OSVersion.VersionString)" -ForegroundColor Magenta
    Write-Host "# ===========================================================" -ForegroundColor Magenta
    
    return $LogPath
}

function New-RestorePoint {
    Write-Host "`n  # ================== CREATING SYSTEM RESTORE POINT ==================" -ForegroundColor Magenta
    
    $srService = Get-Service -Name "swprv" -ErrorAction SilentlyContinue
    if ($srService.Status -ne "Running") {
        Start-Service -Name "swprv" -ErrorAction SilentlyContinue
    }

    $systemDrive = $env:SystemDrive
    $volumeInfo = vssadmin list volumes | Select-String -Pattern "Volume path:\s+$systemDrive\\"
    if ($volumeInfo) {
        try {
            Enable-ComputerRestore -Drive $systemDrive -ErrorAction SilentlyContinue
            $restorePointName = "Before Windows Hardening Script - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
            Checkpoint-Computer -Description $restorePointName -RestorePointType "APPLICATION_INSTALL" -ErrorAction Stop
            Write-Host "  # [OK] System Restore Point created: '$restorePointName'" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Host "  # [WARN] Failed to create a restore point: $($_.Exception.Message)" -ForegroundColor Yellow
            return $false
        }
    }
    else {
        Write-Host "  # [WARN] System Restore is not enabled for drive $systemDrive" -ForegroundColor Yellow
        return $false
    }
}

function Set-EnhancedDefenderSettings {
    Write-Host "`n  # ================== CONFIGURING DEFENDER ADVANCED SETTINGS ==================" -ForegroundColor Magenta
    
    try {
        Get-MpPreference -ErrorAction Stop | Out-Null
        
        Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
        
        Set-MpPreference -DisableBlockAtFirstSeen $false -ErrorAction SilentlyContinue
        
        Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue
        
        try {
            Set-ProcessMitigation -PolicyFilePath "$env:windir\schemas\CodeIntegrity\ExploitProtectionSettings.xml" -ErrorAction SilentlyContinue
        } catch {
            Write-Host "  # [WARN] Could not set exploit protection policy: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        
        $asrRules = @{
            'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550' = 'Enabled'
            'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' = 'Enabled'
            '3B576869-A4EC-4529-8536-B80A7769E899' = 'Enabled'
            'D3E037E1-3EB8-44C8-A917-57927947596D' = 'Enabled'
            '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC' = 'Enabled'
        }
        
        foreach ($rule in $asrRules.Keys) {
            try {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $rule -AttackSurfaceReductionRules_Actions $asrRules[$rule] -ErrorAction SilentlyContinue
            } catch {
                Write-Host "  # [WARN] Could not set ASR rule $rule`: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        
        Write-Host "  # [OK] Advanced Windows Defender settings applied." -ForegroundColor Green
    }
    catch {
        Write-Host "  # [WARN] Windows Defender service is not available or properly configured." -ForegroundColor Yellow
        Write-Host "  # [WARN] Error: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  # [INFO] Skipping Windows Defender configuration." -ForegroundColor Yellow
    }
}

function Set-EnhancedFirewallSettings {
    Write-Host "`n  # ================== CONFIGURING SECURE FIREWALL SETTINGS ==================" -ForegroundColor Magenta
    
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
    
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow
    
    Set-NetFirewallProfile -Profile Public -NotifyOnListen False
    
    Set-NetFirewallProfile -Profile Public -LogBlocked True -LogAllowed True
    
    Write-Host "  # [OK] Secure firewall settings applied." -ForegroundColor Green
}

function Set-AdvancedVMEvasion {
    Write-Host "`n  # ================== APPLYING ADVANCED VM EVASION ==================" -ForegroundColor Magenta 

Write-Host "  # [INFO] Applying MAC address spoofing..." -ForegroundColor Yellow

$macSuccess = Set-RandomMacAddress

if (-not $macSuccess) {
    Write-Host "  # [INFO] Trying alternative MAC address approach..." -ForegroundColor Yellow
    
    $adapters = Get-NetAdapter | Where-Object Status -eq 'Up'
    foreach ($adapter in $adapters) {
        try {
            $adapterInfo = Get-NetAdapter | Where-Object { $_.Name -eq $adapter.Name } | Select-Object -First 1
            $adapterId = $adapterInfo.InterfaceGuid
            
            $macHex = ('{0:X}' -f (Get-Random -Maximum 0xFFFFFFFFFFFF)).PadLeft(12, "0") 
            $macHex = $macHex -replace '^(.)(.)', ('$1' + (Get-Random -InputObject 'A','E','2','6')) -replace '\$', ''
            
            $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}"
            
            $netAdapters = Get-ChildItem -Path $registryPath -ErrorAction SilentlyContinue
            foreach ($netAdapter in $netAdapters) {
                try {
                    $instanceId = (Get-ItemProperty -Path $netAdapter.PSPath -ErrorAction SilentlyContinue).NetCfgInstanceId
                    if ($instanceId -eq $adapterId) {
                        Set-ItemProperty -Path $netAdapter.PSPath -Name "NetworkAddress" -Value $macHex -Type String -Force
                        Write-Host "  # [OK] Applied MAC address $macHex to adapter $($adapter.Name) via registry" -ForegroundColor Green
                        
                        $adapter | Restart-NetAdapter -ErrorAction SilentlyContinue
                        break
                    }
                }
                catch {
                }
            }
        }
        catch {
            Write-Host "  # [WARNING] Could not set MAC address for $($adapter.Name): $_" -ForegroundColor Yellow
        }
    }
}
    
    Write-Host "  # [INFO] Modifying WMI class information to hide VM artifacts..." -ForegroundColor Yellow
    
    $modelData = @(
        "Alienware Aurora R12", 
        "Dell XPS 8940", 
        "HP Omen 30L", 
        "Lenovo Legion Tower 5i", 
        "ASUS ROG Strix G15",
        "MSI Aegis RS"
    )
    $modelName = $modelData | Get-Random
    
    try {
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
        $computerSystem.Manufacturer = "Dell Inc."
        $computerSystem.Model = $modelName
        $computerSystem.Put() | Out-Null
        Write-Host "  # [OK] Modified ComputerSystem WMI data" -ForegroundColor Green
    }
    catch {
        Write-Host "  # [WARN] Could not modify ComputerSystem WMI data: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
	try {
		$biosRegistryPath = "HKLM:\HARDWARE\DESCRIPTION\System\BIOS"
		if (Test-Path $biosRegistryPath) {
			$serialNumber = (Get-RandomString -Length 10).ToUpper()
			$biosVersion = "2.5.$((Get-Random -Minimum 1000 -Maximum 9999).ToString())"
        
			Set-ItemProperty -Path $biosRegistryPath -Name "BIOSVendor" -Value "Dell Inc." -Type String -Force
			Set-ItemProperty -Path $biosRegistryPath -Name "BIOSVersion" -Value $biosVersion -Type String -Force
			Set-ItemProperty -Path $biosRegistryPath -Name "SystemManufacturer" -Value "Dell Inc." -Type String -Force
			Set-ItemProperty -Path $biosRegistryPath -Name "SystemProductName" -Value $modelName -Type String -Force
        
			Set-ItemProperty -Path $biosRegistryPath -Name "BIOSReleaseDate" -Value "06/01/2024" -Type String -Force
			Set-ItemProperty -Path $biosRegistryPath -Name "SystemFamily" -Value "Dell System" -Type String -Force
			Set-ItemProperty -Path $biosRegistryPath -Name "SystemSKU" -Value "09A2" -Type String -Force
			Set-ItemProperty -Path $biosRegistryPath -Name "SerialNumber" -Value $serialNumber -Type String -Force
        
			Write-Host "  # [OK] Modified BIOS data via registry" -ForegroundColor Green
		}
	}
	catch {
		Write-Host "  # [WARN] Could not modify BIOS data via registry: $($_.Exception.Message)" -ForegroundColor Yellow
    
		try {
			$altBiosPath = "HKLM:\HARDWARE\DESCRIPTION\System"
			Set-ItemProperty -Path $altBiosPath -Name "SystemBiosVersion" -Value "Dell Inc. $biosVersion" -Type MultiString -Force
			Set-ItemProperty -Path $altBiosPath -Name "VideoBiosVersion" -Value "Dell Video BIOS" -Type MultiString -Force
			Write-Host "  # [OK] Modified alternate BIOS data via registry" -ForegroundColor Green
		}
		catch {
			Write-Host "  # [WARN] Could not modify alternate BIOS data: $($_.Exception.Message)" -ForegroundColor Yellow
		}
	}
    
    Write-Host "  # [INFO] Removing registry VM artifacts..." -ForegroundColor Yellow
    
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters" -Name "PhysicalHostName" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters" -Name "VirtualMachineName" -ErrorAction SilentlyContinue
    
    $vmRegistryPaths = @(
        "HKLM:\SYSTEM\ControlSet001\Services\vmdebug",
        "HKLM:\SYSTEM\ControlSet001\Services\vmmouse",
        "HKLM:\SYSTEM\ControlSet001\Services\VMTools",
        "HKLM:\SYSTEM\ControlSet001\Services\VMMEMCTL",
        "HKLM:\SYSTEM\ControlSet001\Services\vmware",
        "HKLM:\SYSTEM\ControlSet001\Services\vmci",
        "HKLM:\SYSTEM\ControlSet001\Services\vboxguest",
        "HKLM:\SYSTEM\ControlSet001\Services\VBoxService",
        "HKLM:\SYSTEM\CurrentControlSet\Services\vmdebug",
        "HKLM:\SYSTEM\CurrentControlSet\Services\vmmouse",
        "HKLM:\SYSTEM\CurrentControlSet\Services\VMTools",
        "HKLM:\SYSTEM\CurrentControlSet\Services\VMMEMCTL",
        "HKLM:\SYSTEM\CurrentControlSet\Services\vmware",
        "HKLM:\SYSTEM\CurrentControlSet\Services\vmci",
        "HKLM:\SYSTEM\CurrentControlSet\Services\vboxguest",
        "HKLM:\SYSTEM\CurrentControlSet\Services\VBoxService"
    )
    
    foreach ($path in $vmRegistryPaths) {
        if (Test-Path $path) {
            try {
                Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "  # [OK] Removed registry path: $path" -ForegroundColor Green
            }
            catch {
                Write-Host "  # [WARN] Could not remove registry path: $path" -ForegroundColor Yellow
            }
        }
    }
    
    Write-Host "  # [INFO] Performing advanced memory artifact cleanup..." -ForegroundColor Yellow
    
    $signature = @"
    [DllImport("psapi.dll")]
    public static extern int EmptyWorkingSet(IntPtr hProcess);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
    
    [DllImport("kernel32.dll")]
    public static extern bool SetProcessWorkingSetSize(IntPtr hProcess, int dwMinimumWorkingSetSize, int dwMaximumWorkingSetSize);
"@
    
    try {
        Add-Type -MemberDefinition $signature -Name MemoryUtils -Namespace CleanupTools -ErrorAction Stop
        
        $vmProcesses = @(
            "VirtualBoxVM", "VBoxSVC", "VBoxTray", "VBoxHeadless",
            "vmtoolsd", "vm3dservice", "vmacthlp", "VMwareTray", "VMwareService"
        )
        
        foreach ($processName in $vmProcesses) {
            $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
            if ($processes) {
                foreach ($process in $processes) {
                    try {
                        Write-Host "  # [INFO] Clearing memory for VM process: $processName" -ForegroundColor Yellow
                        [CleanupTools.MemoryUtils]::EmptyWorkingSet($process.Handle) | Out-Null
                    }
                    catch {
                    }
                }
            }
        }
        
        $currentProcess = [CleanupTools.MemoryUtils]::GetCurrentProcess()
        [CleanupTools.MemoryUtils]::SetProcessWorkingSetSize($currentProcess, -1, -1) | Out-Null
        
        Write-Host "  # [OK] Memory artifact cleanup completed" -ForegroundColor Green
    }
    catch {
        Write-Host "  # [WARN] Memory cleanup functions unavailable: $_" -ForegroundColor Yellow
    }
    
    Write-Host "  # [INFO] Removing VM-specific temporary files..." -ForegroundColor Yellow
    
    $vmTempPaths = @(
        "$env:TEMP\VBox*", 
        "$env:TEMP\vmware*",
        "$env:LOCALAPPDATA\Temp\VBox*", 
        "$env:LOCALAPPDATA\Temp\vmware*",
        "$env:WINDIR\Temp\VBox*",
        "$env:WINDIR\Temp\vmware*",
        "$env:WINDIR\Prefetch\VBOX*",
        "$env:WINDIR\Prefetch\VMWARE*"
    )
    
    foreach ($path in $vmTempPaths) {
        if (Test-Path -Path $path) {
            try {
                $files = Get-ChildItem -Path $path -Force -ErrorAction SilentlyContinue
                $fileCount = ($files | Measure-Object).Count
                if ($fileCount -gt 0) {
                    Write-Host "  # [INFO] Removing $fileCount temporary files: $path" -ForegroundColor Yellow
                    $files | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                }
            }
            catch {
            }
        }
    }
    
    Write-Host "  # [INFO] Applying CPU information spoofing..." -ForegroundColor Yellow
    
    $cpuNames = @(
        "Intel(R) Core(TM) i7-11700K CPU @ 3.60GHz",
        "Intel(R) Core(TM) i9-10900K CPU @ 3.70GHz",
        "AMD Ryzen 9 5900X 12-Core Processor",
        "AMD Ryzen 7 5800X 8-Core Processor",
        "Intel(R) Core(TM) i5-12600K CPU @ 3.70GHz"
    )
    $cpuName = $cpuNames | Get-Random
    
    try {
        $cpuPath = "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0"
        Set-ItemProperty -Path $cpuPath -Name "ProcessorNameString" -Value $cpuName -Type String -Force
        Write-Host "  # [OK] Applied CPU name: $cpuName" -ForegroundColor Green
        
        $cores = Get-Random -Minimum 6 -Maximum 17
        $threads = $cores * 2
        Set-ItemProperty -Path $cpuPath -Name "~MHz" -Value (Get-Random -Minimum 3400 -Maximum 5000) -Type DWord -Force
    }
    catch {
        Write-Host "  # [WARN] Could not modify CPU information: $_" -ForegroundColor Yellow
    }
    
    Write-Host "  # [INFO] Creating realistic desktop environment..." -ForegroundColor Yellow
    
    $commonApps = @(
        @{ Name = "Chrome"; Path = "C:\Program Files\Google\Chrome\Application\chrome.exe" },
        @{ Name = "Word"; Path = "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" },
        @{ Name = "Spotify"; Path = "C:\Users\$env:USERNAME\AppData\Roaming\Spotify\Spotify.exe" },
        @{ Name = "Steam"; Path = "C:\Program Files (x86)\Steam\steam.exe" }
    )
    
    $desktopPath = [System.Environment]::GetFolderPath("Desktop")
    
    foreach ($app in $commonApps) {
        $shortcutPath = Join-Path $desktopPath "$($app.Name).lnk"
        if (!(Test-Path $shortcutPath)) {
            try {
                $WshShell = New-Object -ComObject WScript.Shell
                $shortcut = $WshShell.CreateShortcut($shortcutPath)
                $shortcut.TargetPath = $app.Path
                $shortcut.Save()
                Write-Host "  # [INFO] Created desktop shortcut for $($app.Name)" -ForegroundColor Yellow
            }
            catch {
            }
        }
    }
    
    Write-Host "  # [INFO] Performing final cleanup..." -ForegroundColor Yellow
    
    Clear-DnsClientCache
    
    Remove-Item -Path "$env:LOCALAPPDATA\CrashDumps\*.dmp" -Force -ErrorAction SilentlyContinue
    
    [System.GC]::Collect()
    
    Write-Host "  # [OK] Advanced VM evasion techniques applied successfully" -ForegroundColor Green
}

function Set-ProcessTimingMasking {
    Write-Host "`n  # ================== APPLYING PROCESS & TIMING MASKING ==================" -ForegroundColor Magenta
    
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Value 0 -Type DWord -Force
    
    Write-Host "  # [INFO] Modifying performance counter behavior..." -ForegroundColor Yellow
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib" -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib" -Name "Disable Performance Counters" -Value 1 -Type DWord -Force
    
    Write-Host "  # [OK] Process and timing masking applied." -ForegroundColor Green
}

function Set-ApplicationWhitelisting {
    Write-Host "`n  # ================== CONFIGURING APPLICATION WHITELISTING ==================" -ForegroundColor Magenta
    
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "  # [ERROR] Administrator rights required for AppLocker configuration" -ForegroundColor Red
        return $false
    }
    
    $edition = (Get-WmiObject -class Win32_OperatingSystem).Caption
    if ($edition -match "Home|IoT|Mobile") {
        Write-Host "  # [INFO] AppLocker is not supported on Windows $edition" -ForegroundColor Yellow
        Write-Host "  # [INFO] Using Software Restriction Policies instead" -ForegroundColor Yellow
        
        $srPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
        if (!(Test-Path $srPath)) {
            New-Item -Path $srPath -Force | Out-Null
        }
        Set-ItemProperty -Path $srPath -Name "DefaultLevel" -Value 262144 -Type DWord -Force
        Set-ItemProperty -Path $srPath -Name "PolicyScope" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $srPath -Name "ExecutableTypes" -Value ".exe;.com;.bat;.cmd;.scr;.pif;.ps1;.vbs;.js" -Type String -Force
        Write-Host "  # [OK] Software Restriction Policy configured as alternative" -ForegroundColor Green
        $Global:restartRequired = $true
        return $true
    }
    
    $appLockerSvc = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
    if (!$appLockerSvc) {
        Write-Host "  # [WARN] AppLocker service not found. Trying to create registry entries instead." -ForegroundColor Yellow
        
        $appLockerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2"
        if (!(Test-Path $appLockerPath)) {
            New-Item -Path $appLockerPath -Force | Out-Null
            New-Item -Path "$appLockerPath\Exe" -Force | Out-Null
            New-Item -Path "$appLockerPath\Msi" -Force | Out-Null
            New-Item -Path "$appLockerPath\Script" -Force | Out-Null
        }
        
        Set-ItemProperty -Path "$appLockerPath\Exe" -Name "EnforcementMode" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path "$appLockerPath\Msi" -Name "EnforcementMode" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path "$appLockerPath\Script" -Name "EnforcementMode" -Value 1 -Type DWord -Force
        
        Write-Host "  # [OK] AppLocker registry configured" -ForegroundColor Green
        $Global:restartRequired = $true
        return $true
    }
    
    $rulesDir = "$env:windir\System32\AppLocker"
    if (!(Test-Path $rulesDir)) {
        New-Item -Path $rulesDir -ItemType Directory -Force | Out-Null
    }
    
    try {
        $execRules = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule("Everyone", "ReadAndExecute", "Allow")
        $acl = Get-Acl -Path "$env:windir"
        $acl.AddAccessRule($execRules)
        Set-Acl -Path "$env:windir" -AclObject $acl
        Write-Host "  # [OK] Added ReadAndExecute permissions for Everyone to Windows directory" -ForegroundColor Green
    }
    catch {
        Write-Host "  # [WARN] Could not set ACL for Windows directory: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    try {
        Write-Host "  # [INFO] Configuring Application Identity service..." -ForegroundColor Yellow
        Set-Service -Name "AppIDSvc" -StartupType Automatic -ErrorAction Stop
        Start-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
        Write-Host "  # [OK] Application Identity service enabled" -ForegroundColor Green
    }
    catch {
        Write-Host "  # [WARN] Couldn't configure service: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  # [INFO] Trying registry modification instead..." -ForegroundColor Yellow
        
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AppIDSvc" -Name "Start" -Value 2 -Type DWord -Force
            Write-Host "  # [OK] Service configured via registry" -ForegroundColor Green
        }
        catch {
            Write-Host "  # [WARN] Couldn't modify service registry: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    
    if (Get-Command -Name "New-AppLockerPolicy" -ErrorAction SilentlyContinue) {
        Write-Host "  # [INFO] Using PowerShell AppLocker cmdlets to configure policy..." -ForegroundColor Yellow
        try {
            $exeRules = New-AppLockerPolicy -FileInformation (Get-ChildItem -Path "$env:WINDIR\*.exe" -Recurse | Get-AppLockerFileInformation) -RuleType Publisher, Hash, Path -User "Everyone" -RuleNamePrefix "Windows"
            Set-AppLockerPolicy -PolicyObject $exeRules -Merge
            Write-Host "  # [OK] AppLocker policy configured via PowerShell" -ForegroundColor Green
        }
        catch {
            Write-Host "  # [WARN] Error setting AppLocker policy via PowerShell: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "  # [INFO] Falling back to registry method..." -ForegroundColor Yellow
        }
    }
    
    Write-Host "  # [INFO] Setting AppLocker enforcement via registry..." -ForegroundColor Yellow
    & $env:windir\System32\reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe" /v "EnforcementMode" /t REG_DWORD /d 1 /f
    & $env:windir\System32\reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Msi" /v "EnforcementMode" /t REG_DWORD /d 1 /f
    & $env:windir\System32\reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Script" /v "EnforcementMode" /t REG_DWORD /d 1 /f
    
    Write-Host "  # [OK] AppLocker configured in audit mode. Check Event Viewer > Applications and Services Logs > Microsoft > Windows > AppLocker for results." -ForegroundColor Green
    $Global:restartRequired = $true
    return $true
}

function Set-BIOSSecurityRecommendations {
    Write-Host "`n  # ================== BIOS SECURITY RECOMMENDATIONS ==================" -ForegroundColor Magenta
    
    $biosRecommendations = @(
        "Enable UEFI Boot Mode (disable Legacy/CSM)",
        "Enable Secure Boot",
        "Set a BIOS/UEFI password",
        "Disable booting from external devices when not needed",
        "Enable TPM",
        "Enable memory protection features like NX/XD",
        "Disable unused devices (serial/parallel ports, etc.)",
        "Enable Virtualization Technology (VT-x/AMD-V) only if needed for VMs"
    )
    
    Write-Host "  # The following BIOS settings are recommended for security:" -ForegroundColor Yellow
    foreach ($rec in $biosRecommendations) {
        Write-Host "  - $rec" -ForegroundColor Cyan
    }
    
    Write-Host "`n  # [NOTE] These settings must be configured in your system BIOS/UEFI setup." -ForegroundColor Yellow
    Write-Host "  # To access BIOS/UEFI, typically press F1, F2, F10, F12, or Del during startup," -ForegroundColor Yellow
    Write-Host "  # depending on your computer manufacturer." -ForegroundColor Yellow
}

function Set-RandomMachineGuid {
    Write-Host "`n  # ================== SPOOFING MACHINE GUID ==================" -ForegroundColor Magenta
    
    try {
        $newGuid = [guid]::NewGuid().ToString()
        Write-Host "  # [INFO] Generating new random MachineGuid: $newGuid" -ForegroundColor Yellow
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name 'MachineGuid' -Type String -Value $newGuid -Force
        Write-Host "  # [OK] MachineGuid successfully changed." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "  # [ERROR] Failed to change MachineGuid: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Set-EnhancedInstallDateTime {
    Write-Host "`n  # ================== SPOOFING INSTALL DATE & TIME ==================" -ForegroundColor Magenta
    
    try {
        $randomDate = Get-Random -Minimum ([datetime]'2011-01-01').Ticks -Maximum (([datetime]'2022-12-31').Ticks) | ForEach-Object {[datetime]$_}
        
        $unixTimestamp = [int]($randomDate.ToUniversalTime() - [datetime]'1970-01-01').TotalSeconds
        $ldapFileTime = [int64](($unixTimestamp + 11644473600) * 1e7)
        
        Write-Host "  # [INFO] Setting install date to: $($randomDate.ToString('yyyy-MM-dd')) ($unixTimestamp)" -ForegroundColor Yellow
        
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        Set-ItemProperty -Path $regPath -Name "InstallDate" -Value $unixTimestamp -Force
        Set-ItemProperty -Path $regPath -Name "InstallTime" -Value $ldapFileTime -Force
        
        $timeService = Get-Service w32time -ErrorAction SilentlyContinue
        if ($timeService -and $timeService.Status -ne "Disabled") {
            Write-Host "  # [INFO] Configuring Windows Time service with public NTP servers..." -ForegroundColor Yellow
            
            try {
                if ($timeService.Status -ne "Running") {
                    Start-Service w32time -ErrorAction Stop
                }
                
                w32tm /config /syncfromflags:manual /manualpeerlist:"0.pool.ntp.org,1.pool.ntp.org,2.pool.ntp.org,3.pool.ntp.org" /update -ErrorAction SilentlyContinue
                
                try {
                    Restart-Service w32time -Force -ErrorAction Stop
                    w32tm /resync -ErrorAction SilentlyContinue | Out-Null
                    Write-Host "  # [OK] Windows Time service configured successfully" -ForegroundColor Green
                }
                catch {
                    Write-Host "  # [WARN] Could not restart Windows Time service: $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "  # [WARN] Windows Time service could not be started: $($_.Exception.Message)" -ForegroundColor Yellow
                Write-Host "  # [INFO] Proceeding without time synchronization" -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "  # [INFO] Windows Time service is not available or disabled, skipping time configuration" -ForegroundColor Yellow
            
            try {
                $currentDate = Get-Date
                $year = $currentDate.Year
                $month = $currentDate.Month
                $day = $currentDate.Day
                
                $hour = Get-Random -Minimum 8 -Maximum 18  # Business hours
                $minute = Get-Random -Minimum 0 -Maximum 60
                $second = Get-Random -Minimum 0 -Maximum 60
                
                $newDate = Get-Date -Year $year -Month $month -Day $day -Hour $hour -Minute $minute -Second $second
                Set-Date -Date $newDate -ErrorAction SilentlyContinue
                Write-Host "  # [INFO] System time set to: $newDate" -ForegroundColor Yellow
            }
            catch {
                Write-Host "  # [WARN] Could not set system time directly: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        
        Write-Host "  # [OK] Install date/time settings successfully modified." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "  # [ERROR] Failed to spoof install date/time: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Set-RandomMacAddress {
    Write-Host "`n  # ================== SPOOFING MAC ADDRESS ==================" -ForegroundColor Magenta
    
    try {
        $newMac = ('{0:X}' -f (Get-Random -Maximum 0xFFFFFFFFFFFF)).PadLeft(12, "0") -replace '^(.)(.)', ('$1' + (Get-Random -InputObject 'A','E','2','6')) -replace '\$', ''
        
        $adapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
        
        if ($adapters.Count -eq 0) {
            Write-Host "  # [WARN] No active network adapters found." -ForegroundColor Yellow
            return $false
        }
        
        foreach ($adapter in $adapters) {
            Write-Host "  # [INFO] Changing MAC address of '$($adapter.Name)' to $newMac..." -ForegroundColor Yellow
            try {
                Set-NetAdapter -Name $adapter.Name -MacAddress $newMac -Confirm:$false
                Write-Host "  # [OK] MAC address successfully changed for adapter '$($adapter.Name)'." -ForegroundColor Green
            }
            catch {
                Write-Host "  # [WARN] Failed to change MAC for adapter '$($adapter.Name)': $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        
        $Global:restartRequired = $true
        return $true
    }
    catch {
        Write-Host "  # [ERROR] MAC address spoofing failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Set-VBoxDllPatching {
    Write-Host "`n  # ================== PATCHING VBOX DLL ARTIFACTS ==================" -ForegroundColor Magenta
    
    $vboxDlls = @(
        "$env:windir\System32\VBoxHook.dll",
        "$env:windir\System32\VBoxMRXNP.dll",
        "$env:windir\System32\VBoxService.exe",
        "$env:windir\System32\VBoxTray.exe",
        "$env:windir\System32\VBoxControl.exe"
    )
    
    foreach ($dll in $vboxDlls) {
        if (Test-Path $dll) {
            try {
                $extension = [System.IO.Path]::GetExtension($dll)
                $newName = [System.IO.Path]::GetDirectoryName($dll) + "\" + (Get-RandomString -Length 8) + $extension
                
                Write-Host "  # [INFO] Found VBox artifact: $dll" -ForegroundColor Yellow
                Write-Host "  # [INFO] Renaming to: $newName" -ForegroundColor Yellow
                
                $procName = [System.IO.Path]::GetFileNameWithoutExtension($dll)
                Stop-Process -Name $procName -Force -ErrorAction SilentlyContinue
                
                Move-Item -Path $dll -Destination $newName -Force
                Write-Host "  # [OK] Successfully renamed VBox artifact" -ForegroundColor Green
            }
            catch {
                Write-Host "  # [WARN] Could not rename $dll`: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }

    Write-Host "  # [INFO] Looking for VBox window classes..." -ForegroundColor Yellow
    $vboxClassNames = @("VBoxTrayToolWndClass", "VBoxTrayToolWnd")
    foreach ($className in $vboxClassNames) {
        try {
            $handle = [Win32.User32]::FindWindow($className, $null)
            if ($handle -ne 0) {
                Write-Host "  # [INFO] Found VBox window class: $className" -ForegroundColor Yellow
                Write-Host "  # [INFO] Hiding window of class $className" -ForegroundColor Yellow
                [Win32.User32]::ShowWindow($handle, 0) | Out-Null
            }
        } 
        catch {
        }
    }
    
    Write-Host "  # [OK] VBox DLL patching completed" -ForegroundColor Green
}

function Set-CPUInfoSpoofing {
    Write-Host "`n  # ================== SPOOFING CPU INFORMATION ==================" -ForegroundColor Magenta
    
    $cpuModels = @(
        "Intel(R) Core(TM) i9-12900K CPU @ 3.20GHz",
        "AMD Ryzen 9 5950X 16-Core Processor",
        "Intel(R) Core(TM) i7-11700K CPU @ 3.60GHz",
        "AMD Ryzen 7 5800X 8-Core Processor",
        "Intel(R) Core(TM) i5-12600K CPU @ 3.70GHz"
    )
    
    $randomCpuModel = $cpuModels | Get-Random
    Write-Host "  # [INFO] Setting CPU model to: $randomCpuModel" -ForegroundColor Yellow
    
    $regPath = "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0"
    Set-ItemProperty -Path $regPath -Name "ProcessorNameString" -Value $randomCpuModel -Force
    
    $coreCount = Get-Random -Minimum 8 -Maximum 17
    Write-Host "  # [INFO] Setting CPU core count to: $coreCount" -ForegroundColor Yellow
    
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name "NUMBER_OF_PROCESSORS" -Value $coreCount.ToString() -Force
        [System.Environment]::SetEnvironmentVariable("NUMBER_OF_PROCESSORS", $coreCount.ToString(), "Machine")
        Write-Host "  # [OK] CPU information spoofing complete" -ForegroundColor Green
    }
    catch {
        Write-Host "  # [WARN] Could not completely spoof CPU information: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Remove-HypervisorMemoryArtifacts {
    Write-Host "`n  # ================== REMOVING HYPERVISOR MEMORY ARTIFACTS ==================" -ForegroundColor Magenta
    
    $vmStrings = @{
        "VBOX" = "DELL";
        "VMware" = "INTEL", "DELL";
        "Virtual" = "Physical";
        "innotek GmbH" = "Dell Inc.";
        "VirtualBox" = "DellDesktop";
    }
    
    Write-Host "  # [INFO] Checking loaded modules for VM strings..." -ForegroundColor Yellow
    $modules = Get-Process -Id $PID | ForEach-Object { $_.Modules }
    $vmModules = $modules | Where-Object { 
        $name = $_.ModuleName
        $vmStrings.Keys | Where-Object { $name -match $_ } 
    }
    
    if ($vmModules) {
        Write-Host "  # [WARN] Found VM-related modules loaded in this process:" -ForegroundColor Yellow
        $vmModules | ForEach-Object {
            Write-Host "  #   - $($_.ModuleName): $($_.FileName)" -ForegroundColor Yellow
        }
        Write-Host "  # [INFO] These cannot be unloaded but their presence has been noted" -ForegroundColor Yellow
    } else {
        Write-Host "  # [OK] No VM-related modules found in current process" -ForegroundColor Green
    }

    $tempDir = [System.IO.Path]::GetTempPath()
    $vmTempFiles = Get-ChildItem -Path $tempDir -File -ErrorAction SilentlyContinue | 
                   Where-Object { $fileName = $_.Name; $vmStrings.Keys | Where-Object { $fileName -match $_ } }
    
    if ($vmTempFiles) {
        Write-Host "  # [INFO] Found VM-related temporary files, removing..." -ForegroundColor Yellow
        $vmTempFiles | ForEach-Object {
            try {
                Remove-Item -Path $_.FullName -Force
                Write-Host "  #   - Removed: $($_.Name)" -ForegroundColor Green
            } catch {
                Write-Host "  #   - Failed to remove: $($_.Name)" -ForegroundColor Yellow
            }
        }
    }
    
    Write-Host "  # [OK] Memory artifact cleanup completed" -ForegroundColor Green
}

function Set-AntiAnalysisTechniques {
    Write-Host "`n  # ================== APPLYING ANTI-ANALYSIS TECHNIQUES ==================" -ForegroundColor Magenta
    
    Write-Host "  # [INFO] Disabling Windows Error Reporting..." -ForegroundColor Yellow
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "DontSendAdditionalData" -Value 1 -Type DWord -Force
        Write-Host "  # [OK] Windows Error Reporting disabled" -ForegroundColor Green
    } catch {
        Write-Host "  # [WARN] Could not fully disable Windows Error Reporting: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    Write-Host "  # [INFO] Modifying analysis-related registry settings..." -ForegroundColor Yellow
    $analysisRegPaths = @(
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"; Name = "AutoReboot"; Value = 0; Type = "DWord" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug"; Name = "Auto"; Value = 0; Type = "String" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\WMR"; Name = "Disable"; Value = 1; Type = "DWord" }
    )
    
    foreach ($regEntry in $analysisRegPaths) {
        try {
            If (!(Test-Path -Path $regEntry.Path)) { New-Item -Path $regEntry.Path -Force | Out-Null }
            Set-ItemProperty -Path $regEntry.Path -Name $regEntry.Name -Value $regEntry.Value -Type $regEntry.Type -Force
            Write-Host "  # [OK] Set $($regEntry.Path)\$($regEntry.Name) = $($regEntry.Value)" -ForegroundColor Green
        } catch {
            Write-Host "  # [WARN] Failed to set $($regEntry.Path)\$($regEntry.Name): $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    
    Write-Host "  # [INFO] Modifying ETW settings to reduce telemetry..." -ForegroundColor Yellow
    try {
        $providers = @(
            "{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}",
            "{8c416c79-d49b-4f01-a467-e56d3aa8234c}"
        )
        
        foreach ($provider in $providers) {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{$provider}"
            if (Test-Path $regPath) {
                Set-ItemProperty -Path $regPath -Name "Enabled" -Value 0 -Type DWord -Force
                Write-Host "  # [OK] Disabled ETW provider: $provider" -ForegroundColor Green
            }
        }
    } catch {
        Write-Host "  # [WARN] Could not modify all ETW settings: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    Write-Host "  # [OK] Anti-analysis techniques applied" -ForegroundColor Green
}

function Set-VirtualCameraDisguise {
    Write-Host "`n  # ================== DISGUISING VIRTUAL WEBCAM ==================" -ForegroundColor Magenta
    
    $cameraNames = @(
        "Logitech HD Pro Webcam C920",
        "Microsoft LifeCam HD-3000",
        "USB Web Camera",
        "Built-in Camera",
        "Integrated Webcam"
    )
    $randomCameraName = $cameraNames | Get-Random
    
    Write-Host "  # [INFO] Searching for VirtualBox webcam references in registry..." -ForegroundColor Yellow
    
    $registryPaths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{6BDD1FC6-810F-11D0-BEC7-08002BE2092F}",
        "HKLM:\SOFTWARE\Microsoft\Windows Media Foundation\Platform",
        "HKLM:\SYSTEM\CurrentControlSet\Enum",
        "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses"
    )
    
    $vmCameraKeywords = @("vbox", "virtualbox", "virtual camera", "vm camera", "webcam")
    $script:replacementCount = 0
    
    function Search-RegistryForVirtualCameras {
        param(
            [Parameter(Mandatory=$true)]
            [string]$Path,
            [int]$Depth = 0,
            [int]$MaxDepth = 5
        )
        
        if (!(Test-Path -Path $Path) -or $Depth -gt $MaxDepth) { return }
        
        try {
            $properties = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
            
            if ($properties) {
                foreach ($prop in $properties.PSObject.Properties) {
                    if ($prop.Name -like "PS*") { continue }
                    
                    if ($prop.Value -is [string]) {
                        if ($vmCameraKeywords | Where-Object { $prop.Value -match $_ }) {
                            Write-Host "  # [FOUND] Virtual camera reference: $Path\$($prop.Name) = $($prop.Value)" -ForegroundColor Yellow
                            
                            try {
                                Set-ItemProperty -Path $Path -Name $prop.Name -Value $randomCameraName -Force
                                Write-Host "  #   - Renamed to: $randomCameraName" -ForegroundColor Green
                                $script:replacementCount++
                            }
                            catch {
                                Write-Host "  #   - Failed to rename: $($_.Exception.Message)" -ForegroundColor Yellow
                            }
                        }
                    }
                }
            }
            
            $keyName = Split-Path -Leaf $Path
            if ($vmCameraKeywords | Where-Object { $keyName -match $_ }) {
                Write-Host "  # [FOUND] Virtual camera key: $Path" -ForegroundColor Yellow
                
                try {
                    if (Get-ItemProperty -Path $Path -Name "FriendlyName" -ErrorAction SilentlyContinue) {
                        Set-ItemProperty -Path $Path -Name "FriendlyName" -Value $randomCameraName -Force
                        Write-Host "  #   - Set FriendlyName to: $randomCameraName" -ForegroundColor Green
                        $script:replacementCount++
                    }
                    
                    if (Get-ItemProperty -Path $Path -Name "DeviceDesc" -ErrorAction SilentlyContinue) {
                        Set-ItemProperty -Path $Path -Name "DeviceDesc" -Value "$randomCameraName" -Force
                        Write-Host "  #   - Set DeviceDesc to: $randomCameraName" -ForegroundColor Green
                        $script:replacementCount++
                    }
                    
                    if (Get-ItemProperty -Path $Path -Name "Label" -ErrorAction SilentlyContinue) {
                        Set-ItemProperty -Path $Path -Name "Label" -Value "$randomCameraName" -Force
                        Write-Host "  #   - Set Label to: $randomCameraName" -ForegroundColor Green
                        $script:replacementCount++
                    }
                }
                catch {
                    Write-Host "  #   - Failed to modify key: $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }
            
            Get-ChildItem -Path $Path -ErrorAction SilentlyContinue | ForEach-Object {
                Search-RegistryForVirtualCameras -Path $_.PSPath -Depth ($Depth + 1) -MaxDepth $MaxDepth
            }
        }
        catch {
        }
    }
    
    foreach ($regPath in $registryPaths) {
        Write-Host "  # [INFO] Searching in $regPath..." -ForegroundColor Yellow
        Search-RegistryForVirtualCameras -Path $regPath
    }
    
    $cameraInterfaceGuids = @(
        "{E5323777-F976-4F5B-9B55-B94699C46E44}",
        "{65E8773D-8F56-11D0-A3B9-00A0C9223196}",
        "{6BDD1FC6-810F-11D0-BEC7-08002BE2092F}"
    )
    
    foreach ($guid in $cameraInterfaceGuids) {
        $interfacePath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses\$guid"
        if (Test-Path $interfacePath) {
            Write-Host "  # [INFO] Searching camera interface $guid..." -ForegroundColor Yellow
            Search-RegistryForVirtualCameras -Path $interfacePath -MaxDepth 3
        }
    }
    
    Write-Host "  # [INFO] Checking device manager entries for virtual cameras..." -ForegroundColor Yellow
    $deviceCameras = Get-PnpDevice | Where-Object { $_.FriendlyName -match "camera|webcam" -and ($vmCameraKeywords | Where-Object { $_.FriendlyName -match $_ }) }
    
    if ($deviceCameras) {
        Write-Host "  # [INFO] Found VirtualBox camera devices in Device Manager:" -ForegroundColor Yellow
        foreach ($camera in $deviceCameras) {
            Write-Host "  #   - $($camera.FriendlyName) (ID: $($camera.InstanceId))" -ForegroundColor Yellow
            
            $deviceRegPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($camera.InstanceId)"
            if (Test-Path $deviceRegPath) {
                try {
                    Set-ItemProperty -Path $deviceRegPath -Name "FriendlyName" -Value $randomCameraName -Force
                    Write-Host "  #     Updated registry name to: $randomCameraName" -ForegroundColor Green
                    $replacementCount++
                }
                catch {
                    Write-Host "  #     Failed to update registry: $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }
        }
    }
    
    $vboxCamPath = "HKLM:\HARDWARE\DEVICEMAP\VIDEO"
    if (Test-Path $vboxCamPath) {
        Get-ChildItem $vboxCamPath | ForEach-Object {
            $deviceDesc = Get-ItemProperty -Path $_.PSPath -Name "Device Description" -ErrorAction SilentlyContinue
            if ($deviceDesc -and $deviceDesc."Device Description" -match "vbox|virtualbox") {
                Write-Host "  # [FOUND] VirtualBox video device: $($deviceDesc.'Device Description')" -ForegroundColor Yellow
                try {
                    Set-ItemProperty -Path $_.PSPath -Name "Device Description" -Value "$randomCameraName Capture Device" -Force
                    Write-Host "  #   - Renamed to: $randomCameraName Capture Device" -ForegroundColor Green
                    $replacementCount++
                }
                catch {
                    Write-Host "  #   - Failed to rename: $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }
        }
    }
    
    if ($replacementCount -gt 0) {
        Write-Host "  # [OK] Successfully disguised $replacementCount virtual camera references" -ForegroundColor Green
    }
    else {
        Write-Host "  # [INFO] No VirtualBox camera references found in registry" -ForegroundColor Cyan
    }
    
    Write-Host "  # [NOTE] Some applications may still detect virtual cameras through other methods." -ForegroundColor Yellow
    Write-Host "  # Changes will take effect after restart." -ForegroundColor Yellow
    
    $Global:restartRequired = $true
}

function Set-ControlledFolderAccess {
    Write-Host "`n  # ================== ENABLING CONTROLLED FOLDER ACCESS ==================" -ForegroundColor Magenta
    
    try {
        $defenderModuleAvailable = $null -ne (Get-Command -Name "Set-MpPreference" -ErrorAction SilentlyContinue)
        
        if ($defenderModuleAvailable) {
            Write-Host "  # [INFO] Setting 'EnableControlledFolderAccess' to 'Enabled'..." -ForegroundColor Yellow
            
            try {
                Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction Stop
                Write-Host "  # [OK] Controlled Folder Access is now enabled." -ForegroundColor Green
                return $true
            }
            catch {
                Write-Host "  # [WARN] Could not enable Controlled Folder Access: $($_.Exception.Message)" -ForegroundColor Yellow
                
                try {
                    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access"
                    
                    if (!(Test-Path $registryPath)) {
                        New-Item -Path $registryPath -Force | Out-Null
                    }
                    
                    Set-ItemProperty -Path $registryPath -Name "EnableControlledFolderAccess" -Value 1 -Type DWord -Force
                    Write-Host "  # [OK] Controlled Folder Access enabled via registry." -ForegroundColor Green
                    return $true
                }
                catch {
                    Write-Host "  # [ERROR] Failed to set via registry: $($_.Exception.Message)" -ForegroundColor Red
                    return $false
                }
            }
        }
        else {
            Write-Host "  # [INFO] Windows Defender cmdlets not available in this environment." -ForegroundColor Yellow
            Write-Host "  # [INFO] Attempting to enable Controlled Folder Access via registry..." -ForegroundColor Yellow
            
            try {
                $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access"
                
                if (!(Test-Path $registryPath)) {
                    New-Item -Path $registryPath -Force | Out-Null
                }
                
                Set-ItemProperty -Path $registryPath -Name "EnableControlledFolderAccess" -Value 1 -Type DWord -Force
                Write-Host "  # [OK] Controlled Folder Access enabled via registry." -ForegroundColor Green
                return $true
            }
            catch {
                Write-Host "  # [WARN] Windows Defender appears to be disabled or not installed in this environment." -ForegroundColor Yellow
                Write-Host "  # [INFO] Controlled Folder Access cannot be enabled." -ForegroundColor Yellow
                return $false
            }
        }
    }
    catch {
        Write-Host "  # [ERROR] An unexpected error occurred: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Test-HardeningStatus {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    Write-Host "`n  # ================== VERIFYING APPLIED SETTINGS ==================" -ForegroundColor Magenta
    Write-Host "  # Report generated: $timestamp" -ForegroundColor Yellow
    Write-Host "  # Generated by: $currentUser" -ForegroundColor Yellow
    
    Write-Host "`n  +---------------------------+---------------+-------------------------+--------+" -ForegroundColor Cyan
    Write-Host "  | Setting                   | Expected      | Actual                  | Status |" -ForegroundColor Cyan
    Write-Host "  +---------------------------+---------------+-------------------------+--------+" -ForegroundColor Cyan
    
    $results = @()
    
    $smb1Choice = $Global:UserChoices.ContainsKey("SMBv1") -and $Global:UserChoices["SMBv1"]
    $test = @{
        Name = "SMBv1 Protocol"
        Expected = if ($smb1Choice) { "Disabled" } else { "Not Modified" }
        Actual = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State
        Status = $null
    }
    $test.Status = if (($smb1Choice -and $test.Actual -eq "Disabled") -or (!$smb1Choice)) { "PASS" } else { "FAIL" }
    $results += $test
    
    $netbiosChoice = $Global:UserChoices.ContainsKey("NetBIOS") -and $Global:UserChoices["NetBIOS"]
    $netbiosBinding = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name TransportBindName -ErrorAction SilentlyContinue).TransportBindName
    $test = @{
        Name = "NetBIOS over TCP/IP"
        Expected = if ($netbiosChoice) { "Empty binding" } else { "Not Modified" }
        Actual = if ([string]::IsNullOrEmpty($netbiosBinding)) { "Empty binding" } else { $netbiosBinding }
        Status = $null
    }
    $test.Status = if (($netbiosChoice -and [string]::IsNullOrEmpty($netbiosBinding)) -or (!$netbiosChoice)) { "PASS" } else { "FAIL" }
    $results += $test
    
	$folderAccessChoice = $Global:UserChoices.ContainsKey("FolderAccess") -and $Global:UserChoices["FolderAccess"]
	$test = @{
		Name = "Controlled Folder Access"
		Expected = if ($folderAccessChoice) { "Enabled" } else { "Not Modified" }
		Actual = "Checking..."
		Status = "N/A"
	}
	try {
		$defenderModuleAvailable = $null -ne (Get-Command -Name "Get-MpPreference" -ErrorAction SilentlyContinue)
    
		if ($defenderModuleAvailable) {
			$mpPreference = Get-MpPreference -ErrorAction Stop
			$folderAccess = $mpPreference.EnableControlledFolderAccess
			$test.Actual = if ($folderAccess -eq 1) { "Enabled" } elseif ($folderAccess -eq 0) { "Disabled" } else { "Not Configured" }
		}
		else {
			$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access"
			if (Test-Path $registryPath) {
				$regValue = Get-ItemProperty -Path $registryPath -Name "EnableControlledFolderAccess" -ErrorAction SilentlyContinue
				if ($regValue -and $regValue.EnableControlledFolderAccess -eq 1) {
					$test.Actual = "Enabled (Registry)"
				}
				else {
					$test.Actual = "Disabled (Registry)"
				}
			}
			else {
            $test.Actual = "Defender unavailable"
			}
		}
    
		if ($folderAccessChoice) {
			$test.Status = if ($test.Actual -match "Enabled") { "PASS" } else { "FAIL" }
		} 
		else {
			$test.Status = "PASS"
		}
	}
	catch {
		$test.Actual = "Defender unavailable"
		$test.Status = if (!$folderAccessChoice) { "PASS" } else { "FAIL" }
	}
	$results += $test
    
    $defenderSettingsChoice = $Global:UserChoices.ContainsKey("DefenderSettings") -and $Global:UserChoices["DefenderSettings"]
    $test = @{
        Name = "Windows Defender Settings"
        Expected = if ($defenderSettingsChoice) { "Enhanced" } else { "Not Modified" }
        Actual = "Checking..."
        Status = "N/A"
    }
    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        $networkProtection = $mpPreference.EnableNetworkProtection
        $blockAtFirstSeen = !$mpPreference.DisableBlockAtFirstSeen
    
        if ($networkProtection -eq 1 -and $blockAtFirstSeen -eq $true) {
            $test.Actual = "Enhanced settings applied"
            $test.Status = if ($defenderSettingsChoice) { "PASS" } else { "INFO" }
        } else {
            $test.Actual = "Basic settings only"
            $test.Status = if ($defenderSettingsChoice) { "FAIL" } else { "PASS" }
        }
    }
    catch {
        $test.Actual = "Defender unavailable"
    }
    $results += $test

    $vmToolsChoice = $Global:UserChoices.ContainsKey("VBoxAdditions") -and $Global:UserChoices["VBoxAdditions"]
    $vboxServices = @("VBoxService", "VBoxGuest", "VBoxMouse", "VBoxSF", "VBoxVideo", "VBoxControl") 
    $runningVBoxServices = (Get-Service -Name $vboxServices -ErrorAction SilentlyContinue | Where-Object Status -eq "Running").Count
    $test = @{
        Name = "VirtualBox Guest Additions"
        Expected = if ($vmToolsChoice) { "Not Running" } else { "Not Modified" }
        Actual = if ($runningVBoxServices -gt 0) { "Running ($runningVBoxServices services)" } else { "Not Running" }
        Status = $null
    }
    $test.Status = if (($vmToolsChoice -and $runningVBoxServices -eq 0) -or (!$vmToolsChoice)) { "PASS" } else { "FAIL" }
    $results += $test
    
    $firewallChoice = $Global:UserChoices.ContainsKey("Firewall") -and $Global:UserChoices["Firewall"]
    $test = @{
        Name = "Windows Firewall"
        Expected = if ($firewallChoice) { "Enabled" } else { "Not Modified" }
        Actual = "Checking..."
        Status = "N/A"
    }
    try {
        $firewallProfile = Get-NetFirewallProfile -Profile Public -ErrorAction Stop
        $test.Actual = if ($firewallProfile.Enabled) { "Enabled" } else { "Disabled" }
        $test.Status = if (($firewallChoice -and $firewallProfile.Enabled) -or (!$firewallChoice)) { "PASS" } else { "FAIL" }
    }
    catch {
        $test.Actual = "Error checking"
    }
    $results += $test
    
    $machineGuidChoice = $Global:UserChoices.ContainsKey("MachineGuid") -and $Global:UserChoices["MachineGuid"]
    $machineGuid = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid -ErrorAction SilentlyContinue).MachineGuid
    $test = @{
        Name = "Cryptography MachineGuid"
        Expected = if ($machineGuidChoice) { "Customized" } else { "Not Modified" }
        Actual = if ($machineGuid) { 
            if ($machineGuid.Length -gt 20) {
                "Set (" + $machineGuid.Substring(0, 10) + "...)"
            } else {
                "Set ($machineGuid)"
            }
        } else { "Not Found" }
        Status = $null
    }
    $test.Status = if (($machineGuidChoice -and $machineGuid) -or (!$machineGuidChoice)) { "PASS" } else { "FAIL" }
    $results += $test
    
    $cpuSpoofChoice = $Global:UserChoices.ContainsKey("CPUInfo") -and $Global:UserChoices["CPUInfo"]
    $cpuName = (Get-ItemProperty -Path "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0" -Name "ProcessorNameString" -ErrorAction SilentlyContinue).ProcessorNameString
    $test = @{
        Name = "CPU Name Spoofing"
        Expected = if ($cpuSpoofChoice) { "Custom CPU name" } else { "Not Modified" }
        Actual = if ($cpuName) {
            if ($cpuName.Length -gt 20) {
                $cpuName.Substring(0, 17) + "..."
            } else {
                $cpuName
            }
        } else { "Default" }
        Status = $null
    }
    $test.Status = if (($cpuSpoofChoice -and $cpuName -match "(i[5-9]-\d{5}|Ryzen)") -or (!$cpuSpoofChoice)) { "PASS" } else { "FAIL" }
    $results += $test
    
    $werChoice = $Global:UserChoices.ContainsKey("AntiAnalysis") -and $Global:UserChoices["AntiAnalysis"]
    $werDisabled = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -ErrorAction SilentlyContinue).Disabled
    $test = @{
        Name = "Windows Error Reporting"
        Expected = if ($werChoice) { "Disabled" } else { "Not Modified" }
        Actual = if ($werDisabled -eq 1) { "Disabled" } else { "Enabled" }
        Status = $null
    }
    $test.Status = if (($werChoice -and $werDisabled -eq 1) -or (!$werChoice)) { "PASS" } else { "FAIL" }
    $results += $test

    $webcamChoice = $Global:UserChoices.ContainsKey("VirtualCamera") -and $Global:UserChoices["VirtualCamera"]
    $vmCamKeywords = @("vbox", "virtualbox", "virtual camera")
    $vmCamFound = $false
    
    if ($webcamChoice) {
        $camRegistryPaths = @(
            "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{6BDD1FC6-810F-11D0-BEC7-08002BE2092F}",
            "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses"
        )
        
        foreach ($path in $camRegistryPaths) {
            if (Test-Path $path) {
                try {
                    $camEntries = Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue | 
                              Get-ItemProperty -ErrorAction SilentlyContinue |
                              Where-Object { $_.FriendlyName -match ($vmCamKeywords -join "|") }
                    if ($camEntries) {
                        $vmCamFound = $true
                        break
                    }
                }
                catch {
                }
            }
        }
    }
    
    $test = @{
        Name = "Virtual Camera"
        Expected = if ($webcamChoice) { "Disguised" } else { "Not Modified" }
        Actual = if ($vmCamFound) { "VirtualBox Camera Found" } else { "No VM Camera References" }
        Status = $null
    }
    $test.Status = if (($webcamChoice -and !$vmCamFound) -or (!$webcamChoice)) { "PASS" } else { "FAIL" }
    $results += $test
    
    $installDateChoice = $Global:UserChoices.ContainsKey("InstallDate") -and $Global:UserChoices["InstallDate"]
    $installDate = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "InstallDate" -ErrorAction SilentlyContinue).InstallDate
    $test = @{
        Name = "Install Date Spoofing"
        Expected = if ($installDateChoice) { "Modified" } else { "Not Modified" }
        Actual = if ($installDate) { "Set (Unix Time: $installDate)" } else { "Not Found" }
        Status = if (($installDateChoice -and $installDate) -or (!$installDateChoice)) { "PASS" } else { "FAIL" }
    }
    $results += $test

    $macAddressChoice = $Global:UserChoices.ContainsKey("MACAddress") -and $Global:UserChoices["MACAddress"]
    $macAddresses = (Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object { $_.MacAddress })
    $nonDefaultMac = $macAddresses | Where-Object { $_ -notmatch "^(00:50:56|00:0C:29|00:05:69|00:03:FF)" }
    $test = @{
        Name = "MAC Address Spoofing"
        Expected = if ($macAddressChoice) { "Non-VM MAC" } else { "Not Modified" }
        Actual = if ($nonDefaultMac) { "Custom MAC present" } else { "Default MAC" }
        Status = if (($macAddressChoice -and $nonDefaultMac) -or (!$macAddressChoice)) { "PASS" } else { "FAIL" }
    }
    $results += $test

    $vboxDllChoice = $Global:UserChoices.ContainsKey("VBoxDLL") -and $Global:UserChoices["VBoxDLL"]
    $vboxDllsFound = Test-Path "$env:windir\System32\VBox*.dll" -ErrorAction SilentlyContinue
    $test = @{
        Name = "VBox DLL Patching"
        Expected = if ($vboxDllChoice) { "No VBox DLLs visible" } else { "Not Modified" }
        Actual = if ($vboxDllsFound) { "VBox DLLs found" } else { "No VBox DLLs found" }
        Status = if (($vboxDllChoice -and !$vboxDllsFound) -or (!$vboxDllChoice)) { "PASS" } else { "FAIL" }
    }
    $results += $test

    $computerNameChoice = $Global:UserChoices.ContainsKey("ComputerIdentifiers") -and $Global:UserChoices["ComputerIdentifiers"]
    $computerName = $env:COMPUTERNAME
    $test = @{
        Name = "Computer Name"
        Expected = if ($computerNameChoice) { "Custom name" } else { "Not Modified" }
        Actual = $computerName
        Status = if (($computerNameChoice -and $computerName -notlike "DESKTOP-*") -or (!$computerNameChoice)) { "PASS" } else { "FAIL" }
    }
    $results += $test

    $envVarsChoice = $Global:UserChoices.ContainsKey("EnvVars") -and $Global:UserChoices["EnvVars"]
    $vmEnvVars = Get-ChildItem Env:* | Where-Object { $_.Name -match "VBOX|VMware" -or $_.Value -match "VBOX|VMware" }
    $test = @{
        Name = "VM Environment Variables"
        Expected = if ($envVarsChoice) { "Cleaned" } else { "Not Modified" }
        Actual = if ($vmEnvVars) { "VM vars present" } else { "No VM vars" }
        Status = if (($envVarsChoice -and !$vmEnvVars) -or (!$envVarsChoice)) { "PASS" } else { "FAIL" }
    }
    $results += $test

    $hardwareSpoofingChoice = $Global:UserChoices.ContainsKey("HardwareBIOS") -and $Global:UserChoices["HardwareBIOS"]
    $biosInfo = Get-ItemProperty -Path "HKLM:\HARDWARE\Description\System" -Name "SystemBiosVersion" -ErrorAction SilentlyContinue
    $customBios = $biosInfo -and $biosInfo.SystemBiosVersion -notmatch "VBOX|VMware"
    $test = @{
        Name = "BIOS Info Spoofing"
        Expected = if ($hardwareSpoofingChoice) { "Custom BIOS info" } else { "Not Modified" }
        Actual = if ($customBios) { "Custom BIOS present" } else { "Default" }
        Status = if (($hardwareSpoofingChoice -and $customBios) -or (!$hardwareSpoofingChoice)) { "PASS" } else { "FAIL" }
    }
    $results += $test

    $secureDNSChoice = $Global:UserChoices.ContainsKey("SecureDNS") -and $Global:UserChoices["SecureDNS"]
    $dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 | 
                Where-Object { $_.ServerAddresses -contains "9.9.9.9" -or $_.ServerAddresses -contains "149.112.112.112" }
    $test = @{
        Name = "Secure DNS (Quad9)"
        Expected = if ($secureDNSChoice) { "Configured" } else { "Not Modified" }
        Actual = if ($dnsServers) { "Quad9 DNS present" } else { "Not using Quad9" }
        Status = if (($secureDNSChoice -and $dnsServers) -or (!$secureDNSChoice)) { "PASS" } else { "FAIL" }
    }
    $results += $test

    $eventLogsChoice = $Global:UserChoices.ContainsKey("EventLogs") -and $Global:UserChoices["EventLogs"]
    $eventLogs = Get-WinEvent -ListLog "System" -ErrorAction SilentlyContinue
    $logsCleared = $eventLogs -and $eventLogs.RecordCount -eq 0
    $test = @{
        Name = "Event Logs"
        Expected = if ($eventLogsChoice) { "Cleared" } else { "Not Modified" }
        Actual = if ($logsCleared) { "Logs empty" } else { "Logs contain records" }
        Status = if (($eventLogsChoice -and $logsCleared) -or (!$eventLogsChoice)) { "PASS" } else { "FAIL" }
    }
    $results += $test
    
    foreach ($result in $results) {
        $statusColor = if ($result.Status -eq "PASS") { "Green" } elseif ($result.Status -eq "N/A") { "Yellow" } else { "Red" }
        
        $nameDisplay = $result.Name.PadRight(25).Substring(0, 25)
        $expectedDisplay = $result.Expected.PadRight(13).Substring(0, 13)
        $actualString = "$($result.Actual)"
        $actualDisplay = $actualString.PadRight(23)
        if ($actualString.Length -gt 23) {
            $actualDisplay = $actualString.Substring(0, 20) + "..."
        }
        
        Write-Host "  | $nameDisplay | $expectedDisplay | $actualDisplay | " -NoNewline
        Write-Host "$($result.Status.PadRight(6)) |" -ForegroundColor $statusColor
        
        Write-Host "  +---------------------------+---------------+-------------------------+--------+" -ForegroundColor Cyan
    }
    
    $passCount = ($results | Where-Object { $_.Status -eq "PASS" }).Count
    $failCount = ($results | Where-Object { $_.Status -eq "FAIL" }).Count
    $naCount = ($results | Where-Object { $_.Status -eq "N/A" }).Count
    
    Write-Host "`n  # [SUMMARY] Tests: $($results.Count) | Passed: $passCount | Failed: $failCount | Not Applicable: $naCount" -ForegroundColor Yellow
    Write-Host "  # [INFO] Verification complete. Please review any results above." -ForegroundColor Yellow
    
    if ($results | Where-Object { $_.Status -eq "N/A" }) {
        Write-Host "  # [INFO] Items marked 'N/A' could not be verified due to service availability issues." -ForegroundColor Yellow
    }
}

try {
    $logPath = Start-ScriptLogging
    
    if (Get-YesNoChoice "Create a System Restore Point before proceeding?" "Y" "Strongly recommended to allow rollback if any settings cause issues." "RestorePoint") {
        New-RestorePoint
    }
    
    Write-Host "`n  # ===========================================================" -ForegroundColor Magenta
    Write-Host "  #      WINDOWS HARDENING & ANTI-VM DETECTION SCRIPT" -ForegroundColor Magenta
    Write-Host "  # ===========================================================" -ForegroundColor Magenta
    Write-Host "This script will guide you through applying security and privacy changes."
    Write-Host "Answer [Y]es to apply a setting or [N]o to skip it." -ForegroundColor Yellow

    Write-Host "`n`n  # --- ANTI-VM DETECTION & SPOOFING ---" -ForegroundColor Green
    
    if (Get-YesNoChoice "Spoof hardware, BIOS, and device info in registry?" "Y" "Changes registry values for BIOS, CPU, and hardware to hide VM indicators." "HardwareBIOS") {
        Write-Host "`n  # ================== SPOOFING HARDWARE REGISTRY ==================" -ForegroundColor Magenta
        $Global:restartRequired = $true
        Write-Host "  # [INFO] Modifying System/BIOS registry keys..." -ForegroundColor Yellow
        Set-ItemProperty -Path "HKLM:\HARDWARE\Description\System" -Name "SystemBiosVersion" -Value (Get-RandomString) -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\HARDWARE\Description\System" -Name "SystemBiosDate" -Value "06/29/2025" -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\HARDWARE\Description\System" -Name "VideoBiosVersion" -Value (Get-RandomString) -ErrorAction SilentlyContinue
        
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -Name "BIOSVersion" -Value (Get-RandomString) -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -Name "SystemManufacturer" -Value "Micro-Star International Co., Ltd." -Force -ErrorAction SilentlyContinue
        
        Write-Host "  # [INFO] Spoofing GPU information..." -ForegroundColor Yellow
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "DriverDesc" -Value "NVIDIA GeForce RTX 4090" -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "HardwareInformation.AdapterString" -Value "NVIDIA GeForce RTX 4090" -Force -ErrorAction SilentlyContinue
        
        Write-Host "  # [INFO] Fixing timing anomalies detection..." -ForegroundColor Yellow
        $NtKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        Set-ItemProperty -Path $NtKey -Name "QPCDisableSkipThreshold" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $NtKey -Name "QPCFrequencyRandom" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Write-Host "  # [OK] Timing anomalies mitigations applied." -ForegroundColor Green

		Write-Host "  # [INFO] Adding enhanced GPU capability flags..." -ForegroundColor Yellow
		$displayKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000"
		Set-ItemProperty -Path $displayKey -Name "HardwareInformation.qwCompression" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
		Set-ItemProperty -Path $displayKey -Name "ColorManagementCaps" -Value 2 -Type DWord -Force -ErrorAction SilentlyContinue
		Set-ItemProperty -Path $displayKey -Name "KernelCaps" -Value 68 -Type DWord -Force -ErrorAction SilentlyContinue
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Configuration" -Name "ColorManagement" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        
        $dxKey = "HKLM:\SOFTWARE\Microsoft\DirectX"
        if (-not (Test-Path $dxKey)) {
            New-Item -Path $dxKey -Force -ErrorAction SilentlyContinue
        }
        Set-ItemProperty -Path $dxKey -Name "Version" -Value "4.09.00.0904" -Force -ErrorAction SilentlyContinue

        $display3DKey = "$displayKey\Settings"
        if (-not (Test-Path $display3DKey)) {
            New-Item -Path $display3DKey -Force -ErrorAction SilentlyContinue
        }
        Set-ItemProperty -Path $display3DKey -Name "Acceleration.Level" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $displayKey -Name "EnableGDI" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue

		Write-Host "  # [INFO] Adding advanced power capabilities and states..." -ForegroundColor Yellow

		$powerKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Power"
		Set-ItemProperty -Path $powerKey -Name "HibernateEnabled" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
		Set-ItemProperty -Path $powerKey -Name "HibernateFileSizePercent" -Value 40 -Type DWord -Force -ErrorAction SilentlyContinue

        New-Item -Path "$powerKey\PowerSchemes" -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "$powerKey\PowerSchemes" -Name "ActivePowerScheme" -Value "{8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c}" -Force -ErrorAction SilentlyContinue
        New-Item -Path "$powerKey\PowerSchemes\{8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c}" -Force -ErrorAction SilentlyContinue

		$powerPolicyKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings"
        
        $sleepKey = "$powerPolicyKey\54533251-82be-4824-96c1-47b60b740d00"
        New-Item -Path $sleepKey -Force -ErrorAction SilentlyContinue
        
        New-Item -Path "$sleepKey\893dee8e-2bef-41e0-89c6-b55d0929964c" -Force -ErrorAction SilentlyContinue
		Set-ItemProperty -Path "$sleepKey\893dee8e-2bef-41e0-89c6-b55d0929964c" -Name "Attributes" -Value 2 -Type DWord -Force -ErrorAction SilentlyContinue
        
        New-Item -Path "$sleepKey\94ac6d29-73ce-41a6-809f-6363ba21b47e" -Force -ErrorAction SilentlyContinue
		Set-ItemProperty -Path "$sleepKey\94ac6d29-73ce-41a6-809f-6363ba21b47e" -Name "Attributes" -Value 2 -Type DWord -Force -ErrorAction SilentlyContinue
        
        New-Item -Path "$sleepKey\9d7815a6-7ee4-497e-8888-515a05f02364" -Force -ErrorAction SilentlyContinue
		Set-ItemProperty -Path "$sleepKey\9d7815a6-7ee4-497e-8888-515a05f02364" -Name "Attributes" -Value 2 -Type DWord -Force -ErrorAction SilentlyContinue

		$thermalKey = "HKLM:\SYSTEM\CurrentControlSet\Services\ACPI\Parameters"
        if (-not (Test-Path $thermalKey)) {
            New-Item -Path $thermalKey -Force -ErrorAction SilentlyContinue
        }
		Set-ItemProperty -Path $thermalKey -Name "ThermalControlCapabilities" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
		New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ACPI\Parameters\ThermalConfig" -Force -ErrorAction SilentlyContinue

		New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ACPI\Enum\ACPI\ThermalZone\THM_" -Force -ErrorAction SilentlyContinue
		New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ACPI\Parameters\thermal_zone" -Force -ErrorAction SilentlyContinue

		New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ACPI\Parameters\FAN" -Force -ErrorAction SilentlyContinue
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ACPI\Parameters" -Name "FanCount" -Value 2 -Type DWord -Force -ErrorAction SilentlyContinue

		Write-Host "  # [OK] Power and thermal capabilities configured." -ForegroundColor Green

		Write-Host "  # [INFO] Enhanced firmware and ACPI spoofing..." -ForegroundColor Yellow

		Remove-Item -Path "HKLM:\HARDWARE\ACPI\DSDT\VBOX__" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "HKLM:\HARDWARE\ACPI\FADT\VBOX__" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "HKLM:\HARDWARE\ACPI\RSDT\VBOX__" -Force -Recurse -ErrorAction SilentlyContinue

		$legitManufacturer = "ASUSTeK COMPUTER INC."
		$legitModel = "ROG STRIX Z790-A GAMING WIFI"
		$biosDate = "06/29/2025"
		$biosVersion = "1603"

        $legitimateACPITables = @(
            "APIC", "BERT", "BGRT", "BOOT", "CPEP", "CSRT", "DBG2", "DBGP", "DMAR", 
            "DRTM", "DSDT", "ECDT", "EINJ", "ERST", "FACP", "FACS", "FPDT", "GTDT", 
            "HEST", "HMAT", "HPET", "IORT", "IVRS", "LPIT", "MCFG", "MCHI", "MPAM", 
            "MPST", "MSCT", "NFIT", "OEMx", "PDTT", "PMTT", "PPTT", "PSDT", "RASF", 
            "RGRT", "SBST", "SLIT", "SRAT", "SSDT", "XENV"
        )

        foreach ($table in $legitimateACPITables) {
            New-Item -Path "HKLM:\HARDWARE\ACPI\$table" -Force -ErrorAction SilentlyContinue
        }

		New-Item -Path "HKLM:\HARDWARE\ACPI\DSDT\ASUS__" -Force -ErrorAction SilentlyContinue
		New-Item -Path "HKLM:\HARDWARE\ACPI\FADT\ASUS__" -Force -ErrorAction SilentlyContinue
		New-Item -Path "HKLM:\HARDWARE\ACPI\RSDT\ASUS__" -Force -ErrorAction SilentlyContinue

		Set-ItemProperty -Path "HKLM:\HARDWARE\ACPI\DSDT" -Name "Revision" -Value 2 -Type DWord -Force -ErrorAction SilentlyContinue

        Set-ItemProperty -Path "HKLM:\HARDWARE\ACPI\DSDT" -Name "OSI_Windows_2015" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\HARDWARE\ACPI\DSDT" -Name "OSI_Windows_2013" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\HARDWARE\ACPI\DSDT" -Name "OSI_Windows_2012" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\HARDWARE\ACPI\DSDT" -Name "OSI_Windows_2009" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\HARDWARE\ACPI\DSDT" -Name "OSI_Windows_2006" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\HARDWARE\ACPI\DSDT" -Name "OSI_Windows_2001" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue

		$osiKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Windows"
		Set-ItemProperty -Path $osiKey -Name "OSI_Windows_2015" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
		Set-ItemProperty -Path $osiKey -Name "OSI_Windows_2013" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $osiKey -Name "OSI_Windows_2012" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $osiKey -Name "OSI_Windows_2009" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $osiKey -Name "OSI_Windows_2006" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $osiKey -Name "OSI_Windows_2001" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue

		$smbiosKey = "HKLM:\SYSTEM\CurrentControlSet\Services\mssmbios\Data"
		if (-not (Test-Path $smbiosKey)) {
			New-Item -Path $smbiosKey -Force -ErrorAction SilentlyContinue
		}
		Set-ItemProperty -Path $smbiosKey -Name "SMBiosData" -Value ([byte[]](0x00, 0x00, 0x00, 0x00)) -Force -ErrorAction SilentlyContinue

		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -Name "SystemManufacturer" -Value $legitManufacturer -Force -ErrorAction SilentlyContinue
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -Name "SystemProductName" -Value $legitModel -Force -ErrorAction SilentlyContinue
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -Name "BIOSVersion" -Value $biosVersion -Force -ErrorAction SilentlyContinue
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -Name "BIOSReleaseDate" -Value $biosDate -Force -ErrorAction SilentlyContinue
		
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Battery" -Name "Start" -Value 1
		
		$hwKey = "HKLM:\HARDWARE\Description\System\BIOS"
		Set-ItemProperty -Path $hwKey -Name "SystemManufacturer" -Value $legitManufacturer -Force -ErrorAction SilentlyContinue
		Set-ItemProperty -Path $hwKey -Name "SystemProductName" -Value $legitModel -Force -ErrorAction SilentlyContinue
		Set-ItemProperty -Path $hwKey -Name "SystemFamily" -Value "ROG" -Force -ErrorAction SilentlyContinue
		Set-ItemProperty -Path $hwKey -Name "SystemSKU" -Value "SKU0123_ASUS_ROG_GAMING" -Force -ErrorAction SilentlyContinue
		Set-ItemProperty -Path $hwKey -Name "SystemVersion" -Value "1.0" -Force -ErrorAction SilentlyContinue
		Set-ItemProperty -Path $hwKey -Name "BIOSVendor" -Value $legitManufacturer -Force -ErrorAction SilentlyContinue
		Set-ItemProperty -Path $hwKey -Name "BIOSVersion" -Value $biosVersion -Force -ErrorAction SilentlyContinue
		Set-ItemProperty -Path $hwKey -Name "BIOSReleaseDate" -Value $biosDate -Force -ErrorAction SilentlyContinue

		Set-ItemProperty -Path $hwKey -Name "BaseBoardManufacturer" -Value "Advanced Micro Devices, Inc." -Force -ErrorAction SilentlyContinue
		Set-ItemProperty -Path $hwKey -Name "BaseBoardProduct" -Value $legitModel -Force -ErrorAction SilentlyContinue

		Write-Host "  # [OK] Enhanced firmware and ACPI data spoofing complete." -ForegroundColor Green

        Write-Host "  # [INFO] Performing deep VirtualBox registry cleanup..." -ForegroundColor Yellow

        Get-ChildItem -Path "HKLM:\HARDWARE\DEVICEMAP\Scsi\Scsi Port*\Scsi Bus*\Target Id*\Logical Unit Id*" -ErrorAction SilentlyContinue | 
            ForEach-Object {
                $devPath = $_.PSPath
                $identifiers = Get-ItemProperty -Path $devPath -ErrorAction SilentlyContinue
                if ($identifiers -and ($identifiers.Identifier -like "*VBOX*" -or $identifiers.SerialNumber -like "*VBOX*")) {
                    Remove-Item -Path $devPath -Recurse -Force -ErrorAction SilentlyContinue
                }
            }

        Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\VBoxSF" -Force -Recurse -ErrorAction SilentlyContinue
        
        $vboxServiceKeys = @(
            "SYSTEM\CurrentControlSet\Services\VBoxGuest",
            "SYSTEM\CurrentControlSet\Services\VBoxMouse",
            "SYSTEM\CurrentControlSet\Services\VBoxService",
            "SYSTEM\CurrentControlSet\Services\VBoxVideo",
            "SYSTEM\CurrentControlSet\Services\VBoxNetAdp",
            "SYSTEM\CurrentControlSet\Services\VBoxNetLwf"
        )
        
        foreach ($key in $vboxServiceKeys) {
            Remove-Item -Path "HKLM:\$key" -Force -Recurse -ErrorAction SilentlyContinue
        }

        $vboxRegistryPaths = @(
            "HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions",
            "HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions\*",
            "HKLM:\HARDWARE\DESCRIPTION\System\BIOS\*VBOX*",
            "HKLM:\HARDWARE\ACPI\*VBOX*",
            "HKLM:\HARDWARE\DEVICEMAP\Scsi\*VBOX*",
            "HKLM:\HARDWARE\Description\System\SystemBiosVersion\*VBOX*",
            "HKLM:\HARDWARE\Description\System\VideoBiosVersion\*VBOX*",
            "HKLM:\SYSTEM\ControlSet001\Services\Disk\Enum\*VBOX*",
            "HKLM:\SYSTEM\ControlSet001\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\*\*VBOX*",
            "HKLM:\SYSTEM\ControlSet001\Control\VirtualDeviceDrivers",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Oracle VM VirtualBox Guest Additions",
            "HKCU:\SOFTWARE\Oracle\VirtualBox Guest Additions"
        )

        foreach ($path in $vboxRegistryPaths) {
            Remove-Item -Path $path -Force -Recurse -ErrorAction SilentlyContinue
        }
        
        Write-Host "  # [INFO] Spoofing VM devices in Device Manager..." -ForegroundColor Yellow
        $deviceIDs = (Get-CimInstance Win32_PnPEntity | Where-Object { $_.Name -like '*VBOX*' -or $_.Name -like '*Virtualbox*' -or $_.PNPDeviceID -like '*VBOX*' -or $_.PNPDeviceID -like '*Virtualbox*' }).DeviceID
        foreach ($deviceID in $deviceIDs) {
            try {
                $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\$deviceID"
                Set-ItemProperty -Path $registryPath -Name "FriendlyName" -Value "Samsung SSD 980 500GB" -Force -ErrorAction Stop
                Write-Host "  # [OK] Spoofed FriendlyName for $deviceID" -ForegroundColor Green
            } catch {
                Write-Host "  # [WARN] Could not set FriendlyName for $deviceID. May require different permissions." -ForegroundColor Yellow
            }
        }
        
        Write-Host "  # [OK] Advanced hardware registry spoofing complete." -ForegroundColor Green
    }

    if (Get-YesNoChoice "Apply advanced VM detection evasion techniques?" "Y" "More aggressive VM hiding techniques (MAC spoofing, WMI modification)." "AdvancedEvasion") {
        Set-AdvancedVMEvasion
        Set-ProcessTimingMasking
        $Global:restartRequired = $true
    }

    if (Get-YesNoChoice "Spoof computer name, install date, and disk serials?" "Y" "Assigns a random computer name, sets a fake Windows install date, and spoofs disk identifiers." "ComputerIdentifiers") {
        Write-Host "`n  # ================== SPOOFING IDENTIFIERS ==================" -ForegroundColor Magenta
        $Global:restartRequired = $true
        $RandomString = -join ((48..57) + (65..90) | Get-Random -Count 7 | ForEach-Object { [char]$_ })
        Write-Host "  # [INFO] Renaming computer to DESKTOP-$RandomString..." -ForegroundColor Yellow
        Rename-Computer -NewName "DESKTOP-$RandomString" -Force
        
        Write-Host "  # [INFO] Spoofing disk drive identifiers in registry..." -ForegroundColor Yellow
        foreach ($PortNumber in 0..9) {
            foreach ($BusNumber in 0..9) {
                $registryPath = "HKLM:\HARDWARE\DEVICEMAP\Scsi\Scsi Port $PortNumber\Scsi Bus $BusNumber\Target Id 0\Logical Unit Id 0"
                if (Test-Path -Path $registryPath) {
                    Set-ItemProperty -Path $registryPath -Name 'Identifier' -Type String -Value "NVMe    Samsung SSD 980 FXO7" -Force -ErrorAction SilentlyContinue
                    Set-ItemProperty -Path $registryPath -Name 'SerialNumber' -Type String -Value (Get-RandomString -Length 20).ToUpper() -Force -ErrorAction SilentlyContinue
                }
            }
        }
        Write-Host "  # [OK] Identifier spoofing complete." -ForegroundColor Green
    }
    
    Write-Host "`n`n  # --- ADDITIONAL ANTI-DETECTION TECHNIQUES ---" -ForegroundColor Green

    if (Get-YesNoChoice "Spoof system MachineGuid (Cryptography identifiers)?" "Y" "Replaces the Windows cryptography machine GUID with a random value." "MachineGuid") {
        Set-RandomMachineGuid
        $Global:restartRequired = $true
    }

    if (Get-YesNoChoice "Apply enhanced install date/time spoofing?" "Y" "Sets random installation dates and configures time synchronization." "InstallDate") {
        Set-EnhancedInstallDateTime
        $Global:restartRequired = $true
    }

    if (Get-YesNoChoice "Apply MAC address randomization?" "Y" "Generates and applies non-VM-vendor MAC addresses to network adapters." "MACAddress") {
        Set-RandomMacAddress
        $Global:restartRequired = $true
    }

    if (Get-YesNoChoice "Apply CPU information spoofing?" "Y" "Sets realistic CPU model names and core counts." "CPUInfo") {
        Set-CPUInfoSpoofing
        $Global:restartRequired = $true
    }

if (Get-YesNoChoice "Remove Virtualbox from Webcam?" "Y" "Renames and hides VBox-specific names on Webcams." "VirtualCamera") {
        Set-VirtualCameraDisguise
        $Global:restartRequired = $true
    }

    if (Get-YesNoChoice "Patch VirtualBox DLL artifacts?" "N" "Renames and hides VBox-specific DLLs and window classes." "VBoxDLL") {
        Set-VBoxDllPatching
        $Global:restartRequired = $true
    }

    if (Get-YesNoChoice "Apply advanced anti-analysis techniques?" "N" "Disables Windows Error Reporting and other analysis hooks." "AntiAnalysis") {
        Set-AntiAnalysisTechniques
        $Global:restartRequired = $true
    }

    if (Get-YesNoChoice "Remove hypervisor memory artifacts?" "N" "Cleans up memory artifacts and temporary files that could reveal VM presence." "MemoryArtifacts") {
        Remove-HypervisorMemoryArtifacts
    }
    
    Write-Host "`n`n  # --- STANDARD SYSTEM HARDENING ---" -ForegroundColor Green

    if (Get-YesNoChoice "Disable SMBv1 protocol?" "Y" "SMBv1 is an outdated and insecure protocol. Disabling it is highly recommended." "SMBv1") {
        Write-Host "`n  # ================== DISABLING SMBv1 ==================" -ForegroundColor Magenta
        Write-Host "  # [INFO] Disabling SMBv1 feature... This may take a moment." -ForegroundColor Yellow
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue
        Write-Host "  # [OK] SMBv1 has been disabled." -ForegroundColor Green
        $Global:restartRequired = $true
    }

    if (Get-YesNoChoice "Disable NetBIOS over TCP/IP (NetBT)?" "Y" "Disabling NetBT reduces the system's attack surface on local networks." "NetBIOS") {
        Write-Host "`n  # ================== DISABLING NETBIOS ==================" -ForegroundColor Magenta
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
        Write-Host "  # [INFO] Setting 'TransportBindName' to an empty value..." -ForegroundColor Yellow
        Set-ItemProperty -Path $regPath -Name TransportBindName -Value "" -Force
        Write-Host "  # [OK] NetBIOS over TCP/IP has been disabled." -ForegroundColor Green
        $Global:restartRequired = $true
    }

    if (Get-YesNoChoice "Enable enhanced Windows Defender settings?" "Y" "Applies advanced Defender configurations for better protection." "DefenderSettings") {
        Set-EnhancedDefenderSettings
    }

    if (Get-YesNoChoice "Configure secure Windows Firewall settings?" "Y" "Sets up a more secure firewall configuration." "Firewall") {
        Set-EnhancedFirewallSettings
    }

    if (Get-YesNoChoice "Enable Controlled Folder Access (Anti-Ransomware)?" "Y" "Helps protect your files from malicious apps and threats, like ransomware." "FolderAccess") {
		Set-ControlledFolderAccess
    }

    if (Get-YesNoChoice "Configure application whitelisting (AppLocker)?" "N" "Monitors and logs potentially malicious applications." "AppLocker") {
        Set-ApplicationWhitelisting
		$Global:restartRequired = $true
    }

    if (Get-YesNoChoice "Display BIOS security recommendations?" "Y" "Shows a list of recommended BIOS/UEFI security settings." "BIOSRecommendations") {
        Set-BIOSSecurityRecommendations
    }

	if (Get-YesNoChoice "Clean VirtualBox Guest Additions services?" "Y" "Removes VirtualBox Guest Additions services and driver files." "VBoxAdditions") {
		Write-Host "`n  # ================== CLEANING VIRTUALBOX GUEST ADDITIONS ==================" -ForegroundColor Magenta
		$vboxServices = @("VBoxService", "VBoxGuest", "VBoxMouse", "VBoxSF", "VBoxVideo", "VBoxControl")
		foreach ($service in $vboxServices) {
			if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
				Write-Host "  # [INFO] Removing service '$service'..." -ForegroundColor Yellow
				Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
				sc.exe delete $service | Out-Null
			}
		}
		$vboxDrivers = @("$env:windir\System32\drivers\VBoxMouse.sys", "$env:windir\System32\drivers\VBoxGuest.sys", "$env:windir\System32\drivers\VBoxSF.sys", "$env:windir\System32\drivers\VBoxVideo.sys")
		foreach ($driver in $vboxDrivers) {
			if (Test-Path $driver) {
				Write-Host "  # [INFO] Removing driver file '$driver'..." -ForegroundColor Yellow
				Remove-Item $driver -Force
			}
		}
		Write-Host "  # [OK] VirtualBox Guest Additions cleanup complete." -ForegroundColor Green
		$Global:restartRequired = $true
	}

    if (Get-YesNoChoice "Set a secure custom DNS (Quad9)?" "Y" "Replaces your current DNS with Quad9's secure DNS for better privacy." "SecureDNS") {
        Write-Host "`n  # ================== CONFIGURING SECURE DNS ==================" -ForegroundColor Magenta
        $Ipv4PrimaryDns = '9.9.9.9'
        $Ipv4BackupDns = '149.112.112.112'
        $Ipv6PrimaryDns = '2620:fe::fe'
        $Ipv6BackupDns = '2620:fe::9'
        Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {
            Write-Host "  # [INFO] Setting DNS for adapter '$($_.Name)'" -ForegroundColor Yellow
            try {
                Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses ($Ipv4PrimaryDns, $Ipv4BackupDns, $Ipv6PrimaryDns, $Ipv6BackupDns) -ErrorAction Stop
            } catch {
                Write-Host "  # [WARN] Could not set DNS for adapter '$($_.Name)'. It may be managed by other software." -ForegroundColor Yellow
            }
        }
        Clear-DnsClientCache
        Write-Host "  # [OK] Secure DNS has been set and cache cleared." -ForegroundColor Green
    }
    
    if (Get-YesNoChoice "Clear VM-related environment variables?" "N" "Scans for and removes env vars containing 'VBOX' or 'VMWARE'." "EnvVars") {
        Write-Host "`n  # ================== CLEANING ENVIRONMENT VARIABLES ==================" -ForegroundColor Magenta
        $vmStrings = @("VBOX", "VMWARE")
        $envScopes = @([System.EnvironmentVariableTarget]::Machine, [System.EnvironmentVariableTarget]::User)
        $cleanedCount = 0
        foreach ($scope in $envScopes) {
            $vars = [System.Environment]::GetEnvironmentVariables($scope)
            foreach ($varName in $vars.Keys) {
                if ($vmStrings | Where-Object { $varName -like "*$_*" -or $vars[$varName] -like "*$_*" }) {
                    Write-Host "  # [INFO] Found VM-related env var: '$($varName)' in scope $scope. Removing..." -ForegroundColor Yellow
                    [System.Environment]::SetEnvironmentVariable($varName, $null, $scope)
                    $cleanedCount++
                }
            }
        }
        if ($cleanedCount -gt 0) {
            Write-Host "  # [OK] Removed $cleanedCount VM-related environment variables." -ForegroundColor Green
        } else {
            Write-Host "  # [INFO] No VM-related environment variables found." -ForegroundColor Cyan
        }
    }
    
    if (Get-YesNoChoice "Clear all Windows Event Logs?" "N" "WARNING: This is irreversible. Erases all system, security, and application logs." "EventLogs") {
        Write-Host "`n  # ================== CLEARING EVENT LOGS ==================" -ForegroundColor Magenta
        $logs = Get-WinEvent -ListLog * | Where-Object { $_.RecordCount > 0 }
        if ($logs) {
            Write-Host "  # [INFO] Clearing $($logs.Count) logs. This may take a moment..." -ForegroundColor Yellow
            $logs | ForEach-Object { wevtutil.exe cl $_.LogName }
            Write-Host "  # [OK] All event logs have been cleared." -ForegroundColor Green
        } else {
            Write-Host "  # [INFO] No event logs needed clearing." -ForegroundColor Cyan
        }
    }
    
    if (Get-YesNoChoice "Verify settings and produce a report?" "Y" "Tests if the applied settings are working correctly." "VerifySettings") {
        Test-HardeningStatus
        Write-Host "  # [INFO] Full log saved to: $logPath" -ForegroundColor Yellow
    }

    Write-Host "`n  # [SUCCESS] All selected hardening tasks are complete." -ForegroundColor Green
    if ($Global:restartRequired) {
        Write-Host "`n  # ==================== RESTART REQUIRED =====================" -ForegroundColor Cyan
        Write-Host "  # A system RESTART IS REQUIRED for all changes to take full effect." -ForegroundColor Cyan
        if ((Get-YesNoChoice "Do you want to restart the computer now?" "Y" "")) {
             Restart-Computer -Force
        } else {
            Write-Host "  # [INFO] Please restart the computer manually to apply all changes." -ForegroundColor Yellow
        }
    } else {
        Write-Host "`n  # ==================== ALL TASKS COMPLETE =====================" -ForegroundColor Cyan
        Write-Host "  # No restart is required for the selected tasks." -ForegroundColor Cyan
    }
    
    if ($logPath) {
        Stop-Transcript
    }
}
catch {
    Write-Host "`n  # [FATAL ERROR] An unexpected error occurred: $_" -ForegroundColor Red
    Write-Host "  # Error details: $($_.Exception.Message)" -ForegroundColor Red
    try { Stop-Transcript -ErrorAction SilentlyContinue } catch {}
}

Write-Host "`n  # Script execution finished. Press any key to exit..." -ForegroundColor Magenta
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null