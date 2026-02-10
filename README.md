# CloakBox - VM Detection Bypass 🛡️

> **⚠️ NOTICE: For support questions, please contact Croakq on Discord.**

**Bypass virtual machine detection using a custom VirtualBox fork**

![GitHub all releases](https://img.shields.io/github/downloads/Batlez/CloakBox/total?style=for-the-badge)

Created by **Vektor T13** | Maintained by **Batlez** | Works in **2026!** | Setup time: **30 minutes**

## 📥 Download
- **Primary**: [GitHub Releases](https://github.com/Batlez/CloakBox/releases)
- **Virus Scan**: [VirusTotal Scan](https://www.virustotal.com/gui/file/17ba6063ba20eba0ffc6538609d0cd216e015efd146e6e82e7de33e743cd8905/detection)

## 🎯 What it bypasses
✅ Examity | ✅ Respondus | ✅ Safe Exam Browser | ✅ ProctorU | ✅ Pearson VUE | ✅ Lockdown Browser | ✅ Honorlock | ✅ And More!

##
<p align="center"><strong><span style="font-size:1.5em">Click to see screenshots of CloakBox successfully bypassing exam proctoring detection</span></strong></p>

<details>
  <summary>Click to expand screenshots</summary>

![image](https://github.com/Batlez/HiddenVM/assets/63690709/51e1df60-4338-4da9-b5a3-ffe61c054797)
![image](https://github.com/Batlez/HiddenVM/assets/63690709/9f3ae77a-2bea-4824-bf3f-24556fb54045)
![image](https://github.com/Batlez/HiddenVM/assets/63690709/438c960f-f712-4016-8f92-0ad2c731a8bc)
![image](https://github.com/Batlez/HiddenVM/assets/63690709/17213a48-d6f3-4f82-87ac-2cb2f6f197f4)
![image](https://github.com/Batlez/HiddenVM/assets/63690709/47acefba-842b-4493-ad16-4709b9039dbc)
</details>

## ⚡ Quick Start

1. **Download & Unzip CloakBox**
   - Unzip to `C:\CloakBox`.

2. **Install CloakBox & Extension Pack**
   - Go to `CloakBox\Installer`.
   - Run `CloakBox.exe` (as admin).
   - Install the Oracle VirtualBox Extension Pack 7.2.4 if prompted.

3. **Create & Configure Your VM**
   - Recommended: Run `Run-Outside-VM.ps1` from `CloakBox\Utilities\Outside-VM`  
     This script **guides you step-by-step** through optimal VM creation and setup, including recommended storage size, disk format, and hardware spoofing.
   - If you are experienced, you may create/configure your VM manually according to your own preferences.

4. **Install Windows**
   - Install Windows (10 or 11; see troubleshooting if you have issues with 11).

5. **Host-Side Script Execution**
   - Run `Enable PS Scripts.bat` to allow PowerShell scripts.
   - Run `Run-Outside-VM.ps1` (if not already used for VM creation).
   - Optionally run `PS2-Mouse-Fix.ps1` if you encounter mouse issues.

6. **Inside-VM Spoofing & Checks**
   - After Windows installation and boot, inside the VM run scripts from `CloakBox\Utilities\Inside-VM`:
     - `Enable PS Scripts.bat` (again, if needed)
     - `Run-Inside-VM.ps1` (advanced guest spoofing)
     - `AntiOS 3.4.5.exe` (optional, for deep cleaning/spoofing)
     - `VM-Checker.ps1` (check your VM for detectable artifacts)
     - `Pearson OnVUE.ps1` (for pre-exam or OnVUE system test)

7. **Troubleshooting: Windows 11 Install**
   - If you have issues installing Windows 11:
     - Disable UEFI/Secure Boot (use Legacy BIOS for the VM)
     - Disable TPM
     - Try Windows 10 instead for reliability
     - For CloakBox: System > Motherboard > Uncheck “Enable EFI”

**Your VM should now be ready and properly spoofed for exam or privacy testing.**

## 🎥 Need Help?
- **Video Guide**: [YouTube Tutorial](https://www.youtube.com/watch?v=CvfCVzrTnq4)
- **Discord Support**: **Croakq**

## ⚖️ Legal
For ethical testing and research purposes only. Users responsible for compliance with local laws.
