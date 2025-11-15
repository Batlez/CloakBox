# CloakBox - VM Detection Bypass 🛡️

> **⚠️ NOTICE: This project is no longer being actively updated. For support questions, please contact Enver3268 on Discord.**

**Bypass virtual machine detection using a custom VirtualBox fork**

![GitHub all releases](https://img.shields.io/github/downloads/Batlez/CloakBox/total?style=for-the-badge)

Created by **Vektor T13** | Maintained by **Batlez** |⚡Works in 2025! |⏱️ Setup time: ~30 minutes

## 📥 Download
- **Primary**: [GitHub Releases](https://github.com/Batlez/CloakBox/releases)
- **Virus Scan**: [VirusTotal Scan](https://www.virustotal.com/gui/file/17ba6063ba20eba0ffc6538609d0cd216e015efd146e6e82e7de33e743cd8905/detection)

## 🎯 What it bypasses
✅ Examity | ✅ Respondus | ✅ Safe Exam Browser | ✅ ProctorU | ✅ Pearson VUE | ✅ Lockdown Browser | ✅ Honorlock | ✅ Guardian

<details>
<summary>Click ME to see pictures of Cloakbox bypassing</summary>
   
![image](https://github.com/Batlez/HiddenVM/assets/63690709/51e1df60-4338-4da9-b5a3-ffe61c054797)
![image](https://github.com/Batlez/HiddenVM/assets/63690709/9f3ae77a-2bea-4824-bf3f-24556fb54045)
![image](https://github.com/Batlez/HiddenVM/assets/63690709/438c960f-f712-4016-8f92-0ad2c731a8bc)
![image](https://github.com/Batlez/HiddenVM/assets/63690709/17213a48-d6f3-4f82-87ac-2cb2f6f197f4)
![image](https://github.com/Batlez/HiddenVM/assets/63690709/47acefba-842b-4493-ad16-4709b9039dbc)

</details>
<details>
<summary>Fix "Windows version not showing" when creating a VM</summary>

**Disable** SV-IOV setting in your motherboard's BIOS, it should be under: PCI Configuration
</details>

## ⚡ Quick Start
1. **Uninstall** existing VirtualBox/VMWare
2. **Install** CloakBox (run as admin)
3. **Create VM** with 80GB+ storage (.VDI format, SATA)
4. **Install Windows 10** using Media Creation Tool ISO
5. **Run scripts** in this order:
   - `RUN ON PC.ps1` (on host)
   - `RUN IN VM.ps1` (inside VM)
   - `AntiOS.exe` (inside VM)
   - `GPU Spoofer.exe` (inside VM)
   - `VM CHECKER.ps1` (inside VM)
   - `Pearson OnVUE.ps1` (inside VM if using OnVUE)

## 🎥 Need Help?
- **Video Guide**: [YouTube Tutorial](https://www.youtube.com/watch?v=rk_TTvOCUtU)
- **Discord Support**: **Enver3268**

## ⚖️ Legal
For ethical testing and research purposes only. Users responsible for compliance with local laws.
