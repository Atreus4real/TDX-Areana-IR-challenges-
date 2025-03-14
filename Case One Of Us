# TDX ARENA  
**Certification Report**

---

## Sabour Almahdi  
**Final Assessment Report Submission**  
**Case: One of us**  
*17th June 2024*

---

### Executive Summary  
This report details the identification and remediation of malicious files found on a workstation. The investigation involved navigating to the directory containing the suspicious files, attempting to scan the files using ClamAV, generating their MD5 hashes, compressing the files into a single ZIP file, and scanning the compressed file using VirusTotal. The VirusTotal scan revealed a highly malicious file, `file176.exe`, which was identified as a Trojan. The steps outlined provide a comprehensive approach to addressing and preventing similar incidents in the future.

---

### Findings and Analysis  

| **Attribute**         | **Value**                                  |
|-----------------------|--------------------------------------------|
| Malicious File        | `file176.exe`                              |
| File Size             | 223.19 KB                                  |
| MD5 Hash              | `f48a8687e91fd9ef98cd1b7aaeeb2a4c`        |
| SHA-1 Hash            | `8e014393c8d424e28fc4b71f88d237639ca82ff1`|
| First Submission Date | 2022-01-14 07:29:12 UTC                   |
| Malware Type          | Trojan                                     |
| Malware Family        | Shikataganai                               |

**Analysis:**  
This file is identified as a Shikataganai Trojan capable of stealing sensitive data, installing additional malware, and creating backdoors for remote access.

---

### Methodology  

#### Tools and Technologies Used  
- **Linux Command Line**: Directory navigation and file listing.  
- **ClamAV**: Attempted malware scanning.  
- **VirusTotal**: Multi-engine malware analysis.  
- **ZIP Utility**: File compression.  
- **md5sum**: MD5 hash generation.  

---

### Investigation Process  

#### Step 1: Navigate to Directory  
```bash
bruce@workstation:~$ ls  
Desktop Documents Downloads Music Pictures Public Templates Videos  

bruce@workstation:~$ cd Desktop/  
bruce@workstation:~/Desktop$ ls  
chromium.desktop firefox-esr.desktop suspicious-files clamav-ui org.kde.konsole.desktop
