# TDX ARENA  
**Certification Report**

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

Involved navigating to the Desktop directory to confirm the presence of the "suspicious-files" 
folder. This was verified by running the `ls` command.
![image](https://github.com/user-attachments/assets/f1438836-4411-4bc0-9e81-6873630f1a9d)

## The Second step: Attempted to scan the folder with ClamAV 

I tried to scan the directory containing suspicious files using the ClamAV command: 
```
clamscan -r 
home/bruce/Desktop/suspicious-files
```
The `-r` flag specifies that the scan should be recursive, 
meaning it will scan all files and subdirectories within the specified directory. 
![image](https://github.com/user-attachments/assets/81117a3a-86c1-41f0-9cd2-62c349745cc2)

However, it was found that the ClamAV utility was not installed or not found. An attempt to run 
the command with sudo privileges also failed due to lack of sudo permissions. 

## Step Tree: Compressing the files 

I decided to scan the file using VirusTotal. Due to limitations in VirusTotal for scanning multiple 
files simultaneously, I decided to compress the files into a single ZIP file using the zip utility: 
`zip file.zip suspicious-files/*` This command will compress all files directly within the “suspicious
files” directory into a ZIP file named “file.zip”
![image](https://github.com/user-attachments/assets/821a04c1-e6d0-499c-9cc1-64a82a0fde15)

A zip file should appear on the desktop directory as shown below.
![image](https://github.com/user-attachments/assets/ad9dfacf-fa3d-4ee0-b720-6e00c87404a0)


## Step Four: VirusTotal Scan of Compressed File 

After creating the file.zip archive, I selected and uploaded it to VirusTotal for comprehensive 
scanning using multiple antivirus engines.
![image](https://github.com/user-attachments/assets/551a7410-a619-4479-a27a-b28df6131a1f)

## Step Five: Analyzing & Identification of Malicious File 

The VirusTotal scan revealed that *file176.exe* had a high malicious value with 7/66 detections. 
The file type was identified as a DOS EXE as showed:



```bash

