# TDX ARENA  
**Certification Report**

# Case one of us
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

![image](https://github.com/user-attachments/assets/e1931427-6a96-468e-8a2b-5d895be1b15c)

## Step Six: Scanning the targeted file 

After identifying file176.exe as suspicious, I scanned the file individually using VirusTotal. The 
scan results were as follows: 
After identifying `file176.exe` as suspicious, the file was scanned individually using VirusTotal. Results included:  

| **Attribute**         | **Value**                                  |  
|-----------------------|--------------------------------------------|  
| Detections            | Flagged by 5-10 security vendors          |  
| Malware Type          | Trojan (Shikataganai)                      |  
| File Type             | EXE                                        |  

**Malware Capabilities**:  
- Steals sensitive information (passwords, banking details).  
- Downloads and installs additional malware.  
- Grants remote control of the infected machine.  
- Logs keystrokes to capture user credentials.  
- Creates backdoors for future attacks.  


## Step Seven: Calculating MD5 Hash 

After gathering all the information that I needed, one final step was left: calculating the MD5 
hash value. I used the `md5sum` utility to calculate the MD5 hash of the malicious file. 

![image](https://github.com/user-attachments/assets/3e89ae82-fb35-49ee-962c-d824b96daeb3)

`md5sum` command calculates and verifies 128-bit MD5 hashes for files. There for I answered 
the question “Enter an MD5 hash value” by submitting the hash value I completed the 
challenge.

--- 


### Recommendations  

1. **Install ClamAV Properly**  
   Ensure ClamAV is installed and accessible, and verify permissions for scanning.  

2. **Enable Antivirus Software**  
   Ensure that antivirus software is enabled and updated on all systems.  

3. **Regular Scans**  
   Schedule regular scans to detect and remove potential threats promptly.  

4. **Ensure Minimum Necessary Privileges for Users**  
   Grant users only the essential sudo privileges required for specific administrative tasks. This approach limits potential security risks while allowing users to perform necessary actions.  

5. **Add the Malicious File Signature to the AV**  
   Update the antivirus software with the signature of the malicious file to ensure it can be detected and blocked in the future.  

6. **User Training**  
   Educate users on safe computing practices to prevent malware infections. 


