# Imperial Memory Forensics Challenge Report

## Overview
This case involves the extraction and analysis of hidden files from a memory dump. The key 
findings include identifying and extracting a password-protected zip file and subsequently 
uncovering nested hidden files. The approach taken involved using Volatility to analyze the 
memory dump, extracting the relevant process memory, and utilizing string searches to find the 
password and extract the contents. The successful extraction of the hidden files and the 
identification of the MD5 hash demonstrate the effectiveness of the implemented measures
 Key steps included:
- Analyzing processes with **Volatility**.
- Extracting a password-protected ZIP (`gift.7z`).
- Recovering the MD5 hash `0f235385d25ade312a2d151a2cc43865` from `secrets.txt`.

## Key Findings
| **Network & File-related findings** | **Details** |
|:------------------------------------|:-------------|
| **Memory Dump**                     | Emperor.vmem – The memory dump file analyzed. |
| **Suspicious Processes**            | MsMpEng.exe, powershell.exe – Processes identified with potential malicious activity. |
| **Password-Protected File**         | gift.7z – The file identified to contain hidden data. |
| **Hidden Files**                    | secrets.txt – Files extracted from the memory gift.7z. |
| **Password for Zip**                | pG6Vmc9Qd5cpM8e#fCa=x6A3 – Password used to extract the zip file. |
| **FLAG: MD5 Hash**                  | 0f235385d25ade312a2d151a2cc43865 – Calculated from secrets.txt |
| **Magic Bytes**                     | 50 4B 03 04 – Indicates the file is a ZIP archive, confirmed by hexdump analysis. |
| **User Found**                      | Aaron – A user that created the Zip file and the password. |
| **Profile**                         | Windows10 - Profiles include several versions of Windows 10. |

## Tools and Technologies Used
Volatility: A memory forensics tool used to analyze the memory dump and identify suspicious 
processes. 
- `7-Zip`: A file archiver used to extract the contents of the password-protected zip file. 
- `grep`: A command-line utility used for searching specific patterns within files. 
- `md5sum`: A utility to compute and verify MD5 hash values. 
- `strings`: A command-line utility used to extract printable characters from binary files. 
- `hexdump`: Command-line utility used to view binary file content in hexadecimal format.


## Investigation Process
- ***The first step: Identifying the Profile:***

The first thing I did is identifying the profile using Volatility to determine the profile of the 
memory dump for analysis by running the command: `vol.py -f /home/derrek/Desktop/Emperor.vmem imageinfo`

![image](https://github.com/user-attachments/assets/e1e181f9-542b-40c2-9247-cd319e604b6f)
This command outputs various details about the memory dump, including the suggested profile, 
which is essential for accurate analysis. Based on the output, the suggested profiles include 
several versions of Windows10. 

---

- ***The Second step: Identifying Suspicious Processes:***

Next, I used the malfind plugin in Volatility to identify suspicious memory regions associated with 
processes. The command used: `vol.py -f /home/derrek/Desktop/Emperor.vmem -
profile=Win10x64_17134 malfind`
![image](https://github.com/user-attachments/assets/862b68ab-12f5-4895-bd93-3fce9c2e96fe)
This command highlighted suspicious memory regions, particularly for MsMpEng.exe and 
powershell.exe, indicating potential malicious activity.

---
- ***Step Tree: Identifying the Process ID:***

Since the previous step showed that suspicious processes, To proceed with a more targeted 
analysis, I identified the process ID (PID) for powershell.exe using the cmdline plugin in 
Volatility. By executing the command: `vol.py -f /home/derrek/Desktop/Emperor.vmem -
profile=Win10x64_17134 cmdline`
![image](https://github.com/user-attachments/assets/e28e6fec-e762-4d01-8d19-d0ccd69e8f14)
This command showed that the PID for powershell.exe is 5496. 

---
- ***Step Four: Dumping Process Memory***

To further investigate, I dumped the memory of the suspicious processes for detailed analysis. 
The commands used were: `vol.py -f /home/derrek/Desktop/Emperor.vmem -
profile=Win10x64_17134 memdump -p 5496 --dump-dir /home/derrek/dumped_files/`
![image](https://github.com/user-attachments/assets/abf72b94-e5e8-4d47-a365-acd9c2b0f387)
This command retrieves the command-line arguments used by processes in the specified 
memory dump, the command dumped the memory of the process with PID 5496 
(powershell.exe) to the specified directory as showned below:
![image](https://github.com/user-attachments/assets/655732fe-4f1a-4655-a3e9-21d78d773495)
A new file should appear in the specified directory.  

---
- ***Step Five: Extracting and Analyzing Strings:***

I then used the strings command to extract printable strings from the dumped memory and 
searched for relevant keywords to uncover hidden commands or passwords: `strings 
/home/derrek/Desktop/5496.dmp | grep -A 5 -B 5 -Ei 'gift\.7z|zip|password|Compress
Archive|archive' > /home/derrek/Desktop/filtered_output`
![image](https://github.com/user-attachments/assets/c8160f58-af03-4914-b1f6-6f1d8902cfb3)
This command will analyze the binary file, search for relevant strings, and save the results 
to filtered_output. The command was successful and a new file was created as shown below: 
![image](https://github.com/user-attachments/assets/5e0484d4-87a6-4ee1-89e7-3aa4334cecd5)


Then I opened the newly created file and discovered the following:
![image](https://github.com/user-attachments/assets/81343f64-d447-4ffa-8d83-608c3e4c4ade)
The command used 7-Zip (7z.exe) to create an archive and it includes a password for 
encryption. The user referenced in the command is Aaron. This can be seen from the file paths: 
`C:\Users\Aaron\Desktop\gift.7z`

- **7-Zip (7z.exe)**: A file archiver with a high compression ratio. 
- **A command**: Stands for "add" and is used to add files to an archive. 
- **Archive Path**: The location where the archive file will be created. 
- **Source Path**: The file or directory that will be added to the archive. 
- **Password Protection**: The -p switch followed by the password string ensures that the archive 
- will be encrypted with the specified password which is: **G6Vmc$Qd5cpM8ee#Ca=x&A3**

---
- ***Step Six: Extracting the Zip File:***

Using the identified password, I extracted the zip file (gift.7z) by executing the command: `7z x 
/home/derrek/Desktop/gift.7z -o/home/derrek/Desktop/` this command will extract the files 
from gift.7z to your desktop directory.
![image](https://github.com/user-attachments/assets/1d9dd91c-d7e1-4e12-b756-06298871602f)

Once extracted, the file named suspicious.docx was found. But the file was empty. Here is what 
you will see when you open the file:
![image](https://github.com/user-attachments/assets/359e0558-4d32-4616-8732-54af4127c22f)


---

- ***The seventh step: Analyzing Extracted File:***

In this step, I had to think critically because the extracted file was empty. The only thing I could 
come up with was to check the file’s Magic Bytes, so I used the `hexdump` utility.

`hexdump`: This command is used to filter and display the specified files or standard input in a 
human-readable format. It’s commonly used to examine binary files.
![image](https://github.com/user-attachments/assets/202aa43b-5486-4cac-8ace-c5e2374836b0)

The `-C` option displays the input data in a “canonical” format, which includes both hexadecimal 
and ASCII representations. 
The `head` command limits the output to the first few lines (usually 10 lines by default).

The hexdump output indicates that the file starts with `50 4B 03 04`, which corresponds to the 
ASCII characters PK. This signature indicates that the file is a ZIP archive. Once I confirmed 
that, I changed the file extension from docx to 7z.
![image](https://github.com/user-attachments/assets/ff585922-eabf-4479-a181-5db26ac1bb7d)

I then extracted the file and found multiple files and folders, including `secrets.txt`. However, the 
content of the secrets.txt file did not reveal the MD5 hash.

---
- ***The eighth step: Calculating the MD5 Hash:***

Finally, I used the md5sum utility to calculate the MD5 hash of the secrets.txt file, because the 
content of the file was not helpful.

![image](https://github.com/user-attachments/assets/058724c2-a210-46c1-b040-5cb700500164)
This command produced the MD5 hash `0f235385d25ade312a2d151a2cc43865`, which was 
submitted to complete the challenge.



## Recommendations
This investigation successfully identified and mitigated suspicious activities within a memory 
dump using a systematic approach involving memory forensics and file analysis. The detection 
process highlighted the importance of utilizing forensic analysis tools and the need for precise 
configurations in intrusion detection systems. The findings underscore the critical role of 
continuous monitoring and regular updates to security measures to safeguard against evolving 
threats. The recommendations provided aim to enhance the security posture and prevent similar 
incidents in the future, ensuring a robust defense against hidden malicious processes. 

Based on the findings and analysis from the memory dump investigation, the following 
recommendations are made to enhance the security posture and improve the incident response 
processes:

***Enhance Monitoring and Detection Capabilities:*** 
- Deploy Advanced Threat Detection Tools:

Utilize advanced endpoint detection and 
response (EDR) solutions to monitor and analyze system activities in real-time, focusing 
on processes like MsMpEng.exe and powershell.exe. 

- ***Implement Behavioral Analytics:***

Integrate behavioral analytics to detect anomalies 
and suspicious behaviors that could indicate malicious activity.

Regular Memory Forensics and Analysis: 
• Conduct Regular Memory Dumps: Schedule regular memory dump analyses using 
tools like Volatility to proactively identify and investigate suspicious activities. 
• Automate Forensic Analysis: Develop and implement automated scripts to run key 
Volatility plugins and generate reports for quicker incident detection and response. 
Strengthen System Hardening and Configuration: 
• Restrict PowerShell Usage: Implement policies to restrict the use of PowerShell 
scripts, especially for non-administrative users, to minimize the risk of exploitation. 
• Update Security Configurations: Regularly update and audit security configurations 
to ensure that only necessary processes and services are running. 
Improve File Integrity and Encryption Practices: 
• Enforce File Integrity Monitoring: Deploy file integrity monitoring solutions to detect 
unauthorized changes to critical files and configurations. 
• Use Strong Encryption: Ensure that sensitive files are encrypted both at rest and in 
transit using strong encryption standards. 
Incident Response Training and Drills: 
• Conduct Regular Training: Provide ongoing training for the incident response team on 
the latest forensic analysis techniques and tools. 
• Simulate Attack Scenarios: Perform regular incident response drills to simulate 
potential attack scenarios and evaluate the effectiveness of response strategies. 
Enhance Logging and Alerting: 
• Centralize Log Management: Use a centralized log management system to aggregate 
logs from various sources for better analysis and correlation. 
• Set Up Comprehensive Alerts: Configure alerts for specific events, such as the 
execution of PowerShell scripts or the creation of suspicious files, to enable timely 
responses. 
Regularly Update Security Tools: 
• Patch and Update Tools: Ensure all security tools and frameworks, including Volatility, 
are regularly updated to the latest versions to benefit from new features and security 
patches. 
• Review Tool Configurations: Periodically review and adjust the configurations of 
security tools to ensure optimal performance and detection capabilities. 
Conduct Thorough Post-Incident Reviews: 
• Analyze Incident Responses: After each incident, perform a detailed review to 
identify what worked well and what could be improved. 
• Document Lessons Learned: Maintain detailed documentation of lessons learned from each incident to refine and enhance the incident response process continually.
