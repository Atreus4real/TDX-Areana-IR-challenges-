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

## Tools and Technologies Used
Volatility: A memory forensics tool used to analyze the memory dump and identify suspicious 
processes. 
`7-Zip`: A file archiver used to extract the contents of the password-protected zip file. 
`grep`: A command-line utility used for searching specific patterns within files. 
`md5sum`: A utility to compute and verify MD5 hash values. 
`strings`: A command-line utility used to extract printable characters from binary files. 
`hexdump`: Command-line utility used to view binary file content in hexadecimal format.

- Volatility
- 7-Zip
- `strings`, `grep`, `hexdump`, and `md5sum`

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


## Full Report
See the detailed analysis in [Report-Imperial Memory.pdf](./Report-Imperial%20Memory.pdf).

## Reproduce the Steps
```bash
# Example command to dump process memory with Volatility:
vol.py -f Emperor.vmem --profile=Win10x64_17134 memdump -p 5496 --dump-dir ./dumped_files/
