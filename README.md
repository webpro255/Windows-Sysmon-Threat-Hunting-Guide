# Windows & Sysmon Threat Hunting Guide

This repository serves as a quick reference for threat hunters using **Windows Event Codes** and **Sysmon Event Codes** to detect suspicious behavior, identify lateral movement, and investigate system activity.

## Table of Contents
1. [Introduction](#introduction)
2. [Key Windows Event Codes](#key-windows-event-codes)
3. [Sysmon Event Codes](#sysmon-event-codes)
4. [Common Threat Hunting Techniques](#common-threat-hunting-techniques)
5. [Useful Queries and Filters](#useful-queries-and-filters)
6. [Resources and Further Reading](#resources-and-further-reading)

---

## Introduction
In today's threat landscape, understanding how attackers operate within a system is crucial. Leveraging Windows and Sysmon event codes can help detect and prevent attacks before they cause significant damage. This guide will focus on:
- **Windows Event Codes** related to logons, process creation, and privileged access.
- **Sysmon Event Codes** for tracking file changes, process injections, and network activity.

---

## Key Windows Event Codes
These are the most important **Windows Event Codes** for tracking suspicious activities:

| Event ID | Description | Why It’s Useful |
| -------- | ----------- | --------------- |
| 1 | **Process Start** | Logs when a process is started, giving visibility into program executions, useful for detecting unauthorized or suspicious processes. |
| 2 | **Process End** | Tracks when a process ends, useful for detecting when malicious processes are terminated to evade detection. |
| 3 | **Network Connection Detected** | Logs outbound network connections made by a process, useful for tracking suspicious or unauthorized network activity. |
| 4 | **Service Start** | Logs when a service is started, helping to monitor for potentially malicious services being run. |
| 5 | **Service Stop** | Tracks when a service is stopped, which can indicate attempts to disable critical services. |
| 6 | **Special Privilege Logon** | Logs when a user logs on with special privileges, such as an administrator, which could be used for tracking privilege escalation. |
| 7 | **Audit Policy Change** | Logs changes to the system's audit policies, which may indicate attempts to hide malicious activity. |
| 8 | **Logon Failure** | Logs failed login attempts, useful for detecting brute force attacks or unauthorized access attempts. |
| 9 | **Device Connection** | Logs when a device, such as a USB drive, is connected, useful for tracking unauthorized or suspicious external devices. |
| 10 | **Device Disconnection** | Logs when a device is disconnected, useful for monitoring the removal of devices after data has been copied or transferred. |
| 11 | **File System Object Access** | Logs when a file or directory is accessed, useful for detecting unauthorized access to sensitive files. |
| 12 | **Audit Policy Change** | Logs changes to audit policies, which can indicate that an attacker is attempting to disable logging to hide their activities. |
| 13 | **Registry Key Access** | Logs access to the registry, particularly useful for detecting attempts to modify registry keys for persistence or privilege escalation. |
| 14 | **Registry Key Modification** | Tracks when a registry key is modified, which could be indicative of malware attempting to set up persistence or disable security controls. |
| 15 | **Object Deletion** | Detects when files or directories are deleted, useful for monitoring cleanup activities after an attack. |
| 16 | **Object Modification** | Logs when objects (files, directories, or other resources) are modified, helping detect tampering with critical files. |
| 17 | **Registry Key Deletion** | Detects when a registry key is deleted, often used by attackers to remove persistence mechanisms or traces of their activities. |
| 18 | **User Account Deletion** | Logs when a user account is deleted, which could indicate an attacker removing access to cover tracks. |
| 19 | **Group Policy Modification** | Detects when a Group Policy is modified, often an indicator of privilege escalation or attempts to disable security controls. |
| 20 | **Process Injection Detected** | Tracks when malicious code is injected into a legitimate process, commonly used in evasion techniques like process hollowing. |
| 21 | **Driver Installation** | Logs the installation of drivers, which can detect malicious or unauthorized kernel-level drivers being loaded. |
| 22 | **Kernel Module Loaded** | Tracks when a kernel module is loaded, often used by rootkits or other sophisticated attacks to gain control over the system. |
| 23 | **Service Configuration Change** | Logs when a service configuration is modified, which can be used to detect persistence mechanisms or attempts to evade security. |
| 24 | **Script Blocked** | Logs when a script execution is blocked, useful for tracking potentially malicious scripts like PowerShell or JavaScript used in attacks. |
| 25 | **Firewall Rule Changed** | Tracks changes to firewall rules, helping detect attempts to open ports or modify traffic filtering to allow malicious traffic. |
| 4104 | **PowerShell Script Block Logging** | Captures PowerShell script execution for detecting malicious scripts. |
| 4624 | **Successful Logon** | Tracks all successful logins to detect unauthorized access. |
| 4688 | **Process Creation** | Logs process creation, including command-line arguments, for detecting malicious behavior. |
| 4776 | **NTLM Authentication Requests** | Helps track **pass-the-hash** attacks and credential misuse. |
| 7045 | **Service Installed** | Detects new services installed, often used by attackers for persistence. |
| 4104 | **PowerShell Script Block Logging** | Captures PowerShell script execution for detecting malicious scripts. |
| 4688 | **Process Creation** | Logs every new process creation, including command-line arguments, to detect malicious activity. |
| 4624 | **Successful Logon** | Tracks all successful logins, helping detect authorized or unauthorized access. |
| 4625 | **Failed Logon** | Logs failed login attempts, useful for detecting brute-force attacks or unauthorized access attempts. |
| 4648 | **Logon with Explicit Credentials** | Detects when a process logs on using explicit credentials, helping identify lateral movement or credential abuse. |
| 4672 | **Special Privileges Assigned to New Logon** | Logs when a user with special privileges logs on, useful for tracking privileged account activity. |
| 4776 | **NTLM Authentication Request** | Logs NTLM authentication attempts, useful for detecting pass-the-hash attacks or brute-force attempts. |
| 7045 | **Service Installed** | Detects when a new service is installed, which can indicate persistence mechanisms used by attackers. |
| 4697 | **Service Installation (Privileged)** | Logs the installation of services with administrative privileges, useful for detecting privilege escalation. |
| 4703 | **Audit Policy Change** | Monitors changes to system audit policies, which can indicate attempts to hide malicious activities by modifying logging. |
| 4719 | **System Audit Policy Changed** | Logs changes to the audit policy, often a sign attackers are trying to disable or modify logging. |
| 4720 | **User Account Created** | Logs when a new user account is created, helping detect unauthorized account creation for persistence. |
| 4732 | **User Added to Privileged Group** | Logs when a user is added to a privileged group (e.g., Administrators), often associated with privilege escalation attacks. |
| 4771 | **Kerberos Pre-Authentication Failed** | Detects failed Kerberos authentication attempts, useful for identifying brute-force attacks or credential theft. |
| 5140 | **A Network Share Was Accessed** | Logs access to network shares, useful for detecting lateral movement or potential data exfiltration. |
| 4656 | **Handle to Object Requested** | Logs when a process attempts to access an object (file, registry, etc.), useful for detecting unauthorized access attempts. |
| 4663 | **Object Access** | Logs successful attempts to access objects like files or directories, useful for detecting data exfiltration or tampering. |
| 1000 | **Application Error** | Logs application crashes or faults, often associated with malware or other malicious activity causing system instability. |
| 5145 | **File Share Access** | Logs access to file shares over the network, useful for tracking lateral movement and suspicious access to shared resources. |
| 1102 | **Security Log Cleared** | Logs when the security event log is cleared, a common tactic attackers use to cover their tracks. |
| 7036 | **Service Status Changed** | Logs when a service starts or stops, useful for detecting attacks that involve modifying critical services. |
| 4728 | **A Member Was Added to a Security-Enabled Global Group** | Logs when a user is added to a global security group, helping detect unauthorized privilege escalation. |
| 4735 | **A Security-Enabled Global Group Was Changed** | Detects modifications to security-enabled global groups, useful for monitoring unauthorized access or group policy changes. |
| 4740 | **Account Lockout** | Logs when an account is locked out due to too many failed logon attempts, often a sign of brute-force attacks. |
| 4756 | **A Member Was Added to a Security-Enabled Universal Group** | Logs when a user is added to a universal group, which may indicate unauthorized privilege escalation. |
| 4767 | **Account Unlocked** | Tracks when a locked account is unlocked, helping identify if attackers are attempting to regain access. |
| 4778 | **Session Reconnected to Another Device** | Logs when a session is reconnected, useful for detecting unauthorized or suspicious session hijacking. |
| 4782 | **Password Hash Accessed** | Tracks when password hashes are accessed, which can be a sign of credential dumping attacks. |
| 4798 | **User's Local Group Membership Enumeration** | Logs when an enumeration of group memberships for a user is performed, which can indicate attackers performing reconnaissance. |
| 4964 | **Special Groups Logon Tracking** | Detects logons by users who are members of special groups, useful for tracking privileged account usage. |
| 5025 | **Firewall Service Stopped** | Logs when the Windows Firewall service is stopped, which could indicate an attacker is disabling firewall protection. |
| 5038 | **Code Integrity Check Failed** | Logs when a code integrity check fails, often due to tampered or unauthorized drivers being loaded, useful for detecting rootkits. |
| 5058 | **Key File Operation** | Logs cryptographic operations using a key file, useful for detecting unauthorized decryption or encryption activities. |
| 5142 | **Network Share Created** | Logs when a network share is created, which could be indicative of data exfiltration or lateral movement. |
| 5143 | **Network Share Deleted** | Detects the deletion of a network share, useful for identifying attempts to cover tracks after data exfiltration. |
| 6416 | **Code Integrity Violation** | Logs violations of code integrity policies, useful for detecting unauthorized code execution or DLL hijacking. |
| 4725 | **User Account Disabled** | Tracks when a user account is disabled, which can indicate the removal of access privileges in response to suspicious behavior. |
| 4627 | **Group Membership Enumeration** | Detects when a user queries group memberships, often used during reconnaissance by attackers. |
| 4647 | **User Initiated Logoff** | Logs when a user manually logs off, useful for detecting suspicious session terminations. |
| 4769 | **A Kerberos Service Ticket Was Requested** | Logs Kerberos ticket requests, useful for detecting abnormal ticket-granting patterns, like Pass-the-Ticket attacks. |
| 4770 | **A Kerberos Service Ticket Was Renewed** | Logs Kerberos ticket renewals, helping to monitor for suspicious renewal activity that could indicate a prolonged attack. |
| 4673 | **A Privileged Service Was Called** | Detects calls to services with elevated privileges, useful for identifying unauthorized privileged operations. |
| 4690 | **Attempted Access to an Object by an Invalid Handle** | Logs when a process attempts to access an object with an invalid handle, useful for detecting malicious code files or processes incorrectly. |
| 5031 | **Windows Firewall Blocked an Application** | Logs when the Windows Firewall blocks an application, useful for detecting network-based threats attempting to connect externally. |
| 5059 | **Key Migration Operation** | Detects cryptographic key migration, which may signal attempts to export or manipulate security keys. |


---

## Sysmon Event Codes
Below are **Sysmon Event Codes** that are essential for advanced threat hunting:

| Event ID | Description | Why It’s Useful |
| -------- | ----------- | --------------- |
| 1 | **Process Creation** | Logs every new process, helping identify suspicious executables. |
| 3 | **Network Connection** | Tracks network connections made by processes, useful for detecting malicious communication. |
| 5 | **Process Termination** | Logs when a process terminates. Useful for tracking the lifecycle of malicious or suspicious processes. |
| 6 | **Driver Loaded** | Logs when a driver is loaded into the kernel. Detects rootkits or unauthorized kernel-level drivers. |
| 7 | **Image Load** | Logs when a DLL or other executable image is loaded. Can help detect suspicious DLL loads, like those used in DLL hijacking or injection. |
| 8 | **CreateRemoteThread** | Logs when a process creates a remote thread in another process. This is often indicative of process injection or malicious activity. |
| 9 | **RawAccessRead** | Logs when a process reads raw data from the disk, bypassing the file system. Useful for detecting low-level disk access, like ransomware. |
| 10| **Process Access** | Logs when one process accesses another, which can indicate malicious activity like credential theft or process hollowing. |
| 11| **File Creation** | Logs when a file is created or overwritten. Useful for detecting malware or scripts dropped onto a system. |
| 12| **Registry Object Added/Deleted** | Logs when a registry key or value is added or deleted. Helps identify persistence mechanisms via the registry. |
| 13| **Registry Value Set** | Logs when a registry value is modified or created. Key for detecting registry-based persistence techniques. |
| 15| **File Create Stream Hash** | Logs file creation along with the associated file hash. Useful for identifying files that may be used to execute malware. |
| 17| **Pipe Created** | Logs when a named pipe is created, often used in inter-process communication. Detects malicious IPC techniques used in attacks. |
| 18| **Pipe Connected** | Logs when a process connects to a named pipe. Useful for detecting malware or components communicating with each other. |
| 19| **WMI Event Filter** | Logs when a WMI event filter is created. WMI can be used for persistence and lateral movement, making this useful for identifying malicious use. |
| 20| **WMI Event Consumer Activity** | Logs when a WMI consumer is created. Attackers use WMI for persistence, so this helps in detecting it. |
| 22| **DNS Query** | Logs DNS queries made by a process. Useful for detecting suspicious or unusual domain name lookups (e.g., command-and-control traffic). |
| 23| **File Deletion** | Logs when a file is deleted. Helps track when attackers attempt to remove malicious files or cover their tracks. |
| 24| **Clipboard Change** | Logs when the clipboard content is modified. Can detect clipboard hijacking or suspicious activity related to copy-paste of sensitive information. |
| 25| **Process Tampering** | Detects when processes are tampered with, like in-memory injection. Critical for detecting evasive techniques like process hollowing. |
| 26| **File Delete Logged** | Logs the deletion of files, useful in tracking cleanup activity after an attack. |
| 27| **Registry Object Deleted** | Logs when a registry object is deleted, often tied to the removal of persistence mechanisms. |
| 28| **Thread Injection** | Detects when malicious code is injected into legitimate process threads. Useful for identifying sophisticated in-memory attacks. |
| 29| **File Created Logged** | Logs the creation of files, providing visibility into unauthorized file creation attempts, often a precursor to malware execution. |
| 30| **DNS Query Response** | Logs the response to DNS queries, which is useful for detecting command-and-control domains or other suspicious communications. |
| 32| **File Integrity Monitoring** | Tracks file modifications in critical directories. Helps detect tampering with key files or configuration files. |
| 33| **Parent-Child Process Correlation** | Correlates parent and child processes, useful for identifying process creation anomalies or malicious process chains. |
| 35| **Binary File Execution** | Logs the execution of binary files, useful for detecting unauthorized or malicious binary execution in restricted directories. |
| 36| **Image File Execution Options (IFEO) Hijacking** | Detects modifications to Image File Execution Options (IFEO), often used by attackers to hijack legitimate processes for persistence. |
| 37| **LSASS Access Detected** | Logs access to LSASS (Local Security Authority Subsystem Service), which is crucial for detecting credential dumping techniques used by attackers. |
| 38| **AMSI (Antimalware Scan Interface) Detection** | Logs when AMSI is triggered, which is useful for detecting malware attempting to bypass security solutions or evade detection. |
| 39| **Registry Hive Changes** | Tracks changes to registry hives, helping detect modifications attackers make to establish persistence or elevate privileges. |
| 40| **Security Log Tampering** | Detects tampering with security logs, often used by attackers to cover their tracks. |
| 41| **Event Log Service State** | Logs changes to the event logging service, useful for detecting when attackers attempt to disable logging to evade detection. |
| 42| **Remote Thread Injection** | Logs the injection of threads into remote processes, a common attack technique used to execute malicious code in a legitimate process. |
| 43| **Service Configuration Change** | Detects changes in service configurations, which can signal persistence mechanisms or privilege escalation. |
| 44| **Parent Process ID Spoofing** | Detects attempts to spoof the parent process ID, a common technique used in evasion tactics to make malicious processes appear legitimate. |
| 45| **Executable File Permissions Changed** | Logs when the permissions of executable files are changed, which could indicate privilege escalation or malicious tampering. |
| 46| **Suspicious PowerShell Commands Detected** | Detects the execution of potentially malicious PowerShell commands or scripts, which are frequently used in advanced attacks. |
| 47| **USB Device Insertion** | Logs when a USB device is inserted, which can help detect data exfiltration or unauthorized devices. |
| 48| **Kerberos Ticket Requests** | Logs Kerberos ticket requests, useful for detecting pass-the-ticket attacks or abnormal authentication behavior. |
| 49| **Process Command-Line Logging** | Captures the command-line arguments of executed processes, providing insight into the actions being performed, useful for threat hunting. |
| 50| **Persistence Mechanism Detected** | Detects common persistence techniques, such as startup folder modification or registry autorun changes. |
| 51| **Remote Desktop Connection Detected** | Logs remote desktop connections, which can help detect unauthorized remote access to critical systems. |
| 225| **Process Terminated** | Tracks when processes are forcefully terminated, which can indicate malicious attempts to stop security services or evade detection. |


---

## Common Threat Hunting Techniques
### 1. **Detecting Malicious PowerShell Activity**
- Use **Event ID 4104** to capture PowerShell script execution.
- Pair it with **Event ID 4688** to see how PowerShell was launched (e.g., with encoded commands).

### 2. **Monitoring Privileged Account Access**
- Track **Event ID 4624** and **4625** for logon successes and failures.
- Use **Event ID 4672** to see when accounts with special privileges log on.

### 3. **Identifying Lateral Movement**
- Use **Event ID 4648** (Logon with explicit credentials) to detect lateral movement.
- Combine it with **Event ID 4776** to track NTLM authentication attempts.

### 4. **Tracking Process Injection**
- Use **Sysmon Event ID 8** (CreateRemoteThread) to detect when one process creates a thread in another, often indicative of process injection.
- Cross-check with **Sysmon Event ID 10** (Process Access) to see if a process is attempting to read or manipulate another process’s memory.
- Pair with **Event ID 4688** to track the parent-child relationship and determine if a suspicious process is trying to inject itself into a legitimate process.

### 5. **Detecting Persistence via Services**
- Use **Event ID 7045** to detect when a new service is installed on a machine, a common persistence technique used by attackers.
- Pair it with **Event ID 4697** to monitor for privileged service installation, which indicates a service was installed with elevated permissions.
- Monitor **Sysmon Event ID 1** (Process Creation) to track the process responsible for creating the service and see if it’s linked to suspicious activity.

### 6. **Monitoring File and Registry Changes**
- Use **Sysmon Event ID 11** (File Creation) to monitor for the creation of suspicious files, such as malware payloads, scripts, or tools.
- Pair with **Sysmon Event ID 12** (Registry Object Added/Deleted) and **Event ID 13** (Registry Value Set) to detect registry-based persistence techniques.
- Combine with **Event ID 4663** to monitor access to sensitive files or directories, useful for detecting data exfiltration or file tampering.

### 7. **Detecting Command-and-Control (C2) Activity**
- Use **Sysmon Event ID 22** (DNS Query) to track DNS queries made by processes. Look for unusual domain names or excessive queries that could indicate beaconing to a command-and-control server.
- Monitor **Sysmon Event ID 3** (Network Connection) for outbound connections to uncommon ports or foreign IP addresses, often indicative of C2 traffic.
- Pair with **Event ID 5140** (A Network Share Object Was Accessed) to detect lateral movement via network shares or file transfers over SMB, often used in conjunction with C2 activity.

### 8. **Identifying Suspicious Scheduled Tasks**
- Use **Event ID 4698** to monitor when new scheduled tasks are created, which attackers often use to maintain persistence.
- Pair with **Event ID 4699** to detect when a scheduled task is deleted, which could indicate cleanup efforts by an attacker.
- Use **Sysmon Event ID 1** to monitor the process that created the scheduled task and determine if it’s legitimate or malicious.

### 9. **Monitoring User Account Activity**
- Use **Event ID 4720** to monitor the creation of new user accounts, which attackers often create for persistence or lateral movement.
- Pair with **Event ID 4732** to detect when a user is added to a privileged group, indicating possible privilege escalation.
- Combine with **Event ID 4647** to detect when a user logs off, useful for tracking user session activity during an incident.

### 10. **Tracking Malicious Script Execution (Other than PowerShell)**
- Use **Sysmon Event ID 1** to detect the creation of processes like `wscript.exe`, `cscript.exe`, or `mshta.exe`, which are often used to execute malicious scripts (e.g., VBScript or JScript).
- Pair with **Sysmon Event ID 7** (Image Load) to detect suspicious DLLs loaded by these scripting engines.
- Monitor **Event ID 800** to detect script-based attacks, including VBScript and JScript execution.

### 11. **Detecting Process Hollowing and Injection**
- Use **Sysmon Event ID 10** (Process Access) to detect suspicious access to another process's memory, often used in process hollowing.
- Pair with **Sysmon Event ID 8** (CreateRemoteThread) to catch remote thread creation between processes, a common indicator of injection techniques.
- Combine with **Event ID 4688** to track the origin of injected processes and the parent-child relationship between them.

### 12. **Monitoring Suspicious WMI Activity**
- Use **Sysmon Event ID 19** (WMI Event Filter Activity) to detect the creation of suspicious WMI filters, often used in attacks for persistence or lateral movement.
- Pair with **Sysmon Event ID 20** (WMI Consumer Activity) to detect WMI consumers executing commands or scripts, which attackers may use to execute malicious code.
- Combine with **Sysmon Event ID 1** (Process Creation) to monitor the execution of suspicious processes triggered by WMI.

### 13. **Detecting Ransomware Activity**
- Use **Sysmon Event ID 11** (File Creation) to detect the creation of new, encrypted files during a ransomware attack.
- Pair with **Sysmon Event ID 23** (File Deletion) to track files being deleted as ransomware overwrites or destroys original files.
- Monitor **Event ID 4656** and **4663** to detect unauthorized access to sensitive files or directories, which are often targeted in ransomware attacks.

### 14. **Detecting Credential Dumping**
- Use **Sysmon Event ID 10** (Process Access) to detect processes attempting to read LSASS (Local Security Authority Subsystem Service) memory, which is commonly done by tools like Mimikatz for credential dumping.
- Pair with **Sysmon Event ID 1** (Process Creation) to track processes like `mimikatz.exe` or `procdump.exe` that are often used for credential harvesting.
- Combine with **Event ID 4672** (Special Privileges Assigned) to detect accounts with elevated privileges that might be used in the credential dumping process.

### 15. **Detecting Suspicious Network Scanning**
- Use **Sysmon Event ID 3** (Network Connection) to track processes making frequent connections to multiple hosts in a short period, indicative of network scanning or reconnaissance.
- Pair with **Event ID 5140** (A Network Share Object Was Accessed) to detect access to network shares, often used in conjunction with network scanning to identify sensitive resources.
- Combine with **Sysmon Event ID 22** (DNS Query) to detect abnormal domain lookups as part of a scanning or reconnaissance campaign.

### 16. **Monitoring DLL Injection and DLL Hijacking**
- Use **Sysmon Event ID 7** (Image Load) to monitor DLLs loaded by critical processes like `explorer.exe` or `svchost.exe`, helping you detect malicious DLL injection.
- Pair with **Sysmon Event ID 1** (Process Creation) to track the processes responsible for loading potentially malicious DLLs.
- Combine with **Sysmon Event ID 10** (Process Access) to monitor for suspicious memory access between processes, which can indicate DLL injection.

### 17. **Detecting Data Exfiltration**
- Use **Event ID 5140** (A Network Share Object Was Accessed) to track access to network shares, particularly when sensitive data is accessed and copied.
- Combine with **Sysmon Event ID 3** (Network Connection) to monitor large outbound data transfers to suspicious or foreign IP addresses, indicating potential data exfiltration.
- Use **Sysmon Event ID 22** (DNS Query) to detect unusual DNS queries, which may indicate domain name resolution for exfiltration via DNS tunneling.

### 18. **Detecting Malicious Use of Scheduled Tasks**
- Use **Event ID 4698** to detect the creation of new scheduled tasks, which are often used by attackers for persistence.
- Pair with **Event ID 4699** to detect the deletion of scheduled tasks, which can indicate that an attacker is trying to hide their tracks.
- Monitor **Sysmon Event ID 1** (Process Creation) to track processes initiated by scheduled tasks.

### 19. **Monitoring Application Whitelisting Bypass**
- Use **Sysmon Event ID 1** (Process Creation) to track processes running unusual or suspicious executables, which may indicate the use of **LOLBins** (Living off the Land Binaries) to bypass application whitelisting.
- Pair with **Sysmon Event ID 7** (Image Load) to monitor DLLs loaded by suspicious processes attempting to bypass security controls.
- Combine with **Sysmon Event ID 11** (File Creation) to detect new files that are created and executed to bypass whitelisting mechanisms.

### 20. **Tracking External Attack Vectors (e.g., Phishing)**
- Use **Sysmon Event ID 1** (Process Creation) to track processes spawned by email clients, especially those that open attachments or suspicious files.
- Pair with **Sysmon Event ID 3** (Network Connection) to monitor outbound connections made by processes launched from attachments or downloads.
- Use **Sysmon Event ID 22** (DNS Query) to detect unusual domain lookups from processes that may have originated from phishing emails.

### 21. **Detecting Brute Force Attacks**
- Use **Event ID 4625** to detect failed logon attempts, particularly when multiple failures occur in a short period, which is indicative of a brute-force attack.
- Combine with **Event ID 4771** (Kerberos Pre-Authentication Failed) to detect failed Kerberos authentication attempts, often used in brute-force attacks.
- Use **Sysmon Event ID 3** (Network Connection) to monitor multiple authentication attempts from the same IP address across various hosts.

### 22. **Tracking Software Exploitation and Post-Exploitation Frameworks**
- Use **Sysmon Event ID 1** (Process Creation) to detect known exploitation frameworks like **Metasploit**, **Cobalt Strike**, or **Empire** launching malicious payloads.
- Combine with **Sysmon Event ID 11** (File Creation) to track the creation of payloads or shellcode that are dropped onto the system.
- Monitor **Sysmon Event ID 3** (Network Connection) for outbound connections from these exploitation frameworks as they establish command-and-control channels.

---

## Useful Queries and Filters

### Using Kibana as a Basic Search Tool
Kibana is not just a tool for complex queries—it's a powerful search engine that can be used for basic searches to find paths, processes, or other key information quickly. You can input raw strings, event IDs, or even partial command lines to narrow down your search and manually hunt for malicious activity.

#### **Manual Search Tips**:
1. **Avoid Wildcards** (`*`): Instead of relying on wildcards (which can be unreliable or slow), try searching for **specific terms** or **partial matches** directly by refining your query.
2. **Look for Exact Paths**: If you’re hunting for suspicious file creation or execution, manually enter the **full or partial file path** (without wildcards) to locate exact matches.
3. **Command Line Searches**: When searching for specific command-line executions, focus on **exact keywords** (e.g., "powershell.exe", "mimikatz.exe") rather than using wildcards.
4. **Use Event IDs**: Event IDs are a straightforward and effective way to filter for specific system activities (e.g., logon events, process creation, network connections).

---

### Example Queries and Manual Search Techniques

### Kibana Query Example: Process Creation and PowerShell Activity
```kql
winlog.event_id: 4688 AND process_name: "powershell.exe" AND process.command_line: "encodedcommand"
```
### Kibana Query Example: Suspicious Network Connections
```
winlog.event_id: 3 AND destination_port: 443 AND NOT source_ip: "192.168.0.0/16"
```
### Kibana Query Example: Detecting Mimikatz Usage
```
winlog.event_id: 4688 AND process_name: "mimikatz.exe"
```
### Kibana Query Example: Scheduled Task Creation
```
winlog.event_id: 4698 AND task_name: "backup_task"
```
### Kibana Query Example: Registry Key Modification (Run Keys)
```
winlog.event_id: 13 AND registry_path: "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
```
### Kibana Query Example: Privilege Escalation via Service Installation
```
winlog.event_id: 7045 AND service_name: "MyService"
```
### Kibana Query Example: Lateral Movement Detection (Explicit Credential Logon)
```
winlog.event_id: 4648 AND target_user: "Administrator"
```
### Kibana Query Example: Process Injection Detection (Remote Thread Creation)
```
winlog.event_id: 8 AND process_name: "svchost.exe"
```
### Kibana Query Example: Detecting Brute Force Attempts
```
winlog.event_id: 4625 AND event.outcome: "failure" AND target_user: "admin"
```
### Kibana Query Example: Detecting DLL Injection (Suspicious DLL Load)
```
winlog.event_id: 7 AND image_path: "C:\\Windows\\System32\\malicious.dll"
```
### Kibana Query Example: Command-and-Control via DNS Queries
```
winlog.event_id: 22 AND dns_question_name: "maliciousdomain.com"
```
### Kibana Query Example: Tracking File Deletion (Covering Tracks)
```
winlog.event_id: 23 AND file_name: "C:\\Temp\\malicious_file.txt"
```
### Kibana Query Example: Detecting In-Memory Attacks
```
winlog.event_id: 10 AND process_name: "explorer.exe"
```
### Kibana Query Example: Detecting Pass-the-Hash Attacks
```
winlog.event_id: 4771 AND event.outcome: "failure"
```
### Kibana Query Example: System Shutdown or Reboot Monitoring
```
winlog.event_id: 1074 AND event.outcome: "success"
```

---


## Disclaimer and Future Updates

This repository is by no means an **exhaustive resource** for Windows and Sysmon Event Codes, queries, and threat hunting techniques. As I continue to explore new methods, tools, and strategies in the field of cybersecurity, I will be adding more **queries**, **filters**, and **techniques** to this repository.

The goal is to provide a **living resource** for anyone looking to improve their **threat hunting** and **incident response** skills. If you have suggestions, find useful queries, or think certain topics should be expanded, feel free to reach out or contribute. I encourage others in the cybersecurity community to share their knowledge as well.

Stay tuned for **future updates** as I keep learning and adapting to new threats and tools in the ever-evolving landscape of cybersecurity!

---
