---
author:
    name: nxb1t
    avatar: https://nxb1t.is-a.dev/assets/img/profile.jpeg
date: 2024-09-21
category:
    - Active Directory
    - Digital Forensics
    - Incident Response
    - Threat Hunting
tags: [Active Directory, Digital Forensics, Incident Response, Threat Hunting]
---

# Practical Incident Response - Active Directory

## Introduction

Hello everyone! It’s been a while since my last blog post.<br>
This time, I wanted to make a blog on simulating Incident Response in an Active Directory environment by doing some common attack scenarios, so we can get some basic level of practical experience around this area. While I am not an expert in Incident Response, I have some basic knowledge and also really passionate about this field. Here I won't be showing how I carried out the attack simulation, I will leave it for you guys to explore on your own :).

Before continuing, please checkout the following link to setup the AD Lab used in this blog, The lab's theme is centered around a hypothetical tech company named **XOPS** :

[!ref Active Directory Home Lab](https://nxb1t.is-a.dev/incident-response/ad_lab/)

**Ok, What is Incident Response ?** <br>
Incident response is a structured process organizations use to detect and respond to cyber threats, security breaches, and other unexpected events. The goal of incident response is to minimize damage, reduce recovery time and costs, and restore operations. There are various models for incident response lifecycle, such as PICERL, a six-step framework, and the more modern DAIR. In our blog, we will use the DAIR (Dynamic Approach to Incident Response) model, which is a five-step, continuous approach.

1. Preparation - Implementing security policies.
2. Detect - Continuously monitoring security events.
3. Verify and Triage - Quickly verifying security incidents and performing analysis.
4. Scope, Contain, Eradicate, Recover, Remediate - Identifying affected areas, containing threats, eradicating them, and conducting recovery.
5. Lessons Learned - Learning from incidents and using threat intelligence to improve security controls and prevent new threats.

You can learn more on DAIR from [here](https://medium.com/@cyberengage.org/rethinking-incident-response-from-picerl-to-dair-7b153a76e044).

The preparation phase of DAIR is done while we setup the AD Lab. The remaining phases are done when the incident happened.

There are multiple job roles for Incident Response :-

* A **Security Engineer** takes care of maintaining security infrastructure
* A **Security Analyst L1** monitors alerts and performs initial triage
* A **Security Analyst L2** analyzes incidents and conducts threat hunting
* A **Security Analyst L3** investigates complex incidents and leads response efforts

We are kind of doing the jobs of all roles in this blog :D.

---

## The Incident

XOPS, a leading player in the software market, recently fell victim to a ransomware attack. The company had only recently introduced a SOC team and had basic security configurations in place. Unfortunately, the attacker bypassed these tools and managed to compromise multiple systems. The initial entry point was a malicious software download by one of XOPS’ employees. The employee intended to download a portable version of Notepad++ from Google but was redirected to a malicious site due to search engine poisoning.

![](/assets/img/ad_ir/npp1.png)

The employee only realized the infection when they noticed a ransom note on their system.

![](/assets/img/ad_ir/note.png)

When he saw the ransom note, he quickly reported it to the relevant stakeholders. As a Security Analyst, we are assigned to evaluate, hunt and remediate the threat.

---

## The Response

Since there were no alerts raised by any of the security controls, we need to start from the beginning by examining the logs, analyzing the downloaded file and so on.

The tools we will use as part of threat hunting are :-

* Elastic SIEM
* FTK Imager
* Volatility
* Loki
* CAPA
* IDA
* x64dbg
* Fakenet-NG
* dnSpy

The employee informed us of the specific package they downloaded and executed, which pointed us towards Notepad++. Using this information, we began our hunt by focusing on activities associated with Notepad++.

### Log Analysis

Based on the initial information, we identified two key events related to the Notepad++ package in the event logs : the first one was a FileCreate event (**ID - 11**), indicating the package was saved on the system, and the second was a Process Creation event (**ID - 1**), showing that the application was executed.

We can see the file creation event have a `notepad++.lnk` shortcut file being saved, which is really unusual for a portable program.

![**Searching Notepad++**](/assets/img/ad_ir/initial_vector.png)

Focusing on the Process Creation event (**ID - 1**), we observed details such as the process name, arguments, and parent process information. The process name and parent process stood out in this context, indicating unusual activity. Specifically, the process name didn't align with typical Notepad++ behavior (npp.dll), and the parent process (cmd.exe) was not one usually associated with launching a legitimate application like Notepad++.

However the npp.dll is actually notepad++.exe and the attacker renamed it for crafting an attack path based on the shortcut file.

```js query
/**  pe.original_file_name is a metadata showing the original file name during compile time **/

host.name : "c1" and winlog.event_id: "1" and process.pe.original_file_name: "notepad++.exe"
```

![**Notepad++ Process Creation**](/assets/img/ad_ir/initial_vector_2.png)

By examining the cmd process, we noticed an interesting command line associated with it. The parent process was Powershell, and its command line revealed that it was fetching a file from an external website and executing it in hidden mode.

![**Parent Process Commandline**](/assets/img/ad_ir/initial_vector_3.png)

We can leverage the timeline feature in Kibana (**Security --> Timelines --> Create New Timeline**) to gain a broader understanding of the PowerShell process. By reviewing the timeline, we can piece together related events and activities surrounding the PowerShell execution, such as subsequent actions, and interactions with other processes or network connections.

![**Creating Timeline**](/assets/img/ad_ir/process_timeline.png)

Using the analyzer feature, we were able to view all the child process created by the Powershell process.

![**Using Process Analyzer**](/assets/img/ad_ir/process_timeline_2.png)

We noticed a process named `Registry.exe` spawning numerous child process. Additionally, the process name mimics the legitimate Windows process Registry. We obtained the process's SHA-256 hash: `ac18ceefb605f3b87c5becb64a2320bc1cfa2c97345cc1abd9efb62fee8ffc2c`, which will be useful for IOCs.

![**Loader Process Hash**](/assets/img/ad_ir/initial_hash.png)

We can see the commandline arguments of all child process spawned by the malicious Registry process, indicating that certain enumerations like ip lookup, user lookup and querying ssh information being conducted.

![**Process Commandline Arguements**](/assets/img/ad_ir/child_process.png)

While examining the network connections created by the malicious process, we noticed connections to the same IP address from which the executable was downloaded, but on an HTTPS port, indicating a potential C&C connection. Connections on port 8080 likely correspond to staged payloads. Additionally, we observed connections to LDAP initiated by the same process.


![**Network Connections Initiated by the Process**](/assets/img/ad_ir/networking_ips.png)

We will start by examining the LDAP queries. By focusing on the time range from the first LDAP request to the last made by the process, we can isolate several queries. Among these, the first and second queries stand out. Notably, the second query is associated with the Kerberoasting technique, which is used to retrieve all Service Principal Names (SPNs) and their associated accounts.

![**LDAP Queries**](/assets/img/ad_ir/ldap_search.png)

Looking for any service tickets Requested (**ID - 4769**) for any user in the same timeframe as the ldap queries, we can see one event stands out for username `bkp_op`. Kerberoasting tools like Rubeus by default request service tickets using RC4 (0x17) encryption, which is weak and easy to bruteforce. Moreover, the Ticket Options is also unique compared to legitimate ticket requests.

```js query
winlog.event_id:"4769" and winlog.event_data.TicketEncryptionType:"0x17" and winlog.event_data.TicketOptions: "0x40800000" or winlog.event_data.TicketOptions: "0x40810010"
```

![**Weak Kerberoast Service Ticket Request**](/assets/img/ad_ir/kerberoast.png)

Looking back to network connections, we can see a connection to ssh. Which indicates the attacker likely used pivoting to access the internal network of the compromised machine.

![](/assets/img/ad_ir/beacon_ssh.png)

We also recall the attacker querying PuTTY's `SshHostKeys`, which might have been an attempt to identify SSH sessions that could be used for lateral movement. Additionally, we observed a new login from the bkp_op user, indicating further escalation within the network.

![**SSH Logins**](/assets/img/ad_ir/ssh_login.png)

We had the /tmp/ folder under monitoring with auditd, so using that filter, we can see all programs executed from it. The attacker used evil-winrm from the /tmp/ folder, indicating an attempt to access other machines within the network.

![**Execution of Evil-WinRM**](/assets/img/ad_ir/ssh_evilwinrm.png)

Based on the timeline of the evil-winrm execution, we reviewed the logon events related to the bkp_op user to verify if any lateral movement from the compromised Ubuntu server had occurred.

![**Network Login Events related to bkp_op User**](/assets/img/ad_ir/winrm_logon.png)

To gain a better understanding, we correlated logon events with process creation on the C2 machine. This approach helped us map out the activities and interactions between logins and processes, providing clearer insights into any lateral movement or further exploitation that occurred.

```js query
sequence
[authentication where winlog.event_id == "4624" and winlog.event_data.TargetUserName == "bkp_op"]
[process where host.name == "c2" and winlog.event_id == "1" and user.name: "bkp_op"]
```

![**Correlating Logon Events with Process Creation**](/assets/img/ad_ir/correlation.png)

We observed the creation of the process `wsmprovhost.exe`, which indicates the establishment of a WinRM session on the host. The subsequent process chain reveals the dropping of another loader, suggesting that the attacker continued their activities by deploying additional malicious tools.

![**Checking Child Process of Second Loader using Analyzer**](/assets/img/ad_ir/correlation_process.png)

The attacker used the same loader but modified its name. The hash of both loaders are identical: `ac18ceefb605f3b87c5becb64a2320bc1cfa2c97345cc1abd9efb62fee8ffc2c`

![**Second loader hash**](/assets/img/ad_ir/c2_beacon_hash.png)

The `bkp_op` user is part of Backup Operators group which gives him SeBackupPrivilege, this privilege can bypass all ACLs and allow the user to read most of the System files. The attacker leveraged this privilege and dumped the SYSTEM and SAM registry hives.

![**Commandline Arguements of Child Process**](/assets/img/ad_ir/process_commandlines.png)

After that, we didn't see any telemetry from the C2 machine towards the Domain Controller or any other systems, suggesting that the attacker was unable to escalate further. We also checked the DC logs and didn't saw anything unusual.

Additionally, we didn't find any data related to the creation of the ransom note.

![**Missing Events related to Ransom Note**](/assets/img/ad_ir/missing_events.png)

### Memory Forensics

Through log analysis, we were able to understand the attacker's path, the TTPs they used, and the network-level IOCs. To identify the tools used and, in particular, to decrypt the ransomware-encrypted files, we need to analyze the memory of the loader process. After isolating the client machines we took memory dump, the ubuntu machine didn't had anything unusual running.

Using volatility3 we can look at the modules loaded by the loader process, in it the `clr.dll` really stands out. clr.dll only comes in context of a program either if its a .NET application or it explicitly loads clr.dll to interact with CLR runtime.

![**Loaded Modules**](/assets/img/ad_ir/mem_loadedmodules.png)

Based on the previous analysis we can assume its a C2 beacon as many C2 frameworks utilize CLR for inline-execution of .NET assemblies to avoid security controls. We can utilize the Volatility `windows.vadyarascan` module to scan memory regions to identify any known C2 framework shellcode. If no known signatures are found, additional analysis of the sample will be required. In our case, the yara rule for Havoc C2 got a match.

![**Havoc yara rule match**](/assets/img/ad_ir/mem_yara.png)

To get more detailed information about Havoc payload, like agent id and encryption keys, we can use a volatility [plugin](https://github.com/Immersive-Labs-Sec/HavocC2-Forensics/blob/main/Volatility/havoc.py) created by ImmersiveLabs. If we were caputing network packets we could utilise this information to decrypt them and get more insight on the C2 communictaions, anyway in our lab we were't capturing network packets.

![**Havoc agent details**](/assets/img/ad_ir/mem_havoc_meta.png)

Since its Havoc C2, it is high likely the attacker utilizing inline-execution function to execute .NET programs based on our previous finding about clr.dll. If that's the case, then those programs could stay in memory and we can extract them by dumping the loader's process memory.

![**Dump loader process memory**](/assets/img/ad_ir/mem_procdump.png)

Here we used the Foremost tool to extract the executable files.

![**Extracted executables from the process memory**](/assets/img/ad_ir/mem_foremost.png)

Scanning those files using loki showed the presence of SharpSploit related files.

![**Scanning for malicious files using Loki tool**](/assets/img/ad_ir/mem_lokiscan.png)

Some files weren't detected by loki indicating its not a known malicious file, we can analyse them further during the Malware Analysis time.

![**Suspicious .NET executable**](/assets/img/ad_ir/mem_susfile.png)

The memory dump from C2 Machine didn't had any new tactics or techniques and were almost similar.

### Host Analysis

While analyzing the logs, we didn't observe any persistence techniques used by the threat actor on any of the Windows machines. We also manually checked for backdoors in the autorun directory and other common locations, but found nothing. However, our Ubuntu machine had the least telemetry, so we need to check if any persistence mechanisms were added on that host.

From the logs, we verified that the attacker did not escalate to higher privileges, as the `bkp_op` user was not in the sudoers group. Upon examining the `.bashrc` file, we found an interesting entry pointing to another .bashrc file in the .local directory.

![](/assets/img/ad_ir/persis_bashrc.png)

Upon checking, it turned out to be a Bash reverse shell.

![](/assets/img/ad_ir/persis_bashrc2.png)

### Malware Analysis

We need to thoroughly analyze the loader and its associated files. From the YARA scan we previously conducted, we identified some of the executables, including SharpChrome and SharpUp, as well as another executable with no known signature. We will analyse the loader and the files extracted from memory which weren't detected based known signatures in a sandbox environment.

Starting with the loader, we can use `capa` tool to assess its capabilities. While we observed many features, not all of them may be true positives. But this gives us an high level overview of the loader's capabilities. Capa also showed that this loader is a rust compiled binary.

![**Checking loader Capabilities using CAPA**](/assets/img/ad_ir/rev_capa.png)

The RC4 match was PRGA.

![**RC4 Encryption Match**](/assets/img/ad_ir/rev_capa2.png)

We can use IDA for static analysis of the binary. In the main function we found a function related to VEH (Vectored Exception Handling), which can be employed to evade Endpoint Security Controls.

![**Loader Main Function in IDA**](/assets/img/ad_ir/rev_loader.png)

We discovered a function that loads amsi.dll and looks for function AmsiScanBuffer, further down it also had function looking for NtTraceControl. But there weren't any patching signs, so since its using VEH this has to be a patchless approach by setting up exception at function entry.

![**Function utilizing AMSI bypass**](/assets/img/ad_ir/rev_loader2.png)

NtGetThreadContext and NtSetThreadContext function calls were also seen, which are used to set hardware breakpoints.

![**Using NtGetThreadContext and NtSetThreadContext**](/assets/img/ad_ir/rev_loader5.png)

Going further, we encountered an interesting string. Its been processed inside a loop with range 256 which sort of correlates with CAPA result of RC4 encryption.

![**Interesting string found**](/assets/img/ad_ir/rev_loader3.png)

We created a dummy .NET program named reg and hosted it in our localhost using fakenet-ng. By redirecting traffic to localhost, we conducted dynamic analysis using x64dbg. We can see the hardware breakpoints being created at AmsiScanBuffer and NtTraceControl using NtSetThreadContext API, the address of the AmsiScanBuffer and NtTraceControl can be seen at Dr0 and Dr1 registers, this is done initially before loading the staged payload to evade security controls.

!!! Note
While i was using the exe version of fakenet-ng, I encountered an error (Error 87) which prevented the request redirecting to localhost.

![](/assets/img/ad_ir/fakenet-issue.png)

So I had to run fakenet-ng as a python module and implementing the fix as mentioned in the github issue [here](https://github.com/mandiant/flare-fakenet-ng/issues/173).

`python -m fakenet.fakenet`

![](/assets/img/ad_ir/fakenet-fix.png)
!!!

![**Hardware Breakpoints at AmsiScanBuffer and NtTraceControl**](/assets/img/ad_ir/rev_loader7.png)

After fetching the staged payload `reg`, the loader seems to do decryption using the `0xdeadbeef` string. Because we couldn't find any traces of our dummy program in-memory, which means the dummy program became gibberish due to the decryption operation.

![**Key for RC4 Decryption**](/assets/img/ad_ir/rev_loader4.png)

Once the payload is decrypted, the loader creates a new CLR instance effectively executing the .NET assembly in-memory.

![**CLR Mechanism in loader**](/assets/img/ad_ir/rev_loader6.png)

After analyzing the loader, we examined the suspicious binary extracted from memory, which turned out to be a .NET executable. By decompiling it with dnSpy, we confirmed that it was the ransomware responsible for encrypting files. The ransomware used RC4 encryption and the encryption key was visible in the binary. With this key, we were able to decrypt the encrypted files.

![**Decompiling the extracted binary from memory**](/assets/img/ad_ir/rev_susfiledecomp.png)

### Attack Overview

After conducting a thorough analysis of the endpoints, we were able to piece together the entire attack path and TTPs used. The attacker choose to deliver malware via malicious shortcut file, this is a widely used technique by Threat Actors, especially in malware campaigns like Qakbot.

!!! Note
Timeline is really important in Incident Response, since the blog have became queit long i have skipped that part, but you can check [here](https://www.cybertriage.com/glossary-term/timeline-analysis-for-incident-response/) to learn more on that topic.
!!!

![**Attack Path Diagram**](/assets/img/ad_ir/attack_path.png)

| Tactic              | Technique used                              | Technique ID         | Tools used                         |
| ------------------- | ------------------------------------------- | -------------------- | ---------------------------------- |
| Initial Access      | Drive-by Compromise (Malvertising)          | T1189                |        -                           |
| Execution           | Malicious File (Shortcut File) , Command and Scripting Interpreter (Powershell) | T1204.002, T1059.001 |    - |
| Defense Evasion     | Indicator Blocking (Etw and AMSI Patching)  | T1562.006            |        Rust Loader |
| Command and Control | Web Protocol  (Using HTTPS as C2 channel)   | T1071.001            |    Havoc C2 |
| Discovery           | Remote Discovery (Querying Domain Joined Computers) | T1018        |    ldapsearch |
| Credential Access   | Kerberoasting, Credential From Web Browsers | T1558.003, T1555.003 |    Rubeus, SharpChrome |
| Lateral Movement    | SSH, Windows Remote Management              | T1021.004, T1021.006 |    SSH, EvilWinRM |
| Persistence         | Unix Shell Modification                     | T1546.004            |    Bash Reverse Shell |
| Impact              | Data Encrypted For Impact                   | T1486                |    .NET based Ransomware |



### Detection Engineering

From this incident, we gained valuable insights, such as the need for a proper alerting mechanism, better password policies, and other improvements. In this section, we will focus on creating alert rules and policies to ensure timely detection and response to similar attacks in the future.

#### Detecting CLR Loader

While analyzing the loader's memory, we found an indicator that may suggest the execution of .NET assemblies in memory: the presence of CLR DLLs, the loader was written in rust so no way it loads clr.dll by default. So by tweaking our sysmon config we can add more visibility on module loading and detect if any malicious beacons are running in our system.

The given rule is a basic one that logs when `clr.dll` is loaded by any process, excluding those running from the Windows directory. As a result, even if a normal .NET application is run, it will be logged. This may lead to false positives, but with proper correlation, we can identify potential CLR loaders and inline execution of .NET assemblies.

```xml
<!--SYSMON EVENT ID 7 : DLL (IMAGE) LOADED BY PROCESS [ImageLoad]-->
<!--COMMENT:	Can cause high system load, disabled by default.-->
<!--COMMENT:	[ https://attack.mitre.org/wiki/Technique/T1073 ] [ https://attack.mitre.org/wiki/Technique/T1038 ] [ https://attack.mitre.org/wiki/Technique/T1034 ] -->

<!--DATA: UtcTime, ProcessGuid, ProcessId, Image, ImageLoaded, Hashes, Signed, Signature, SignatureStatus-->
<RuleGroup name="Detect CLR DLLs being loaded by process" groupRelation="or">
    <ImageLoad onmatch="include">
        <ImageLoaded condition="is">C:\Windows\Microsoft.NET\Framework\v4.0.30319\clr.dll</ImageLoaded>
	    <ImageLoaded condition="is">C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll</ImageLoaded>
    </ImageLoad>
</RuleGroup>
<RuleGroup name="" groupRelation="or">
    <ImageLoad onmatch="exclude">
        <Image condition="contains">C:\Windows\</Image>
    </ImageLoad>
</RuleGroup>
```

```
sysmon64 -c .\sysmonconfig-export.xml
```

![](/assets/img/ad_ir/detect_clr_pwsh.png)


After manually updating the Sysmon configuration on the client machines, I re-ran the loader, and we can now observe the loading of `clr.dll` by the Registry process.

![**Detecting CLR Dlls Loaded By the Loader**](/assets/img/ad_ir/detect_clr.png)

To quickly detect the loader if someone downloads it again, we need to create a YARA rule based on the indicators of compromise (IOCs) identified during malware analysis. These IOCs include unique strings, imported functions, and techniques such as setting hardware breakpoints at `AmsiScanBuffer` and `NtTraceControl`. Using this information, we can craft a YARA rule for this specific sample.

```yaml rust_veh_loader.yar
rule rust_veh_loader {
        meta:
                author = "nxb1t"
                description = "Detects rust based loaders utilizing VEH"
                os = "windows"
        strings:
                $a1 = { 0F 85 ?? 01 00 00 80 3D ?? 15 10 00 01 75 ?? 48 8B ?? ?? 15 10 00 }
                $a2 = "AddVectoredExceptionHandler"
                $a3 = "rustc"
                $a4 = "NtGetContextThread"
                $a5 = "NtSetContextThread"
                $a6 = "NtTraceControl"
                $a7 = "AmsiScanBuffer"
        condition:
                $a1 and $a2 and $a3 and 1 of ($a4,$a5,$a6,$a7)
}
```

![**Yara rule working as Intended**](/assets/img/ad_ir/detect_loki.png)

#### Detecting Kerberoasting

Kerberoasting is a very serious security issue we need to continuosly monitor. During log analysis, we detected kerberoasting attempts, based on the queries we can create an alert rule to quickly notify us in case of any potential Kerberoasting attempt.

We can create new alert rules in Elastic SIEM by going to **Security --> Rules --> Create new rule**.

![**Elastic SIEM Rules**](/assets/img/ad_ir/detect_kerb_alert.png)

Add the name of rule , description and severity. We can additionally add MITRE TTP and on what integrations this rule depends on , what are the false positive and so on.

![**Creating New Alert Rule**](/assets/img/ad_ir/detect_kerb_alert2.png)

This is the correlation rule we developed to detect Kerberoasting attacks in our lab's context. Whether through inline execution or network pivoting, when a beacon attempts Kerberoasting, it will establish a Kerberos connection on port 88. By correlating this with any weak TGT requests and considering ticket options used by tools like Rubeus and Impacket-GetUserSPNs, we can detect these attacks in a timely manner. However, if the attack originates from a compromised Linux system, we would need to create a separate rule that focuses solely on Service Ticket Requests without correlating to any specific process.

```js query
sequence by source.ip
      [network where winlog.event_id == "3"
       and destination.port == "88"
       and not process.executable == "C:\\Windows\\system32\\lsass.exe"]
      [authentication where winlog.event_id == "4769"
       and winlog.event_data.TicketEncryptionType == "0x17"
       and (winlog.event_data.TicketOptions == "0x40800000" or winlog.event_data.TicketOptions == "0x40810010")]
```

![**Adding Rule Query**](/assets/img/ad_ir/detect_kerb_alert1.png)

We can add connectors for instant notifications when the rule is triggered, in our case I selected none.

![**Adding Action Connectors**](/assets/img/ad_ir/detect_kerb_alert3.png)

Here I am repeating the kerberoasting attack by pivoting to internal network and using Impacket-GetUserSPNs.

![**Kerberoasting using Impacket**](/assets/img/ad_ir/detect_kerb_pivot.png)

As you can see, our rule successfully triggered when the attack was conducted.

![**Alert Triggered**](/assets/img/ad_ir/detect_kerb_alert4.png)

Investigating the alert on timeline give more details about the events took place.

![**Detailed View Of Alert**](/assets/img/ad_ir/detect_kerb_timeline.png)

!!! Note
What if the attacker only searched for SPN accounts without proceeding with Kerberoasting?<br>
This is where LDAP query monitoring becomes useful. By creating an alert for potentially malicious LDAP queries based on event log `1644`, we can detect the presence of malicious actors early on. Additionally, incorporating deception techniques, such as a decoy user with an attached SPN, can help detect potential Kerberoasting attempts while minimizing false positives.
!!!

#### Detecting Browser Credential Stealing

Credential theft is a serious issue that we must actively defend against. If compromised credentials belong to high-privileged users in cloud or other infrastructures, it significantly increases the attack surface and potential damage to our organization. During our Memory Forensics Analysis, one of the executables we extracted from the process memory was SharpChrome, which abuses the DPAPI (Windows Data Protection API) to list all saved passwords in Chromium-based browsers.

**Netero1010** has beautifully explained detection strategies in his [blog](https://www.netero1010-securitylab.com/detection/browser-credential-stealing-detection), He utilizes File Object Access auditing for detecting these type of attacks.

One detection blindspot he mentioned was utilizing process injection. In that case, the credential-stealing activity would appear to originate from the legitimate browser process.

So, Let's simulate the blindspot scenario of injecting shellcode into chrome process and running SharpChrome from there.

![**Remote Process Injection**](/assets/img/ad_ir/detect_shellinj.png)

Shellcode successfully injected into chrome process (PID - **5764**) and we ran the SharpChrome with the dotnet inline-execute method.

![**Executing SharpChrome from the Injected Process**](/assets/img/ad_ir/detect_chrome.png)

When we check the Chrome processes in Process Hacker, we can see that one Chrome process (PID - **5764**) is highlighted in green, indicating that it has .NET assemblies loaded.

![**Chrome Process List**](/assets/img/ad_ir/detect_chrome_proc.png)

When we check event ID **4663**, we can see that the injected Chrome process has accessed the `Login Data` and `Local State` files, which at first glance may appear to be legitimate activity.

In the generated event, process id is shown in hex format, thats why I entered `0x1684` in query which equals to `5764`.

![**File Object Access Event**](/assets/img/ad_ir/detect_chrome_ls.png)

As a detection strategy for this blindspot, we can correlate the file object access event with the Sysmon rule we created earlier.

```js query
sequence
[process where winlog.event_id == "7" and rule.name == "Detect CLR DLLs being loaded by process"]
[any where winlog.event_id == "4663" and winlog.event_data.SubjectUserName == "adam"]
```

![**Correlation of Events**](/assets/img/ad_ir/detect_chrome_byp.png)

#### Detecting Evil WinRM

For detecting the use of Evil-WinRM we can either utilize the strategies like correlating the process creation and login event

```js query
sequence
[authentication where winlog.event_id == "4624" and winlog.event_data.TargetUserName == "bkp_op"]
[process where host.name == "c2" and winlog.event_id == "1" and user.name: "bkp_op"]
```

or I found a nice [blog](https://medium.com/@cY83rR0H1t/evil-winrm-detection-de2874af7eb0) by cY83rR0H1t with even better approach using event ids `4103` and `800`.


#### Detecting Linux Persistence Mechanisms

Checkout Elastic Security's [Primer on Persistence Mechanisms](https://www.elastic.co/security-labs/primer-on-persistence-mechanisms) for a detailed walkthrough on detecting persistence mechanisms and linux detection engineering.

---

## Conclusion

Through this blog i hope you guys got a basic understanding of practical steps in Incident Response. In an enterprise scenario the logs would be huge and without proper threat hunting and detection engineering skillset it would be hard to find the threats and contain them on time with minimal impact.

## References

* [Intrinsec - Kerberos OPSEC](https://www.intrinsec.com/kerberos_opsec_part_1_kerberoasting/)
* [No Hassle Guide to EQL for Threat Hunting](https://www.varonis.com/blog/guide-no-hassle-eql-threat-hunting)
* [ImmersiveLabs - Havoc C2 Defensive Operators Guide](https://www.immersivelabs.com/blog/havoc-c2-framework-a-defensive-operators-guide/)
* [MDSec - Detecting and Advancing In-Memory .NET Tradecraft](https://www.mdsec.co.uk/2020/06/detecting-and-advancing-in-memory-net-tradecraft/)
* [Dr Josh Stroschein - The Cyber Yeti](https://www.youtube.com/@jstrosch)
* [Cyber Attack & Defense](https://www.youtube.com/@CyberAttackDefense)
* [Attack Detect Defend](https://www.youtube.com/@rot169/videos)
