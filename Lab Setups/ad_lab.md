---
author:
    name: nxb1t
    avatar: https://nxb1t.is-a.dev/assets/img/profile.jpeg
date: 2024-09-21
category:
    - Active Directory
    - Lab
    - Incident Response
tags: [Active Directory, Lab, Incident Response]
---

# Active Directory Lab

Hello everyone, welcome to my blog on setting up a simple AD lab for practicing Incident Response, Threat Hunting, and Digital Forensics. Once set up, the lab can be easily customized based on use cases, making it more flexible. In this blog, I am focusing only on a host-based incident response scenario, so the policies and integrations I am adding are tailored to that. To make the lab more realistic, the lab's theme is centered around a hypothetical tech company named **XOPS**.

---

## Setting up the Lab

We’re building the infrastructure for XOPS, which includes both Windows and Linux machines connected to the AD environment. The Linux systems are primarily used for automation and backup services. Certain users are restricted to logging in only on specific computers, and the Linux server has LDAP enabled for SSH authentication.

In this lab we are only using **Windows Defender** as endpoint security product and not relying on any EDR/XDR products. 

You can refer to [Active Directory Lab](https://github.com/AdiH8/Active-Directory-Lab) by AdiH8 for setting up the DC and configuring a basic AD Environment, this requires manual interactions, but if you prefer automated setup you can use [GOAD](https://github.com/Orange-Cyberdefense/GOAD) project.

This is how my setup looks like, I have 16 GB of ram in my system, so if yours is less you can reduce the number of client machines.

| Machine | RAM |
|---------|-------------|
|**Windows Server 2019** | 2GB |
|**CLIENT 1** | 2GB |
|**CLIENT 2** | 2GB |
|**Ubuntu Server** | 1GB |

![Lab Diagram](/assets/img/ad_ir/infra.png)

**Configuring Ubuntu Server to join AD Machine**

We need to configure ubuntu server to allow AD users ssh login via LDAP. Configuring it is relatively simple. Make sure to set DNS in `/etc/resolv.conf` to the IP of DC, in my case its `172.16.0.1`.

```bash

# Install necessary programs
sudo apt update
sudo apt install realmd sssd sssd-tools libnss-sss libpam-sss adcli

# check if domain is discoverable from the ubuntu, If its not detecting make sure dns is set correct
sudo realm discover xops.local

# join the domain
sudo realm join --user=DomainAdmin xops.local

# list joined domain
sudo realm list
```

![](/assets/img/ad_ir/ubuntuad.png)

After joining the domain, we have to configure few settings to make sure home directory are correctly generated for the domain users, also to make login easier by removing the need of entering domain name along with username (e.g `user` instead of `user@xops.local`).

Edit `/etc/sssd/sssd.conf` and make sure the following line are included, this will allow domain users to ssh login using only their username without the need of specifying domain name.

```bash
use_fully_qualified_names = False

```

Then run the following command to automatically create home directory for domain users.

```bash
sudo pam-auth-update --enable mkhomedir
```

Restart the sssd service to apply all changes .

```bash
sudo systemctl restart sssd
```

## Configuring Logging On Machines

In this section we will setup logging mechanisms for both Windows and Ubuntu Machines.

### Setting Up Auditing in Windows Machines

Active Directory provides auditing capabilities, with audit policies created and managed through Group Policy Objects (GPOs). These audit policies provide visibility into various security-related activities, such as account logon attempts, changes to user accounts, access to sensitive resources, and system-level events. 

New GPO can be created by right clicking on Domain in Group Policy Management application in DC Machine. 

![](/assets/img/ad_ir/group_policies.png)

Some of the important policies and their corresponding event ids we will focus on this blog are :

-> **Logon Auditing** <br>
Logon events help us identify any malicious or anomalous behaviors related to user logons.<br>

| Event ID | Description|
|---------|-------------|
|**4624** | An account successfully logged in | 
|**4964** | Special Group has been assigned to new logon |

-> **Kerberos Auditing** <br>
Kerberos events gives us better visibility into how tickets are used and helps detect malicious actions related to Kerberos. <br>

| Event ID | Description |
|---------|-------------|
|**4768** | A Kerberos authentication (TGT) was requested | 
|**4769** | A Kerberos service ticket was requested |

-> **Privilege Auditing** <br>
Sensitive privilege events helps us identify unusual usage of elevated permissions and privileged users. <br>

| Event ID | Description |
|---------|-------------|
|**4672** | Special privileges assigned to new logon | 
|**4673** | A privileged service was called |

These event logging can be enabled under <br> 
```
Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> Audit Policies
```

* **Logon Auditing** : Logon/Logoff -> Audit Logon , Audit Special Logon
* **Kerberos Auditing** : <br> 
Account Logon -> Audit Kerberos Authentication Service , Audit Kerberos Service Ticket Operations
* **Privilege Auditing** : Privilege Use -> Audit Sensitive Privilege Use

![](/assets/img/ad_ir/ad_policies.png)

--> **Powershell Logging** <br> 

Powershell logging is essential to identify malicious scripts run on endpoints, it can be enabled under :-

```
Computer Configuration -> Policies -> Administrative Templates -> Windows Components -> Windows Powershell
```

| Event ID | Description |
|---------|-------------|
|**4103** | Powershell Module Logging | 
|**4104** | Powershell Script Block Logging | 


![](/assets/img/ad_ir/powershell_logging.png)

--> **LDAP Query Monitoring** <br>

Monitoring LDAP queries offers an advantage in detecting potential Kerberoasting and AS-REP Roasting attempts, even if no vulnerable service accounts are present in the environment.

So, for detailed logging of ldap queries, we will enable ldap client verbose with 4 registry keys.

```
Computer Configuration -> Preferences -> Windows Settings -> Registry
```

| No | Action | Hive              | Key Path                                           | Value name           | Value type    | Value data | Base    |
|----|--------|-------------------|----------------------------------------------------|----------------------|---------------|------------|---------|
| 1  | Update | HKEY_LOCAL_MACHINE| SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics | 15 Field Engineering | REG_DWORD     |  5         | Decimal |
| 2  | Update | HKEY_LOCAL_MACHINE| SYSTEM\CurrentControlSet\Services\NTDS\Parameters  | Expensive Search Results Threshold  | REG_DWORD| 1| Decimal |
| 3  | Update | HKEY_LOCAL_MACHINE| SYSTEM\CurrentControlSet\Services\NTDS\Parameters  | Inefficient Search Results Threshold| REG_DWORD| 1| Decimal | 
| 4  | Update | HKEY_LOCAL_MACHINE| SYSTEM\CurrentControlSet\Services\NTDS\Parameters  | Search Time Threshold (msecs)       | REG_DWORD| 1| Decimal |

![](/assets/img/ad_ir/ldap_registry.png)

| Event ID | Description |
|----------| ------------|
| 1644     | This event logs an entry for each LDAP search made by a client against the directory that breaches the inexpensive and/or inefficient search thresholds.    |

### Installing Sysmon

Sysmon offers enhanced logging capabilities for process creation, network connections, and file access-related information. Deploying Sysmon in any Active Directory (AD) environment is highly recommended for improved security monitoring.

We can deploy Sysmon on all systems using GPO policy. Download the [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) executable and create a share in the DC for deployment. Sysmon's power relies on how we configure the tool, by default sysmon doesn't offer high level of logging, but with proper configuration we can improve it. I used [SwiftOnSecurity's](https://github.com/SwiftOnSecurity/sysmon-config) sysmon config as the base config as it covers starter rules, we can modify from there based on our needs.

![](/assets/img/ad_ir/sysmon_share.png)

We can use batch script to automate sysmon deployment, this will make things easier and we don't need to go to all machines and install from there manually.

```batch
:: - Reference : https://cybergladius.com/automated-sysmon-deployment/
@echo off

:: - Variables for script.
set str_sysmonShare=DC\Sysmon

:: - Check if running as an Admin
net.exe session 1>NUL 2>NUL || (Echo This script requires elevated rights. & Exit /b 1)

:: - Check is SysMon is running
sc query "Sysmon64" | Find "RUNNING"
If "%ERRORLEVEL%" EQU "1" (
goto StartSysmon
)

:: - Check if SysMon is installed, if not install it.
:StartSysmon
net start sysmon64
If "%ERRORLEVEL%" EQU "1" (
goto InstallSysmon
) else ( exit 0 )

:: - Install the SysMon agent from the Share.
:InstallSysmon
"\\%str_sysmonShare%\Sysmon64.exe" -i -accepteula
If "%ERRORLEVEL%" EQU "1" (
echo "An Error occured while loading the SysMon Config."
)

exit 0

```

Then we have to add Domain Computers group read access in share, which makes the share accessible for all computers.

![](/assets/img/ad_ir/sysmon_share2.png)

![](/assets/img/ad_ir/sysmon_share3.png)

Finally create the GPO and add the batch file in Startup scripts, apply `gpudate /force` on clients and reboot.

![](/assets/img/ad_ir/sysmon_gpo.png)

![](/assets/img/ad_ir/gpupdate.png)

Use `sc query sysmon64` to verify the Sysmon Service is running.

![](/assets/img/ad_ir/sysmon_deployed.png)

Some Important event ids generated by Sysmon are :- <br>

| Event ID | Description |
|---------|-------------|
|**1** | Process Created | 
|**3** | Network Connection |
|**7** | Image Loaded |
|**11** | File Create |

### Configuring Ubuntu Machine

For setting up logging in ubuntu we will use auditd. auditd is the Linux Audit daemon responsible for tracking and logging system activities. It provides detailed event records, including file access, user actions, and security policy changes, making it valuable for monitoring and incident response.

```bash
# install auditd
sudo apt install -y auditd
```

By default auditd only logs events like ssh login, use of sudo, pam. This is great but can be improved to get more telemetry from the systems. We can monitor specific files and folders for any modifications being occured there. Monitoring `/tmp/` folder is highly useful to trace if any data is being dumped there and so on.

We can monitor tmp folder by applying this auditd rule :

```bash
sudo echo "-w /tmp/ -p rwxa -k tmp_watch" > /etc/audit/rules.d/audit.rules
```

What it does is, monitor tmp folder for any read,write,execute,append actions performed. Then we have to restart auditd service to apply the rule.

```bash
sudo systemctl restart auditd
```

### Installing SIEM Agents on Machines

For SIEM, ELK stack is the best free option. Elastic even provides a 14 day free trial of their cloud version so we don't have to setup anything locally.

Once the free account is created, Install the elastic agent on the DC and clients, [refer here](https://www.elastic.co/guide/en/fleet/current/install-fleet-managed-elastic-agent.html) for a detailed guide on installing the agents. Agents can be also deployed using GPO, but here i installed them manually on clients and DC.

![](/assets/img/ad_ir/fleet.png)

Once the agents are installed, enable the `System` integration and `Windows` integration for the agents. These two integrations will forward events from **Application** , **Security** , **Sysmon** and **Powershell/Operational** event log channels.

![](/assets/img/ad_ir/c_agent_intg.png)

For DC, we need to create a separate agent policy and add one more additional integration named **Custom Windows Event Logs** to collect LDAP queries.

![](/assets/img/ad_ir/dc_agent_intg.png)

In the channel name enter : Directory Service.

![](/assets/img/ad_ir/custom_evnt.png)

And for linux machines, we need to use **auditd** integration.

![](/assets/img/ad_ir/ubuntuagent.png)

---

With this, our Lab is setup to log many of the events and we can conduct different types of attack simulations for learning Incident Response, Digital Forensics and Threat Hunting. You are free to add more integrations and logging mechaninsms to make this lab even better for your use-cases.

Check out an example Incident Response scenario based on this Lab :-

[!ref Practical Incident Response - Active Directory](https://nxb1t.is-a.dev/incident-response/practical_ir_ad/)

## References

* [GPO Monitor LDAP Queries](https://techexpert.tips/windows/gpo-monitor-ldap-queries-active-directory/)
* [Build it Before Breaking It](https://medium.com/bugbountywriteup/build-it-before-breaking-it-5d8c5b8171fc)