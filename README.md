# CTF Writeups

A collection of penetration testing writeups from Hack The Box, TryHackMe, and picoCTF, documenting methodology, exploitation, and privilege escalation across a range of vulnerability classes.

Each writeup follows a consistent structure — enumeration, exploitation, privilege escalation, lessons learned — with an attack-flow diagram and a full breakdown of tools and reasoning. The goal is reproducibility: another reader should be able to follow the same path from initial recon to full compromise.


## Structure

Writeups are organized by platform, then by difficulty:
```
CTF-writeups/
├── HTB/
│   ├── Very Easy/
│   ├── Easy/
│   ├── Medium/
│   └── Hard/
├── THM/
│   ├── Easy/
│   └── Medium/
├── PicoCTF/
│   ├── Medium/
│   └── Hard/
└── README.md
```

Each writeup is a self-contained Markdown file named after the machine or room (e.g., HTB/Easy/connected.md).

## Writeup Format

Every report follows the same template:

- **Overview** — platform, difficulty, objective
- **Enumeration** — reconnaissance and service discovery
- **Exploitation** — vulnerability identification and exploit walkthrough
- **Privilege Escalation** — post-exploitation and root/admin path (marked N/A where not applicable)
- **Attack Flow** — Mermaid diagram of the full chain
- **Lessons Learned** — technical takeaways and real-world relevance
- **Tools Used**

Flags are intentionally omitted (`[USER_FLAG]` / `[ROOT_FLAG]` placeholders) — these writeups focus on methodology, not flag-hunting.

## Writeups

| Machine | Platform | Difficulty | Category | Date |
|--------|----------|------------|----------|------|
| Archetype | HackTheBox | Very Easy | MSSQL | May 2026 |
| Vaccine | HackTheBox | Very Easy | SQL Injection | May 2026 |
| Cap | HacktheBox | Easy | PCAP analysis | May 2026 |
| W1se Guy | TryHackMe | Easy | Cryptography | March 2026 |
| CyberHeroes | TryHackMe | Easy | Login Bypass | March 2026 |
| Brooklyn NineNine | TryHackMe | Easy | Steganography | April 2026 |
| Overpass | TryHackMe | Easy | ROT47 | April 2026 |
| Wonderland | TryHackMe | Medium | Multiple Privilege Escalation | April 2026 |
| Mr Robot | TryHackMe | Medium | Exposed WordPress Installation | April 2026 |
| Develpy | TryHackMe | Medium | Python exploitation | May 2026 |
| SSTI2 | PicoCTF | Medium | SSTI | July 2026 |
| ORDER ORDER | PicoCTF | Hard | Second-order SQLi | July 2026 |
| ...      | ...       | ...  | ...           | ...      |

## Tools

Nmap · RustScan · ffuf · Gobuster · sqlmap · Burp Suite · Netcat · Hydra · John the Ripper / ssh2john · fcrackzip · stegseek · CyberChef · Impacket · Evil-WinRM · LinPEAS / WinPEAS · GTFOBins

## Disclaimer

All writeups document activity performed against machines and challenges from authorized, legal platforms (Hack The Box, TryHackMe, picoCTF) for educational purposes only.
