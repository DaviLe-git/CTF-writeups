# CTF Writeups

A collection of penetration testing writeups from Hack The Box, TryHackMe, and picoCTF, documenting methodology, exploitation, and privilege escalation across a range of vulnerability classes.

Each writeup follows a consistent structure — enumeration, exploitation, privilege escalation, lessons learned — with an attack-flow diagram and a full breakdown of tools and reasoning. The goal is reproducibility: another reader should be able to follow the same path from initial recon to full compromise.


Structure

Writeups are organized by platform, then by difficulty:

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

Each writeup is a self-contained Markdown file named after the machine or room (e.g., HTB/Easy/connected.md).


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
