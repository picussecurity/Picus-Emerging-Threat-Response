# Play Ransomware
Play ransomware, also known as PlayCrypt, was first observed in late June 2022, and the group has compromised nearly 300 organizations worldwide. Play ransomware operators exploit known vulnerabilities and follow recent ransomware trends like double extortion and inhibiting system recovery. <br><br>
In this repo, Picus provides TTPs and IOCs related to Play ransomware.

Test security controls against Play Ransomware 
--------------------------------------
Picus can help you simulate Play ransomware attacks for free. No setup or signup is required.<br>
Use [Picus Emerging Threat Simulator](https://www.picussecurity.com/emerging-threat-simulator?utm_source=github&utm_medium=organic+social&utm_campaign=PLS+Offensive+-+ET+Simulator) and test your defenses in a few clicks.<br> 

If you are looking for more detailed information, check out our blog post on Play:<br>
* [Play Ransomware Analysis, Simulation and Mitigation- CISA Alert AA23-352A](https://www.picussecurity.com/resource/blog/play-ransomware-analysis-simulation-and-mitigation-cisa-alert-aa23-352a)<br>

Play - Metadata
----------------------
| | |
|:---|:---|
| **Associated Groups** | Aliases - PlayCrypt<br>Affiliates - Hive, Nokoyawa, Quantum, Conti |
| **Associated Country** | - |
| **First Seen** | June 2022 |
| **Target Sectors** | Construction, Education, Government, Finance, Healthcare, Insurance, Media, Technology, Telecommunication |
| **Target Countries** | United States, Australia, Austria, Denmark, Germany, Israel, Portugal, Sweden, South Korea, Taiwan, United Kingdom |

Play - Modus Operandi
----------------------
| | |
|:---|:---|
| **Business Models** | Double Extortion<br>Initial Access Brokers (IABs) |
| **Extortion Tactics** | File Encryption<br>Data Leakage |
| **Initial Access Methods** | Exploit Public-Facing Application<br>Valid Accounts<br>Phishing |
| **Impact Methods** | Data Encryption<br>Data Exfiltration |


Utilized Tools and Malware by Play
----------------------
| MITRE ATT&CK Tactic | Tools |
|:---|:---|
| Execution | PowerShell |
| Privilege Escalation | WinPEAS |
| Defense Evasion | GMER<br>IOBit<br>Process Hacker<br>PowerTool |
| Credential Access | Mimikatz |
| Discovery | ADfind.exe<br>Nltest<br>Netscan<br>Bloodhound<br>Grixba |
| Lateral Movement | PsExec<br>SystemBC<br>Mimikatz<br>Empire |
| Command and Control | Cobalt Strike<br>Empire<br>PsExec |
| Exfiltration | WinRAR<br>WinSCP |
| Impact | Play ransomware<br>AlphaVSS |

Disclaimer
----------
©2024 Picus Security <br>
All rights reserved. 
