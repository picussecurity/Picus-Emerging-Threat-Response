# Akira Ransomware
Akira ransomware started its operations in March 2023 and has been actively targeting various businesses and critical infrastructure organizations worldwide. Akira has different ransomware variants named Akira, Megazord, and Akira_v2, and these variants are capable of encrypting Windows, Linux, and VMware ESXi systems.<br><br>
In this repo, Picus provides TTPs and IOCs related to Akira ransomware.

Test security controls against Akira Ransomware 
--------------------------------------
Picus can help you simulate Akira ransomware attacks for free. No setup or signup is required.<br>
Use [Picus Emerging Threat Simulator](https://www.picussecurity.com/emerging-threat-simulator?utm_source=github&utm_medium=organic+social&utm_campaign=PLS+Offensive+-+ET+Simulator) and test your defenses in a few clicks.<br> 

If you are looking for more detailed information, check out our blog post on Akira:<br>
* [Akira Ransomware Analysis, Simulation and Mitigation- CISA Alert AA24-109A](https://www.picussecurity.com/resource/blog/akira-ransomware-analysis-simulation-and-mitigation-cisa-alert-aa24-109a)<br>

Akira - Metadata
----------------------
| | |
|:---|:---|
| **Associated Groups** | Aliases - Megazord<br>Affiliates - Conti, Ryuk |
| **Associated Country** | - |
| **First Seen** | March 2023 |
| **Target Sectors** | Construction, Education, Entertainment, Finance, Manufacturing, Media, Telecommunication |
| **Target Countries** | United States, Argentina, Australia, Bangladesh, Canada, Denmark, France, Germany, Italy, Nicaragua, Portugal, Saudi Arabia, South Africa, Spain, United Kingdom |

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
| Execution | PowerShell<br>WMI |
| Defense Evasion | KillAV<br>PowerTool |
| Credential Access | Mimikatz<br>LaZagne |
| Discovery | ADFind<br>Advanced IP Scanner<br>MASSCAN<br>PCHunter<br>Sharphound |
| Lateral Movement | RDP |
| Command and Control | AnyDesk<br>Cloudflare Tunnel<br>MobaXterm<br>ngrok<br>Radmin<br>RustDesk |
| Exfiltration | FileZilla<br>rclone<br>WinSCP |
| Impact | Akira ransomware<br>Akira_v2 ransomware<br>Megazord ransomware |

Disclaimer
----------
©2024 Picus Security <br>
All rights reserved. 