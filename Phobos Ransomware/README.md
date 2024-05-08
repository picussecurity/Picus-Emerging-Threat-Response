# Phobos Ransomware
Phobos ransomware started its operations as a variant of Crysis/Dharma ransomware in May 2019.  Phobos ransomware operates as the Ransomware-as-a-Service business model and has influenced many other ransomware variants such as Backmydata, Devos, Eking, Eight, 8Base, and Faust ransomware. <br><br>
In this repo, Picus provides TTPs and IOCs related to Phobos ransomware.

Test security controls against Phobos Ransomware 
--------------------------------------
Picus can help you simulate Phobos ransomware attacks for free. No setup or signup is required.<br>
Use [Picus Emerging Threat Simulator](https://www.picussecurity.com/emerging-threat-simulator?utm_source=github&utm_medium=organic+social&utm_campaign=PLS+Offensive+-+ET+Simulator) and test your defenses in a few clicks.<br> 

If you are looking for more detailed information, check out our blog post on Phobos:<br>
* [Phobos Ransomware Analysis, Simulation and Mitigation- CISA Alert AA24-060A](https://www.picussecurity.com/resource/blog/phobos-ransomware-analysis-simulation-and-mitigation-cisa-alert-aa24-060a)<br>

Phobos - Metadata
----------------------
| | |
|:---|:---|
| **Associated Groups** | Affiliates - Crysis, Dharma, Backmydata, Devos, Eking, Eight 8Base, Faust |
| **Associated Country** | - |
| **First Seen** | May 2019 |
| **Target Sectors** | Automotive, Construction, Finance, Healthcare, Hospitality, IT, Manufacturing, Real Estate |
| **Target Countries** | United States, Australia, Brazil, Canada, Romania, United Kingdom |

Phobos - Modus Operandi
----------------------
| | |
|:---|:---|
| **Business Models** | Ransomware-as-a-Service (RaaS)<br>Double Extortion |
| **Extortion Tactics** | File Encryption<br>Data Leakage |
| **Initial Access Methods** | Exploit Public-Facing Application<br>Valid Accounts<br>Phishing |
| **Impact Methods** | Data Encryption<br>Data Exfiltration |


Utilized Tools and Malware by Play
----------------------
| MITRE ATT&CK Tactic | Tools |
|:---|:---|
| Execution | PowerShell<br>WMI |
| Privilege Escalation | Smokeloader |
| Defense Evasion | PowerTool<br>Process Hacker<br>Universal Virus Sniffer<br>DefenderControl |
| Credential Access | Mimikatz<br>LaZagne |
| Discovery | Network Scanner<br>Bloodhound<br>Sharphound |
| Lateral Movement | PsExec<br>RDP |
| Command and Control | Smokeloader<br>AnyDesk<br>WinSCP |
| Exfiltration | WinRAR<br>WinSCP<br>WizTree64<br>MegaSync |
| Impact | Phobos ransomware<br>VSSAdmin |

Disclaimer
----------
©2024 Picus Security <br>
All rights reserved. 