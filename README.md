# Picus Emerging Threat Response
Emerging Threats are urgent cybersecurity issues that need to be addressed immediately. However, it is not always easy to find risk-free proof-of-concept exploits for the latest emerging threats. </br>

Picus Security created this repo for professionals looking to validate their security posture against the latest cyber threats with a few clicks. 

Validate security controls against the latest vulnerability exploits
--------------------------------------
Picus can help you validate security controls for the latest threats for free. No setup or signup is required. </br>
Use [Picus Emerging Threat Simulator](https://www.picussecurity.com/emerging-threat-simulator?utm_source=github&utm_medium=organic+social&utm_campaign=PLS+Offensive+-+ET+Simulator) and test your defenses in a few clicks.

If you are looking for full access to our threat library and actionable mitigations, get [your 14-day free trial](https://discover.picussecurity.com/start-your-free-trial?utm_source=github&utm_medium=organic+social&utm_campaign=PLS+Offensive+-+ET+Simulator) of the Picus Platform. 

Proof-of-Concept Exploits in this repo
----------------------

#### [JetBrains TeamCity CVE-2023-42793 PoC Exploit](https://github.com/picussecurity/Picus-Emerging-Threat-Response/tree/main/JetBrains%20TeamCity%20CVE-2023-42793%20PoC%20Exploit)
CVE-2023-42793 vulnerability is an authentication bypass vulnerability. The vulnerability is found in the "RequestInterceptiors.java" file, and it is caused by the wildcard path "//RPC2" in the "myPreHandlingDisabled" PathSet. If any incoming HTTP request matches the wildcard path "//RPC2", the TeamCity server does not perform authentication checks. Adversaries abuse this vulnerability to obtain an access token by sending an HTTP POST request to "/app/rest/users/id:1/tokens/RPC2" endpoint.

#### [Palo Alto PAN-OS CVE-2024-3400 PoC Exploit](https://github.com/picussecurity/Picus-Emerging-Threat-Response/tree/main/Palo%20Alto%20PAN-OS%20CVE-2024-3400%20PoC%20Exploit)
CVE-2024-3400 is a command injection vulnerability found in the GlobalProtect feature of PAN-OS software. The telemetry functionality in the GlobalProtect uses the curl command to send logs from a temporary directory. Using malformed SESSID, adversaries were able to inject shell commands with root privileges via unauthenticated HTTP post requests.

Ransomware Threats in this repo
----------------------
#### [Akira Ransomware](https://github.com/picussecurity/Picus-Emerging-Threat-Response/tree/main/Akira%20Ransomware)
Akira ransomware started its operations in March 2023 and has been actively targeting various businesses and critical infrastructure organizations worldwide. Akira has different ransomware variants named Akira, Megazord, and Akira_v2, and these variants are capable of encrypting Windows, Linux, and VMware ESXi systems.

#### [Phobos Ransomware](https://github.com/picussecurity/Picus-Emerging-Threat-Response/tree/main/Phobos%20Ransomware)
Phobos ransomware started its operations as a variant of Crysis/Dharma ransomware in May 2019.  Phobos ransomware operates as the Ransomware-as-a-Service business model and has influenced many other ransomware variants such as Backmydata, Devos, Eking, Eight, 8Base, and Faust ransomware.

#### [Play Ransomware](https://github.com/picussecurity/Picus-Emerging-Threat-Response/tree/main/Play%20Ransomware)
Play ransomware, also known as PlayCrypt, was first observed in late June 2022, and the group has compromised nearly 300 organizations worldwide. Play ransomware operators exploit known vulnerabilities and follow recent ransomware trends like double extortion and inhibiting system recovery.

Disclaimer
----------
©2024 Picus Security <br>
All rights reserved.
