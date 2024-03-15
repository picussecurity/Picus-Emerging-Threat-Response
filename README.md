# Picus Emerging Threat Response
Emerging Threats are urgent cybersecurity issues that need to be addressed immediately. However, it is not always easy to find risk-free proof-of-concept exploits for the latest emerging threats. </br>

Picus Security created this repo for professionals looking to validate their security posture against the latest cyber threats with a few click. 

Validate security controls against the latest vulnerability exploits
--------------------------------------
Picus can help you validate security controls for the latest threats for free. No setup or signup required. </br>
Use [Picus Emerging Threat Simulator](https://insights.picussecurity.com/emerging-threat-simulator-announcement?utm_source=github&utm_medium=organic+social&utm_campaign=PLS+Offensive+-+ET+Simulator) and test your defenses in a few clicks.

If you are looking for full access to our threat library and actionable mitigations, get [your 14-day free trial](https://discover.picussecurity.com/start-your-free-trial?utm_source=github&utm_medium=organic+social&utm_campaign=PLS+Offensive+-+ET+Simulator) of Picus Platform. 

Proof-of-Concept Exploits in this repo
----------------------
#### [JetBrains TeamCity CVE-2024-27198 PoC Exploit](https://github.com/picussecurity/Picus-Emerging-Threat-Response/tree/main/JetBrains%20TeamCity%20CVE-2024-27198%20PoC%20Exploit)
CVE-2024-27198 vulnerability is caused by a CWE-288 weakness found in BaseController class of web-openapi.jar library. When an API endpoint receives a request appended with. jsp, the BaseController class allows the request to bypass authentication.
The example HTTP POST request below exploits CVE-2024-27198 vulnerability to add a new administrator user. Note the ";.jsp" located after the API endpoint.

#### [JetBrains TeamCity CVE-2024-27199 PoC Exploit](https://github.com/picussecurity/Picus-Emerging-Threat-Response/tree/main/JetBrains%20TeamCity%20CVE-2024-27199%20PoC%20Exploit)
CVE-2024-27199 vulnerability is caused by a CWE-23 weakness found in many API endpoints. Normally, these endpoints require authentication prior to disclosing requested information. However, the CVE-2024-27199 vulnerability allows adversaries to use double dot path segment "/../" to bypass and traverse alternative endpoint bypassing authentication. 

Disclaimer
----------
We do not have any disclamer.
