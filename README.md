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

#### [ConnectWise ScreenConnect CVE-2024-1709 PoC Exploit](https://github.com/picussecurity/Picus-Emerging-Threat-Response/tree/main/JetBrains%20TeamCity%20CVE-2024-27199%20PoC%20Exploit)
CVE-2024-1709 vulnerability is caused by inadequate path validation when ScreenConnect extracts files from ZIP archives, specifically in the context of handling ScreenConnect extensions. The original code (before the patch) did not strictly validate or sanitize the paths of extracted files, potentially allowing a malicious zip file to traverse directories (ZipSlip) and place files outside the intended target directory. 

#### [Atlassian Confluence CVE-2023-22527 PoC Exploit](https://github.com/picussecurity/Picus-Emerging-Threat-Response/tree/main/Atlassian%20Confluence%20CVE-2023-22527%20PoC%20Exploit)
Atlassian Confluence CVE-2023-22527 vulnerability is an OGNL injection vulnerability that allows unauthenticated adversaries to execute arbitrary commands remotely in a vulnerable Confluence instance. The vulnerability stems from a Velocity template file named "text-inline.vm". This file allows adversaries to execute commands by using the expression "#request['.KEY_velocity.struts2.context'].internalGet('ognl')".

#### [Ivanti CVE-2023-46805 PoC Exploit](https://github.com/picussecurity/Picus-Emerging-Threat-Response/tree/main/Ivanti%20CVE-2023-46805%20PoC%20Exploit)
Ivanti CVE-2023-46805 vulnerability is an authentication bypass vulnerability found in the web component of Ivanti Connect Secure and Policy Secure products. The vulnerability is caused by a path traversal vulnerability found in the "/api/v1/totp/user-backup-code" endpoint. Additionally, this endpoint does not require any authentication, allowing adversaries to access public-facing endpoints. Adversaries combine the lack of authentication and path traversal vulnerability to access resources located in the endpoint.
 
#### [Ivanti CVE-2024-21887 PoC Exploit](https://github.com/picussecurity/Picus-Emerging-Threat-Response/tree/main/Ivanti%20CVE-2024-21887%20PoC%20Exploit)
Ivanti CVE-2024-21887 vulnerability is a command injection vulnerability found in "/api/v1/license/key-status/path:node_name" API endpoint. Adversaries were able to access this endpoint using the CVE-20203-46805 vulnerability and append their payload to be executed by the vulnerable Ivanti product.

#### [JetBrains TeamCity CVE-2023-42793 PoC Exploit](https://github.com/picussecurity/Picus-Emerging-Threat-Response/tree/main/JetBrains%20TeamCity%20CVE-2023-42793%20PoC%20Exploit)
CVE-2023-42793 vulnerability is an authentication bypass vulnerability. The vulnerability is found in the "RequestInterceptiors.java" file, and it is caused by the wildcard path "//RPC2" in the "myPreHandlingDisabled" PathSet. If any incoming HTTP request matches the wildcard path "//RPC2", the TeamCity server does not perform authentication checks. Adversaries abuse this vulnerability to obtain an access token by sending an HTTP POST request to "/app/rest/users/id:1/tokens/RPC2" endpoint.

#### [Adobe ColdFusion CVE-2023-26360 PoC Exploit](https://github.com/picussecurity/Picus-Emerging-Threat-Response/tree/main/Adobe%20ColdFusion%20CVE-2023-26360%20PoC%20Exploit)
CVE-2023-26360 is an improper access control vulnerability caused by deserializing untrusted data without proper validation. When an attacker crafts a malicious HTTP request with "_cfclient=true" in the URL, the Adobe ColdFusion server invokes the "convertToTemplateProxy" function and deserializes the malicious JSON input provided by the attacker. Adversaries use this method for different purposes, such as arbitrary code execution, arbitrary file read, and remote code execution.

#### [Citrix Bleed CVE-2023-4966 PoC Exploit](https://github.com/picussecurity/Picus-Emerging-Threat-Response/tree/main/Citrix%20Bleed%20CVE-2023-4699%20PoC%20Exploit)
NetScaler ADC and Gateway products use the NetScaler Packet Processing Engine (nsppe) to handle TCP/IP connections and HTTP services. In vulnerable NetScaler ADC and Gateway products, the nsspe binary that implements the OpenID Connect Discovery endpoint is vulnerable to buffer overflow attacks. If adversaries send a maliciously crafted HTTP request to this endpoint with a too-long Host header, the vulnerable endpoint returns the leaked memory in the response. When too much memory is leaked, adversaries can read a valid session cookie of a legitimate user and bypass authentication.

#### [Sophos CVE-2023-1671 PoC Exploit](https://github.com/picussecurity/Picus-Emerging-Threat-Response/tree/main/Sophos%20CVE-2023-1671%20PoC%20Exploit)
Sophos CVE-2023-1671 vulnerability stems from a vulnerable component named warn-proceed handler. The weakness is classified as CWE-77 and allows adversaries to manipulate input for pre-authenticated command injection. User inputs sent through "/index.php?c=blocked" using an HTTP POST request are routed to UsrBlocked.php and processed by escapeshellarg function.

Disclaimer
----------
©2024 Picus Security <br>
All rights reserved.
