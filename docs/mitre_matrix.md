# MITRE ATT&CK Matrix

Every technique used by SentinelLog and the alert types that map to it.

| Technique ID | Name | Tactic | Alert Types That Trigger It |
|---|---|---|---|
| T1033 | System Owner/User Discovery | Discovery | `WHOAMI_EXECUTION` |
| T1046 | Network Service Discovery | Discovery | `PORT_SCAN` |
| T1059 | Command and Scripting Interpreter | Execution | `SYSMON_SUSPICIOUS_PROCESS` |
| T1059.001 | PowerShell | Execution | `POWERSHELL_EXECUTION` |
| T1070.001 | Clear Windows Event Logs | Defense Evasion | `EVENT_LOG_CLEARED` |
| T1071.004 | DNS | Command and Control | `DNS_TUNNELING` |
| T1078 | Valid Accounts | Initial Access | `IMPOSSIBLE_TRAVEL` |
| T1098 | Account Manipulation | Persistence | `CLOUD_PERSISTENCE` |
| T1098.007 | Account Manipulation: Additional Local or Domain Groups | Persistence | `AD_PRIVILEGE_ESCALATION` |
| T1110 | Brute Force | Credential Access | `AUTH_BRUTE_FORCE`, `AUTH_FAILURES_THEN_SUCCESS`, `MULTI_ACCOUNT_FAILURES`, `HTTP_BRUTE_FORCE`, `VPN_BRUTE_FORCE`, `CLOUD_BRUTE_FORCE` |
| T1136.001 | Create Account: Local Account | Persistence | `ACCOUNT_CREATED` |
| T1190 | Exploit Public-Facing Application | Initial Access | `DIRECTORY_TRAVERSAL`, `SQL_INJECTION`, `COMMAND_INJECTION` |
| T1200 | Hardware Additions | Initial Access | `USB_INSERTION` |
| T1505.003 | Server Software Component: Web Shell | Persistence | `WEBSHELL` |
| T1531 | Account Access Removal | Impact | `ACCOUNT_DELETED` |
| T1558 | Steal or Forge Kerberos Tickets | Credential Access | `S4U_ABUSE` |
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | Credential Access | `KERBEROASTING` |
| T1558.004 | Steal or Forge Kerberos Tickets: AS-REP Roasting | Credential Access | `ASREP_ROASTING` |
| T1567 | Exfiltration Over Web Service | Exfiltration | `LARGE_DATA_EXFIL` |
| T1595 | Active Scanning | Reconnaissance | `WEB_RECONNAISSANCE`, `ATTACK_CHAIN` |

`T1190` is shared by four web-attack alerts and `T1110` by five brute-force
style alerts, so the HTML dashboard groups alerts by technique and shows a
count per technique.
