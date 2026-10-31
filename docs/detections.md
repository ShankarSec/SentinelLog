# Detections

SentinelLog ships **27 detection rules** plus the **attack-chain correlation
engine**, which gives 28 alert types. Each row below is one alert type.

| Alert Type | Severity | MITRE ID | Description | Log Source |
|---|---|---|---|---|
| `AUTH_BRUTE_FORCE` | MEDIUM-CRITICAL* | T1110 | Repeated failed logins from one IP within 5 minutes (4+ failures) | SSH, Windows Security |
| `AUTH_FAILURES_THEN_SUCCESS` | MEDIUM-CRITICAL* | T1110 | Successful login after 4+ failures within 5 minutes | SSH, Windows Security |
| `MULTI_ACCOUNT_FAILURES` | MEDIUM | T1110 | Failures against 3+ usernames from one IP within 5 minutes | SSH |
| `ACCOUNT_CREATED` | MEDIUM | T1136.001 | New local account created | Linux useradd, Windows 4720 |
| `ACCOUNT_DELETED` | MEDIUM | T1531 | Account deleted | Linux userdel, Windows 4726 |
| `EVENT_LOG_CLEARED` | HIGH | T1070.001 | Windows Event ID 104 (log cleared) | Windows Event Log |
| `WHOAMI_EXECUTION` | LOW | T1033 | whoami.exe process creation (Event ID 4688) | Windows Security |
| `POWERSHELL_EXECUTION` | MEDIUM | T1059.001 | powershell.exe process creation (Event ID 4688) | Windows Security |
| `LARGE_DATA_EXFIL` | HIGH | T1567 | Outbound transfer larger than 25 MB | Network flow |
| `USB_INSERTION` | LOW | T1200 | USB storage device inserted | Windows device events |
| `HTTP_BRUTE_FORCE` | MEDIUM | T1110 | 4+ unique HTTP /login failures from one IP within 5 minutes | HTTP access log |
| `SYSMON_SUSPICIOUS_PROCESS` | HIGH | T1059 | Encoded PowerShell, Mimikatz or rundll32 abuse | Sysmon (Event ID 1) |
| `PORT_SCAN` | MEDIUM | T1046 | One IP touching 5+ unique ports | Firewall |
| `DNS_TUNNELING` | HIGH | T1071.004 | 5+ DNS queries with unusually long labels from one IP | DNS |
| `WEB_RECONNAISSANCE` | MEDIUM | T1595 | One IP probing 3+ admin/sensitive pages | HTTP access log |
| `DIRECTORY_TRAVERSAL` | HIGH | T1190 | ../../ traversal to sensitive files | Apache, Nginx, IIS |
| `SQL_INJECTION` | HIGH | T1190 | UNION SELECT in a request | Apache, Nginx, IIS |
| `COMMAND_INJECTION` | CRITICAL | T1190 | cmd= parameter in a request | Apache, Nginx, IIS |
| `WEBSHELL` | CRITICAL | T1505.003 | Successful (200) request to a shell-like path | IIS |
| `KERBEROASTING` | HIGH | T1558.003 | 5+ TGS requests (Event ID 4769) from one IP | Active Directory |
| `ASREP_ROASTING` | HIGH | T1558.004 | 4+ TGT requests with pre-auth disabled (0x40800000) | Active Directory |
| `AD_PRIVILEGE_ESCALATION` | CRITICAL | T1098.007 | Member added to a privileged group (Event ID 4732) | Active Directory |
| `S4U_ABUSE` | HIGH | T1558 | 4+ service-for-user requests (Event ID 4771) from one IP | Active Directory |
| `VPN_BRUTE_FORCE` | MEDIUM | T1110 | 5+ VPN auth failures from one IP within 5 minutes | OpenVPN, Cisco, Fortinet |
| `IMPOSSIBLE_TRAVEL` | HIGH | T1078 | Same user authenticating from two IPs within 30 minutes | OpenVPN, Cisco, Fortinet |
| `CLOUD_BRUTE_FORCE` | MEDIUM | T1110 | 4+ cloud console login failures from one IP within 5 minutes | AWS, Azure, GCP |
| `CLOUD_PERSISTENCE` | CRITICAL | T1098 | Backdoor user / admin role / access key creation | AWS, Azure, GCP |
| `ATTACK_CHAIN` | CRITICAL | T1595 | 3+ distinct alert types from one IP within the correlation window | Correlation engine |

\* Severity is calculated from the number of failed attempts
(`src/severity.py`): `AUTH_BRUTE_FORCE` is MEDIUM at 4, HIGH at 5+ and
CRITICAL at 10+; `AUTH_FAILURES_THEN_SUCCESS` is HIGH at 3-4 and CRITICAL
at 5+.

Thresholds and time windows are function arguments in `src/detector.py`
(for example `detect_kerberoasting(events, threshold=5)`).
