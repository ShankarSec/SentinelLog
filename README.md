# SentinelLog v2.0

**SOC Detection & Incident Analysis Platform**

SentinelLog analyzes security log files offline, raises MITRE ATT&CK-mapped
alerts, correlates them into attack chains, scores the overall risk and
writes incident reports. It is a learning/portfolio project: pure Python,
no database, no web framework, no cloud services.

## Features

- 20 log formats parsed (SSH, Windows Security, Sysmon, Firewall, DNS, Apache, Nginx, IIS, Active Directory, VPN, Cloud and more)
- 27 detection rules with MITRE ATT&CK mapping (28 alert types including `ATTACK_CHAIN`)
- Attack Chain Correlation Engine
- Threat Scoring (0-100 risk score)
- Extended IOC extraction (12 categories)
- 4 report formats: TXT, JSON, HTML Dashboard, PDF
- Deduplication
- Alert IDs (`ALERT-0001`, ...)
- Enterprise support: Kerberos (Kerberoasting, AS-REP Roasting, S4U), VPN (Brute Force, Impossible Travel), Cloud (AWS/Azure/GCP persistence)

## Quick Start

bash
pip install -r requirements.txt
python src/cli.py analyze-all sample_logs/


## Report Formats


reports/incident_report.txt    - Human-readable
reports/incident_report.json   - Machine-readable
reports/incident_report.html   - Interactive dashboard
reports/incident_report.pdf    - SOC export


## Usage

bash
python src/cli.py analyze-all sample_logs/ --output reports/ --window 10
python src/cli.py analyze single.log
python src/cli.py version
python src/cli.py rules


Options for `analyze` and `analyze-all`:

| Option | Default | Meaning |
|---|---|---|
| `--output DIR` | `reports` | Output directory for the four reports |
| `--window MIN` | `10` | Attack-chain correlation window in minutes |
| `--no-dedup` | off | Keep repeated `(source_ip, alert_type)` alerts |

## Detection Coverage

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

\* Severity depends on the number of failed attempts. See [docs/detections.md](docs/detections.md).

## MITRE ATT&CK Coverage

| Technique | Tactic | Alerts |
|---|---|---|
| T1033 System Owner/User Discovery | Discovery | 1 |
| T1046 Network Service Discovery | Discovery | 1 |
| T1059 Command and Scripting Interpreter | Execution | 1 |
| T1059.001 PowerShell | Execution | 1 |
| T1070.001 Clear Windows Event Logs | Defense Evasion | 1 |
| T1071.004 DNS | Command and Control | 1 |
| T1078 Valid Accounts | Initial Access | 1 |
| T1098 Account Manipulation | Persistence | 1 |
| T1098.007 Account Manipulation: Additional Local or Domain Groups | Persistence | 1 |
| T1110 Brute Force | Credential Access | 6 |
| T1136.001 Create Account: Local Account | Persistence | 1 |
| T1190 Exploit Public-Facing Application | Initial Access | 3 |
| T1200 Hardware Additions | Initial Access | 1 |
| T1505.003 Server Software Component: Web Shell | Persistence | 1 |
| T1531 Account Access Removal | Impact | 1 |
| T1558 Steal or Forge Kerberos Tickets | Credential Access | 1 |
| T1558.003 Steal or Forge Kerberos Tickets: Kerberoasting | Credential Access | 1 |
| T1558.004 Steal or Forge Kerberos Tickets: AS-REP Roasting | Credential Access | 1 |
| T1567 Exfiltration Over Web Service | Exfiltration | 1 |
| T1595 Active Scanning | Reconnaissance | 2 |

Full mapping: [docs/mitre_matrix.md](docs/mitre_matrix.md).

## Architecture

```
┌─────────────┐     ┌─────────┐     ┌────────────┐     ┌─────────────┐     ┌──────────┐
│  Log Files  │────▶│ Parser  │────▶│ Detectors  │────▶│ Correlation │────▶│ Reporter │
└─────────────┘     └─────────┘     └────────────┘     └─────────────┘     └──────────┘
                                                                  │
                                                                  ▼
                                                           ┌─────────────┐
                                                           │  Scoring    │
                                                           └─────────────┘
```

See [docs/architecture.md](docs/architecture.md) and
[docs/attack_chains.md](docs/attack_chains.md).

## Testing

bash
python -m pytest tests/ -v


## Project Structure

```
SentinelLog/
├── sample_logs/        # 21 sample log files (SSH, Windows, Sysmon, firewall, DNS,
│                       #   Apache, Nginx, IIS, Active Directory, VPN, cloud, ...)
├── reports/            # generated: incident_report.{txt,json,html,pdf}
├── screenshots/
├── tests/
│   ├── test_apache.py
│   ├── test_dns.py
│   ├── test_http_bruteforce.py
│   ├── test_portscan.py
│   ├── test_sysmon.py
│   ├── test_web_recon.py
│   ├── test_windows_security.py
│   ├── test_correlation.py
│   ├── test_ioc_expansion.py
│   ├── test_scoring.py
│   ├── test_dedup.py
│   ├── test_enterprise.py
│   └── test_end_to_end.py
├── rules/
│   ├── authentication.yaml
│   └── ssh.yaml
├── docs/
│   ├── architecture.md
│   ├── detections.md
│   ├── mitre_matrix.md
│   └── attack_chains.md
├── src/
│   ├── cli.py
│   ├── detector.py
│   ├── parser.py
│   ├── ioc.py
│   ├── mitre.py
│   ├── reporter.py
│   ├── scoring.py
│   ├── severity.py
│   ├── rule_loader.py
│   ├── __init__.py
│   └── test_*.py       # original v1.0 unit tests (run with PYTHONPATH=src)
├── requirements.txt
├── README.md
└── .gitignore
```
