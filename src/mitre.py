MITRE_TECHNIQUES = {

    "SSH_BRUTE_FORCE": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access"
    },

    "AUTH_BRUTE_FORCE": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access"
    },

    "HTTP_BRUTE_FORCE": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access"
    },

    "AUTH_FAILURES_THEN_SUCCESS": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access"
    },

    "ACCOUNT_CREATED": {
        "id": "T1136.001",
        "name": "Create Account: Local Account",
        "tactic": "Persistence"
    },

    "ACCOUNT_DELETED": {
        "id": "T1531",
        "name": "Account Access Removal",
        "tactic": "Impact"
    },

    "EVENT_LOG_CLEARED": {
        "id": "T1070.001",
        "name": "Clear Windows Event Logs",
        "tactic": "Defense Evasion"
    },

    "WHOAMI_EXECUTION": {
        "id": "T1033",
        "name": "System Owner/User Discovery",
        "tactic": "Discovery"
    },

    "POWERSHELL_EXECUTION": {
        "id": "T1059.001",
        "name": "PowerShell",
        "tactic": "Execution"
    },

    "USB_INSERTION": {
        "id": "T1200",
        "name": "Hardware Additions",
        "tactic": "Initial Access"
    },

    "LARGE_DATA_EXFIL": {
        "id": "T1567",
        "name": "Exfiltration Over Web Service",
        "tactic": "Exfiltration"
    },

    "MULTI_ACCOUNT_FAILURES": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access"
    },

    "SYSMON_SUSPICIOUS_PROCESS": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution"
    },

    "DNS_TUNNELING": {
    "id": "T1071.004",
    "name": "DNS",
    "tactic": "Command and Control"
    },

    "WEB_RECONNAISSANCE": {
    "id": "T1595",
    "name": "Active Scanning",
    "tactic": "Reconnaissance"
    },

    "DIRECTORY_TRAVERSAL": {
    "id": "T1190",
    "name": "Exploit Public-Facing Application",
    "tactic": "Initial Access"
    },

    "SQL_INJECTION": {
    "id": "T1190",
    "name": "Exploit Public-Facing Application",
    "tactic": "Initial Access"
    },

    "COMMAND_INJECTION": {
    "id": "T1190",
    "name": "Exploit Public-Facing Application",
    "tactic": "Initial Access"
    },
    
    "PORT_SCAN": {
    "id": "T1046",
    "name": "Network Service Discovery",
    "tactic": "Discovery"
    },

    "WEBSHELL": {
    "id": "T1505.003",
    "name": "Server Software Component: Web Shell",
    "tactic": "Persistence"
    },

    "ATTACK_CHAIN": {
    "id": "T1595",
    "name": "Active Scanning",
    "tactic": "Reconnaissance"
    },

    "KERBEROASTING": {
    "id": "T1558.003",
    "name": "Steal or Forge Kerberos Tickets: Kerberoasting",
    "tactic": "Credential Access"
    },

    "ASREP_ROASTING": {
    "id": "T1558.004",
    "name": "Steal or Forge Kerberos Tickets: AS-REP Roasting",
    "tactic": "Credential Access"
    },

    "AD_PRIVILEGE_ESCALATION": {
    "id": "T1098.007",
    "name": "Account Manipulation: Additional Local or Domain Groups",
    "tactic": "Persistence"
    },

    "S4U_ABUSE": {
    "id": "T1558",
    "name": "Steal or Forge Kerberos Tickets",
    "tactic": "Credential Access"
    },

    "VPN_BRUTE_FORCE": {
    "id": "T1110",
    "name": "Brute Force",
    "tactic": "Credential Access"
    },

    "IMPOSSIBLE_TRAVEL": {
    "id": "T1078",
    "name": "Valid Accounts",
    "tactic": "Initial Access"
    },

    "CLOUD_BRUTE_FORCE": {
    "id": "T1110",
    "name": "Brute Force",
    "tactic": "Credential Access"
    },

    "CLOUD_PERSISTENCE": {
    "id": "T1098",
    "name": "Account Manipulation",
    "tactic": "Persistence"
    },
}


def get_mitre_mapping(alert_type):
    return MITRE_TECHNIQUES.get(
        alert_type,
        {
            "id": "UNKNOWN",
            "name": "Unknown Technique",
            "tactic": "Unknown"
        }
    )
