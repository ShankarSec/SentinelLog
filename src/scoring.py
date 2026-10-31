"""Threat scoring engine for SentinelLog."""

WEIGHTS = {
    "AUTH_BRUTE_FORCE": 15,
    "AUTH_FAILURES_THEN_SUCCESS": 25,
    "MULTI_ACCOUNT_FAILURES": 15,
    "ACCOUNT_CREATED": 10,
    "ACCOUNT_DELETED": 10,
    "EVENT_LOG_CLEARED": 20,
    "WHOAMI_EXECUTION": 5,
    "POWERSHELL_EXECUTION": 10,
    "LARGE_DATA_EXFIL": 30,
    "USB_INSERTION": 5,
    "SYSMON_SUSPICIOUS_PROCESS": 25,
    "PORT_SCAN": 10,
    "DNS_TUNNELING": 25,
    "WEB_RECONNAISSANCE": 15,
    "DIRECTORY_TRAVERSAL": 20,
    "SQL_INJECTION": 30,
    "COMMAND_INJECTION": 40,
    "WEBSHELL": 50,
    "HTTP_BRUTE_FORCE": 15,
    "ATTACK_CHAIN": 100,
    "KERBEROASTING": 30,
    "ASREP_ROASTING": 30,
    "AD_PRIVILEGE_ESCALATION": 50,
    "S4U_ABUSE": 30,
    "VPN_BRUTE_FORCE": 15,
    "IMPOSSIBLE_TRAVEL": 30,
    "CLOUD_BRUTE_FORCE": 15,
    "CLOUD_PERSISTENCE": 50,
}


def calculate_risk_score(alerts):
    """
    Calculate the overall risk score (0-100).

    Sums the weight of every alert (unknown types weigh 0) and caps
    the total at 100, then classifies the result.
    """
    total = sum(WEIGHTS.get(a.get("alert_type", ""), 0) for a in alerts)
    score = min(total, 100)

    if score >= 80:
        classification = "CRITICAL"
    elif score >= 60:
        classification = "HIGH"
    elif score >= 30:
        classification = "MEDIUM"
    else:
        classification = "LOW"

    return {
        "risk_score": score,
        "max_score": 100,
        "classification": classification,
        "total_weight": total,
    }
