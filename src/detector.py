import re
from collections import defaultdict
from datetime import datetime, timedelta

try:
    from .severity import calculate_severity
    from .mitre import get_mitre_mapping
except ImportError:
    from severity import calculate_severity
    from mitre import get_mitre_mapping


def detect_ssh_bruteforce(events, threshold=4, window_minutes=5):
    failed_attempts = defaultdict(list)

    # Collect failed SSH attempts by source IP
    for event in events:
        if (
            event["event_type"] == "authentication_failure"
            and event["source_ip"]
            and event["timestamp"]
        ):
            failed_attempts[event["source_ip"]].append(event)

    alerts = []

    time_window = timedelta(minutes=window_minutes)

    # Analyze each source IP
    for ip, attempts in failed_attempts.items():

        # Sort events by timestamp
        attempts.sort(key=lambda event: event["timestamp"])

        for i in range(len(attempts)):

            window_start = attempts[i]["timestamp"]
            window_end = window_start + time_window

            window_events = [
                event
                for event in attempts[i:]
                if event["timestamp"] <= window_end
            ]

            if len(window_events) >= threshold:

                alerts.append({
                    "alert_type": "AUTH_BRUTE_FORCE",
                    "severity": calculate_severity(
                       "SSH_BRUTE_FORCE",
                       len(window_events)
                     ),
                    "source_ip": ip,
                    "timestamp": window_events[0]["timestamp"].isoformat(),
                    "failed_attempts": len(window_events),
                    "window_minutes": window_minutes,
                    "first_seen": window_events[0]["timestamp"].isoformat(),
                    "last_seen": window_events[-1]["timestamp"].isoformat(),
                    "mitre_attack": get_mitre_mapping("SSH_BRUTE_FORCE"),
                    "description": (
                        f"Possible authentication brute-force activity detected from "
                        f"{ip}: {len(window_events)} failed attempts "
                        f"within {window_minutes} minutes"
                    )
                })

                break

    return alerts
def detect_failure_then_success(events, threshold=4, window_minutes=5):
    suspicious = {}

    # Group SSH events by source IP
    events_by_ip = defaultdict(list)

    for event in events:
        if (
            event["source_ip"]
            and event["timestamp"]
        ):
            events_by_ip[event["source_ip"]].append(event)

    time_window = timedelta(minutes=window_minutes)

    for ip, ip_events in events_by_ip.items():
        ip_events.sort(key=lambda event: event["timestamp"])

        for i, event in enumerate(ip_events):
            if event["event_type"] != "authentication_success":
                continue

            success_time = event["timestamp"]

            # Find failures before this successful login
            previous_events = [
                previous
                for previous in ip_events[:i]
                if (
                    previous["event_type"] == "authentication_failure"
                    and previous["timestamp"] >= success_time - time_window
                )
            ]

            if len(previous_events) >= threshold:
                suspicious[ip] = {
                    "alert_type": "AUTH_FAILURES_THEN_SUCCESS",
                    "severity": calculate_severity(
                       "AUTH_FAILURES_THEN_SUCCESS",
                        len(previous_events)
                     ),
                    "source_ip": ip,
                    "timestamp": previous_events[0]["timestamp"].isoformat(),
                    "failed_attempts": len(previous_events),
                    "successful_username": event["username"],
                    "window_minutes": window_minutes,
                    "first_failure": previous_events[0]["timestamp"].isoformat(),
                    "success_time": success_time.isoformat(),
                    "mitre_attack": get_mitre_mapping(
                      "AUTH_FAILURES_THEN_SUCCESS"
                       ),
                    "description": (
                    f"Successful authentication from {ip} occurred after "
                    f"{len(previous_events)} failed attempts "
                    f"within {window_minutes} minutes"
                  )
                }
                break

    return list(suspicious.values())
def detect_account_creation(events):
    """
    Detect Linux account creation events.
    """

    alerts = []

    for event in events:
        if event.get("event_type") == "account_created":
            alerts.append({
                "alert_type": "ACCOUNT_CREATED",
                "severity": "MEDIUM",
                "username": event.get("username"),
                "timestamp": (
                    event["timestamp"].isoformat()
                    if event.get("timestamp")
                    else None
                ),
                "description": (
                    f"Account creation detected for user {event.get('username')}"
                ),
                "mitre_attack": {
                    "id": "T1136.001",
                    "name": "Create Account: Local Account",
                    "tactic": "Persistence"
                }
            })

    return alerts
def detect_account_deletion(events):
    """
    Detect Linux account deletion events.
    """

    alerts = []

    for event in events:
        if event.get("event_type") == "account_deleted":
            alerts.append({
                "alert_type": "ACCOUNT_DELETED",
                "severity": "MEDIUM",
                "username": event.get("username"),
                "timestamp": (
                    event["timestamp"].isoformat()
                    if event.get("timestamp")
                    else None
                ),
                "description": (
                    f"Account deletion detected for user {event.get('username')}"
                ),
                "mitre_attack": {
                    "id": "T1531",
                    "name": "Account Access Removal",
                    "tactic": "Impact"
                }
            })

    return alerts
def detect_multi_account_failures(events, threshold=3, window_minutes=5):
    """
    Detect SSH authentication failures against multiple usernames
    from the same source IP within a time window.
    """

    from collections import defaultdict
    from datetime import timedelta

    failures_by_ip = defaultdict(list)
    alerts = []

    for event in events:
        if (
            event.get("event_type") == "authentication_failure"
            and event.get("source_ip")
            and event.get("username")
            and event.get("timestamp")
        ):
            failures_by_ip[event["source_ip"]].append(event)

    for source_ip, failures in failures_by_ip.items():
        failures.sort(key=lambda event: event["timestamp"])

        for start_index, first_event in enumerate(failures):
            window_end = (
                first_event["timestamp"]
                + timedelta(minutes=window_minutes)
            )

            window_events = [
                event
                for event in failures[start_index:]
                if event["timestamp"] <= window_end
            ]

            usernames = sorted({
                event["username"]
                for event in window_events
            })

            if len(usernames) >= threshold:
                alerts.append({
                    "alert_type": "MULTI_ACCOUNT_FAILURES",
                    "severity": "MEDIUM",
                    "source_ip": source_ip,
                    "timestamp": window_events[0]["timestamp"].isoformat(),
                    "usernames": usernames,
                    "failed_attempts": len(window_events),
                    "window_minutes": window_minutes,
                    "mitre_attack": {
                        "id": "T1110",
                        "name": "Brute Force",
                        "tactic": "Credential Access"
                    },
                    "description": (
                        f"SSH authentication failures against "
                        f"{len(usernames)} usernames from {source_ip} "
                        f"within {window_minutes} minutes"
                    )
                })

                break

    return alerts

def detect_event_log_cleared(events):
    """
    Detect Windows Event Log clearing events.
    Event ID 104 indicates an event log was cleared.
    """
    alerts = []

    for event in events:
        if (
            event.get("event_type") == "event_log_cleared"
            and event.get("event_id") == 104
        ):
            alerts.append({
                "alert_type": "EVENT_LOG_CLEARED",
                "severity": "HIGH",
                "timestamp": (
                    event["timestamp"].isoformat()
                    if event.get("timestamp")
                    else None
                ),
                "description": (
                    "Windows event log clearing detected "
                    "(Event ID 104)"
                ),
                "mitre_attack": {
                    "id": "T1070.001",
                    "name": "Clear Windows Event Logs",
                    "tactic": "Defense Evasion"
                }
            })

    return alerts

def detect_whoami_execution(events):
    """
    Detect Windows whoami.exe process execution.
    """
    alerts = []

    for event in events:
        if (
            event.get("event_type") == "whoami_execution"
            and event.get("event_id") == 4688
            and event.get("process_name", "").lower() == "whoami.exe"
        ):
            alerts.append({
                "alert_type": "WHOAMI_EXECUTION",
                "severity": "LOW",
                "timestamp": (
                    event["timestamp"].isoformat()
                    if event.get("timestamp")
                    else None
                ),
                "description": (
                    "Execution of whoami.exe detected "
                    "(Windows Event ID 4688)"
                ),
                "mitre_attack": {
                    "id": "T1033",
                    "name": "System Owner/User Discovery",
                    "tactic": "Discovery"
                }
            })

    return alerts

def detect_powershell_execution(events):
    """
    Detect Windows PowerShell process execution.
    Event ID 4688 records process creation.
    """
    alerts = []

    for event in events:
        if (
            event.get("event_type") == "powershell_execution"
            and event.get("event_id") == 4688
            and event.get("process_name", "").lower()
            == "powershell.exe"
        ):
            alerts.append({
                "alert_type": "POWERSHELL_EXECUTION",
                "severity": "MEDIUM",
                "timestamp": (
                    event["timestamp"].isoformat()
                    if event.get("timestamp")
                    else None
                ),
                "description": (
                    "PowerShell process execution detected "
                    "(Windows Event ID 4688)"
                ),
                "mitre_attack": {
                    "id": "T1059.001",
                    "name": "PowerShell",
                    "tactic": "Execution"
                }
            })

    return alerts

def detect_large_data_exfiltration(events):
    alerts = []

    threshold = 25 * 1024 * 1024  # 25 MB

    for event in events:

        if event.get("event_type") != "large_data_transfer":
            continue

        bytes_sent = event.get("bytes_sent", 0)

        if bytes_sent > threshold:

            alerts.append({
                "alert_type": "LARGE_DATA_EXFIL",
                "severity": "HIGH",
                "source_ip": event.get("source_ip"),
                "destination_ip": event.get("destination_ip"),
                "timestamp": (
                    event["timestamp"].isoformat()
                    if event.get("timestamp")
                    else None
                ),
                "bytes_sent": bytes_sent,
                "description": (
                    f"Outbound transfer exceeded 25 MB threshold "
                    f"({bytes_sent} bytes)"
                ),
                "mitre_attack": {
                    "id": "T1567",
                    "name": "Exfiltration Over Web Service",
                    "tactic": "Exfiltration"
                }
            })

    return alerts

def detect_usb_insertion(events):
    """
    Detect USB insertion events in parsed log records.
    """

    alerts = []

    for event in events:
        if event.get("event_type") == "usb_insertion":

            device_name = event.get(
                "device_name",
                "Unknown USB device"
            )

            alerts.append({
                "alert_type": "USB_INSERTION",
                "severity": "LOW",
                "timestamp": (
                    event["timestamp"].isoformat()
                    if event.get("timestamp")
                    else None
                ),
                "source_ip": event.get("source_ip"),
                "device_name": device_name,
                "description": (
                    f"USB storage device insertion detected: "
                    f"{device_name}"
                ),
                "mitre_attack": {
                    "id": "T1200",
                    "name": "Hardware Additions",
                    "tactic": "Initial Access"
                }
            })

    return alerts

def detect_http_bruteforce(events, threshold=4, window_minutes=5):
    """
    Detect repeated HTTP login failures from the same source IP.
    Ignore exact duplicate HTTP failure records.
    """

    from collections import defaultdict
    from datetime import timedelta

    failures_by_ip = defaultdict(list)
    alerts = []
    time_window = timedelta(minutes=window_minutes)

    # Collect failed HTTP login attempts.
    for event in events:
        if (
            event.get("service") == "http"
            and event.get("event_type") == "http_authentication_failure"
            and event.get("request_path", "").rstrip("/") == "/login"
            and event.get("source_ip")
            and event.get("timestamp")
        ):
            # Build a key to identify duplicate failure records.
            duplicate_key = (
                event["source_ip"],
                event["timestamp"],
                event.get("http_method"),
                event.get("request_path"),
                event.get("http_status"),
                event.get("user_agent"),
            )

            # Skip records already collected.
            if any(
                existing.get("_duplicate_key") == duplicate_key
                for existing in failures_by_ip[event["source_ip"]]
            ):
                continue

            # Store the key for duplicate detection.
            event_copy = event.copy()
            event_copy["_duplicate_key"] = duplicate_key

            failures_by_ip[event["source_ip"]].append(event_copy)

    # Analyze each IP address independently.
    for source_ip, failures in failures_by_ip.items():
        failures.sort(key=lambda event: event["timestamp"])

        for start_index, first_event in enumerate(failures):
            window_end = first_event["timestamp"] + time_window

            window_events = [
                event
                for event in failures[start_index:]
                if event["timestamp"] <= window_end
            ]

            if len(window_events) >= threshold:
                alerts.append({
                    "alert_type": "HTTP_BRUTE_FORCE",
                    "severity": "MEDIUM",
                    "source_ip": source_ip,
                    "timestamp": window_events[0]["timestamp"].isoformat(),
                    "failed_attempts": len(window_events),
                    "window_minutes": window_minutes,
                    "first_seen": window_events[0]["timestamp"].isoformat(),
                    "last_seen": window_events[-1]["timestamp"].isoformat(),
                    "mitre_attack": {
                        "id": "T1110",
                        "name": "Brute Force",
                        "tactic": "Credential Access"
                    },
                    "description": (
                        f"Possible HTTP brute-force activity detected "
                        f"from {source_ip}: {len(window_events)} "
                        f"unique HTTP login failure records within "
                        f"{window_minutes} minutes"
                    )
                })
                break

    return alerts

def detect_sysmon_suspicious_process(events):

    alerts = []

    for event in events:

        if (
            event.get("event_type")
            == "sysmon_process_creation"
        ):

            image = event.get(
                "image",
                ""
            ).lower()

            command_line = event.get(
                "command_line",
                ""
            ).lower()

            suspicious = False
            reason = ""

            if "powershell.exe" in image and "-enc" in command_line:

                suspicious = True
                reason = "Encoded PowerShell"

            elif "mimikatz" in image:

                suspicious = True
                reason = "Mimikatz Execution"

            elif "rundll32.exe" in image:

                suspicious = True
                reason = "Rundll32 Abuse"

            if suspicious:

                alerts.append({
                    "alert_type":
                    "SYSMON_SUSPICIOUS_PROCESS",

                    "severity":
                    "HIGH",

                    "timestamp":
                    (
                        event["timestamp"].isoformat()
                        if event.get("timestamp")
                        else None
                    ),

                    "image":
                    image,

                    "command_line":
                    command_line,

                    "description":
                    reason,

                    "mitre_attack": {
                        "id": "T1059",
                        "name": "Command and Scripting Interpreter",
                        "tactic": "Execution"
                    }
                })

    return alerts

def detect_port_scan(events, threshold=5):

    alerts = []

    ports_by_ip = defaultdict(set)
    first_seen_by_ip = {}

    for event in events:

        if (
            event.get("event_type") == "firewall_connection"
            and event.get("source_ip")
            and event.get("port")
        ):

            ports_by_ip[
                event["source_ip"]
            ].add(
                event["port"]
            )

            ts = event.get("timestamp")
            ip = event["source_ip"]

            if ts and (
                ip not in first_seen_by_ip or ts < first_seen_by_ip[ip]
            ):
                first_seen_by_ip[ip] = ts

    for source_ip, ports in ports_by_ip.items():

        if len(ports) >= threshold:

            alerts.append({
                "alert_type": "PORT_SCAN",
                "severity": "MEDIUM",
                "source_ip": source_ip,
                "timestamp": (
                    first_seen_by_ip[source_ip].isoformat()
                    if source_ip in first_seen_by_ip
                    else None
                ),
                "ports_scanned": sorted(list(ports)),
                "description": (
                    f"Possible port scan detected from "
                    f"{source_ip}. "
                    f"{len(ports)} unique ports targeted."
                ),
                "mitre_attack": {
                    "id": "T1046",
                    "name": "Network Service Discovery",
                    "tactic": "Discovery"
                }
            })

    return alerts

def detect_dns_tunneling(events, threshold=5):

    alerts = []

    domains_by_ip = defaultdict(list)
    first_seen_by_ip = {}

    for event in events:

        if (
            event.get("event_type") == "dns_query"
            and event.get("source_ip")
            and event.get("domain")
        ):

            domains_by_ip[
                event["source_ip"]
            ].append(
                event["domain"]
            )

            ts = event.get("timestamp")
            ip = event["source_ip"]

            if ts and (
                ip not in first_seen_by_ip or ts < first_seen_by_ip[ip]
            ):
                first_seen_by_ip[ip] = ts

    for source_ip, domains in domains_by_ip.items():

        suspicious_domains = [
            domain
            for domain in domains
            if len(domain.split(".")[0]) > 10
        ]

        if len(suspicious_domains) >= threshold:

            alerts.append({
                "alert_type": "DNS_TUNNELING",
                "severity": "HIGH",
                "source_ip": source_ip,
                "timestamp": (
                    first_seen_by_ip[source_ip].isoformat()
                    if source_ip in first_seen_by_ip
                    else None
                ),
                "description":
                "Possible DNS tunneling activity detected.",
                "mitre_attack": {
                    "id": "T1071.004",
                    "name": "DNS",
                    "tactic": "Command and Control"
                }
            })

    return alerts

def detect_web_recon(events, threshold=2):

    alerts = []
    pages_by_ip = defaultdict(set)
    first_seen_by_ip = {}

    for event in events:
        if event.get("event_type") == "admin_page_access":
            pages_by_ip[event["source_ip"]].add(event["request_path"])

            ts = event.get("timestamp")
            ip = event["source_ip"]

            if ts and (
                ip not in first_seen_by_ip or ts < first_seen_by_ip[ip]
            ):
                first_seen_by_ip[ip] = ts

    for source_ip, pages in pages_by_ip.items():

        if len(pages) >= threshold:
            alerts.append({
                "alert_type": "WEB_RECONNAISSANCE",
                "severity": "MEDIUM",
                "source_ip": source_ip,
                "timestamp": (
                    first_seen_by_ip[source_ip].isoformat()
                    if source_ip in first_seen_by_ip
                    else None
                ),
                "description": (
                    f"Possible web reconnaissance "
                    f"activity from {source_ip}"
                ),
                "mitre_attack": {
                    "id": "T1595",
                    "name": "Active Scanning",
                    "tactic": "Reconnaissance"
                }
            })

        elif len(pages) >= 1:
            has_login_failures = any(
                e.get("source_ip") == source_ip
                and e.get("event_type") == "http_authentication_failure"
                for e in events
            )
            if has_login_failures:
                alerts.append({
                    "alert_type": "WEB_RECONNAISSANCE",
                    "severity": "LOW",
                    "source_ip": source_ip,
                    "timestamp": (
                        first_seen_by_ip[source_ip].isoformat()
                        if source_ip in first_seen_by_ip
                        else None
                    ),
                    "description": (
                        f"Admin page access combined with login failures "
                        f"from {source_ip} (possible reconnaissance)"
                    ),
                    "mitre_attack": {
                        "id": "T1595",
                        "name": "Active Scanning",
                        "tactic": "Reconnaissance"
                    }
                })

    return alerts   

def detect_apache_attacks(events):

    alerts = []
    seen = set()

    for event in events:

        if event.get("service") != "apache":
            continue

        request = event.get(
            "request",
            ""
        ).lower()

        source_ip = event.get("source_ip")

        # Directory Traversal
        if (
            "../../etc/passwd" in request
            or "../../etc/shadow" in request
        ):

            alert_key = (
                source_ip,
                "DIRECTORY_TRAVERSAL"
            )

            if alert_key in seen:
                continue

            seen.add(alert_key)

            alerts.append({
                "alert_type": "DIRECTORY_TRAVERSAL",
                "severity": "HIGH",
                "source_ip": source_ip,
                "timestamp": (event["timestamp"].isoformat() if event.get("timestamp") else None),
                "description":
                "Possible directory traversal attack.",
                "mitre_attack": {
                    "id": "T1190",
                    "name": "Exploit Public-Facing Application",
                    "tactic": "Initial Access"
                }
            })

        # SQL Injection
        elif "union select" in request:

            alert_key = (
                source_ip,
                "SQL_INJECTION"
            )

            if alert_key in seen:
                continue

            seen.add(alert_key)

            alerts.append({
                "alert_type": "SQL_INJECTION",
                "severity": "HIGH",
                "source_ip": source_ip,
                "timestamp": (event["timestamp"].isoformat() if event.get("timestamp") else None),
                "description":
                "Possible SQL injection attack.",
                "mitre_attack": {
                    "id": "T1190",
                    "name": "Exploit Public-Facing Application",
                    "tactic": "Initial Access"
                }
            })

        # Command Injection
        elif "cmd=" in request:

            alert_key = (
                source_ip,
                "COMMAND_INJECTION"
            )

            if alert_key in seen:
                continue

            seen.add(alert_key)

            alerts.append({
                "alert_type": "COMMAND_INJECTION",
                "severity": "CRITICAL",
                "source_ip": source_ip,
                "timestamp": (event["timestamp"].isoformat() if event.get("timestamp") else None),
                "description":
                "Possible command injection attack.",
                "mitre_attack": {
                    "id": "T1190",
                    "name": "Exploit Public-Facing Application",
                    "tactic": "Initial Access"
                }
            })

    return alerts

def detect_nginx_attacks(events):
    alerts = []
    seen = set()

    for event in events:
        if event.get("service") != "nginx":
            continue

        request = event.get("request", "").lower()
        source_ip = event.get("source_ip")

        if "../../etc/passwd" in request or "../../etc/shodow" in request or "../../etc/shadow" in request:
            key = (source_ip, "DIRECTORY_TRAVERSAL")
            if key not in seen:
                seen.add(key)
                alerts.append({
                    "alert_type": "DIRECTORY_TRAVERSAL",
                    "severity": "HIGH",
                    "source_ip": source_ip,
                    "timestamp": (event["timestamp"].isoformat() if event.get("timestamp") else None),
                    "description": "Possible directory traversal attack (nginx).",
                    "mitre_attack": {
                        "id": "T1190",
                        "name": "Exploit Public-Facing Application",
                        "tactic": "Initial Access"
                    }
                })

        elif "union select" in request:
            key = (source_ip, "SQL_INJECTION")
            if key not in seen:
                seen.add(key)
                alerts.append({
                    "alert_type": "SQL_INJECTION",
                    "severity": "HIGH",
                    "source_ip": source_ip,
                    "timestamp": (event["timestamp"].isoformat() if event.get("timestamp") else None),
                    "description": "Possible SQL injection attack (nginx).",
                    "mitre_attack": {
                        "id": "T1190",
                        "name": "Exploit Public-Facing Application",
                        "tactic": "Initial Access"
                    }
                })

        elif "cmd=" in request:
            key = (source_ip, "COMMAND_INJECTION")
            if key not in seen:
                seen.add(key)
                alerts.append({
                    "alert_type": "COMMAND_INJECTION",
                    "severity": "CRITICAL",
                    "source_ip": source_ip,
                    "timestamp": (event["timestamp"].isoformat() if event.get("timestamp") else None),
                    "description": "Possible command injection attack (nginx).",
                    "mitre_attack": {
                        "id": "T1190",
                        "name": "Exploit Public-Facing Application",
                        "tactic": "Initial Access"
                    }
                })

    return alerts

def detect_iis_attacks(events):
    alerts = []
    seen = set()

    for event in events:
        if event.get("service") != "iis":
            continue

        path = event.get("request_path", "").lower()
        status = event.get("http_status", 0)
        source_ip = event.get("source_ip")

        if "../../" in path:
            key = (source_ip, "DIRECTORY_TRAVERSAL")
            if key not in seen:
                seen.add(key)
                alerts.append({
                    "alert_type": "DIRECTORY_TRAVERSAL",
                    "severity": "HIGH",
                    "source_ip": source_ip,
                    "timestamp": (event["timestamp"].isoformat() if event.get("timestamp") else None),
                    "description": "Possible directory traversal attack (IIS).",
                    "mitre_attack": {
                        "id": "T1190",
                        "name": "Exploit Public-Facing Application",
                        "tactic": "Initial Access"
                    }
                })

        elif "union select" in path:
            key = (source_ip, "SQL_INJECTION")
            if key not in seen:
                seen.add(key)
                alerts.append({
                    "alert_type": "SQL_INJECTION",
                    "severity": "HIGH",
                    "source_ip": source_ip,
                    "timestamp": (event["timestamp"].isoformat() if event.get("timestamp") else None),
                    "description": "Possible SQL injection attack (IIS).",
                    "mitre_attack": {
                        "id": "T1190",
                        "name": "Exploit Public-Facing Application",
                        "tactic": "Initial Access"
                    }
                })

        elif "cmd=" in path:
            key = (source_ip, "COMMAND_INJECTION")
            if key not in seen:
                seen.add(key)
                alerts.append({
                    "alert_type": "COMMAND_INJECTION",
                    "severity": "CRITICAL",
                    "source_ip": source_ip,
                    "timestamp": (event["timestamp"].isoformat() if event.get("timestamp") else None),
                    "description": "Possible command injection attack (IIS).",
                    "mitre_attack": {
                        "id": "T1190",
                        "name": "Exploit Public-Facing Application",
                        "tactic": "Initial Access"
                    }
                })

        elif "shell" in path and status == 200:
            key = (source_ip, "WEBSHELL")
            if key not in seen:
                seen.add(key)
                alerts.append({
                    "alert_type": "WEBSHELL",
                    "severity": "CRITICAL",
                    "source_ip": source_ip,
                    "timestamp": (event["timestamp"].isoformat() if event.get("timestamp") else None),
                    "description": f"Possible webshell access detected: {event.get('request_path')}",
                    "mitre_attack": {
                        "id": "T1505.003",
                        "name": "Server Software Component: Web Shell",
                        "tactic": "Persistence"
                    }
                })

    return alerts   


# ----------------------------------------------------------------------
# Phase 9: Enterprise detectors (Active Directory, VPN, Cloud)
# ----------------------------------------------------------------------

def detect_kerberoasting(events, threshold=5):
    """
    Detect Kerberoasting: repeated EventID 4769 (TGS requests)
    from the same IP.
    """
    tgs_by_ip = defaultdict(list)

    for event in events:
        if (
            event.get("service") == "active_directory"
            and event.get("event_type") == "kerberos_tgs_grant"
            and event.get("source_ip")
        ):
            tgs_by_ip[event["source_ip"]].append(event)

    alerts = []

    for ip, events_list in tgs_by_ip.items():
        if len(events_list) >= threshold:
            alerts.append({
                "alert_type": "KERBEROASTING",
                "severity": "HIGH",
                "source_ip": ip,
                "timestamp": _first_timestamp(events_list),
                "request_count": len(events_list),
                "description": (
                    f"Possible Kerberoasting detected from {ip}: "
                    f"{len(events_list)} TGS requests for "
                    f"{events_list[0].get('username', 'unknown')}"
                ),
                "mitre_attack": {
                    "id": "T1558.003",
                    "name": "Steal or Forge Kerberos Tickets: Kerberoasting",
                    "tactic": "Credential Access"
                }
            })

    return alerts


def detect_asrep_roasting(events, threshold=4):
    """
    Detect AS-REP Roasting: repeated EventID 4768 with
    TicketOptions=0x40800000 (pre-authentication disabled).
    """
    asrep_by_ip = defaultdict(list)

    for event in events:
        if (
            event.get("service") == "active_directory"
            and event.get("event_type") == "kerberos_tgs_request"
            and event.get("source_ip")
            and "0x40800000" in event.get("extra", "")
        ):
            asrep_by_ip[event["source_ip"]].append(event)

    alerts = []

    for ip, events_list in asrep_by_ip.items():
        if len(events_list) >= threshold:
            alerts.append({
                "alert_type": "ASREP_ROASTING",
                "severity": "HIGH",
                "source_ip": ip,
                "timestamp": _first_timestamp(events_list),
                "request_count": len(events_list),
                "description": (
                    f"Possible AS-REP Roasting detected from {ip}: "
                    f"{len(events_list)} pre-auth disabled requests for "
                    f"{events_list[0].get('username', 'unknown')}"
                ),
                "mitre_attack": {
                    "id": "T1558.004",
                    "name": "Steal or Forge Kerberos Tickets: AS-REP Roasting",
                    "tactic": "Credential Access"
                }
            })

    return alerts


def detect_privilege_escalation_ad(events):
    """
    Detect privilege escalation: EventID 4732 (group membership change)
    targeting privileged groups (Domain Admins, Administrators, etc.).
    """
    privileged_groups = [
        "domain admins",
        "administrators",
        "enterprise admins",
        "schema admins",
        "account operators",
    ]

    alerts = []

    for event in events:
        if (
            event.get("service") == "active_directory"
            and event.get("event_type") == "group_membership_change"
        ):
            extra = event.get("extra", "")
            group_match = re.search(
                r"TargetGroup=(.+)", extra, re.IGNORECASE
            )
            target_group = group_match.group(1).strip() if group_match else ""

            if any(g in target_group.lower() for g in privileged_groups):
                alerts.append({
                    "alert_type": "AD_PRIVILEGE_ESCALATION",
                    "severity": "CRITICAL",
                    "source_ip": event.get("source_ip"),
                    "timestamp": _event_timestamp(event),
                    "username": event.get("username"),
                    "target_group": target_group,
                    "description": (
                        f"Privileged group membership change: "
                        f"{event.get('username')} added to {target_group}"
                    ),
                    "mitre_attack": {
                        "id": "T1098.007",
                        "name": (
                            "Account Manipulation: Additional Local "
                            "or Domain Groups"
                        ),
                        "tactic": "Persistence"
                    }
                })

    return alerts


def detect_s4u_abuse(events, threshold=4):
    """
    Detect S4U abuse: repeated EventID 4771 from the same IP.
    """
    s4u_by_ip = defaultdict(list)

    for event in events:
        if (
            event.get("service") == "active_directory"
            and event.get("event_type") == "kerberos_s4u"
            and event.get("source_ip")
        ):
            s4u_by_ip[event["source_ip"]].append(event)

    alerts = []

    for ip, events_list in s4u_by_ip.items():
        if len(events_list) >= threshold:
            alerts.append({
                "alert_type": "S4U_ABUSE",
                "severity": "HIGH",
                "source_ip": ip,
                "timestamp": _first_timestamp(events_list),
                "request_count": len(events_list),
                "description": (
                    f"Possible S4U abuse detected from {ip}: "
                    f"{len(events_list)} service-for-user requests"
                ),
                "mitre_attack": {
                    "id": "T1558",
                    "name": "Steal or Forge Kerberos Tickets",
                    "tactic": "Credential Access"
                }
            })

    return alerts


def detect_vpn_bruteforce(events, threshold=5, window_minutes=5):
    """
    Detect VPN brute force: repeated auth failures from the same IP.
    Works across all VPN vendors (OpenVPN, Cisco, Fortinet).
    """
    failures_by_ip = defaultdict(list)

    for event in events:
        if (
            event.get("service") == "vpn"
            and event.get("event_type") == "vpn_auth_failure"
            and event.get("source_ip")
            and event.get("timestamp")
        ):
            failures_by_ip[event["source_ip"]].append(event)

    alerts = []
    time_window = timedelta(minutes=window_minutes)

    for ip, failures in failures_by_ip.items():
        failures.sort(key=lambda e: e["timestamp"])

        for i in range(len(failures)):
            window_end = failures[i]["timestamp"] + time_window
            window_events = [
                e for e in failures[i:] if e["timestamp"] <= window_end
            ]

            if len(window_events) >= threshold:
                alerts.append({
                    "alert_type": "VPN_BRUTE_FORCE",
                    "severity": "MEDIUM",
                    "source_ip": ip,
                    "timestamp": window_events[0]["timestamp"].isoformat(),
                    "vpn_vendor": window_events[0].get("vpn_vendor", ""),
                    "failed_attempts": len(window_events),
                    "description": (
                        f"Possible VPN brute-force from {ip}: "
                        f"{len(window_events)} failed attempts within "
                        f"{window_minutes} minutes"
                    ),
                    "mitre_attack": {
                        "id": "T1110",
                        "name": "Brute Force",
                        "tactic": "Credential Access"
                    }
                })
                break

    return alerts


def detect_impossible_travel(events, window_minutes=30):
    """
    Detect impossible travel: the same user authenticating from different
    IPs within 30 minutes (simplified - no GeoIP library needed).
    """
    successes_by_user = defaultdict(list)

    for event in events:
        if (
            event.get("service") == "vpn"
            and event.get("event_type") == "vpn_auth_success"
            and event.get("username")
            and event.get("source_ip")
            and event.get("timestamp")
        ):
            successes_by_user[event["username"]].append(event)

    alerts = []
    window = timedelta(minutes=window_minutes)

    for user, successes in successes_by_user.items():
        successes.sort(key=lambda e: e["timestamp"])

        for i in range(len(successes) - 1):
            for j in range(i + 1, len(successes)):
                gap = successes[j]["timestamp"] - successes[i]["timestamp"]

                if gap > window:
                    break

                if successes[i]["source_ip"] != successes[j]["source_ip"]:
                    gap_min = int(gap.total_seconds() / 60)
                    alerts.append({
                        "alert_type": "IMPOSSIBLE_TRAVEL",
                        "severity": "HIGH",
                        "source_ip": successes[j]["source_ip"],
                        "timestamp": successes[i]["timestamp"].isoformat(),
                        "username": user,
                        "ip_1": successes[i]["source_ip"],
                        "ip_2": successes[j]["source_ip"],
                        "time_gap_minutes": gap_min,
                        "description": (
                            f"Impossible travel: {user} authenticated from "
                            f"{successes[i]['source_ip']} and "
                            f"{successes[j]['source_ip']} within "
                            f"{gap_min} minutes"
                        ),
                        "mitre_attack": {
                            "id": "T1078",
                            "name": "Valid Accounts",
                            "tactic": "Initial Access"
                        }
                    })
                    break

    return alerts


def detect_cloud_bruteforce(events, threshold=4, window_minutes=5):
    """
    Detect cloud console/portal brute force across AWS, Azure and GCP.
    """
    failures_by_ip = defaultdict(list)

    for event in events:
        if (
            event.get("service") == "cloud"
            and event.get("event_type") == "cloud_auth_failure"
            and event.get("source_ip")
            and event.get("timestamp")
        ):
            failures_by_ip[event["source_ip"]].append(event)

    alerts = []
    time_window = timedelta(minutes=window_minutes)

    for ip, failures in failures_by_ip.items():
        failures.sort(key=lambda e: e["timestamp"])

        for i in range(len(failures)):
            window_end = failures[i]["timestamp"] + time_window
            window_events = [
                e for e in failures[i:] if e["timestamp"] <= window_end
            ]

            if len(window_events) >= threshold:
                provider = window_events[0].get("cloud_provider", "cloud")
                alerts.append({
                    "alert_type": "CLOUD_BRUTE_FORCE",
                    "severity": "MEDIUM",
                    "source_ip": ip,
                    "timestamp": window_events[0]["timestamp"].isoformat(),
                    "cloud_provider": provider,
                    "failed_attempts": len(window_events),
                    "description": (
                        f"Possible {provider.upper()} console brute-force "
                        f"from {ip}: {len(window_events)} failed logins "
                        f"within {window_minutes} minutes"
                    ),
                    "mitre_attack": {
                        "id": "T1110",
                        "name": "Brute Force",
                        "tactic": "Credential Access"
                    }
                })
                break

    return alerts


def detect_cloud_persistence(events):
    """
    Detect cloud persistence: creating users, assigning admin roles,
    or creating access keys.
    """
    persistence_events = {
        "aws": ["createuser", "putuserpolicy", "createaccesskey"],
        "azure": ["roleassignmentcreated"],
        "gcp": ["iam.setiampolicy"],
    }

    alerts = []

    for event in events:
        if event.get("service") != "cloud":
            continue

        provider = event.get("cloud_provider", "").lower()
        cloud_event = event.get("cloud_event", "").lower()
        policy = event.get("policy", "").lower()
        target = event.get("target", "").lower()

        is_persistence = cloud_event in persistence_events.get(provider, [])

        # Privileged policy / role assignment on any cloud API call
        if event.get("event_type") == "cloud_api_call" and (
            "administrator" in policy
            or "admin" in policy
            or "owner" in target
        ):
            is_persistence = True

        if is_persistence:
            alerts.append({
                "alert_type": "CLOUD_PERSISTENCE",
                "severity": "CRITICAL",
                "source_ip": event.get("source_ip"),
                "timestamp": _event_timestamp(event),
                "cloud_provider": provider,
                "username": event.get("username"),
                "target": event.get("target", ""),
                "description": (
                    f"Cloud persistence detected on {provider.upper()}: "
                    f"{event.get('cloud_event')} by "
                    f"{event.get('username')} targeting "
                    f"{event.get('target') or 'N/A'}"
                ),
                "mitre_attack": {
                    "id": "T1098",
                    "name": "Account Manipulation",
                    "tactic": "Persistence"
                }
            })

    return alerts


# ----------------------------------------------------------------------
# Phase 4: Attack chain correlation engine
# ----------------------------------------------------------------------

CHAIN_NAMES = {
    "PORT_SCAN": "Port Scan",
    "WEB_RECONNAISSANCE": "Web Recon",
    "DNS_TUNNELING": "DNS Tunneling",
    "SQL_INJECTION": "SQL Injection",
    "COMMAND_INJECTION": "Command Injection",
    "DIRECTORY_TRAVERSAL": "Directory Traversal",
    "WEBSHELL": "Webshell",
    "AUTH_BRUTE_FORCE": "Brute Force",
    "LARGE_DATA_EXFIL": "Data Exfiltration",
    "KERBEROASTING": "Kerberoasting",
    "ASREP_ROASTING": "AS-REP Roasting",
    "AD_PRIVILEGE_ESCALATION": "AD Privilege Escalation",
    "S4U_ABUSE": "S4U Abuse",
    "VPN_BRUTE_FORCE": "VPN Brute Force",
    "IMPOSSIBLE_TRAVEL": "Impossible Travel",
    "CLOUD_BRUTE_FORCE": "Cloud Brute Force",
    "CLOUD_PERSISTENCE": "Cloud Persistence",
}


def _event_timestamp(event):
    """Return an event's timestamp as an ISO string, or None."""
    return event["timestamp"].isoformat() if event.get("timestamp") else None


def _first_timestamp(events_list):
    """Return the earliest timestamp (ISO string) in a list of events."""
    stamps = [e["timestamp"] for e in events_list if e.get("timestamp")]
    return min(stamps).isoformat() if stamps else None


def _to_datetime(value):
    """Convert an ISO string or datetime into a datetime (None if invalid)."""
    if isinstance(value, datetime):
        return value

    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None

    return None


def detect_attack_chain(alerts, window_minutes=10):
    """
    Correlate alerts from the same source IP within a time window.
    If 3+ distinct alert types from the same IP exist within the window,
    emit ONE ATTACK_CHAIN alert with severity CRITICAL.
    Individual alerts are never removed - the chain is additional.
    """
    window = timedelta(minutes=window_minutes)
    by_ip = defaultdict(list)

    for alert in alerts:
        if alert.get("alert_type") == "ATTACK_CHAIN":
            continue

        ip = alert.get("source_ip")
        ts = _to_datetime(alert.get("timestamp"))

        if not ip or ts is None:
            continue

        by_ip[ip].append((ts, alert))

    chain_alerts = []

    for ip, items in by_ip.items():
        items.sort(key=lambda item: item[0])

        best_window = []

        for i in range(len(items)):
            window_end = items[i][0] + window
            members = [it for it in items[i:] if it[0] <= window_end]
            distinct = {a.get("alert_type") for _, a in members}

            if len(distinct) > len({a.get("alert_type") for _, a in best_window}):
                best_window = members

        # Chronological, de-duplicated list of alert types
        chain = []
        for _, a in best_window:
            alert_type = a.get("alert_type")
            if alert_type not in chain:
                chain.append(alert_type)

        if len(chain) < 3:
            continue

        readable = [CHAIN_NAMES.get(t, t) for t in chain]

        chain_alerts.append({
            "alert_type": "ATTACK_CHAIN",
            "severity": "CRITICAL",
            "source_ip": ip,
            "timestamp": best_window[0][0].isoformat(),
            "chain": chain,
            "chain_readable": readable,
            "chain_count": len(chain),
            "description": (
                f"Multi-stage attack chain detected from {ip}: "
                + " \u2192 ".join(readable)
            ),
            "mitre_attack": {
                "id": "T1595",
                "name": "Active Scanning",
                "tactic": "Reconnaissance"
            }
        })

    return chain_alerts
