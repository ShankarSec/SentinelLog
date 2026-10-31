import re
from datetime import datetime


def _parse_date_or_datetime(text):
    """
    Parse 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM:SS' into a datetime.
    Date-only values resolve to midnight (original v1.0 behaviour).
    """
    fmt = "%Y-%m-%d %H:%M:%S" if " " in text else "%Y-%m-%d"
    return datetime.strptime(text, fmt)


def parse_log_line(line):
    event = {
        "raw": line.strip(),
        "timestamp": None,
        "event_type": "unknown",
        "username": None,
        "source_ip": None,
        "port": None,
        "service": None,
    }

    # Extract timestamp
    timestamp_match = re.search(
        r"^([A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2})",
        line
    )

    if timestamp_match:
        timestamp_text = timestamp_match.group(1)

        current_year = datetime.now().year

        event["timestamp"] = datetime.strptime(
            f"{current_year} {timestamp_text}",
            "%Y %b %d %H:%M:%S"
        )

    # Detect SSH service
    if "sshd" in line:
        event["service"] = "ssh"

    # Active Directory / Kerberos events (only the supported Event IDs)
    ad_match = re.search(
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+EventID=(\d+)\s+"
        r"User=([\w\\@.]+)\s+SourceIP=([0-9.]+)(?:\s+(.*))?",
        line
    )

    ad_event_types = {
        4768: "kerberos_tgs_request",
        4769: "kerberos_tgs_grant",
        4771: "kerberos_s4u",
        4776: "kerberos_service_ticket",
        4728: "kerberos_ticket_granted",
        4732: "group_membership_change",
    }

    if ad_match and int(ad_match.group(2)) in ad_event_types:
        event["timestamp"] = datetime.strptime(
            ad_match.group(1), "%Y-%m-%d %H:%M:%S"
        )
        event["event_id"] = int(ad_match.group(2))
        event["username"] = ad_match.group(3)
        event["source_ip"] = ad_match.group(4)
        event["service"] = "active_directory"
        event["extra"] = (ad_match.group(5) or "").strip()
        event["event_type"] = ad_event_types[event["event_id"]]

        return event

    # VPN logs (OpenVPN, Cisco, Fortinet)
    vpn_match = re.search(
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+(AUTH_\w+)"
        r"\s+user=(\S+)\s+ip=([0-9.]+)(?:\s+reason=(\S+))?",
        line
    )

    if vpn_match:
        event["timestamp"] = datetime.strptime(
            vpn_match.group(1), "%Y-%m-%d %H:%M:%S"
        )
        event["service"] = "vpn"
        event["vpn_vendor"] = vpn_match.group(2).lower()
        event["username"] = vpn_match.group(4)
        event["source_ip"] = vpn_match.group(5)
        event["reason"] = vpn_match.group(6) or ""

        if vpn_match.group(3) == "AUTH_FAILED":
            event["event_type"] = "vpn_auth_failure"
        elif vpn_match.group(3) == "AUTH_SUCCESS":
            event["event_type"] = "vpn_auth_success"

        return event

    # Cloud logs (AWS CloudTrail, Azure, GCP)
    cloud_match = re.search(
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+source=(\w+)\s+"
        r"event=(\S+)\s+user=(\S+)\s+ip=([0-9.]+)"
        r"(?:\s+(?:result|status)=(\w+))?"
        r"(?:\s+target=(\S+))?(?:\s+policy=(\S+))?",
        line
    )

    if cloud_match:
        event["timestamp"] = datetime.strptime(
            cloud_match.group(1), "%Y-%m-%d %H:%M:%S"
        )
        event["service"] = "cloud"
        event["cloud_provider"] = cloud_match.group(2).lower()
        event["cloud_event"] = cloud_match.group(3)
        event["username"] = cloud_match.group(4)
        event["source_ip"] = cloud_match.group(5)
        event["result"] = cloud_match.group(6) or ""
        event["target"] = cloud_match.group(7) or ""
        event["policy"] = cloud_match.group(8) or ""

        result = event["result"].lower()
        if result in ("failure", "failed"):
            event["event_type"] = "cloud_auth_failure"
        elif result in ("success", "succeeded"):
            event["event_type"] = "cloud_auth_success"
        else:
            event["event_type"] = "cloud_api_call"

        return event

    # Detect failed SSH login
    failed_match = re.search(
        r"Failed password for (\S+) from ([0-9.]+) port (\d+)",
        line
    )

    if failed_match:
        event["event_type"] = "authentication_failure"
        event["username"] = failed_match.group(1)
        event["source_ip"] = failed_match.group(2)
        event["port"] = int(failed_match.group(3))
        return event

    # Detect successful SSH login
    success_match = re.search(
        r"Accepted password for (\S+) from ([0-9.]+) port (\d+)",
        line
    )

    if success_match:
        event["event_type"] = "authentication_success"
        event["username"] = success_match.group(1)
        event["source_ip"] = success_match.group(2)
        event["port"] = int(success_match.group(3))
        return event

    account_match = re.search(
        r"useradd.*new user: name=(\S+),",
        line
    )

    if account_match:
        event["event_type"] = "account_created"
        event["username"] = account_match.group(1)
        event["service"] = "user_management"
        return event


    deletion_match = re.search(
        r"userdel.*delete user ['\"]([^'\"]+)['\"]",
        line
    )

    if deletion_match:
        event["event_type"] = "account_deleted"
        event["username"] = deletion_match.group(1)
        event["service"] = "user_management"
        return event

    # Detect Windows Event Log cleared (Event ID 104)
    if re.search(r"Event ID 104\b", line):
        event["event_type"] = "event_log_cleared"
        event["service"] = "windows_eventlog"
        event["event_id"] = 104
        return event

    # Detect Windows whoami execution (Event ID 4688)
    if (
        re.search(r"Event ID 4688\b", line)
        and re.search(r"\bwhoami\.exe\b", line, re.IGNORECASE)
    ):
        event["event_type"] = "whoami_execution"
        event["service"] = "windows_process"
        event["event_id"] = 4688
        event["process_name"] = "whoami.exe"
        return event

    # Detect Windows PowerShell execution (Event ID 4688)
    if (
        re.search(r"Event ID 4688\b", line)
        and re.search(r"\bpowershell\.exe\b", line, re.IGNORECASE)
    ):
        event["event_type"] = "powershell_execution"
        event["service"] = "windows_process"
        event["event_id"] = 4688
        event["process_name"] = "powershell.exe"
        return event

        # Detect large outbound network transfer
    transfer_match = re.search(
        r"src_ip=([0-9.]+)\s+dest_ip=([0-9.]+)\s+bytes_sent=(\d+)",
        line
    )

    if transfer_match:
        event["event_type"] = "large_data_transfer"
        event["source_ip"] = transfer_match.group(1)
        event["destination_ip"] = transfer_match.group(2)
        event["bytes_sent"] = int(transfer_match.group(3))
        event["service"] = "network"
        return event

        # Detect USB device insertion
    if re.search(r"\bUSB_INSERTION\b", line, re.IGNORECASE):
        event["event_type"] = "usb_insertion"
        event["service"] = "windows_device"

        device_match = re.search(
            r"\bDevice=([^\s]+)",
            line,
            re.IGNORECASE
        )

        if device_match:
            event["device_name"] = device_match.group(1)

        event["device_type"] = "USB"
        return event

    # Detect HTTP access log events
    http_match = re.search(
        r'^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s+'
        r'([0-9.]+)\s*-\s*-\s*'
        r'"([A-Z]+)\s+(\S+)\s+HTTP/[\d.]+"\s+'
        r'(\d{3})\s+"([^"]*)"',
        line
    )

    if http_match:
        timestamp_text = http_match.group(1)

        event["timestamp"] = datetime.strptime(
            timestamp_text,
            "%Y-%m-%d %H:%M:%S"
        )

        event["source_ip"] = http_match.group(2)
        event["http_method"] = http_match.group(3)
        event["request_path"] = http_match.group(4)
        event["http_status"] = int(http_match.group(5))
        event["user_agent"] = http_match.group(6)
        event["service"] = "http"

        path = event["request_path"].rstrip("/")

        # Login failures
        if (
            path == "/login"
            and event["http_status"] in (401, 403)
        ):
            event["event_type"] = "http_authentication_failure"

        # Login success
        elif (
            path == "/login"
            and event["http_status"] == 200
        ):
            event["event_type"] = "http_authentication_success"

        # Admin page access
        elif path in (
            "/admin",
            "/config",
            "/backup",
            "/phpmyadmin"
        ):
            event["event_type"] = "admin_page_access"

        else:
            event["event_type"] = "http_request"

        return event

        # Detect Sysmon Process Creation (Event ID 1)
    sysmon_match = re.search(
        r"EventID=(\d+).*?Image=(.*?)\s+CommandLine=\"(.*?)\"",
        line
    )

    if sysmon_match:

        event_id = int(sysmon_match.group(1))
        image = sysmon_match.group(2)
        command_line = sysmon_match.group(3)

        if event_id == 1:

            sysmon_ts = re.search(
                r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",
                line
            )

            if sysmon_ts:
                event["timestamp"] = datetime.strptime(
                    sysmon_ts.group(1), "%Y-%m-%d %H:%M:%S"
                )

            event["event_type"] = "sysmon_process_creation"
            event["service"] = "sysmon"
            event["event_id"] = 1
            event["image"] = image
            event["command_line"] = command_line

            return event

    windows_match = re.search(
        r"(\d{4}-\d{2}-\d{2}(?: \d{2}:\d{2}:\d{2})?).*?EventID=(\d+).*?User=(\S+)(?:.*?SourceIP=([0-9.]+))?",
        line
    )

    if windows_match:

        event["timestamp"] = _parse_date_or_datetime(
            windows_match.group(1)
        )

        event_id = int(windows_match.group(2))

        event["event_id"] = event_id
        event["username"] = windows_match.group(3)
        event["source_ip"] = windows_match.group(4)
        event["service"] = "windows_security"

        if event_id == 4625:
            event["event_type"] = "authentication_failure"

        elif event_id == 4624:
            event["event_type"] = "authentication_success"

        elif event_id == 4720:
            event["event_type"] = "account_created"

        elif event_id == 4726:
            event["event_type"] = "account_deleted"

        return event


    firewall_match = re.search(
        r"(\d{4}-\d{2}-\d{2}(?: \d{2}:\d{2}:\d{2})?)\s+SRC=([0-9.]+)\s+DST=([0-9.]+)\s+DPT=(\d+)",
        line
    )

    if firewall_match:

        event["timestamp"] = _parse_date_or_datetime(
            firewall_match.group(1)
        )

        event["event_type"] = "firewall_connection"
        event["service"] = "firewall"

        event["source_ip"] = firewall_match.group(2)
        event["destination_ip"] = firewall_match.group(3)
        event["port"] = int(firewall_match.group(4))

        return event


    dns_match = re.search(
        r"(\d{4}-\d{2}-\d{2}(?: \d{2}:\d{2}:\d{2})?)\s+SRC=([0-9.]+)\s+QUERY=(\S+)\s+TYPE=(\S+)",
        line
    )

    if dns_match:

        event["timestamp"] = _parse_date_or_datetime(
            dns_match.group(1)
        )

        event["event_type"] = "dns_query"
        event["service"] = "dns"

        event["source_ip"] = dns_match.group(2)
        event["domain"] = dns_match.group(3)
        event["record_type"] = dns_match.group(4)

        return event


    apache_match = re.search(
        r"\[client ([0-9.]+)\]\s+(.*)",
        line
    )

    if apache_match:

        apache_ts = re.search(
            r"^\[\w{3} (\w{3} \d{1,2} \d{2}:\d{2}:\d{2})(?:\.\d+)? (\d{4})\]",
            line
        )

        if apache_ts:
            try:
                event["timestamp"] = datetime.strptime(
                    f"{apache_ts.group(1)} {apache_ts.group(2)}",
                    "%b %d %H:%M:%S %Y"
                )
            except ValueError:
                pass

        event["event_type"] = "apache_request"
        event["service"] = "apache"
        event["source_ip"] = apache_match.group(1)
        event["request"] = apache_match.group(2)

        return event
    
    nginx_match = re.search(
        r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] (\d+\.\d+\.\d+\.\d+) (\w+) (.+)",
        line
    )

    if nginx_match:

        event["timestamp"] = datetime.strptime(
            nginx_match.group(1),
            "%Y/%m/%d %H:%M:%S"
        )

        event["event_type"] = "nginx_error"
        event["service"] = "nginx"
        event["source_ip"] = nginx_match.group(3)
        event["http_method"] = nginx_match.group(4)
        event["request"] = nginx_match.group(5)

        return event

    # IIS W3C Extended Log Format
    iis_match = re.search(
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+([0-9.]+)\s+([A-Z]+)\s+(.+)\s+(\d{3})",
        line
    )

    if iis_match and not line.startswith("#"):

        event["timestamp"] = datetime.strptime(
            iis_match.group(1),
            "%Y-%m-%d %H:%M:%S"
        )

        event["event_type"] = "iis_request"
        event["service"] = "iis"
        event["source_ip"] = iis_match.group(2)
        event["http_method"] = iis_match.group(3)
        event["request_path"] = iis_match.group(4)
        event["http_status"] = int(iis_match.group(5))

        return event   
    
    return event
