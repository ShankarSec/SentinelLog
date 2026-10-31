import argparse
import glob
import os

try:
    from .parser import parse_log_line
    from .detector import (
        detect_ssh_bruteforce,
        detect_failure_then_success,
        detect_account_creation,
        detect_account_deletion,
        detect_multi_account_failures,
        detect_event_log_cleared,
        detect_whoami_execution,
        detect_powershell_execution,
        detect_large_data_exfiltration,
        detect_usb_insertion,
        detect_http_bruteforce,
        detect_sysmon_suspicious_process,
        detect_port_scan,
        detect_dns_tunneling,
        detect_web_recon,
        detect_apache_attacks,
        detect_nginx_attacks,
        detect_iis_attacks,
        detect_kerberoasting,
        detect_asrep_roasting,
        detect_privilege_escalation_ad,
        detect_s4u_abuse,
        detect_vpn_bruteforce,
        detect_impossible_travel,
        detect_cloud_bruteforce,
        detect_cloud_persistence,
        detect_attack_chain,
    )
    from .ioc import extract_iocs
    from .reporter import (
        save_json_report,
        save_text_report,
        save_html_report,
        save_pdf_report,
    )
    from .rule_loader import load_rules
    from .scoring import calculate_risk_score
except ImportError:
    from parser import parse_log_line
    from detector import (
        detect_ssh_bruteforce,
        detect_failure_then_success,
        detect_account_creation,
        detect_account_deletion,
        detect_multi_account_failures,
        detect_event_log_cleared,
        detect_whoami_execution,
        detect_powershell_execution,
        detect_large_data_exfiltration,
        detect_usb_insertion,
        detect_http_bruteforce,
        detect_sysmon_suspicious_process,
        detect_port_scan,
        detect_dns_tunneling,
        detect_web_recon,
        detect_apache_attacks,
        detect_nginx_attacks,
        detect_iis_attacks,
        detect_kerberoasting,
        detect_asrep_roasting,
        detect_privilege_escalation_ad,
        detect_s4u_abuse,
        detect_vpn_bruteforce,
        detect_impossible_travel,
        detect_cloud_bruteforce,
        detect_cloud_persistence,
        detect_attack_chain,
    )
    from ioc import extract_iocs
    from reporter import (
        save_json_report,
        save_text_report,
        save_html_report,
        save_pdf_report,
    )
    from rule_loader import load_rules
    from scoring import calculate_risk_score


VERSION = "2.0.0"


def load_log_file(log_file):

    events = []

    with open(log_file, "r", encoding="utf-8") as file:

        for line in file:

            if line.strip():

                events.append(
                    parse_log_line(line)
                )

    return events


def run_detectors(events):

    alerts = []

    alerts.extend(detect_ssh_bruteforce(events))
    alerts.extend(detect_failure_then_success(events))
    alerts.extend(detect_account_creation(events))
    alerts.extend(detect_account_deletion(events))
    alerts.extend(detect_multi_account_failures(events))
    alerts.extend(detect_event_log_cleared(events))
    alerts.extend(detect_whoami_execution(events))
    alerts.extend(detect_powershell_execution(events))
    alerts.extend(detect_large_data_exfiltration(events))
    alerts.extend(detect_usb_insertion(events))
    alerts.extend(detect_http_bruteforce(events))
    alerts.extend(detect_sysmon_suspicious_process(events))
    alerts.extend(detect_port_scan(events))
    alerts.extend(detect_dns_tunneling(events))
    alerts.extend(detect_web_recon(events))
    alerts.extend(detect_apache_attacks(events))
    alerts.extend(detect_nginx_attacks(events))
    alerts.extend(detect_iis_attacks(events))

    # Enterprise detectors (Active Directory, VPN, Cloud)
    alerts.extend(detect_kerberoasting(events))
    alerts.extend(detect_asrep_roasting(events))
    alerts.extend(detect_privilege_escalation_ad(events))
    alerts.extend(detect_s4u_abuse(events))
    alerts.extend(detect_vpn_bruteforce(events))
    alerts.extend(detect_impossible_travel(events))
    alerts.extend(detect_cloud_bruteforce(events))
    alerts.extend(detect_cloud_persistence(events))

    return alerts


def deduplicate_alerts(alerts):
    """
    Remove repeated alerts with the same (source_ip, alert_type).

    ATTACK_CHAIN alerts are never deduplicated, and alerts without a
    source IP are always kept (nothing to de-duplicate them on).
    """
    seen = set()
    unique = []

    for alert in alerts:
        if (
            alert.get("alert_type") == "ATTACK_CHAIN"
            or not alert.get("source_ip")
        ):
            unique.append(alert)
            continue

        key = (alert.get("source_ip"), alert.get("alert_type"))

        if key not in seen:
            seen.add(key)
            unique.append(alert)

    return unique


def _timestamp_sort_key(alert):
    """Sort key: timestamped alerts first (oldest first), others last."""
    stamp = alert.get("timestamp")
    return (stamp is None, stamp or "")


def finalize_alerts(alerts, dedup=True, window_minutes=10):
    """
    Post-process raw detector output:
    dedup -> attack-chain correlation -> chronological order -> alert IDs.
    """
    if dedup:
        alerts = deduplicate_alerts(alerts)

    alerts = list(alerts) + detect_attack_chain(
        alerts,
        window_minutes=window_minutes
    )

    alerts = sorted(alerts, key=_timestamp_sort_key)

    finalized = []

    for number, alert in enumerate(alerts, start=1):
        entry = {"alert_id": f"ALERT-{number:04d}"}
        entry.update(
            {k: v for k, v in alert.items() if k != "alert_id"}
        )
        finalized.append(entry)

    return finalized


def generate_reports(events, alerts, output_dir="reports"):

    iocs = extract_iocs(events)
    risk = calculate_risk_score(alerts)
    total_events = len(events)

    os.makedirs(output_dir, exist_ok=True)

    json_path = os.path.join(output_dir, "incident_report.json")
    txt_path = os.path.join(output_dir, "incident_report.txt")
    html_path = os.path.join(output_dir, "incident_report.html")
    pdf_path = os.path.join(output_dir, "incident_report.pdf")

    print(f"[+] Alerts detected: {len(alerts)}")
    print(f"[+] Risk score: {risk['risk_score']}/100 ({risk['classification']})")
    print(f"[+] IP addresses: {len(iocs['ip_addresses'])}")
    print(f"[+] Usernames: {len(iocs['usernames'])}")
    print(f"[+] Ports: {len(iocs['ports'])}")

    save_json_report(
        alerts, iocs, json_path,
        risk_score=risk, total_events=total_events
    )

    save_text_report(
        alerts, iocs, txt_path,
        risk_score=risk, total_events=total_events
    )

    save_html_report(
        alerts, iocs, html_path,
        risk_score=risk, total_events=total_events
    )

    save_pdf_report(alerts, iocs, risk, pdf_path)

    print("\n[+] Analysis complete.")
    print(f"[+] JSON report: {json_path}")
    print(f"[+] TXT report : {txt_path}")
    print(f"[+] HTML report: {html_path}")
    print(f"[+] PDF report : {pdf_path}")


def analyze_log(log_file, output_dir="reports", window=10, dedup=True):

    print("\n========================================")
    print("           SENTINELLOG")
    print("       Security Log Analyzer")
    print("========================================\n")

    print(f"[+] Analyzing: {log_file}")

    events = load_log_file(log_file)

    print(f"[+] Events parsed: {len(events)}")

    alerts = finalize_alerts(
        run_detectors(events),
        dedup=dedup,
        window_minutes=window
    )

    generate_reports(events, alerts, output_dir)


def analyze_all_logs(directory, output_dir="reports", window=10, dedup=True):

    print("\n========================================")
    print("           SENTINELLOG")
    print("       Multi Log Analyzer")
    print("========================================\n")

    print(f"[+] Scanning directory: {directory}")

    events = []

    log_files = sorted(
        glob.glob(os.path.join(directory, "*.log"))
    )

    for logfile in log_files:

        print(f"[+] Loading: {logfile}")

        events.extend(
            load_log_file(logfile)
        )

    print(f"[+] Events parsed: {len(events)}")

    alerts = finalize_alerts(
        run_detectors(events),
        dedup=dedup,
        window_minutes=window
    )

    generate_reports(events, alerts, output_dir)


def show_version():

    print(
        f"SentinelLog version {VERSION}"
    )


def show_rules():

    rules = load_rules(
        "rules/authentication.yaml"
    )

    print("\nAvailable Detection Rules")
    print("-------------------------")

    for number, rule in enumerate(
        rules,
        start=1
    ):

        print(f"{number}. {rule['id']}")
        print(
            f"   Category : "
            f"{rule.get('category', 'N/A')}"
        )

        print(
            f"   Protocol : "
            f"{rule.get('protocol', 'N/A')}"
        )

        print(
            f"   Enabled  : "
            f"{rule.get('enabled', False)}"
        )

        print(
            f"   Description: "
            f"{rule.get('description', 'N/A')}"
        )

        print()
def _add_analysis_options(sub_parser):
    """Add the options shared by analyze and analyze-all."""

    sub_parser.add_argument(
        "--output",
        default="reports",
        help="Output directory"
    )

    sub_parser.add_argument(
        "--window",
        type=int,
        default=10,
        help="Correlation window in minutes"
    )

    sub_parser.add_argument(
        "--no-dedup",
        action="store_true",
        help="Disable alert deduplication"
    )


def main():

    parser = argparse.ArgumentParser(
        description=(
            "SentinelLog - SOC Detection & Incident Analysis Platform"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python src/cli.py analyze-all sample_logs/ "
            "--output reports/ --window 10\n"
            "  python src/cli.py analyze single.log\n"
            "  python src/cli.py version\n"
            "  python src/cli.py rules\n"
        )
    )

    subparsers = parser.add_subparsers(
        dest="command"
    )

    subparsers.add_parser(
        "version",
        help="Show SentinelLog version"
    )

    subparsers.add_parser(
        "rules",
        help="Show available detection rules"
    )

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze a single log file"
    )

    analyze_parser.add_argument(
        "logfile"
    )

    _add_analysis_options(analyze_parser)

    analyze_all_parser = subparsers.add_parser(
        "analyze-all",
        help="Analyze all log files in a directory"
    )

    analyze_all_parser.add_argument(
        "directory"
    )

    _add_analysis_options(analyze_all_parser)

    args = parser.parse_args()

    if args.command == "analyze":

        analyze_log(
            args.logfile,
            output_dir=args.output,
            window=args.window,
            dedup=not args.no_dedup
        )

    elif args.command == "analyze-all":

        analyze_all_logs(
            args.directory,
            output_dir=args.output,
            window=args.window,
            dedup=not args.no_dedup
        )

    elif args.command == "version":

        show_version()

    elif args.command == "rules":

        show_rules()

    else:

        parser.print_help()


if __name__ == "__main__":
    main()
