from parser import parse_log_line
from detector import (
    detect_ssh_bruteforce,
    detect_failure_then_success
)
from ioc import extract_iocs
from reporter import (
    save_json_report,
    save_text_report
)


events = []

with open("sample_logs/auth_sample.log", "r") as file:
    for line in file:
        events.append(parse_log_line(line))


# Detect threats
alerts = []

alerts.extend(
    detect_ssh_bruteforce(events)
)

alerts.extend(
    detect_failure_then_success(events)
)


# Extract IOCs
iocs = extract_iocs(events)


# Generate reports
save_json_report(
    alerts,
    iocs,
    "reports/incident_report.json"
)

save_text_report(
    alerts,
    iocs,
    "reports/incident_report.txt"
)


print("=== REPORTING ENGINE TEST ===")
print("Alerts detected:", len(alerts))
print("JSON report: reports/incident_report.json")
print("TXT report : reports/incident_report.txt")
