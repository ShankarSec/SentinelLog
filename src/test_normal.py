from parser import parse_log_line
from detector import (
    detect_ssh_bruteforce,
    detect_failure_then_success
)


events = []

with open("sample_logs/normal_login.log", "r") as file:
    for line in file:
        events.append(parse_log_line(line))


bruteforce_alerts = detect_ssh_bruteforce(events)
sequence_alerts = detect_failure_then_success(events)


print("Brute-force alerts:", bruteforce_alerts)
print("Failure → success alerts:", sequence_alerts)
