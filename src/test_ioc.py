from parser import parse_log_line
from ioc import extract_iocs


events = []

with open("sample_logs/auth_sample.log", "r") as file:
    for line in file:
        events.append(parse_log_line(line))


iocs = extract_iocs(events)

print("=== IOC EXTRACTION ===")

print("IP addresses:", iocs["ip_addresses"])
print("Usernames:", iocs["usernames"])
print("Ports:", iocs["ports"])
print("Domains:", iocs["domains"])
print("URLs:", iocs["urls"])
print("Hashes:", iocs["hashes"])
