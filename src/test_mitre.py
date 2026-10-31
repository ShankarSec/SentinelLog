from mitre import get_mitre_mapping


print("=== MITRE ATT&CK MAPPING ===")

print(
    "SSH_BRUTE_FORCE:",
    get_mitre_mapping("SSH_BRUTE_FORCE")
)

print(
    "SSH_FAILURES_THEN_SUCCESS:",
    get_mitre_mapping("SSH_FAILURES_THEN_SUCCESS")
)

print(
    "UNKNOWN_ALERT:",
    get_mitre_mapping("UNKNOWN_ALERT")
)
