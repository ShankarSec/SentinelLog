from rule_loader import load_rules


rules = load_rules("rules/ssh.yaml")

print("=== LOADED RULES ===")

for rule in rules:
    print(f"ID          : {rule['id']}")
    print(f"Name        : {rule['name']}")
    print(f"Description : {rule['description']}")
    print(f"MITRE       : {rule['mitre_attack']}")
    print(f"Severity    : {rule['severity']}")
    print()
