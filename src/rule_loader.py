import yaml
from pathlib import Path


def load_rules(rule_file):
    """
    Load detection rules from a YAML file.
    """

    rule_path = Path(rule_file)

    if not rule_path.exists():
        raise FileNotFoundError(
            f"Rule file not found: {rule_file}"
        )

    with open(rule_path, "r") as file:
        data = yaml.safe_load(file)

    return data.get("rules", [])
