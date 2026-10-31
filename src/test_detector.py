import unittest

from parser import parse_log_line
from detector import (
    detect_ssh_bruteforce,
    detect_failure_then_success,
)


class TestSSHDetection(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Load the sample authentication log once."""
        cls.events = []

        with open("sample_logs/auth_sample.log", "r") as file:
            for line in file:
                event = parse_log_line(line)

                if event:
                    cls.events.append(event)

    def test_ssh_bruteforce_detection(self):
        """Check that SSH brute-force activity is detected."""
        alerts = detect_ssh_bruteforce(self.events)

        self.assertTrue(
            alerts,
            "Expected an SSH brute-force alert, but none was generated.",
        )

        alert = alerts[0]

        self.assertEqual(alert["alert_type"], "AUTH_BRUTE_FORCE")
        self.assertEqual(alert["severity"], "MEDIUM")
        self.assertEqual(alert["failed_attempts"], 4)

    def test_failure_then_success_detection(self):
        """Check that failed logins followed by success are detected."""
        alerts = detect_failure_then_success(self.events)

        self.assertTrue(
            alerts,
            "Expected a failure-then-success alert, but none was generated.",
        )

        alert = alerts[0]

        self.assertEqual(
            alert["alert_type"],
            "AUTH_FAILURES_THEN_SUCCESS",
        )
        self.assertEqual(alert["severity"], "HIGH")
        self.assertEqual(alert["failed_attempts"], 4)

    def test_bruteforce_mitre_mapping(self):
        """Check the MITRE ATT&CK mapping for SSH brute force."""
        alerts = detect_ssh_bruteforce(self.events)

        self.assertTrue(alerts, "No SSH brute-force alert was generated.")

        self.assertEqual(
            alerts[0]["mitre_attack"]["id"],
            "T1110",
        )


if __name__ == "__main__":
    unittest.main()

