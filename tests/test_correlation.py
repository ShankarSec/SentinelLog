import unittest

from src.detector import detect_attack_chain


def make_alert(alert_type, ip, timestamp):
    """Build a minimal alert dict for correlation tests."""
    return {
        "alert_type": alert_type,
        "source_ip": ip,
        "timestamp": timestamp,
        "severity": "HIGH",
    }


class TestAttackChain(unittest.TestCase):

    def test_three_alerts_same_ip_creates_chain(self):
        alerts = [
            make_alert("PORT_SCAN", "10.0.0.1", "2026-10-23T10:00:00"),
            make_alert("WEB_RECONNAISSANCE", "10.0.0.1", "2026-10-23T10:01:00"),
            make_alert("SQL_INJECTION", "10.0.0.1", "2026-10-23T10:02:00"),
        ]

        chains = detect_attack_chain(alerts)

        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0]["alert_type"], "ATTACK_CHAIN")
        self.assertEqual(chains[0]["severity"], "CRITICAL")
        self.assertEqual(chains[0]["chain_count"], 3)
        self.assertEqual(
            chains[0]["chain"],
            ["PORT_SCAN", "WEB_RECONNAISSANCE", "SQL_INJECTION"],
        )
        self.assertIn("Port Scan", chains[0]["description"])
        self.assertEqual(chains[0]["mitre_attack"]["id"], "T1595")

    def test_two_alerts_no_chain(self):
        alerts = [
            make_alert("PORT_SCAN", "10.0.0.1", "2026-10-23T10:00:00"),
            make_alert("SQL_INJECTION", "10.0.0.1", "2026-10-23T10:01:00"),
        ]

        self.assertEqual(detect_attack_chain(alerts), [])

    def test_repeated_same_type_is_not_a_chain(self):
        alerts = [
            make_alert("PORT_SCAN", "10.0.0.1", "2026-10-23T10:00:00"),
            make_alert("PORT_SCAN", "10.0.0.1", "2026-10-23T10:01:00"),
            make_alert("PORT_SCAN", "10.0.0.1", "2026-10-23T10:02:00"),
        ]

        self.assertEqual(detect_attack_chain(alerts), [])

    def test_different_ips_are_not_correlated(self):
        alerts = [
            make_alert("PORT_SCAN", "10.0.0.1", "2026-10-23T10:00:00"),
            make_alert("WEB_RECONNAISSANCE", "10.0.0.2", "2026-10-23T10:01:00"),
            make_alert("SQL_INJECTION", "10.0.0.3", "2026-10-23T10:02:00"),
        ]

        self.assertEqual(detect_attack_chain(alerts), [])

    def test_alerts_outside_window_are_not_chained(self):
        alerts = [
            make_alert("PORT_SCAN", "10.0.0.1", "2026-10-23T10:00:00"),
            make_alert("WEB_RECONNAISSANCE", "10.0.0.1", "2026-10-23T10:20:00"),
            make_alert("SQL_INJECTION", "10.0.0.1", "2026-10-23T10:40:00"),
        ]

        self.assertEqual(detect_attack_chain(alerts, window_minutes=10), [])
        self.assertEqual(len(detect_attack_chain(alerts, window_minutes=60)), 1)

    def test_alerts_without_timestamp_are_skipped(self):
        alerts = [
            make_alert("PORT_SCAN", "10.0.0.1", None),
            make_alert("WEB_RECONNAISSANCE", "10.0.0.1", None),
            make_alert("SQL_INJECTION", "10.0.0.1", "2026-10-23T10:02:00"),
            {"alert_type": "WEBSHELL", "timestamp": "2026-10-23T10:03:00"},
        ]

        self.assertEqual(detect_attack_chain(alerts), [])

    def test_one_chain_per_ip_and_input_not_modified(self):
        alerts = [
            make_alert("PORT_SCAN", "10.0.0.1", "2026-10-23T10:00:00"),
            make_alert("WEB_RECONNAISSANCE", "10.0.0.1", "2026-10-23T10:01:00"),
            make_alert("SQL_INJECTION", "10.0.0.1", "2026-10-23T10:02:00"),
            make_alert("COMMAND_INJECTION", "10.0.0.1", "2026-10-23T10:03:00"),
        ]

        chains = detect_attack_chain(alerts)

        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0]["chain_count"], 4)
        self.assertEqual(len(alerts), 4)


if __name__ == "__main__":
    unittest.main()
