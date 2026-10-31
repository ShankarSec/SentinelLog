import unittest

from src.cli import deduplicate_alerts, finalize_alerts


def make_alert(alert_type, ip, timestamp="2026-10-23T10:00:00"):
    """Build a minimal alert dict for dedup tests."""
    return {
        "alert_type": alert_type,
        "source_ip": ip,
        "timestamp": timestamp,
        "severity": "HIGH",
    }


class TestDeduplication(unittest.TestCase):

    def test_same_type_same_ip_is_collapsed(self):
        alerts = [make_alert("SQL_INJECTION", "10.10.10.5")] * 3
        self.assertEqual(len(deduplicate_alerts(alerts)), 1)

    def test_same_type_different_ips_are_kept(self):
        alerts = [
            make_alert("SQL_INJECTION", "10.10.10.5"),
            make_alert("SQL_INJECTION", "10.10.10.6"),
        ]
        self.assertEqual(len(deduplicate_alerts(alerts)), 2)

    def test_different_types_same_ip_are_kept(self):
        alerts = [
            make_alert("SQL_INJECTION", "10.10.10.5"),
            make_alert("COMMAND_INJECTION", "10.10.10.5"),
        ]
        self.assertEqual(len(deduplicate_alerts(alerts)), 2)

    def test_attack_chain_is_never_deduplicated(self):
        alerts = [make_alert("ATTACK_CHAIN", "10.10.10.5")] * 2
        self.assertEqual(len(deduplicate_alerts(alerts)), 2)

    def test_alerts_without_source_ip_are_kept(self):
        alerts = [
            {"alert_type": "ACCOUNT_CREATED", "username": "a"},
            {"alert_type": "ACCOUNT_CREATED", "username": "b"},
        ]
        self.assertEqual(len(deduplicate_alerts(alerts)), 2)

    def test_first_occurrence_is_kept(self):
        first = make_alert("SQL_INJECTION", "10.10.10.5", "2026-10-23T10:00:00")
        later = make_alert("SQL_INJECTION", "10.10.10.5", "2026-10-23T11:00:00")
        self.assertIs(deduplicate_alerts([first, later])[0], first)


class TestFinalizeAlerts(unittest.TestCase):

    def test_alert_ids_are_sequential_and_first_field(self):
        alerts = [
            make_alert("PORT_SCAN", "10.0.0.1", "2026-10-23T10:00:00"),
            make_alert("WEB_RECONNAISSANCE", "10.0.0.1", "2026-10-23T10:01:00"),
            make_alert("SQL_INJECTION", "10.0.0.1", "2026-10-23T10:02:00"),
        ]

        result = finalize_alerts(alerts)

        self.assertEqual(
            [a["alert_id"] for a in result],
            ["ALERT-0001", "ALERT-0002", "ALERT-0003", "ALERT-0004"],
        )
        self.assertEqual(next(iter(result[0])), "alert_id")
        self.assertEqual(
            sum(1 for a in result if a["alert_type"] == "ATTACK_CHAIN"), 1
        )

    def test_no_dedup_keeps_duplicates(self):
        alerts = [make_alert("SQL_INJECTION", "10.10.10.5")] * 3
        self.assertEqual(len(finalize_alerts(alerts, dedup=False)), 3)
        self.assertEqual(len(finalize_alerts(alerts, dedup=True)), 1)

    def test_untimestamped_alerts_sort_last(self):
        alerts = [
            {"alert_type": "SYSMON_SUSPICIOUS_PROCESS"},
            make_alert("PORT_SCAN", "10.0.0.1"),
        ]
        result = finalize_alerts(alerts)
        self.assertEqual(result[0]["alert_type"], "PORT_SCAN")


if __name__ == "__main__":
    unittest.main()
