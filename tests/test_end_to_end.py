import json
import tempfile
import unittest
from pathlib import Path

from src.cli import analyze_all_logs

ROOT = Path(__file__).resolve().parent.parent

NEW_ALERT_TYPES = {
    "KERBEROASTING", "ASREP_ROASTING", "AD_PRIVILEGE_ESCALATION",
    "S4U_ABUSE", "VPN_BRUTE_FORCE", "IMPOSSIBLE_TRAVEL",
    "CLOUD_BRUTE_FORCE", "CLOUD_PERSISTENCE",
}


class TestEndToEnd(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Run the full pipeline once on the bundled sample logs."""
        cls.tmp = tempfile.TemporaryDirectory()
        analyze_all_logs(str(ROOT / "sample_logs"), output_dir=cls.tmp.name)
        cls.out = Path(cls.tmp.name)
        cls.report = json.loads(
            (cls.out / "incident_report.json").read_text(encoding="utf-8")
        )

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_all_four_report_formats_are_written(self):
        for name in ("txt", "json", "html", "pdf"):
            path = self.out / f"incident_report.{name}"
            self.assertTrue(path.exists(), name)
            self.assertGreater(path.stat().st_size, 0, name)

        pdf = (self.out / "incident_report.pdf").read_bytes()
        self.assertTrue(pdf.startswith(b"%PDF"))

    def test_alert_volume_and_risk(self):
        self.assertGreaterEqual(self.report["summary"]["alerts_detected"], 38)
        self.assertGreaterEqual(self.report["risk_score"]["score"], 95)
        self.assertEqual(self.report["risk_score"]["classification"], "CRITICAL")

    def test_enterprise_alert_types_present(self):
        types = {a["alert_type"] for a in self.report["alerts"]}
        self.assertTrue(NEW_ALERT_TYPES <= types, NEW_ALERT_TYPES - types)
        self.assertIn("ATTACK_CHAIN", types)

    def test_alert_ids_unique_and_first(self):
        ids = [a["alert_id"] for a in self.report["alerts"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(ids[0], "ALERT-0001")
        self.assertEqual(next(iter(self.report["alerts"][0])), "alert_id")

    def test_every_alert_has_a_timestamp_key(self):
        for alert in self.report["alerts"]:
            self.assertIn("timestamp", alert)

    def test_new_ioc_types_populated(self):
        iocs = self.report["iocs"]
        for key in ("urls", "emails", "md5_hashes", "sha1_hashes",
                    "windows_paths", "registry_keys", "hostnames"):
            self.assertTrue(iocs[key], key)

    def test_html_has_all_sections(self):
        html = (self.out / "incident_report.html").read_text(encoding="utf-8")
        for title in ("Executive Summary", "Severity Distribution",
                      "Attack Chain", "Alerts", "Timeline",
                      "MITRE ATT&amp;CK Distribution", "Top Source IPs",
                      "Top Users", "Indicators of Compromise"):
            self.assertIn(title, html, title)
        # Self-contained: no scripts, no external stylesheets or images
        self.assertNotIn("<script", html)
        self.assertNotIn("<link", html)
        self.assertNotIn("<img", html)


if __name__ == "__main__":
    unittest.main()
