import unittest
from unittest.mock import patch

from src.scoring import WEIGHTS, calculate_risk_score


class TestScoring(unittest.TestCase):

    def test_empty_alerts(self):
        result = calculate_risk_score([])
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["classification"], "LOW")
        self.assertEqual(result["max_score"], 100)

    def test_single_critical_alert(self):
        result = calculate_risk_score([{"alert_type": "WEBSHELL"}])
        self.assertEqual(result["risk_score"], WEIGHTS["WEBSHELL"])
        self.assertEqual(result["classification"], "MEDIUM")

    def test_attack_chain_is_critical(self):
        result = calculate_risk_score([{"alert_type": "ATTACK_CHAIN"}])
        self.assertEqual(result["risk_score"], 100)
        self.assertEqual(result["classification"], "CRITICAL")

    def test_score_is_capped_at_100(self):
        alerts = [{"alert_type": "WEBSHELL"}] * 10
        result = calculate_risk_score(alerts)
        self.assertEqual(result["risk_score"], 100)
        self.assertEqual(result["total_weight"], 500)

    def test_unknown_alert_type_weighs_zero(self):
        result = calculate_risk_score([{"alert_type": "NOT_A_REAL_TYPE"}])
        self.assertEqual(result["risk_score"], 0)

    def test_classification_boundaries(self):
        cases = [
            (29, "LOW"), (30, "MEDIUM"), (59, "MEDIUM"),
            (60, "HIGH"), (79, "HIGH"), (80, "CRITICAL"),
        ]

        for target, expected in cases:
            with self.subTest(score=target):
                with patch.dict(WEIGHTS, {"TEST_ALERT": target}):
                    result = calculate_risk_score(
                        [{"alert_type": "TEST_ALERT"}]
                    )

                self.assertEqual(result["risk_score"], target)
                self.assertEqual(result["classification"], expected)


if __name__ == "__main__":
    unittest.main()
