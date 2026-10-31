import unittest

from src.parser import parse_log_line
from src.detector import detect_apache_attacks

class TestApache(unittest.TestCase):

    def test_apache_attack(self):

        line = (
            "[client 1.1.1.1] "
            "GET ../../etc/passwd"
        )

        event = parse_log_line(line)

        alerts = detect_apache_attacks(
            [event]
        )

        self.assertEqual(
            len(alerts),
            1
        )

if __name__ == "__main__":
    unittest.main()
