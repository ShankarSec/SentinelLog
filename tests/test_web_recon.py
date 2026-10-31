import unittest

from src.parser import parse_log_line
from src.detector import detect_web_recon

class TestWebRecon(unittest.TestCase):

    def test_web_recon(self):

        lines = [
            '[2026-10-23 10:00:01] 1.1.1.1 - - "GET /admin HTTP/1.1" 200 "UA"',
            '[2026-10-23 10:00:02] 1.1.1.1 - - "GET /config HTTP/1.1" 200 "UA"',
            '[2026-10-23 10:00:03] 1.1.1.1 - - "GET /phpmyadmin HTTP/1.1" 200 "UA"',
        ]

        events = [parse_log_line(x) for x in lines]

        alerts = detect_web_recon(events)

        self.assertEqual(len(alerts), 1)

if __name__ == "__main__":
    unittest.main()
