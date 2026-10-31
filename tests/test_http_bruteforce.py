import unittest

from src.parser import parse_log_line
from src.detector import detect_http_bruteforce


class TestHttpBruteforce(unittest.TestCase):

    def test_http_bruteforce(self):

        lines = [
            '[2024-11-13 12:15:32] 1.1.1.1 - - "POST /login HTTP/1.1" 401 "UA"',
            '[2024-11-13 12:15:33] 1.1.1.1 - - "POST /login HTTP/1.1" 401 "UA"',
            '[2024-11-13 12:15:34] 1.1.1.1 - - "POST /login HTTP/1.1" 401 "UA"',
            '[2024-11-13 12:15:35] 1.1.1.1 - - "POST /login HTTP/1.1" 401 "UA"',
        ]

        events = [
            parse_log_line(line)
            for line in lines
        ]

        alerts = detect_http_bruteforce(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["alert_type"],
            "HTTP_BRUTE_FORCE"
        )


if __name__ == "__main__":
    unittest.main()
