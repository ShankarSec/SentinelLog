import unittest

from src.parser import parse_log_line
from src.detector import detect_dns_tunneling

class TestDNS(unittest.TestCase):

    def test_dns_tunneling(self):

        lines = [
            "2026-10-23 SRC=1.1.1.1 QUERY=aaaaaaaaaaaa.example.com TYPE=A",
            "2026-10-23 SRC=1.1.1.1 QUERY=bbbbbbbbbbbb.example.com TYPE=A",
            "2026-10-23 SRC=1.1.1.1 QUERY=cccccccccccc.example.com TYPE=A",
            "2026-10-23 SRC=1.1.1.1 QUERY=dddddddddddd.example.com TYPE=A",
            "2026-10-23 SRC=1.1.1.1 QUERY=eeeeeeeeeeee.example.com TYPE=A",
        ]

        events = [parse_log_line(line) for line in lines]

        alerts = detect_dns_tunneling(events)

        self.assertEqual(len(alerts), 1)

if __name__ == "__main__":
    unittest.main()
