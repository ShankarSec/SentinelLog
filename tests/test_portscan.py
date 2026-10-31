import unittest

from src.parser import parse_log_line
from src.detector import detect_port_scan


class TestPortScan(unittest.TestCase):

    def test_port_scan(self):

        lines = [
            "2026-10-23 SRC=1.1.1.1 DST=2.2.2.2 DPT=22",
            "2026-10-23 SRC=1.1.1.1 DST=2.2.2.2 DPT=80",
            "2026-10-23 SRC=1.1.1.1 DST=2.2.2.2 DPT=135",
            "2026-10-23 SRC=1.1.1.1 DST=2.2.2.2 DPT=445",
            "2026-10-23 SRC=1.1.1.1 DST=2.2.2.2 DPT=3389",
        ]

        events = [
            parse_log_line(line)
            for line in lines
        ]

        alerts = detect_port_scan(events)

        self.assertEqual(
            len(alerts),
            1
        )


if __name__ == "__main__":
    unittest.main()
