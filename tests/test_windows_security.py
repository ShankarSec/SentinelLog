import unittest

from src.parser import parse_log_line


class TestWindowsSecurity(unittest.TestCase):

    def test_4625(self):

        line = (
            "2026-10-23 EventID=4625 "
            "User=Administrator "
            "SourceIP=192.168.1.100"
        )

        event = parse_log_line(line)

        self.assertEqual(
            event["event_type"],
            "authentication_failure"
        )


if __name__ == "__main__":
    unittest.main()
