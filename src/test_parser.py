import unittest

from parser import parse_log_line


class TestLogParser(unittest.TestCase):

    def test_parse_ssh_authentication_failure(self):
        line = (
            "Sep 26 18:01:01 kali sshd[1001]: "
            "Failed password for admin from 192.168.56.10 "
            "port 40111 ssh2"
        )

        event = parse_log_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event["event_type"], "authentication_failure")
        self.assertEqual(event["username"], "admin")
        self.assertEqual(event["source_ip"], "192.168.56.10")
        self.assertEqual(event["port"], 40111)
        self.assertEqual(event["service"], "ssh")

    def test_parse_ssh_authentication_success(self):
        line = (
            "Sep 26 18:01:09 kali sshd[1005]: "
            "Accepted password for analyst from 192.168.56.10 "
            "port 40115 ssh2"
        )

        event = parse_log_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event["event_type"], "authentication_success")
        self.assertEqual(event["username"], "analyst")
        self.assertEqual(event["source_ip"], "192.168.56.10")
        self.assertEqual(event["port"], 40115)
        self.assertEqual(event["service"], "ssh")

    def test_parsed_event_preserves_raw_log(self):
        line = (
            "Sep 26 18:01:01 kali sshd[1001]: "
            "Failed password for admin from 192.168.56.10 "
            "port 40111 ssh2"
        )

        event = parse_log_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event["raw"], line)

    def test_unrecognized_log_line(self):
        """Check that unrecognized log lines are preserved as unknown events."""
        line = "This is not a recognized log entry"
        event = parse_log_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event["raw"], line)
        self.assertEqual(event["event_type"], "unknown")
        self.assertIsNone(event["source_ip"])
        self.assertIsNone(event["service"])


if __name__ == "__main__":
    unittest.main()
