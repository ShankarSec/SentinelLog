import unittest

from src.parser import parse_log_line

class TestSysmon(unittest.TestCase):

    def test_sysmon_process_creation(self):

        line = (
            '2026-10-23 EventID=1 '
            'Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe '
            'CommandLine="powershell.exe -enc TEST"'
        )

        event = parse_log_line(line)

        self.assertEqual(
            event["event_type"],
            "sysmon_process_creation"
        )

if __name__ == "__main__":
    unittest.main()
