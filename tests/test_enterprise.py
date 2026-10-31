import unittest
from datetime import datetime, timedelta

from src.parser import parse_log_line
from src.detector import (
    detect_kerberoasting,
    detect_asrep_roasting,
    detect_privilege_escalation_ad,
    detect_s4u_abuse,
    detect_vpn_bruteforce,
    detect_impossible_travel,
    detect_cloud_bruteforce,
    detect_cloud_persistence,
)

BASE = datetime(2026, 10, 23, 10, 0, 0)


def stamp(offset_seconds):
    """Return a log timestamp `offset_seconds` after BASE."""
    return (BASE + timedelta(seconds=offset_seconds)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def ad_events(event_id, count, extra="", user=r"DOMAIN\\svc_backup"):
    """Parse `count` Active Directory log lines."""
    return [
        parse_log_line(
            f"{stamp(i)} EventID={event_id} User={user} "
            f"SourceIP=192.168.1.50 {extra}".rstrip()
        )
        for i in range(count)
    ]


class TestParsers(unittest.TestCase):

    def test_ad_line_is_parsed(self):
        event = ad_events(4769, 1)[0]
        self.assertEqual(event["service"], "active_directory")
        self.assertEqual(event["event_type"], "kerberos_tgs_grant")
        self.assertEqual(event["source_ip"], "192.168.1.50")

    def test_windows_security_line_still_parsed_as_windows(self):
        event = parse_log_line(
            "2026-10-23 10:00:01 EventID=4625 User=Administrator "
            "SourceIP=192.168.1.100"
        )
        self.assertEqual(event["service"], "windows_security")
        self.assertEqual(event["event_type"], "authentication_failure")

    def test_vpn_line_is_parsed(self):
        event = parse_log_line(
            "2026-10-23 10:00:01 [OpenVPN] AUTH_FAILED user=remote_user "
            "ip=203.0.113.50 reason=invalid_password"
        )
        self.assertEqual(event["service"], "vpn")
        self.assertEqual(event["vpn_vendor"], "openvpn")
        self.assertEqual(event["event_type"], "vpn_auth_failure")

    def test_cloud_line_is_parsed(self):
        event = parse_log_line(
            "2026-10-23 10:00:01 source=gcp event=login.userlogin "
            "user=admin@corp.iam.gserviceaccount.com ip=203.0.113.200 "
            "status=FAILURE"
        )
        self.assertEqual(event["cloud_provider"], "gcp")
        self.assertEqual(event["event_type"], "cloud_auth_failure")


class TestActiveDirectory(unittest.TestCase):

    def test_kerberoasting(self):
        alerts = detect_kerberoasting(ad_events(4769, 5))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "KERBEROASTING")
        self.assertEqual(alerts[0]["mitre_attack"]["id"], "T1558.003")

    def test_kerberoasting_below_threshold(self):
        self.assertEqual(detect_kerberoasting(ad_events(4769, 4)), [])

    def test_asrep_roasting(self):
        events = ad_events(4768, 4, "TicketOptions=0x40800000")
        alerts = detect_asrep_roasting(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "ASREP_ROASTING")

    def test_asrep_ignores_normal_tgt_requests(self):
        events = ad_events(4768, 6, "TicketOptions=0x40810000")
        self.assertEqual(detect_asrep_roasting(events), [])

    def test_ad_privilege_escalation(self):
        events = ad_events(
            4732, 1, r"TargetGroup=DOMAIN\Domain Admins", user=r"DOMAIN\jdoe"
        )
        alerts = detect_privilege_escalation_ad(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "AD_PRIVILEGE_ESCALATION")
        self.assertEqual(alerts[0]["severity"], "CRITICAL")

    def test_ad_non_privileged_group_is_ignored(self):
        events = ad_events(4732, 1, r"TargetGroup=DOMAIN\Printer Users")
        self.assertEqual(detect_privilege_escalation_ad(events), [])

    def test_s4u_abuse(self):
        alerts = detect_s4u_abuse(ad_events(4771, 4))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "S4U_ABUSE")


class TestVPN(unittest.TestCase):

    @staticmethod
    def vpn_event(offset, kind, user, ip, vendor="OpenVPN"):
        """Parse a single VPN log line."""
        extra = " reason=bad" if kind == "AUTH_FAILED" else ""
        return parse_log_line(
            f"{stamp(offset)} [{vendor}] {kind} user={user} ip={ip}{extra}"
        )

    def test_vpn_bruteforce(self):
        events = [
            self.vpn_event(i, "AUTH_FAILED", "u", "203.0.113.50")
            for i in range(6)
        ]
        alerts = detect_vpn_bruteforce(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "VPN_BRUTE_FORCE")

    def test_vpn_few_failures_no_alert(self):
        events = [
            self.vpn_event(i, "AUTH_FAILED", "u", "203.0.113.50")
            for i in range(4)
        ]
        self.assertEqual(detect_vpn_bruteforce(events), [])

    def test_impossible_travel(self):
        events = [
            self.vpn_event(0, "AUTH_SUCCESS", "travel", "203.0.113.50"),
            self.vpn_event(30 * 60, "AUTH_SUCCESS", "travel", "198.51.100.99"),
        ]
        alerts = detect_impossible_travel(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "IMPOSSIBLE_TRAVEL")
        self.assertEqual(alerts[0]["time_gap_minutes"], 30)

    def test_same_ip_is_not_impossible_travel(self):
        events = [
            self.vpn_event(0, "AUTH_SUCCESS", "travel", "203.0.113.50"),
            self.vpn_event(60, "AUTH_SUCCESS", "travel", "203.0.113.50"),
        ]
        self.assertEqual(detect_impossible_travel(events), [])

    def test_logins_far_apart_are_not_impossible_travel(self):
        events = [
            self.vpn_event(0, "AUTH_SUCCESS", "travel", "203.0.113.50"),
            self.vpn_event(31 * 60, "AUTH_SUCCESS", "travel", "198.51.100.99"),
        ]
        self.assertEqual(detect_impossible_travel(events), [])


class TestCloud(unittest.TestCase):

    def test_cloud_bruteforce(self):
        events = [
            parse_log_line(
                f"{stamp(i)} source=aws event=ConsoleLogin "
                f"user=root@corp.com ip=203.0.113.100 result=Failure"
            )
            for i in range(5)
        ]
        alerts = detect_cloud_bruteforce(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "CLOUD_BRUTE_FORCE")
        self.assertEqual(alerts[0]["cloud_provider"], "aws")

    def test_cloud_persistence_create_user(self):
        event = parse_log_line(
            f"{stamp(0)} source=aws event=CreateUser user=root@corp.com "
            f"ip=203.0.113.100 target=BackdoorUser"
        )
        alerts = detect_cloud_persistence([event])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "CLOUD_PERSISTENCE")
        self.assertEqual(alerts[0]["severity"], "CRITICAL")

    def test_cloud_persistence_gcp_and_azure(self):
        events = [
            parse_log_line(
                f"{stamp(0)} source=azure event=RoleAssignmentCreated "
                f"user=svc@corp.onmicrosoft.com ip=198.51.100.50 target=Owner"
            ),
            parse_log_line(
                f"{stamp(1)} source=gcp event=iam.setIamPolicy "
                f"user=admin@corp.iam.gserviceaccount.com "
                f"ip=203.0.113.200 target=roles/owner"
            ),
        ]
        self.assertEqual(len(detect_cloud_persistence(events)), 2)

    def test_cloud_login_failure_is_not_persistence(self):
        event = parse_log_line(
            f"{stamp(0)} source=aws event=ConsoleLogin user=root@corp.com "
            f"ip=203.0.113.100 result=Failure"
        )
        self.assertEqual(detect_cloud_persistence([event]), [])


if __name__ == "__main__":
    unittest.main()
