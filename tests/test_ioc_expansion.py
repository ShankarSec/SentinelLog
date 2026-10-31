import unittest

from src.ioc import extract_iocs


def iocs_for(raw):
    """Extract IOCs from a single raw log line."""
    return extract_iocs([{"raw": raw}])


class TestIOCExpansion(unittest.TestCase):

    def test_url_extraction(self):
        iocs = iocs_for("GET /x?u=https://evil.example.com/payload.exe now")
        self.assertIn("https://evil.example.com/payload.exe", iocs["urls"])

    def test_email_extraction(self):
        iocs = iocs_for("contact admin@corp.example.com please")
        self.assertEqual(iocs["emails"], ["admin@corp.example.com"])

    def test_md5_extraction(self):
        md5 = "5d41402abc4b2a76b9719d911017c592"
        iocs = iocs_for(f"token={md5}")
        self.assertEqual(iocs["md5_hashes"], [md5])
        self.assertEqual(iocs["sha1_hashes"], [])

    def test_sha1_extraction(self):
        sha1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        iocs = iocs_for(f"hash={sha1}")
        self.assertEqual(iocs["sha1_hashes"], [sha1])
        self.assertEqual(iocs["md5_hashes"], [])

    def test_sha256_extraction(self):
        sha256 = "a" * 64
        iocs = iocs_for(f"hash={sha256}")
        self.assertEqual(iocs["sha256_hashes"], [sha256])
        self.assertEqual(iocs["md5_hashes"], [])
        self.assertEqual(iocs["sha1_hashes"], [])

    def test_windows_path_extraction(self):
        iocs = iocs_for(r"file=C:\Windows\System32\config\SAM")
        self.assertIn(r"C:\Windows\System32\config\SAM", iocs["windows_paths"])

    def test_unc_path_extraction(self):
        iocs = iocs_for(r"path=\\fileserver\share\secret.doc 200")
        self.assertIn(r"\\fileserver\share\secret.doc", iocs["windows_paths"])

    def test_registry_key_extraction(self):
        iocs = iocs_for(r"key=HKLM\Software\Microsoft\Windows\Run")
        self.assertEqual(
            iocs["registry_keys"],
            [r"HKLM\Software\Microsoft\Windows\Run"],
        )

    def test_hostname_extraction_excludes_files_and_ips(self):
        iocs = iocs_for("GET /cmd.php 10.10.10.5 evil.example.com payload.exe")
        self.assertIn("evil.example.com", iocs["hostnames"])
        self.assertNotIn("cmd.php", iocs["hostnames"])
        self.assertNotIn("payload.exe", iocs["hostnames"])
        self.assertNotIn("10.10.10.5", iocs["hostnames"])

    def test_results_are_sorted_and_unique(self):
        events = [{"raw": "a@x.com b@x.com"}, {"raw": "a@x.com"}]
        self.assertEqual(extract_iocs(events)["emails"], ["a@x.com", "b@x.com"])

    def test_legacy_keys_are_preserved(self):
        iocs = iocs_for("nothing here")
        for key in ("ip_addresses", "usernames", "ports", "domains",
                    "urls", "hashes"):
            self.assertIn(key, iocs)


if __name__ == "__main__":
    unittest.main()
