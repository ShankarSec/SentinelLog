import re


# File extensions that must not be classified as domains / hostnames
NON_DOMAIN_EXTENSIONS = {
    "exe", "dll", "sys", "bat", "cmd",
    "ps1", "psm1", "vbs", "js", "msi",
    "scr", "cpl", "drv", "ocx", "sh",
    "py", "jar", "log", "txt", "json",
    "xml", "yaml", "yml", "ini", "conf",
    "cfg", "dat", "zip", "rar", "pdf",
    "doc", "docx", "xls", "xlsx", "png",
    "jpg", "jpeg", "gif", "html", "css",
    "php", "aspx", "asp", "jsp", "htm",
    "bak", "tmp", "key", "pem", "sam",
}

IPV4_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

URL_PATTERN = re.compile(r'https?://[^\s"<>]+')
EMAIL_PATTERN = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
WINDOWS_PATH_PATTERN = re.compile(r'[A-Za-z]:\\[^\s,"\'<>|*?]+')
UNC_PATH_PATTERN = re.compile(r'\\\\[A-Za-z0-9_.]+\\[^\s,"\'<>|*?]+')
REGISTRY_PATTERN = re.compile(r'HK(?:LM|CU|CR|U|CC)\\[^\s,"\'<>|*?]+')
HOSTNAME_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)


def extract_iocs(events):
    """
    Extract Indicators of Compromise from parsed events.

    Scans structured event fields and every raw log line. Returns a dict
    of sorted, de-duplicated lists (legacy v1.0 keys are preserved).
    """
    ip_addresses = set()
    usernames = set()
    ports = set()
    domains = set()
    urls = set()
    hashes = set()
    emails = set()
    md5_hashes = set()
    sha1_hashes = set()
    sha256_hashes = set()
    windows_paths = set()
    registry_keys = set()
    hostnames = set()

    for event in events:

        # Extract structured IP
        if event.get("source_ip"):
            ip_addresses.add(event["source_ip"])

        # Extract username
        if event.get("username"):
            usernames.add(event["username"])

        # Extract port
        if event.get("port"):
            ports.add(event["port"])

        # Analyze raw log line for additional IOCs
        raw = event.get("raw", "")

        # IPv4 addresses
        found_ips = re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            raw
        )

        for ip in found_ips:
            ip_addresses.add(ip)

        # URLs
        found_urls = re.findall(
            r"https?://[^\s]+",
            raw
        )

        for url in found_urls:
            urls.add(url)

        # Domain names
        # Cloud API names (event=iam.setIamPolicy) look like domains
        host_text = re.sub(r"\bevent=\S+", "", raw)

        found_domains = re.findall(
            r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
            host_text
        )

        non_domain_extensions = NON_DOMAIN_EXTENSIONS

        for domain in found_domains:
            extension = domain.rsplit(".", 1)[-1].lower()

            if extension not in non_domain_extensions:
                domains.add(domain)

        # MD5 / SHA1 / SHA256 hashes
        found_hashes = re.findall(
            r"\b[a-fA-F0-9]{32}\b|"
            r"\b[a-fA-F0-9]{40}\b|"
            r"\b[a-fA-F0-9]{64}\b",
            raw
        )

        for file_hash in found_hashes:
            hashes.add(file_hash)

        # ---- Extended IOC types (v2.0) ----
        for url in URL_PATTERN.findall(raw):
            urls.add(url)

        for email in EMAIL_PATTERN.findall(raw):
            emails.add(email.rstrip("."))

        md5_hashes.update(MD5_PATTERN.findall(raw))
        sha1_hashes.update(SHA1_PATTERN.findall(raw))
        sha256_hashes.update(SHA256_PATTERN.findall(raw))

        windows_paths.update(WINDOWS_PATH_PATTERN.findall(raw))
        windows_paths.update(UNC_PATH_PATTERN.findall(raw))
        registry_keys.update(REGISTRY_PATTERN.findall(raw))

        for host in HOSTNAME_PATTERN.findall(host_text):
            tld = host.rsplit(".", 1)[-1].lower()

            if IPV4_PATTERN.match(host) or tld in NON_DOMAIN_EXTENSIONS:
                continue

            hostnames.add(host)

    return {
        "ip_addresses": sorted(ip_addresses),
        "usernames": sorted(usernames),
        "ports": sorted(ports),
        "domains": sorted(domains),
        "urls": sorted(urls),
        "hashes": sorted(hashes),
        "emails": sorted(emails),
        "md5_hashes": sorted(md5_hashes),
        "sha1_hashes": sorted(sha1_hashes),
        "sha256_hashes": sorted(sha256_hashes),
        "windows_paths": sorted(windows_paths),
        "registry_keys": sorted(registry_keys),
        "hostnames": sorted(hostnames),
    }
