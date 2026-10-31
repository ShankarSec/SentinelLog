# Attack Chain Correlation

## How it works

`detect_attack_chain(alerts, window_minutes=10)` in `src/detector.py`:

1. Skips alerts that have no `source_ip` or no usable `timestamp`.
2. Groups the remaining alerts by source IP and sorts each group by time.
3. Slides a window of `window_minutes` over each group and counts the
   **distinct alert types** inside it.
4. If the best window holds **3 or more** distinct types, it emits **one**
   `ATTACK_CHAIN` alert (severity `CRITICAL`) for that IP.

The chain is **additional**: the individual alerts stay in the report.
`ATTACK_CHAIN` alerts are never deduplicated and never feed the correlation
engine themselves.

The pipeline order matters: detectors -> deduplication -> correlation ->
alert IDs -> scoring -> reports.

## Window configuration

```
python src/cli.py analyze-all sample_logs/ --window 10
```

`--window` is in minutes (default 10). A larger window finds slower attacks
but increases false positives; a smaller window only reports fast,
automated attacks.

## Example chain output

```json
{
    "alert_id": "ALERT-0006",
    "alert_type": "ATTACK_CHAIN",
    "severity": "CRITICAL",
    "source_ip": "10.10.10.5",
    "timestamp": "2026-10-23T09:59:50",
    "chain": ["PORT_SCAN", "DNS_TUNNELING", "WEB_RECONNAISSANCE",
              "DIRECTORY_TRAVERSAL", "SQL_INJECTION", "COMMAND_INJECTION"],
    "chain_count": 6,
    "description": "Multi-stage attack chain detected from 10.10.10.5: Port Scan → DNS Tunneling → Web Recon → Directory Traversal → SQL Injection → Command Injection",
    "mitre_attack": {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"}
}
```

`chain` lists the alert types in order of first appearance; `chain_readable`
holds the display names used in the HTML dashboard and PDF.

## False-positive considerations

- **Shared IPs** - NAT gateways, proxies, VPN concentrators and scanners
  aggregate many users behind one IP, so unrelated alerts can look like a
  chain. Review the underlying alerts before escalating.
- **Authorized scanning** - vulnerability scanners and pen-test hosts
  legitimately trigger port-scan, web-recon and injection alerts together.
  Allow-list known scanner IPs.
- **Timestamp quality** - date-only logs resolve to midnight, which can
  group unrelated events or split a real chain. Prefer logs with full
  timestamps. Alerts without timestamps are skipped.
- **Clock skew** - log sources with different clocks can reorder events.
- **Deduplication** - because alerts are deduplicated per
  `(source_ip, alert_type)` first, a chain never counts the same type twice.
- **Window size** - tune `--window` to your environment.
