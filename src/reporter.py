import json
from collections import Counter
from datetime import datetime
from html import escape
from pathlib import Path

try:
    from .scoring import calculate_risk_score
except ImportError:
    from scoring import calculate_risk_score


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

SEVERITY_COLORS = {
    "CRITICAL": "#ff4757",
    "HIGH": "#ff6b35",
    "MEDIUM": "#ffd32a",
    "LOW": "#7bed9f",
}

# (iocs key, display label) - order used by every report format
IOC_CATEGORIES = [
    ("ip_addresses", "IP Addresses"),
    ("usernames", "Usernames"),
    ("ports", "Ports"),
    ("domains", "Domains"),
    ("hostnames", "Hostnames"),
    ("urls", "URLs"),
    ("emails", "Email Addresses"),
    ("md5_hashes", "MD5 Hashes"),
    ("sha1_hashes", "SHA1 Hashes"),
    ("sha256_hashes", "SHA256 Hashes"),
    ("windows_paths", "Windows Paths"),
    ("registry_keys", "Registry Keys"),
]


# ----------------------------------------------------------------------
# Shared helpers
# ----------------------------------------------------------------------

def count_iocs(iocs):
    """
    Count unique IOCs across all report categories.
    (The legacy combined 'hashes' list is not counted twice.)
    """
    return sum(len(iocs.get(key, [])) for key, _ in IOC_CATEGORIES)


def _severity_counts(alerts):
    """Return a Counter of alert severities (upper-cased)."""
    return Counter(
        (a.get("severity") or "UNKNOWN").upper() for a in alerts
    )


def _resolve_risk(alerts, risk_score):
    """Use the supplied risk dict, or calculate one from the alerts."""
    return risk_score if risk_score else calculate_risk_score(alerts)


def _timestamp_key(alert):
    """Sort key: timestamped alerts first (oldest first), others last."""
    stamp = alert.get("timestamp")
    return (stamp is None, stamp or "")


def _alert_id(alert, number):
    """Return the alert's ID, falling back to its position."""
    return alert.get("alert_id") or f"ALERT-{number:04d}"


def _time_only(stamp):
    """Return HH:MM:SS from an ISO timestamp string."""
    if not stamp:
        return "--:--:--"

    try:
        return datetime.fromisoformat(stamp).strftime("%H:%M:%S")
    except ValueError:
        return str(stamp)


def _alert_usernames(alert):
    """Collect every username referenced by an alert."""
    names = []

    for key in ("username", "successful_username"):
        if alert.get(key):
            names.append(alert[key])

    names.extend(alert.get("usernames") or [])

    return list(dict.fromkeys(names))


def _mitre_distribution(alerts):
    """Group alerts by MITRE technique: {id: {name, tactic, count}}."""
    table = {}

    for alert in alerts:
        mitre = alert.get("mitre_attack") or {}
        technique = mitre.get("id")

        if not technique:
            continue

        entry = table.setdefault(technique, {
            "name": mitre.get("name", ""),
            "tactic": mitre.get("tactic", ""),
            "count": 0,
        })
        entry["count"] += 1

    return table


def _open_for_write(output_file):
    """Create parent folders and open a UTF-8 text file for writing."""
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    return open(output_path, "w", encoding="utf-8")


# ----------------------------------------------------------------------
# JSON
# ----------------------------------------------------------------------

def save_json_report(alerts, iocs, output_file,
                     risk_score=None, total_events=None):
    """
    Save security analysis results as a JSON report.
    """

    sev_counts = _severity_counts(alerts)
    risk = _resolve_risk(alerts, risk_score)

    summary = {
        "alerts_detected": len(alerts),
        "ioc_count": count_iocs(iocs),
        "severity_breakdown": {
            level: sev_counts.get(level, 0) for level in SEVERITY_ORDER
        },
    }

    if total_events is not None:
        summary["events_parsed"] = total_events

    report = {
        "summary": summary,
        "risk_score": {
            "score": risk["risk_score"],
            "max": risk["max_score"],
            "classification": risk["classification"],
        },
        "alerts": alerts,
        "iocs": iocs,
    }

    with _open_for_write(output_file) as file:
        json.dump(report, file, indent=4, default=str)


# ----------------------------------------------------------------------
# TXT
# ----------------------------------------------------------------------

def save_text_report(alerts, iocs, output_file,
                     risk_score=None, total_events=None):
    """
    Save security analysis results as a human-readable TXT report.
    """

    risk = _resolve_risk(alerts, risk_score)

    with _open_for_write(output_file) as file:

        # Header
        file.write("========================================\n")
        file.write("        SENTINELLOG INCIDENT REPORT\n")
        file.write("========================================\n\n")

        # Risk score
        file.write("RISK SCORE\n")
        file.write("----------------------------------------\n")
        file.write(
            f"Score         : {risk['risk_score']}/{risk['max_score']}\n"
        )
        file.write(f"Classification: {risk['classification']}\n")
        file.write("\n")

        # Severity Summary
        sev_counts = _severity_counts(alerts)

        file.write("SEVERITY SUMMARY\n")
        file.write("----------------------------------------\n")
        file.write(f"CRITICAL : {sev_counts.get('CRITICAL', 0)}\n")
        file.write(f"HIGH     : {sev_counts.get('HIGH', 0)}\n")
        file.write(f"MEDIUM   : {sev_counts.get('MEDIUM', 0)}\n")
        file.write(f"LOW      : {sev_counts.get('LOW', 0)}\n")
        file.write("\n")

        # Statistics
        source_ips = Counter(
            a.get("source_ip") for a in alerts if a.get("source_ip")
        )

        file.write("STATISTICS\n")
        file.write("----------------------------------------\n")

        if total_events is not None:
            file.write(f"Events Parsed: {total_events}\n")

        file.write(f"Total Alerts : {len(alerts)}\n")
        file.write(f"Total IOCs   : {count_iocs(iocs)}\n")
        file.write("\nTop Source IPs:\n")
        for ip, count in source_ips.most_common(5):
            file.write(f"  {ip} ({count})\n")
        file.write("\n")

        # Alerts
        file.write("ALERTS\n")
        file.write("----------------------------------------\n")

        for number, alert in enumerate(alerts, start=1):
            file.write(f"\nAlert ID   : {_alert_id(alert, number)}\n")
            file.write(f"Type       : {alert.get('alert_type')}\n")
            file.write(f"Severity   : {alert.get('severity')}\n")
            file.write(f"Source IP  : {alert.get('source_ip')}\n")
            file.write(f"Timestamp  : {alert.get('timestamp')}\n")
            file.write(f"Description: {alert.get('description')}\n")

            if alert.get("chain"):
                steps = alert.get("chain_readable") or alert["chain"]
                file.write(f"Chain      : {' > '.join(steps)}\n")

            mitre = alert.get("mitre_attack", {})
            file.write(f"MITRE ID   : {mitre.get('id')}\n")
            file.write(f"Technique  : {mitre.get('name')}\n")
            file.write(f"Tactic     : {mitre.get('tactic')}\n")

        # IOCs
        file.write("\nIOCs\n")
        file.write("----------------------------------------\n")

        for key, label in IOC_CATEGORIES:
            file.write(f"{label + ':':<17}{iocs.get(key, [])}\n")


# ----------------------------------------------------------------------
# HTML dashboard
# ----------------------------------------------------------------------

_HTML_CSS = """
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Segoe UI', Arial, sans-serif; background: #1a1a2e;
       color: #eee; padding: 20px; line-height: 1.4; }
.container { max-width: 1200px; margin: 0 auto; }
h1 { text-align: center; color: #00d4ff; margin-bottom: 4px; }
.subtitle { text-align: center; color: #888; margin-bottom: 10px; }
h2 { color: #00d4ff; margin: 28px 0 10px; border-bottom: 1px solid #333;
     padding-bottom: 5px; }
h4 { color: #00d4ff; margin: 14px 0 4px; font-size: 0.95em; }
.cards { display: flex; gap: 15px; flex-wrap: wrap; margin: 15px 0; }
.card { background: #16213e; border-radius: 8px; padding: 20px; flex: 1;
        min-width: 160px; text-align: center; }
.card .number { font-size: 2em; font-weight: bold; color: #00d4ff; }
.card .label { color: #888; font-size: 0.9em; margin-top: 4px; }
table { width: 100%; border-collapse: collapse; margin: 10px 0;
        background: #16213e; border-radius: 8px; overflow: hidden; }
th { background: #0f3460; padding: 10px; text-align: left; }
td { padding: 8px 10px; border-bottom: 1px solid #2a2a4a;
     vertical-align: top; word-break: break-word; }
tr:hover td { background: #1b2a4e; }
tr.chain-row td { background: rgba(255, 71, 87, 0.22); }
.table-wrap { overflow-x: auto; }
.badge { padding: 3px 9px; border-radius: 4px; font-size: 0.85em;
         font-weight: bold; display: inline-block; color: #000; }
.badge.critical { background: #ff4757; color: #fff; }
.badge.high { background: #ff6b35; color: #fff; }
.badge.medium { background: #ffd32a; color: #000; }
.badge.low { background: #7bed9f; color: #000; }
.bar { display: flex; align-items: center; margin: 6px 0; }
.bar .label { width: 170px; font-size: 0.9em; flex-shrink: 0;
              overflow: hidden; text-overflow: ellipsis; }
.bar .fill { height: 20px; border-radius: 3px; background: #00d4ff; }
.bar .count { margin-left: 8px; font-size: 0.9em; }
.chain-box { border: 2px solid #ff4757; border-radius: 8px; padding: 18px;
             margin: 12px 0; background: #16213e; }
.chain-flow { display: flex; flex-wrap: wrap; align-items: center;
              gap: 8px; margin-bottom: 12px; }
.chain-step { background: #0f3460; border: 1px solid #ff4757;
              border-radius: 20px; padding: 7px 14px; font-weight: bold; }
.chain-arrow { color: #ff4757; font-size: 1.3em; }
.chain-meta { color: #bbb; font-size: 0.92em; }
.timeline { border-left: 3px solid #0f3460; margin: 10px 0 10px 8px;
            padding-left: 22px; }
.tl-item { position: relative; margin: 0 0 14px; font-size: 0.93em; }
.tl-dot { position: absolute; left: -31px; top: 4px; width: 14px;
          height: 14px; border-radius: 50%; border: 2px solid #1a1a2e; }
.tl-time { color: #00d4ff; font-family: Consolas, monospace; }
.tl-type { font-weight: bold; margin: 0 6px; }
.tl-ip { color: #aaa; margin-right: 6px; }
.ioc-list { background: #16213e; border-radius: 8px; padding: 10px 14px;
            font-family: Consolas, monospace; font-size: 0.88em;
            word-break: break-all; }
.muted { color: #888; }
@media (max-width: 700px) { .bar .label { width: 110px; } }
"""


def _bar_chart(rows, max_width=300, color="#00d4ff"):
    """Render horizontal bars from [(label, count)] pairs."""
    if not rows:
        return '<p class="muted">No data.</p>'

    peak = max(count for _, count in rows) or 1
    html = ""

    for label, count in rows:
        width = max(int(count / peak * max_width), 4)
        html += (
            '<div class="bar">'
            f'<span class="label">{escape(str(label))}</span>'
            f'<div class="fill" style="width:{width}px;'
            f'background:{color}"></div>'
            f'<span class="count">{count}</span></div>'
        )

    return html


def _html_summary_cards(alerts, iocs, risk, total_events):
    """Section 1: executive summary cards."""
    color = SEVERITY_COLORS.get(risk["classification"], "#00d4ff")
    events = "N/A" if total_events is None else total_events

    return f"""
    <h2>1. Executive Summary</h2>
    <div class="cards">
        <div class="card"><div class="number">{events}</div>
            <div class="label">Total Events Parsed</div></div>
        <div class="card"><div class="number">{len(alerts)}</div>
            <div class="label">Total Alerts</div></div>
        <div class="card"><div class="number">{count_iocs(iocs)}</div>
            <div class="label">Unique IOCs</div></div>
        <div class="card"><div class="number" style="color:{color}">
            {risk['risk_score']}/{risk['max_score']}</div>
            <div class="label">Risk Score</div></div>
        <div class="card"><div class="number">
            <span class="badge {risk['classification'].lower()}">
            {risk['classification']}</span></div>
            <div class="label">Classification</div></div>
    </div>"""


def _html_severity(alerts):
    """Section 2: severity distribution bars."""
    counts = _severity_counts(alerts)
    peak = max([counts.get(s, 0) for s in SEVERITY_ORDER] + [1])
    bars = ""

    for level in SEVERITY_ORDER:
        count = counts.get(level, 0)
        width = int(count / peak * 300)
        bars += (
            '<div class="bar">'
            f'<span class="label">{level}</span>'
            f'<div class="fill" style="width:{width}px;'
            f'background:{SEVERITY_COLORS[level]}"></div>'
            f'<span class="count">{count}</span></div>'
        )

    return f"<h2>2. Severity Distribution</h2>{bars}"


def _html_chains(alerts):
    """Section 3: attack chain flow (only if chains exist)."""
    chains = [a for a in alerts if a.get("alert_type") == "ATTACK_CHAIN"]

    if not chains:
        return ""

    html = "<h2>3. Attack Chain</h2>"

    for chain in chains:
        steps = chain.get("chain_readable") or chain.get("chain") or []
        flow = '<span class="chain-arrow">&rarr;</span>'.join(
            f'<span class="chain-step">{escape(str(step))}</span>'
            for step in steps
        )
        severity = (chain.get("severity") or "CRITICAL")

        html += f"""
        <div class="chain-box">
            <div class="chain-flow">{flow}</div>
            <div class="chain-meta">
                Source IP: <b>{escape(str(chain.get('source_ip')))}</b>
                &nbsp;|&nbsp; Timestamp:
                <b>{escape(str(chain.get('timestamp')))}</b>
                &nbsp;|&nbsp; Severity:
                <span class="badge {severity.lower()}">{escape(severity)}</span>
            </div>
        </div>"""

    return html


def _html_alert_table(alerts):
    """Section 4: alerts table sorted by timestamp."""
    rows = ""

    for number, a in enumerate(sorted(alerts, key=_timestamp_key), 1):
        mitre = a.get("mitre_attack", {})
        sev = (a.get("severity") or "").upper()
        row_class = (
            ' class="chain-row"'
            if a.get("alert_type") == "ATTACK_CHAIN" else ""
        )
        rows += f"""
        <tr{row_class}>
            <td>{escape(_alert_id(a, number))}</td>
            <td>{escape(str(a.get('alert_type', '')))}</td>
            <td><span class="badge {sev.lower()}">{escape(sev)}</span></td>
            <td>{escape(str(a.get('source_ip') or 'N/A'))}</td>
            <td>{escape(str(a.get('timestamp') or 'N/A'))}</td>
            <td>{escape(str(a.get('description', '')))}</td>
            <td>{escape(str(mitre.get('id', '')))}</td>
        </tr>"""

    return f"""
    <h2>4. Alerts</h2>
    <div class="table-wrap"><table>
        <tr><th>Alert ID</th><th>Type</th><th>Severity</th>
        <th>Source IP</th><th>Timestamp</th><th>Description</th>
        <th>MITRE ID</th></tr>
        {rows}
    </table></div>"""


def _html_timeline(alerts):
    """Section 5: vertical timeline."""
    stamped = sorted(
        (a for a in alerts if a.get("timestamp")), key=_timestamp_key
    )
    unstamped = [a for a in alerts if not a.get("timestamp")]

    def node(a):
        color = SEVERITY_COLORS.get(
            (a.get("severity") or "").upper(), "#00d4ff"
        )
        return (
            '<div class="tl-item">'
            f'<span class="tl-dot" style="background:{color}"></span>'
            f'<span class="tl-time">[{_time_only(a.get("timestamp"))}]</span>'
            f'<span class="tl-type">[{escape(str(a.get("alert_type")))}]</span>'
            f'<span class="tl-ip">[{escape(str(a.get("source_ip") or "N/A"))}]</span>'
            f'{escape(str(a.get("description", "")))}</div>'
        )

    html = '<h2>5. Timeline</h2><div class="timeline">'
    html += "".join(node(a) for a in stamped)
    html += "</div>"

    if unstamped:
        html += (
            "<h4>Untimestamped Events</h4>"
            '<div class="timeline">'
            + "".join(node(a) for a in unstamped)
            + "</div>"
        )

    return html


def _html_mitre(alerts):
    """Section 6: MITRE ATT&CK distribution."""
    table = _mitre_distribution(alerts)
    rows = ""

    for technique, entry in sorted(
        table.items(), key=lambda item: (-item[1]["count"], item[0])
    ):
        rows += f"""
        <tr>
            <td>{escape(technique)}</td>
            <td>{escape(entry['name'])}</td>
            <td>{escape(entry['tactic'])}</td>
            <td>{entry['count']}</td>
        </tr>"""

    return f"""
    <h2>6. MITRE ATT&amp;CK Distribution</h2>
    <div class="table-wrap"><table>
        <tr><th>Technique ID</th><th>Name</th><th>Tactic</th>
        <th>Alert Count</th></tr>
        {rows}
    </table></div>"""


def _html_top_sources(alerts):
    """Sections 7 and 8: top source IPs and top users."""
    ips = Counter(
        a.get("source_ip") for a in alerts if a.get("source_ip")
    )
    users = Counter()

    for alert in alerts:
        users.update(_alert_usernames(alert))

    return (
        "<h2>7. Top Source IPs</h2>"
        + _bar_chart(ips.most_common(10))
        + "<h2>8. Top Users</h2>"
        + _bar_chart(users.most_common(5), color="#ff6b35")
    )


def _html_iocs(iocs):
    """Section 9: IOC sub-sections."""
    html = "<h2>9. Indicators of Compromise</h2>"

    for key, label in IOC_CATEGORIES:
        items = iocs.get(key, [])
        body = (
            escape(", ".join(str(x) for x in items))
            if items else '<span class="muted">None found</span>'
        )
        html += f'<h4>{label} ({len(items)})</h4><div class="ioc-list">{body}</div>'

    return html


def save_html_report(alerts, iocs, output_file,
                     risk_score=None, total_events=None):
    """
    Save security analysis results as a self-contained HTML dashboard
    (dark theme, inline CSS, no external dependencies).
    """

    risk = _resolve_risk(alerts, risk_score)
    generated = datetime.now().strftime("%Y-%m-%d %H:%M")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>SentinelLog - Incident Report</title>
    <style>{_HTML_CSS}</style>
</head>
<body>
<div class="container">
    <h1>SENTINELLOG - Incident Report</h1>
    <p class="subtitle">SOC Detection &amp; Incident Analysis Platform
        &middot; Generated {generated}</p>
    {_html_summary_cards(alerts, iocs, risk, total_events)}
    {_html_severity(alerts)}
    {_html_chains(alerts)}
    {_html_alert_table(alerts)}
    {_html_timeline(alerts)}
    {_html_mitre(alerts)}
    {_html_top_sources(alerts)}
    {_html_iocs(iocs)}
</div>
</body>
</html>"""

    with _open_for_write(output_file) as file:
        file.write(html)


# ----------------------------------------------------------------------
# PDF
# ----------------------------------------------------------------------

def _pdf_text(value):
    """Make text safe for the built-in Helvetica font (Latin-1 only)."""
    text = str(value if value is not None else "")
    text = text.replace("\u2192", "->").replace("\u2014", "-")

    return text.encode("latin-1", "replace").decode("latin-1")


def save_pdf_report(alerts, iocs, risk_score, output_file):
    """
    Generate a professional PDF incident report using fpdf2.
    """
    from fpdf import FPDF
    from fpdf.enums import WrapMode

    risk = _resolve_risk(alerts, risk_score)
    total_ioc_count = count_iocs(iocs)
    sev_counts = _severity_counts(alerts)

    class ReportPDF(FPDF):
        """PDF with a page-number footer."""

        def footer(self):
            """Draw the page footer."""
            self.set_y(-12)
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(120, 120, 120)
            self.cell(0, 8, f"SentinelLog - Page {self.page_no()}",
                      align="C")
            self.set_text_color(0, 0, 0)

    pdf = ReportPDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    def line(text, height=7, style="", size=11):
        """Write one wrapped line of text starting at the left margin."""
        pdf.set_font("Helvetica", style, size)
        pdf.multi_cell(
            0, height, _pdf_text(text),
            new_x="LMARGIN", new_y="NEXT", wrapmode=WrapMode.CHAR
        )

    def heading(text):
        """Write a section heading."""
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, _pdf_text(text), new_x="LMARGIN", new_y="NEXT")

    # Page 1: Cover
    pdf.add_page()
    pdf.ln(40)
    pdf.set_font("Helvetica", "B", 24)
    pdf.cell(0, 12, "SENTINELLOG", align="C",
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 14)
    pdf.cell(0, 10, "SOC Incident Report", align="C",
             new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 8, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
             align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8,
             f"Risk Score: {risk['risk_score']}/100 "
             f"({risk['classification']})",
             align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 8, f"Total Alerts: {len(alerts)}", align="C",
             new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Total IOCs: {total_ioc_count}", align="C",
             new_x="LMARGIN", new_y="NEXT")

    # Page 2: Severity Summary + Statistics
    pdf.add_page()
    heading("Severity Summary")
    for level in SEVERITY_ORDER:
        line(f"{level:<10}: {sev_counts.get(level, 0)}")

    pdf.ln(4)
    heading("Statistics")
    line(f"Total Alerts : {len(alerts)}")
    line(f"Total IOCs   : {total_ioc_count}")

    pdf.ln(2)
    line("Top Source IPs", style="B")
    source_ips = Counter(
        a.get("source_ip") for a in alerts if a.get("source_ip")
    )
    for ip, count in source_ips.most_common(5):
        line(f"  {ip} ({count})")

    chains = [a for a in alerts if a.get("alert_type") == "ATTACK_CHAIN"]
    if chains:
        pdf.ln(4)
        heading("Attack Chains")
        for chain in chains:
            line(chain.get("description", ""))

    # Page 3+: Alerts (table format)
    pdf.add_page()
    heading("Alerts")

    widths = (24, 58, 20, 30, 58)
    headers = ("Alert ID", "Type", "Severity", "Source IP", "MITRE")

    def table_header():
        """Draw the alerts table header row."""
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(15, 52, 96)
        pdf.set_text_color(255, 255, 255)
        for width, title in zip(widths, headers):
            pdf.cell(width, 7, title, border=1, fill=True)
        pdf.ln()
        pdf.set_text_color(0, 0, 0)

    table_header()

    for number, alert in enumerate(alerts, start=1):
        if pdf.get_y() > 255:
            pdf.add_page()
            table_header()

        mitre = alert.get("mitre_attack", {})
        sev = (alert.get("severity") or "").upper()
        is_chain = alert.get("alert_type") == "ATTACK_CHAIN"

        if is_chain:
            pdf.set_fill_color(255, 220, 224)
        else:
            pdf.set_fill_color(245, 245, 250)

        pdf.set_font("Helvetica", "B" if is_chain else "", 9)
        cells = (
            _alert_id(alert, number),
            alert.get("alert_type", ""),
            sev,
            alert.get("source_ip") or "N/A",
            f"{mitre.get('id', '')} {mitre.get('name', '')}",
        )
        for width, text in zip(widths, cells):
            pdf.cell(width, 6, _pdf_text(text)[:40], border="LTR",
                     fill=True)
        pdf.ln()

        pdf.set_font("Helvetica", "", 8)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(
            sum(widths), 5,
            _pdf_text(
                f"{alert.get('timestamp') or 'no timestamp'} - "
                f"{alert.get('description', '')}"
            ),
            border="LBR", new_x="LMARGIN", new_y="NEXT",
            wrapmode=WrapMode.CHAR
        )

    # Last page: IOCs
    pdf.add_page()
    heading("Indicators of Compromise")

    for key, label in IOC_CATEGORIES:
        items = iocs.get(key, [])
        line(f"{label} ({len(items)})", style="B", size=10)
        line(", ".join(str(x) for x in items) if items else "None found",
             height=5, size=9)
        pdf.ln(1)

    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(output_path))
