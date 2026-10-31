# Architecture

SentinelLog is an offline, file-based pipeline. Nothing is sent over the
network and no database is used.

```
┌─────────────┐     ┌─────────┐     ┌────────────┐     ┌─────────────┐     ┌──────────┐
│  Log Files  │────▶│ Parser  │────▶│ Detectors  │────▶│ Correlation │────▶│ Reporter │
└─────────────┘     └─────────┘     └────────────┘     └─────────────┘     └──────────┘
                                                                  │
                                                                  ▼
                                                           ┌─────────────┐
                                                           │  Scoring    │
                                                           └─────────────┘
```

## Data flow

1. **Log files** - `analyze-all` reads every `*.log` file in a directory
   (`analyze` reads a single file). Each non-empty line becomes one event.
2. **Parser** (`src/parser.py`) - turns a raw line into an event dict
   (`timestamp`, `event_type`, `service`, `source_ip`, `username`, ...).
   Unrecognised lines are kept as `unknown` events so IOC extraction still
   sees them.
3. **Detectors** (`src/detector.py`) - 27 detection rules read the event list
   and emit alert dicts. Every alert carries `alert_type`, `severity`,
   `timestamp`, a description and a MITRE ATT&CK mapping.
4. **Deduplication** (`src/cli.py`) - alerts with the same
   `(source_ip, alert_type)` are collapsed (disable with `--no-dedup`).
5. **Correlation** (`detect_attack_chain`) - 3+ distinct alert types from the
   same IP inside the window (`--window`, default 10 min) produce one
   `ATTACK_CHAIN` alert. Individual alerts are kept.
6. **Alert IDs** - alerts are ordered by timestamp and numbered
   `ALERT-0001`, `ALERT-0002`, ...
7. **Scoring** (`src/scoring.py`) - alert weights are summed and capped at
   100 to give the risk score and classification.
8. **IOC extraction** (`src/ioc.py`) - 12 IOC categories are pulled from the
   structured fields and every raw log line.
9. **Reporter** (`src/reporter.py`) - writes TXT, JSON, HTML dashboard and PDF.

## Module responsibilities

| Module | Responsibility |
|---|---|
| `src/cli.py` | Argument parsing, orchestration, deduplication, alert IDs |
| `src/parser.py` | One log line -> one event dict (20 log formats) |
| `src/detector.py` | Detection rules and the attack-chain correlation engine |
| `src/severity.py` | Severity levels for brute-force style alerts |
| `src/mitre.py` | Alert type -> MITRE ATT&CK technique lookup |
| `src/scoring.py` | Alert weights and the 0-100 risk score |
| `src/ioc.py` | IOC extraction (IPs, users, ports, domains, URLs, emails, hashes, paths, registry keys, hostnames) |
| `src/reporter.py` | TXT / JSON / HTML / PDF report writers |
| `src/rule_loader.py` | Loads YAML rule metadata (`rules/*.yaml`) for `cli.py rules` |

## Event model

Common fields: `raw`, `timestamp`, `event_type`, `username`, `source_ip`,
`port`, `service`. Parsers add source-specific fields, for example
`event_id` / `extra` (Active Directory), `vpn_vendor` (VPN) and
`cloud_provider` / `cloud_event` / `target` / `policy` (cloud).
