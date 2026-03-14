# NetSentry

NetSentry is a local network intrusion-detection and packet-forensics application. It captures traffic from one network interface, evaluates packets with detectors, stores findings and PCAP evidence, and presents live activity through a browser dashboard.

## What it provides

- Live packet metadata streamed to the dashboard
- Detection of ARP spoofing, vertical and horizontal port scans, DNS tunneling patterns, SYN floods, and rogue DHCP servers
- Severity scoring and console alerts
- SQLite-backed finding history and trend summaries
- Rotating PCAP evidence with retention controls
- Incident grouping, notes, status tracking, linked event review, and JSON or Markdown reports
- Source-based PCAP export for an IP or MAC address
- Runtime configuration in one file: [`config.yaml`](config.yaml)

## Requirements

- Python 3.11 or newer
- Windows: [Npcap](https://npcap.com/) in WinPcap-compatible mode, usually with an elevated terminal
- Linux/macOS: libpcap

## Run

List capturable interfaces:

```bash
python run.py -i
```

Start NetSentry with an interface IP, system name, PCAP name, or human-readable name:

```bash
python run.py "192.168.1.##"
```

The launcher starts three local components:

- API: `http://127.0.0.1:8000`
- Dashboard: `http://127.0.0.1:8080/dashboard/`
- Live capture stream/control service: `http://127.0.0.1:8765`

Use `Ctrl+C` to stop the capture pipeline and both web services cleanly.

## Dashboard workflow

1. **Live incidents** shows current findings and severity. Detector and capture-interface controls apply immediately.
2. **Trends** summarizes activity over time and highlights recurring source addresses.
3. **Live network data** displays packet metadata without requiring a packet analyzer.
4. **Network health** compares current packet rate and protocol mix with the session baseline.
5. **Investigations** groups related findings. Select an incident to review its event sequence, update its title/status/assignee/notes, or export a report. The same panel lists recent evidence and supports source-traffic exports.

Once started, go to `http://127.0.0.1:8080/dashboard/` to use the application.

## Configuration

Edit [`config.yaml`](config.yaml) before starting NetSentry. Configuration is read at process startup, so restart the launcher after a change.

| Section | Controls |
| --- | --- |
| `server` | Bind address, API/dashboard/live ports, and launcher timeouts |
| `capture` | Packet queue size, maintenance frequency, and live replay buffering |
| `detectors` | Detection thresholds/windows, DNS exclusions, and trusted DHCP servers |
| `correlation` | Incident grouping window and processing limit |
| `evidence` | Database, PCAP, export, report, and custody paths; rotation size and retention |
| `response` | Alert severity threshold and webhook timeout |
| `dashboard` | Query sizes, trend defaults, refresh timing, and browser-side buffers |

## How it works

```text
Network interface
    -> Scapy capture queue
    -> PCAP evidence writer
    -> packet normalization
    -> detectors
    -> severity + alerts
    -> SQLite findings
    -> grouping, reports, API, and dashboard
```

The capture pipeline is intentionally modular: each detector implements the common detector interface and returns a normalized finding. Storage, correlation, evidence, response, and presentation remain separate so they can be tested or extended independently.

## Data locations

Default runtime data is under `data/`:

- `events.db` — findings and investigation state
- `pcaps/` — rotating packet captures
- `exports/` — source-filtered PCAP exports
- `reports/` — investigation reports
- `custody_log.jsonl` — evidence integrity history

## Project structure

| Path | Purpose |
| --- | --- |
| `capture/` | Interface discovery, packet capture, normalization, and PCAP writing |
| `detectors/` | Threat-specific detection logic |
| `core/` | Capture pipeline and live stream/control server |
| `storage/` | SQLite schema and finding/investigation queries |
| `correlation/` | Incident grouping, severity, sessions, and traffic exports |
| `evidence/` | PCAP vault and integrity records |
| `forensics/` | Timelines, replay, and report generation |
| `response/` | Alert dispatching |
| `api/`, `dashboard/` | HTTP API and browser interface |
| `scripts/` | Authorized-lab traffic simulators |
| `tests/` | Unit and integration tests |
