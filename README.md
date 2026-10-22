# Sentinel — Network Intrusion Detection System

![Quality checks](https://github.com/XaedynA/sentinel-nids/actions/workflows/tests.yml/badge.svg)
A defensive, local-first Python portfolio project. Analyzes PCAP/PCAPNG captures, flags suspicious network patterns, visualizes traffic, and stores optional scan history in SQLite.

## Features
- Detects potential port scans, high SYN rates, high packet volume, high DNS query rates and repeated long DNS labels
- Interactive Streamlit dashboard with traffic charts, severity filtering and CSV/JSON export
- Optional local SQLite scan history (`~/.nids_portfolio/alerts.sqlite3`)
- Offline PCAP analysis and opt-in short live capture to PCAP for your own/authorized network interfaces
- Unit tests and GitHub Actions CI

## Architecture
`PCAP / authorized local capture → Scapy parser → PacketRecord → heuristic detector → dashboard/CLI → optional SQLite history`

## Setup on macOS
```bash
git clone https://github.com/XaedynA/sentinel-nids.git
cd sentinel-nids
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python samples/generate_demo.py
python -m nids.cli samples/demo.pcap
streamlit run dashboard.py
```
Open the local Streamlit address, upload `samples/demo.pcap`, and click **Save analysis to local history** to persist a scan. The sample is synthetic and should trigger two alerts with default thresholds.

## Live capture (optional)
```bash
python -m nids.capture --list-interfaces
python -m nids.capture --interface en0 --seconds 15 --output my_capture.pcap
```
Select the actual authorized interface; `en0` is an example. macOS BPF device access may require additional permissions or `sudo` **only for the separate capture command**. Never run Streamlit as root. Do not capture traffic without permission. Upload the resulting PCAP to the dashboard.

## Tests
```bash
python -m pytest -v
```

## Detection methods
Fixed time buckets group packets by source IP. TCP SYN packets without ACK contribute to scan and SYN-rate rules; all IP packets contribute to volume; DNS queries contribute to DNS-rate and long-label heuristics. Default thresholds: 12 distinct target/port pairs, 80 SYNs, 500 packets, 50 DNS queries, or 3 DNS queries with labels >=45 characters in a 10-second window. These are heuristic indicators and may produce false positives or miss real attacks.

## Limitations and privacy
- Not an intrusion prevention system; no traffic is blocked.
- Does not reassemble streams, inspect TLS contents, or validate whether alerts are actual intrusions.
- Uses fixed time buckets. Captures exceeding 200,000 total frames (including non-IP traffic) are rejected instead of silently producing an incomplete report. Dashboard uploads are limited to 20 MB.
- Local SQLite history stores alerts and metadata, not packet payloads. It may contain source IPs; protect your database.
- Do not commit sensitive PCAPs, databases, secrets or real network traffic to GitHub.
- The demo generator may emit harmless Scapy MAC/BPF permission warnings; it writes synthetic data only.

## Verification and triage

The regression suite covers IPv4/IPv6 and DNS parsing, non-IP frame accounting, threshold boundaries, unordered input, ACK exclusion, nonfinite timestamps, SQLite history, and CLI JSON/CSV exports. CI runs Python 3.11 and 3.12 and uploads coverage and JUnit results.

```bash
python -m nids.cli samples/demo.pcap --json alerts.json --csv alerts.csv
```

For each alert, confirm the time window and source, compare against authorized scanning/monitoring, and correlate with host or firewall logs before escalating. Preserve evidence securely. A quiet capture is not proof that a network is safe.

The detector aggregates counts and distinct destination/port pairs without retaining per-packet lists. Memory still grows with distinct source/time buckets and destination pairs; the parser's frame cap bounds imported captures. History queries are capped at 1,000 results and connections are closed explicitly.

## Portfolio talking points
Explain threshold tradeoffs, false positives, packet metadata, SQLite schema, and why live capture is opt-in.

## Public demo deployment

Set `PUBLIC_DEMO=true` to disable shared history in the dashboard. Use synthetic captures on public instances. Start with `streamlit run dashboard.py --server.address 0.0.0.0 --server.port $PORT --server.maxUploadSize 20`. Local history remains available when public demo mode is off.
