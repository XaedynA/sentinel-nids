# Sentinel — Network Intrusion Detection System

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
cd ~/Downloads/network-intrusion-detection-system
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
- Uses fixed time buckets and at most 200,000 IP packets per imported capture.
- Local SQLite history stores alerts and metadata, not packet payloads. It may contain source IPs; protect your database.
- Do not commit sensitive PCAPs, databases, secrets or real network traffic to GitHub.
- The demo generator may emit harmless Scapy MAC/BPF permission warnings; it writes synthetic data only.

## Portfolio talking points
Explain threshold tradeoffs, false positives, packet metadata, SQLite schema, and why live capture is opt-in.
