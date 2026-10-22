"""Command-line interface for offline network traffic analysis."""
import argparse
import csv
import json
from pathlib import Path
from .detector import detect
from .pcap import read_pcap


def main():
    parser = argparse.ArgumentParser(description="Analyze a PCAP for suspicious network patterns")
    parser.add_argument("pcap", help="Path to .pcap or .pcapng file")
    parser.add_argument("--json", dest="json_path", help="Write alerts to JSON file")
    parser.add_argument("--csv", dest="csv_path", help="Write alerts to CSV file")
    parser.add_argument("--window", type=int, default=10, help="Window size in seconds")
    parser.add_argument("--scan-ports", type=int, default=12)
    parser.add_argument("--syn-threshold", type=int, default=80)
    parser.add_argument("--volume-threshold", type=int, default=500)
    args = parser.parse_args()
    if min(args.window, args.scan_ports, args.syn_threshold, args.volume_threshold) <= 0:
        parser.error("Thresholds and window must be positive")
    try:
        records = read_pcap(args.pcap)
        alerts = detect(records, args.window, args.scan_ports, args.syn_threshold, args.volume_threshold)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"Analysis failed: {exc}\n")
    print(f"Analyzed {len(records)} IP packets; found {len(alerts)} alerts")
    for a in alerts:
        print(f"[{a.severity.upper()}] {a.type} source={a.source} count={a.count} {a.detail}")
    data = [a.to_dict() for a in alerts]
    if args.json_path:
        Path(args.json_path).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    if args.csv_path:
        with open(args.csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["type", "source", "window_start", "count", "detail", "severity"])
            writer.writeheader()
            writer.writerows(data)

if __name__ == "__main__":
    main()
