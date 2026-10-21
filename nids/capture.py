"""Opt-in capture command. Capture only authorized traffic."""
import argparse
from scapy.all import get_if_list
from .live import capture_to_pcap

def main():
    parser = argparse.ArgumentParser(description="Capture authorized local traffic to a PCAP")
    parser.add_argument("--list-interfaces", action="store_true")
    parser.add_argument("--interface")
    parser.add_argument("--seconds", type=int, default=15)
    parser.add_argument("--max-packets", type=int, default=2000)
    parser.add_argument("--output", default="capture.pcap")
    args = parser.parse_args()
    if args.list_interfaces:
        print("\n".join(get_if_list()))
        return
    if not args.interface:
        parser.error("--interface is required unless listing interfaces")
    n = capture_to_pcap(args.interface, args.output, args.seconds, args.max_packets)
    print(f"Captured {n} packets" + (f" to {args.output}" if n else " (no file written)"))

if __name__ == "__main__":
    main()
