"""Authorized local interface capture. Requires macOS capture permissions."""
from __future__ import annotations
from scapy.all import sniff, wrpcap

def capture_to_pcap(interface, output, seconds=15, max_packets=2000):
    if not interface or seconds < 1 or seconds > 120 or not 1 <= max_packets <= 20000:
        raise ValueError("Specify an interface, 1-120 seconds, and 1-20000 packets")
    packets = sniff(iface=interface, timeout=seconds, count=max_packets, store=True)
    if packets:
        wrpcap(str(output), packets)
    return len(packets)
