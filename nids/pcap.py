"""Offline PCAP/PCAPNG parsing. No live capture or elevated privileges required."""
from pathlib import Path
from .detector import PacketRecord


def read_pcap(path: str, max_packets: int = 200_000) -> list[PacketRecord]:
    if isinstance(max_packets, bool) or not isinstance(max_packets, int) or max_packets < 1:
        raise ValueError("max_packets must be a positive integer")
    from scapy.all import PcapReader, IP, IPv6, TCP, UDP, DNS, DNSQR

    records = []
    with PcapReader(str(Path(path))) as reader:
        for index, packet in enumerate(reader):
            if index >= max_packets:
                raise ValueError("Capture exceeds packet limit; split it into smaller captures")
            if IP in packet:
                src, dst = packet[IP].src, packet[IP].dst
            elif IPv6 in packet:
                src, dst = packet[IPv6].src, packet[IPv6].dst
            else:
                continue
            if TCP in packet:
                protocol, port, flags = "TCP", int(packet[TCP].dport), str(packet[TCP].flags)
            elif UDP in packet:
                protocol, port, flags = "UDP", int(packet[UDP].dport), ""
            else:
                protocol, port, flags = "OTHER", None, ""
            query = ""
            if DNS in packet and DNSQR in packet and int(packet[DNS].qr) == 0:
                raw = packet[DNSQR].qname
                query = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
            records.append(PacketRecord(float(packet.time), src, dst, protocol, port, flags, len(packet), query))
    return records
