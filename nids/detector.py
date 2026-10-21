from __future__ import annotations
"""Simple, explainable, window-based intrusion detection heuristics."""
from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import Iterable

@dataclass(frozen=True)
class PacketRecord:
    timestamp: float
    src: str
    dst: str
    protocol: str
    dst_port: int | None = None
    tcp_flags: str = ""
    size: int = 0
    dns_query: str = ""

@dataclass(frozen=True)
class Alert:
    type: str
    source: str
    window_start: float
    count: int
    detail: str
    severity: str

    def to_dict(self):
        return asdict(self)


def detect(records: Iterable[PacketRecord], window_seconds: int = 10,
           scan_ports: int = 12, syn_threshold: int = 80,
           volume_threshold: int = 500) -> list[Alert]:
    """Detect source-level suspicious activity in fixed time windows.

    Thresholds are heuristics, not proof of malicious behavior.
    """
    if min(window_seconds, scan_ports, syn_threshold, volume_threshold) <= 0:
        raise ValueError("All thresholds and window_seconds must be positive")
    groups = defaultdict(list)
    for p in records:
        groups[(p.src, int(p.timestamp // window_seconds))].append(p)

    alerts = []
    for (src, bucket), packets in sorted(groups.items()):
        start = bucket * window_seconds
        syns = [p for p in packets if p.protocol.upper() == "TCP" and
                "S" in p.tcp_flags.upper() and "A" not in p.tcp_flags.upper()]
        unique_ports = {(p.dst, p.dst_port) for p in syns if p.dst_port is not None}
        if len(unique_ports) >= scan_ports:
            alerts.append(Alert("POSSIBLE_PORT_SCAN", src, start, len(unique_ports),
                                f"SYN attempts to {len(unique_ports)} distinct destination/port pairs", "medium"))
        if len(syns) >= syn_threshold:
            alerts.append(Alert("HIGH_SYN_RATE", src, start, len(syns),
                                f"{len(syns)} TCP SYN packets without ACK", "high"))
        if len(packets) >= volume_threshold:
            alerts.append(Alert("HIGH_PACKET_VOLUME", src, start, len(packets),
                                f"{len(packets)} packets in {window_seconds} seconds", "medium"))
    # Additional explainable DNS heuristics: high query volume and long labels.
    for (src, bucket), packets in sorted(groups.items()):
        dns = [p.dns_query.rstrip(".") for p in packets if p.dns_query]
        if len(dns) >= 50:
            alerts.append(Alert("HIGH_DNS_QUERY_RATE", src, bucket * window_seconds,
                                len(dns), f"{len(dns)} DNS queries in {window_seconds} seconds", "medium"))
        long_queries = [q for q in dns if any(len(label) >= 45 for label in q.split("."))]
        if len(long_queries) >= 3:
            alerts.append(Alert("LONG_DNS_LABELS", src, bucket * window_seconds,
                                len(long_queries), "Repeated DNS queries with unusually long labels", "low"))
    return alerts
