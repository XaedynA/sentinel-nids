"""Create a synthetic capture containing a port scan and SYN burst."""
from pathlib import Path
from scapy.all import Ether, IP, TCP, wrpcap

packets = []
for i in range(25):
    p = Ether()/IP(src="192.0.2.10", dst="198.51.100.20")/TCP(sport=40000+i, dport=1000+i, flags="S")
    p.time = 1 + i * 0.01
    packets.append(p)
for i in range(90):
    p = Ether()/IP(src="192.0.2.30", dst="198.51.100.20")/TCP(sport=50000+i, dport=443, flags="S")
    p.time = 2 + i * 0.01
    packets.append(p)
out = Path(__file__).parent / "demo.pcap"
wrpcap(str(out), packets)
print(f"Created {out} ({len(packets)} synthetic packets)")
