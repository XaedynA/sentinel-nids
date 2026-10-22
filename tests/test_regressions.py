import json
import subprocess
import sys
import pytest
from nids.pcap import read_pcap
from nids.detector import PacketRecord, detect
from nids.history import list_scans


def test_generator_unsorted_windows_and_ack_exclusion():
    records = [PacketRecord(t, '192.0.2.1', '198.51.100.1', 'TCP', 80, flags)
               for t, flags in [(10, 'S'), (0, 'S'), (0, 'SA'), (0, 'S')]]
    alerts = detect(iter(records), syn_threshold=2)
    assert [(a.type, a.window_start, a.count) for a in alerts] == [('HIGH_SYN_RATE', 0, 2)]

@pytest.mark.parametrize('timestamp', [float('nan'), float('inf'), -float('inf')])
def test_nonfinite_timestamp(timestamp):
    with pytest.raises(ValueError, match='finite'):
        detect([PacketRecord(timestamp, 'a', 'b', 'TCP')])

def test_parser_ipv4_ipv6_dns_and_non_ip(tmp_path):
    from scapy.all import Ether, IP, IPv6, TCP, UDP, DNS, DNSQR, ARP, wrpcap
    path = tmp_path/'mixed.pcap'
    wrpcap(str(path), [Ether()/ARP(), Ether()/IP(src='192.0.2.1')/TCP(dport=443, flags='S'),
                      Ether()/IPv6(src='2001:db8::1')/UDP(dport=53)/DNS(qd=DNSQR(qname='example.org'))])
    records = read_pcap(path, max_packets=3)
    assert len(records) == 2
    assert records[0].dst_port == 443
    assert records[1].dns_query == 'example.org.'
    with pytest.raises(ValueError, match='packet limit'):
        read_pcap(path, max_packets=2)

@pytest.mark.parametrize('limit', [0, -1, True, 1.5])
def test_invalid_parser_limit(limit):
    with pytest.raises(ValueError):
        read_pcap('unused.pcap', limit)

def test_history_limit(tmp_path):
    with pytest.raises(ValueError):
        list_scans(tmp_path/'history.db', limit=-1)

def test_cli_exports_and_missing_file(tmp_path):
    from scapy.all import Ether, IP, TCP, wrpcap
    path = tmp_path/'input.pcap'
    out = tmp_path/'alerts.json'
    csv = tmp_path/'alerts.csv'
    wrpcap(str(path), [Ether()/IP()/TCP(dport=p, flags='S') for p in range(12)])
    result = subprocess.run([sys.executable, '-m', 'nids.cli', str(path), '--json', str(out), '--csv', str(csv)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(out.read_text())[0]['type'] == 'POSSIBLE_PORT_SCAN'
    assert 'POSSIBLE_PORT_SCAN' in csv.read_text()
    result = subprocess.run([sys.executable, '-m', 'nids.cli', str(tmp_path/'missing')], capture_output=True, text=True)
    assert result.returncode == 2
    assert 'Traceback' not in result.stderr
