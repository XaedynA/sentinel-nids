import json
from nids.detector import PacketRecord, detect
from nids.history import save_scan, list_scans

def test_dns_rate():
    packets = [PacketRecord(1, "192.0.2.1", "8.8.8.8", "UDP", 53, "", 75, "example.org") for _ in range(50)]
    assert "HIGH_DNS_QUERY_RATE" in [a.type for a in detect(packets)]

def test_long_dns_labels():
    packets = [PacketRecord(1, "192.0.2.1", "8.8.8.8", "UDP", 53, "", 75, "x"*50+".example.org") for _ in range(3)]
    assert "LONG_DNS_LABELS" in [a.type for a in detect(packets)]

def test_history_round_trip(tmp_path):
    path = tmp_path / "db.sqlite3"
    packets = [PacketRecord(1, "192.0.2.1", "198.51.100.1", "TCP", p, "S", 60) for p in range(12)]
    alerts = detect(packets)
    scan_id = save_scan("demo.pcap", packets, alerts, path)
    rows = list_scans(path)
    assert rows[0]["id"] == scan_id
    assert rows[0]["packet_count"] == 12
    assert json.loads(rows[0]["alerts_json"])[0]["type"] == "POSSIBLE_PORT_SCAN"
