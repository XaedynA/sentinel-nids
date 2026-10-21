from nids.detector import PacketRecord, detect


def pkt(t, port=80, src="192.0.2.10", flags="S"):
    return PacketRecord(t, src, "198.51.100.20", "TCP", port, flags, 60)


def test_port_scan():
    alerts = detect([pkt(1, port=p) for p in range(20, 32)])
    assert [a.type for a in alerts] == ["POSSIBLE_PORT_SCAN"]


def test_syn_rate():
    alerts = detect([pkt(1) for _ in range(80)])
    assert "HIGH_SYN_RATE" in [a.type for a in alerts]


def test_volume():
    alerts = detect([pkt(1, flags="A") for _ in range(500)])
    assert [a.type for a in alerts] == ["HIGH_PACKET_VOLUME"]


def test_normal_traffic():
    assert detect([pkt(1, flags="A"), pkt(2, flags="PA")]) == []


def test_separate_windows():
    assert detect([pkt(1) for _ in range(50)] + [pkt(11) for _ in range(50)]) == []


def test_invalid_threshold():
    import pytest
    with pytest.raises(ValueError):
        detect([], window_seconds=0)
