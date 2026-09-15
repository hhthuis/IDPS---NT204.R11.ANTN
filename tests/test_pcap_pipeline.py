import json

from scapy.all import Ether, IP, Raw, TCP, UDP, wrpcap

from ids.cli import run_pcap


def test_pcap_to_jsonl_pipeline(tmp_path):
    pcap_path = tmp_path / "input.pcap"
    output_path = tmp_path / "events.jsonl"

    packets = [
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=50000, dport=80, flags="S"),

        Ether()
        / IP(src="10.0.0.3", dst="10.0.0.4")
        / UDP(sport=53000, dport=9999)
        / Raw(b"test"),
    ]

    wrpcap(str(pcap_path), packets)

    packet_count = run_pcap(pcap_path, output_path)

    events = [
        json.loads(line)
        for line in output_path.read_text(
            encoding="utf-8"
        ).splitlines()
    ]

    assert packet_count == 2
    assert len(events) == 2

    assert events[0]["network"]["src_ip"] == "10.0.0.1"
    assert events[0]["network"]["dst_ip"] == "10.0.0.2"
    assert events[0]["transport"]["protocol"] == "TCP"
    assert "SYN" in events[0]["transport"]["fields"]["flags"]

    assert events[1]["transport"]["protocol"] == "UDP"
    assert events[1]["payload"]["length"] == 4
    assert events[1]["payload"]["preview"] == "test"