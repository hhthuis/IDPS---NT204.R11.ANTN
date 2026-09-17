import json

import pytest
from scapy.all import Ether, IP, Raw, TCP, UDP, wrpcap

from ids.cli import run_pcap


CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
TCP_PAYLOAD = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
UDP_PAYLOAD = b"hello udp"


@pytest.fixture
def transport_events(tmp_path):
    pcap_path = tmp_path / "transport-test.pcap"
    output_path = tmp_path / "transport-test.jsonl"

    packets = [
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=51000, dport=8080, flags="S", seq=1000),
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(
            sport=8080,
            dport=51000,
            flags="SA",
            seq=2000,
            ack=1001,
        ),
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(
            sport=51000,
            dport=8080,
            flags="A",
            seq=1001,
            ack=2001,
        ),
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(
            sport=51000,
            dport=8080,
            flags="PA",
            seq=1001,
            ack=2001,
        )
        / Raw(TCP_PAYLOAD),
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.0.0.3", dst="10.0.0.4")
        / UDP(sport=53000, dport=9999)
        / Raw(UDP_PAYLOAD),
    ]

    wrpcap(str(pcap_path), packets)
    packet_count = run_pcap(pcap_path, output_path)

    lines = output_path.read_text(encoding="utf-8").splitlines()
    events = [json.loads(line) for line in lines]

    return packet_count, events


def test_pipeline_writes_one_event_per_packet(transport_events):
    packet_count, events = transport_events

    assert packet_count == 5
    assert len(events) == 5
    assert [event["packet_id"] for event in events] == [1, 2, 3, 4, 5]
    assert all(event["parse_status"] == "ok" for event in events)
    assert all(event["errors"] == [] for event in events)


def test_tcp_handshake(transport_events):
    _, events = transport_events
    syn, syn_ack, ack = events[:3]

    assert syn["network"]["src_ip"] == "10.0.0.1"
    assert syn["network"]["dst_ip"] == "10.0.0.2"
    assert syn["transport"]["protocol"] == "TCP"
    assert syn["transport"]["src_port"] == 51000
    assert syn["transport"]["dst_port"] == 8080
    assert syn["transport"]["fields"]["flags"] == ["SYN"]
    assert syn["transport"]["fields"]["sequence_number"] == 1000
    assert syn["payload"]["length"] == 0

    assert syn_ack["network"]["src_ip"] == "10.0.0.2"
    assert syn_ack["network"]["dst_ip"] == "10.0.0.1"
    assert syn_ack["transport"]["fields"]["flags"] == ["SYN", "ACK"]
    assert syn_ack["transport"]["fields"]["sequence_number"] == 2000
    assert syn_ack["transport"]["fields"]["acknowledgment_number"] == 1001

    assert ack["transport"]["fields"]["flags"] == ["ACK"]
    assert ack["transport"]["fields"]["sequence_number"] == 1001
    assert ack["transport"]["fields"]["acknowledgment_number"] == 2001
    assert ack["payload"]["length"] == 0
