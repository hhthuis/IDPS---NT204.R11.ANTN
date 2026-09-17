import json

from scapy.all import Ether, IP, Raw, TCP, wrpcap

from ids.cli import run_pcap


def test_http_get_request(tmp_path):
    pcap_path = tmp_path / "http-get.pcap"
    output_path = tmp_path / "http-get.jsonl"
    payload = (
        b"GET /products?id=10 HTTP/1.1\r\n"
        b"Host: example.test\r\n"
        b"User-Agent: IDS-Test/1.0\r\n"
        b"Accept: */*\r\n"
        b"\r\n"
    )

    packet = (
        Ether(
            src="02:00:00:00:00:01",
            dst="02:00:00:00:00:02",
        )
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=51000, dport=8080, flags="PA")
        / Raw(payload)
    )

    wrpcap(str(pcap_path), [packet])
    packet_count = run_pcap(pcap_path, output_path)
    event = json.loads(output_path.read_text(encoding="utf-8"))

    assert packet_count == 1
    assert event["parse_status"] == "ok"
    assert event["errors"] == []
    assert event["application"]["protocol"] == "HTTP"
    assert event["application"]["kind"] == "request"

    fields = event["application"]["fields"]
    assert fields["method"] == "GET"
    assert fields["target"] == "/products?id=10"
    assert fields["version"] == "HTTP/1.1"
    assert fields["headers"]["host"] == "example.test"
    assert fields["headers"]["user-agent"] == "IDS-Test/1.0"
    assert fields["headers"]["accept"] == "*/*"
    assert fields["body"] == ""
    assert fields["body_length"] == 0
    assert fields["message_complete"] is True
