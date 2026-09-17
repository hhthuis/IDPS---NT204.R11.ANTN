import base64
import json

from scapy.all import Ether, IP, Raw, TCP, wrpcap

from ids.cli import run_pcap


def test_http_response_with_status_headers_and_body(tmp_path):
    pcap_path = tmp_path / "http-response.pcap"
    output_path = tmp_path / "http-response.jsonl"
    body = b"Hello, IDS!"
    payload = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: IDS-Test/1.0\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"\r\n"
        + body
    )

    packet = (
        Ether(
            src="02:00:00:00:00:02",
            dst="02:00:00:00:00:01",
        )
        / IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(sport=8080, dport=51002, flags="PA")
        / Raw(payload)
    )

    wrpcap(str(pcap_path), [packet])
    packet_count = run_pcap(pcap_path, output_path)
    event = json.loads(output_path.read_text(encoding="utf-8"))

    assert packet_count == 1
    assert event["parse_status"] == "ok"
    assert event["errors"] == []
    assert event["application"]["protocol"] == "HTTP"
    assert event["application"]["kind"] == "response"

    fields = event["application"]["fields"]
    assert fields["version"] == "HTTP/1.1"
    assert fields["status_code"] == 200
    assert fields["reason_phrase"] == "OK"
    assert fields["headers"]["server"] == "IDS-Test/1.0"
    assert fields["headers"]["content-type"] == (
        "text/plain; charset=utf-8"
    )
    assert fields["content_length"] == len(body)
    assert fields["body_length"] == len(body)
    assert fields["body"] == body.decode("ascii")
    assert base64.b64decode(fields["body_base64"]) == body
    assert fields["remaining_bytes"] == 0
    assert fields["message_complete"] is True
