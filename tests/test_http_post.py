import base64
import json

from scapy.all import Ether, IP, Raw, TCP, wrpcap

from ids.cli import run_pcap


def test_http_post_request_with_body(tmp_path):
    pcap_path = tmp_path / "http-post.pcap"
    output_path = tmp_path / "http-post.jsonl"
    body = b"username=alice&role=admin"
    payload = (
        b"POST /login HTTP/1.1\r\n"
        b"Host: example.test\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"\r\n"
        + body
    )

    packet = (
        Ether(
            src="02:00:00:00:00:01",
            dst="02:00:00:00:00:02",
        )
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=51001, dport=8080, flags="PA")
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
    assert fields["method"] == "POST"
    assert fields["target"] == "/login"
    assert fields["version"] == "HTTP/1.1"
    assert fields["headers"]["host"] == "example.test"
    assert fields["headers"]["content-type"] == (
        "application/x-www-form-urlencoded"
    )
    assert fields["content_length"] == len(body)
    assert fields["body_length"] == len(body)
    assert fields["body"] == body.decode("ascii")
    assert base64.b64decode(fields["body_base64"]) == body
    assert fields["remaining_bytes"] == 0
    assert fields["message_complete"] is True
