import base64

from ids.models import (
    ApplicationInfo,
    CaptureSource,
    NetworkInfo,
    PacketEvent,
    PayloadInfo,
    TransportInfo,
)
from ids.output.jsonl import JsonlWriter


raw_payload = b"GET /login HTTP/1.1\r\nHost: example.test\r\n\r\n"

event = PacketEvent(
    packet_id=1,
    timestamp="2026-09-15T08:30:00.123456Z",
    source=CaptureSource(
        type="pcap",
        name="http_get.pcap",
    ),
    captured_length=105,
    wire_length=105,
    network=NetworkInfo(
        protocol="IPv4",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        ttl=64,
        packet_length=91,
        identification=1234,
        flags=["DF"],
        fragment_offset=0,
    ),
    transport=TransportInfo(
        protocol="TCP",
        src_port=51000,
        dst_port=8080,
        fields={
            "sequence_number": 1001,
            "acknowledgment_number": 2001,
            "flags": ["PSH", "ACK"],
            "window_size": 64240,
        },
    ),
    application=ApplicationInfo(
        protocol="HTTP",
        kind="request",
        fields={
            "method": "GET",
            "target": "/login",
            "version": "HTTP/1.1",
            "headers": {
                "host": "example.test",
            },
            "body": "",
        },
    ),
    payload=PayloadInfo(
        length=len(raw_payload),
        base64=base64.b64encode(raw_payload).decode("ascii"),
        preview=raw_payload.decode("utf-8", errors="replace"),
    ),
)

with JsonlWriter("output/sample-events.jsonl") as writer:
    writer.write(event)

print("Created output/sample-events.jsonl")