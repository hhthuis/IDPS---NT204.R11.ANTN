import json

from ids.models import CaptureSource, PacketEvent
from ids.output.jsonl import JsonlWriter


def test_writer_writes_one_json_object_per_line(tmp_path):
    output_path = tmp_path / "events.jsonl"

    event = PacketEvent(
        packet_id=1,
        timestamp="2026-09-15T08:30:00Z",
        source=CaptureSource(type="pcap", name="test.pcap"),
        captured_length=60,
    )

    with JsonlWriter(output_path) as writer:
        writer.write(event)

    lines = output_path.read_text(encoding="utf-8").splitlines()

    assert len(lines) == 1

    saved_event = json.loads(lines[0])
    assert saved_event["packet_id"] == 1
    assert saved_event["schema_version"] == "1.0"
    assert saved_event["application"]["protocol"] == "UNKNOWN"
    assert saved_event["errors"] == []