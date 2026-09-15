import argparse
from pathlib import Path

from ids.capture.pcap import read_pcap
from ids.models import CaptureSource
from ids.output.jsonl import JsonlWriter
from ids.pipeline import parse_packet


def run_pcap(
    input_path: str | Path,
    output_path: str | Path,
) -> int:
    input_path = Path(input_path)

    source = CaptureSource(
        type="pcap",
        name=input_path.name,
    )

    packet_count = 0

    with JsonlWriter(output_path) as writer:
        for packet_count, packet in enumerate(
            read_pcap(input_path),
            start=1,
        ):
            event = parse_packet(
                packet=packet,
                packet_id=packet_count,
                source=source,
            )
            writer.write(event)

    return packet_count


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Packet Capture and Parser for IDS"
    )

    parser.add_argument(
        "--pcap",
        required=True,
        help="Path to input PCAP file",
    )

    parser.add_argument(
        "--output",
        default="output/events.jsonl",
        help="Path to output JSONL file",
    )

    return parser


def main() -> int:
    parser = build_argument_parser()
    args = parser.parse_args()

    try:
        packet_count = run_pcap(
            input_path=args.pcap,
            output_path=args.output,
        )
    except (OSError, ValueError) as error:
        parser.error(str(error))

    print(
        f"Processed {packet_count} packets. "
        f"Output: {args.output}"
    )

    return 0