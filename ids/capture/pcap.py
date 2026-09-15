from collections.abc import Iterator
from pathlib import Path

from scapy.packet import Packet
from scapy.utils import PcapReader


def read_pcap(input_path: str | Path) -> Iterator[Packet]:
    path = Path(input_path)

    if not path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    reader = PcapReader(str(path))

    try:
        for packet in reader:
            yield packet
    finally:
        reader.close()