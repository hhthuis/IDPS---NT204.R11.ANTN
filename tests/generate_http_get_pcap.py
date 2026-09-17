from pathlib import Path

from scapy.all import Ether, IP, Raw, TCP, wrpcap


output_path = Path("TEST/http-get.pcap")
output_path.parent.mkdir(parents=True, exist_ok=True)

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
    / TCP(
        sport=51000,
        dport=8080,
        flags="PA",
        seq=1001,
        ack=2001,
    )
    / Raw(payload)
)

wrpcap(str(output_path), [packet])
print(f"Created {output_path} with 1 packet")
