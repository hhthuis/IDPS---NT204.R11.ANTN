from pathlib import Path

from scapy.all import Ether, IP, Raw, TCP, wrpcap


output_path = Path("TEST/http-response.pcap")
output_path.parent.mkdir(parents=True, exist_ok=True)

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
    / TCP(
        sport=8080,
        dport=51002,
        flags="PA",
        seq=5001,
        ack=6001,
    )
    / Raw(payload)
)

wrpcap(str(output_path), [packet])
print(f"Created {output_path} with 1 packet")
