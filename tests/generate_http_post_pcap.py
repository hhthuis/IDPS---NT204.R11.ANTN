from pathlib import Path

from scapy.all import Ether, IP, Raw, TCP, wrpcap


output_path = Path("TEST/http-post.pcap")
output_path.parent.mkdir(parents=True, exist_ok=True)

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
    / TCP(
        sport=51001,
        dport=8080,
        flags="PA",
        seq=3001,
        ack=4001,
    )
    / Raw(payload)
)

wrpcap(str(output_path), [packet])
print(f"Created {output_path} with 1 packet")
