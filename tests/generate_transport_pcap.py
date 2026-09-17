from pathlib import Path

from scapy.all import Ether, IP, Raw, TCP, UDP, wrpcap


output_path = Path("TEST/transport-test.pcap")
output_path.parent.mkdir(parents=True, exist_ok=True)

client_mac = "02:00:00:00:00:01"
server_mac = "02:00:00:00:00:02"

packets = [
    # TCP SYN
    Ether(src=client_mac, dst=server_mac)
    / IP(src="10.0.0.1", dst="10.0.0.2")
    / TCP(sport=51000, dport=8080, flags="S", seq=1000),

    # TCP SYN/ACK
    Ether(src=server_mac, dst=client_mac)
    / IP(src="10.0.0.2", dst="10.0.0.1")
    / TCP(
        sport=8080,
        dport=51000,
        flags="SA",
        seq=2000,
        ack=1001,
    ),

    # TCP ACK
    Ether(src=client_mac, dst=server_mac)
    / IP(src="10.0.0.1", dst="10.0.0.2")
    / TCP(
        sport=51000,
        dport=8080,
        flags="A",
        seq=1001,
        ack=2001,
    ),

    # TCP có payload
    Ether(src=client_mac, dst=server_mac)
    / IP(src="10.0.0.1", dst="10.0.0.2")
    / TCP(
        sport=51000,
        dport=8080,
        flags="PA",
        seq=1001,
        ack=2001,
    )
    / Raw(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"),

    # UDP có payload
    Ether(src=client_mac, dst=server_mac)
    / IP(src="10.0.0.3", dst="10.0.0.4")
    / UDP(sport=53000, dport=9999)
    / Raw(b"hello udp"),
]

wrpcap(str(output_path), packets)

print(f"Created {output_path} with {len(packets)} packets")
