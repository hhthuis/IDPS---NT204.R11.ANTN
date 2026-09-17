from pathlib import Path

from scapy.all import DNS, DNSQR, Ether, IP, Raw, UDP, wrpcap


output_path = Path("TEST/dns-query.pcap")
output_path.parent.mkdir(parents=True, exist_ok=True)

dns_message = bytes(
    DNS(
        id=0x1234,
        rd=1,
        qd=DNSQR(qname="example.test", qtype="A"),
    )
)

packet = (
    Ether(
        src="02:00:00:00:00:01",
        dst="02:00:00:00:00:02",
    )
    / IP(src="10.0.0.1", dst="10.0.0.53")
    / UDP(sport=53000, dport=53)
    / Raw(dns_message)
)

wrpcap(str(output_path), [packet])
print(f"Created {output_path} with 1 packet")
