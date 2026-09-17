from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, Raw, UDP, wrpcap


output_path = Path("TEST/dns-response.pcap")
output_path.parent.mkdir(parents=True, exist_ok=True)

dns_message = bytes(
    DNS(
        id=0x1234,
        qr=1,
        aa=1,
        rd=1,
        ra=1,
        qd=DNSQR(qname="example.test", qtype="A"),
        an=DNSRR(
            rrname="example.test",
            type="A",
            rclass="IN",
            ttl=300,
            rdata="192.0.2.10",
        ),
    )
)

packet = (
    Ether(
        src="02:00:00:00:00:02",
        dst="02:00:00:00:00:01",
    )
    / IP(src="10.0.0.53", dst="10.0.0.1")
    / UDP(sport=53, dport=53000)
    / Raw(dns_message)
)

wrpcap(str(output_path), [packet])
print(f"Created {output_path} with 1 packet")
