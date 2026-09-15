from scapy.layers.inet import IP
from scapy.packet import Packet

from ids.models import NetworkInfo


class UnsupportedNetworkProtocol(Exception):
    pass


def parse_ipv4(packet: Packet) -> NetworkInfo:
    if IP not in packet:
        raise UnsupportedNetworkProtocol("Packet does not contain IPv4")

    ip = packet[IP]

    flags_text = str(ip.flags)
    flags = flags_text.split("+") if flags_text else []

    packet_length = (
        int(ip.len)
        if ip.len is not None
        else len(bytes(ip))
    )

    return NetworkInfo(
        protocol="IPv4",
        src_ip=str(ip.src),
        dst_ip=str(ip.dst),
        ttl=int(ip.ttl),
        packet_length=packet_length,
        identification=int(ip.id),
        flags=flags,
        fragment_offset=int(ip.frag),
    )