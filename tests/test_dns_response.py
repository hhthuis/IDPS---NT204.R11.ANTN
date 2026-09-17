import json

from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, Raw, UDP, wrpcap

from ids.cli import run_pcap


def test_dns_response_contains_answer(tmp_path):
    pcap_path = tmp_path / "dns-response.pcap"
    output_path = tmp_path / "dns-response.jsonl"
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

    wrpcap(str(pcap_path), [packet])
    packet_count = run_pcap(pcap_path, output_path)
    event = json.loads(output_path.read_text(encoding="utf-8"))

    assert packet_count == 1
    assert event["parse_status"] == "ok"
    assert event["errors"] == []
    assert event["application"]["protocol"] == "DNS"
    assert event["application"]["kind"] == "response"

    fields = event["application"]["fields"]
    assert fields["transaction_id"] == 0x1234
    assert fields["opcode"] == "QUERY"
    assert fields["response_code"] == "NOERROR"
    assert fields["flags"]["authoritative_answer"] is True
    assert fields["flags"]["recursion_desired"] is True
    assert fields["flags"]["recursion_available"] is True
    assert fields["counts"]["question"] == 1
    assert fields["counts"]["answer"] == 1
    assert fields["message_complete"] is True

    assert fields["answers"] == [
        {
            "name": "example.test",
            "type": "A",
            "type_code": 1,
            "class": "IN",
            "class_code": 1,
            "ttl": 300,
            "data": "192.0.2.10",
        }
    ]
