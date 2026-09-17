import json

from scapy.all import DNS, DNSQR, Ether, IP, Raw, UDP, wrpcap

from ids.cli import run_pcap


def test_dns_query_domain_and_type(tmp_path):
    pcap_path = tmp_path / "dns-query.pcap"
    output_path = tmp_path / "dns-query.jsonl"
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

    wrpcap(str(pcap_path), [packet])
    packet_count = run_pcap(pcap_path, output_path)
    event = json.loads(output_path.read_text(encoding="utf-8"))

    assert packet_count == 1
    assert event["parse_status"] == "ok"
    assert event["errors"] == []
    assert event["application"]["protocol"] == "DNS"
    assert event["application"]["kind"] == "query"

    fields = event["application"]["fields"]
    assert fields["transaction_id"] == 0x1234
    assert fields["opcode"] == "QUERY"
    assert fields["response_code"] == "NOERROR"
    assert fields["flags"]["recursion_desired"] is True
    assert fields["counts"]["question"] == 1
    assert fields["counts"]["answer"] == 0
    assert fields["answers"] == []
    assert fields["message_complete"] is True

    assert fields["questions"] == [
        {
            "name": "example.test",
            "type": "A",
            "type_code": 1,
            "class": "IN",
            "class_code": 1,
        }
    ]
