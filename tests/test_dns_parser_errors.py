import pytest

from ids.parsers.application.dns import DnsParseError, parse_dns


def test_dns_message_shorter_than_header_raises_parse_error():
    with pytest.raises(DnsParseError, match="12-byte header"):
        parse_dns(b"\x12\x34\x01\x00", "UDP")


def test_dns_over_tcp_requires_length_prefix():
    with pytest.raises(DnsParseError, match="length prefix"):
        parse_dns(b"\x00", "TCP")


def test_dns_over_tcp_short_body_is_marked_partial():
    message = (
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x01\x00\x01"
    )
    payload = (len(message) + 5).to_bytes(2, "big") + message

    result = parse_dns(payload, "TCP")

    assert result.complete is False
    assert result.application.fields["message_complete"] is False
    assert result.warnings == [
        "DNS over TCP payload is shorter than its declared message length"
    ]
