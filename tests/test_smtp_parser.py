import pytest
from scapy.all import Ether, IP, Raw, TCP

from ids.models import CaptureSource
from ids.parsers.application.smtp import SmtpParseError, parse_smtp
from ids.pipeline import parse_packet


@pytest.mark.parametrize(
    ("payload", "command", "field_name", "field_value"),
    [
        (b"HELO client.example.test\r\n", "HELO", "domain", "client.example.test"),
        (b"EHLO client.example.test\r\n", "EHLO", "domain", "client.example.test"),
        (
            b"MAIL FROM:<alice@example.test>\r\n",
            "MAIL FROM",
            "mailbox",
            "alice@example.test",
        ),
        (
            b"RCPT TO:<bob@example.test>\r\n",
            "RCPT TO",
            "mailbox",
            "bob@example.test",
        ),
    ],
)
def test_parses_required_smtp_commands(
    payload,
    command,
    field_name,
    field_value,
):
    result = parse_smtp(payload)

    assert result.complete is True
    assert result.warnings == []
    assert result.application.protocol == "SMTP"
    assert result.application.kind == "command"
    assert result.application.fields["command"] == command
    assert result.application.fields[field_name] == field_value
    assert result.application.fields["message_complete"] is True


def test_parses_mail_parameters():
    result = parse_smtp(
        b"MAIL FROM:<alice@example.test> SIZE=123 BODY=8BITMIME\r\n"
    )

    assert result.application.fields["mailbox"] == "alice@example.test"
    assert result.application.fields["parameters"] == [
        "SIZE=123",
        "BODY=8BITMIME",
    ]


def test_parses_pipelined_smtp_commands():
    payload = (
        b"MAIL FROM:<alice@example.test>\r\n"
        b"RCPT TO:<bob@example.test>\r\n"
    )

    result = parse_smtp(payload)
    commands = result.application.fields["commands"]

    assert result.complete is True
    assert result.application.fields["command_count"] == 2
    assert [command["command"] for command in commands] == [
        "MAIL FROM",
        "RCPT TO",
    ]


@pytest.mark.parametrize("status_code", [220, 250, 354, 550])
def test_parses_required_smtp_response_codes(status_code):
    result = parse_smtp(f"{status_code} SMTP response\r\n".encode("ascii"))

    assert result.complete is True
    assert result.warnings == []
    assert result.application.protocol == "SMTP"
    assert result.application.kind == "response"
    assert result.application.fields["status_code"] == status_code
    assert result.application.fields["message"] == "SMTP response"
    assert result.application.fields["message_complete"] is True


def test_parses_multiline_smtp_response():
    payload = (
        b"250-mail.example.test\r\n"
        b"250-PIPELINING\r\n"
        b"250 STARTTLS\r\n"
    )

    result = parse_smtp(payload)

    assert result.complete is True
    assert result.application.fields["status_code"] == 250
    assert result.application.fields["multiline"] is True
    assert result.application.fields["messages"] == [
        "mail.example.test",
        "PIPELINING",
        "STARTTLS",
    ]


def test_incomplete_smtp_line_is_marked_partial():
    result = parse_smtp(b"EHLO client.example.test")

    assert result.complete is False
    assert result.application.fields["message_complete"] is False
    assert result.warnings == ["SMTP line is missing its line terminator"]


def test_unterminated_multiline_response_is_marked_partial():
    result = parse_smtp(b"250-mail.example.test\r\n250-PIPELINING\r\n")

    assert result.complete is False
    assert result.application.fields["message_complete"] is False
    assert result.warnings == [
        "SMTP multiline response is missing its terminating line"
    ]


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"HELO\r\n",
        b"MAIL FROM:\r\n",
        b"RCPT TO:\r\n",
        b"999 invalid response\r\n",
    ],
)
def test_malformed_smtp_payload_raises_parse_error(payload):
    with pytest.raises(SmtpParseError):
        parse_smtp(payload)


def test_pipeline_parses_smtp_command_on_non_standard_port():
    packet = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="10.0.0.1", dst="10.0.0.25")
        / TCP(sport=51000, dport=2600, flags="PA")
        / Raw(b"EHLO client.example.test\r\n")
    )

    event = parse_packet(
        packet,
        packet_id=1,
        source=CaptureSource(type="pcap", name="smtp-command.pcap"),
    )

    assert event.parse_status == "ok"
    assert event.application.protocol == "SMTP"
    assert event.application.kind == "command"
    assert event.application.fields["command"] == "EHLO"
    assert event.application.fields["domain"] == "client.example.test"


def test_pipeline_parses_smtp_response():
    packet = (
        Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
        / IP(src="10.0.0.25", dst="10.0.0.1")
        / TCP(sport=25, dport=51000, flags="PA")
        / Raw(b"220 mail.example.test ESMTP ready\r\n")
    )

    event = parse_packet(
        packet,
        packet_id=1,
        source=CaptureSource(type="pcap", name="smtp-response.pcap"),
    )

    assert event.parse_status == "ok"
    assert event.application.protocol == "SMTP"
    assert event.application.kind == "response"
    assert event.application.fields["status_code"] == 220
    assert event.application.fields["message"] == (
        "mail.example.test ESMTP ready"
    )
