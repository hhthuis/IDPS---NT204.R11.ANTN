import pytest

from ids.parsers.application.http import HttpParseError, parse_http


def test_incomplete_http_body_is_marked_partial():
    payload = (
        b"POST /submit HTTP/1.1\r\n"
        b"Host: example.test\r\n"
        b"Content-Length: 10\r\n"
        b"\r\n"
        b"short"
    )

    result = parse_http(payload)

    assert result.complete is False
    assert result.application.fields["message_complete"] is False
    assert result.application.fields["body"] == "short"
    assert result.warnings == [
        "HTTP body is shorter than the declared Content-Length"
    ]


def test_malformed_http_header_raises_parse_error():
    payload = b"GET / HTTP/1.1\r\nMalformed header\r\n\r\n"

    with pytest.raises(HttpParseError, match="without colon"):
        parse_http(payload)


def test_non_ascii_http_header_name_raises_parse_error():
    payload = b"GET / HTTP/1.1\r\nX-\xff: value\r\n\r\n"

    with pytest.raises(HttpParseError, match="not ASCII"):
        parse_http(payload)
