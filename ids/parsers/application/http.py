import base64
import re
from dataclasses import dataclass, field

from ids.models import ApplicationInfo


HTTP_REQUEST_LINE = re.compile(
    r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) "
    r"(\S+) (HTTP/1\.[01])$",
    re.IGNORECASE,
)
HTTP_RESPONSE_LINE = re.compile(
    r"^(HTTP/1\.[01]) ([1-5][0-9]{2})(?: (.*))?$",
    re.IGNORECASE,
)
HTTP_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


class HttpParseError(ValueError):
    pass


@dataclass(slots=True)
class HttpParseResult:
    application: ApplicationInfo
    complete: bool
    warnings: list[str] = field(default_factory=list)


def _split_head_and_body(payload: bytes) -> tuple[bytes, bytes, bool]:
    if b"\r\n\r\n" in payload:
        head, body = payload.split(b"\r\n\r\n", 1)
        return head, body, True

    if b"\n\n" in payload:
        head, body = payload.split(b"\n\n", 1)
        return head, body, True

    return payload, b"", False


def _parse_headers(lines: list[bytes]) -> dict[str, str]:
    headers: dict[str, str] = {}
    previous_name: str | None = None

    for raw_line in lines:
        if raw_line.startswith((b" ", b"\t")):
            if previous_name is None:
                raise HttpParseError("Header continuation has no previous header")

            continuation = raw_line.strip().decode("latin-1")
            headers[previous_name] = f"{headers[previous_name]} {continuation}"
            continue

        if b":" not in raw_line:
            raise HttpParseError("Malformed HTTP header without colon")

        raw_name, raw_value = raw_line.split(b":", 1)

        try:
            name = raw_name.decode("ascii", errors="strict").strip().lower()
        except UnicodeDecodeError as error:
            raise HttpParseError("HTTP header name is not ASCII") from error

        if not name or not HTTP_HEADER_NAME.fullmatch(name):
            raise HttpParseError(f"Invalid HTTP header name: {name!r}")

        value = raw_value.decode("latin-1").strip()

        if name in headers:
            headers[name] = f"{headers[name]}, {value}"
        else:
            headers[name] = value

        previous_name = name

    return headers


def _parse_content_length(headers: dict[str, str]) -> int | None:
    value = headers.get("content-length")

    if value is None:
        return None

    try:
        content_length = int(value)
    except ValueError as error:
        raise HttpParseError("Invalid HTTP Content-Length") from error

    if content_length < 0:
        raise HttpParseError("HTTP Content-Length cannot be negative")

    return content_length


def _body_fields(
    body: bytes,
    content_length: int | None,
) -> tuple[dict[str, object], bool, list[str]]:
    warnings: list[str] = []
    complete = True
    parsed_body = body
    remaining_bytes = 0

    if content_length is not None:
        if len(body) < content_length:
            complete = False
            warnings.append(
                "HTTP body is shorter than the declared Content-Length"
            )
        else:
            parsed_body = body[:content_length]
            remaining_bytes = len(body) - content_length

    fields: dict[str, object] = {
        "body": parsed_body.decode("utf-8", errors="replace"),
        "body_base64": (
            base64.b64encode(parsed_body).decode("ascii")
            if parsed_body
            else None
        ),
        "body_length": len(parsed_body),
        "content_length": content_length,
        "remaining_bytes": remaining_bytes,
    }

    return fields, complete, warnings


def parse_http(payload: bytes) -> HttpParseResult:
    if not payload:
        raise HttpParseError("HTTP payload is empty")

    head, body, headers_complete = _split_head_and_body(payload)
    lines = head.splitlines()

    if not lines:
        raise HttpParseError("HTTP start line is missing")

    try:
        start_line = lines[0].decode("latin-1")
    except UnicodeDecodeError as error:
        raise HttpParseError("HTTP start line cannot be decoded") from error

    headers = _parse_headers(lines[1:])
    content_length = _parse_content_length(headers)
    body_fields, body_complete, warnings = _body_fields(body, content_length)

    complete = headers_complete and body_complete

    if not headers_complete:
        warnings.insert(0, "HTTP headers are incomplete")

    request_match = HTTP_REQUEST_LINE.fullmatch(start_line)
    response_match = HTTP_RESPONSE_LINE.fullmatch(start_line)

    common_fields: dict[str, object] = {
        "start_line": start_line,
        "headers": headers,
        **body_fields,
        "message_complete": complete,
    }

    if request_match:
        method, target, version = request_match.groups()
        common_fields.update(
            {
                "method": method.upper(),
                "target": target,
                "version": version.upper(),
            }
        )

        application = ApplicationInfo(
            protocol="HTTP",
            kind="request",
            fields=common_fields,
        )
    elif response_match:
        version, status_code, reason_phrase = response_match.groups()
        common_fields.update(
            {
                "version": version.upper(),
                "status_code": int(status_code),
                "reason_phrase": reason_phrase or "",
            }
        )

        application = ApplicationInfo(
            protocol="HTTP",
            kind="response",
            fields=common_fields,
        )
    else:
        raise HttpParseError(f"Unsupported HTTP start line: {start_line!r}")

    return HttpParseResult(
        application=application,
        complete=complete,
        warnings=warnings,
    )
