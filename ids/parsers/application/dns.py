from dataclasses import dataclass, field
from typing import Any

from scapy.layers.dns import DNS, dnsclasses, dnsqtypes, dnstypes

from ids.models import ApplicationInfo


DNS_OPCODE_NAMES = {
    0: "QUERY",
    1: "IQUERY",
    2: "STATUS",
    4: "NOTIFY",
    5: "UPDATE",
}

DNS_RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


class DnsParseError(ValueError):
    pass


@dataclass(slots=True)
class DnsParseResult:
    application: ApplicationInfo
    complete: bool
    warnings: list[str] = field(default_factory=list)


def _decode_dns_name(value: Any) -> str:
    if isinstance(value, bytes):
        raw_name = value[:-1] if value.endswith(b".") else value
        labels: list[str] = []

        for label in raw_name.split(b"."):
            try:
                labels.append(label.decode("idna"))
            except UnicodeError:
                labels.append(label.decode("ascii", errors="replace"))

        return ".".join(labels)
    else:
        name = str(value)

    return name[:-1] if name.endswith(".") else name


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")

    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]

    return str(value)


def _extract_dns_message(
    payload: bytes,
    transport_protocol: str,
) -> tuple[bytes, bool, int, list[str]]:
    protocol = transport_protocol.upper()

    if protocol == "UDP":
        return payload, True, 0, []

    if protocol != "TCP":
        raise DnsParseError(f"Unsupported DNS transport: {transport_protocol}")

    if len(payload) < 2:
        raise DnsParseError("DNS over TCP is missing its length prefix")

    declared_length = int.from_bytes(payload[:2], "big")
    available = payload[2:]
    warnings: list[str] = []

    if declared_length < 12:
        raise DnsParseError("DNS over TCP declares an invalid message length")

    if len(available) < declared_length:
        warnings.append(
            "DNS over TCP payload is shorter than its declared message length"
        )
        return available, False, 0, warnings

    remaining_bytes = len(available) - declared_length
    message = available[:declared_length]
    return message, True, remaining_bytes, warnings


def _parse_questions(records: Any) -> list[dict[str, Any]]:
    questions: list[dict[str, Any]] = []

    for record in list(records or []):
        type_code = int(record.qtype)
        class_code = int(record.qclass)
        questions.append(
            {
                "name": _decode_dns_name(record.qname),
                "type": dnsqtypes.get(type_code, f"TYPE{type_code}"),
                "type_code": type_code,
                "class": dnsclasses.get(class_code, f"CLASS{class_code}"),
                "class_code": class_code,
            }
        )

    return questions


def _parse_resource_records(records: Any) -> list[dict[str, Any]]:
    parsed_records: list[dict[str, Any]] = []

    for record in list(records or []):
        type_code = int(record.type)
        class_code = int(record.rclass)
        parsed_records.append(
            {
                "name": _decode_dns_name(record.rrname),
                "type": dnstypes.get(type_code, f"TYPE{type_code}"),
                "type_code": type_code,
                "class": dnsclasses.get(class_code, f"CLASS{class_code}"),
                "class_code": class_code,
                "ttl": int(record.ttl),
                "data": _json_safe(getattr(record, "rdata", None)),
            }
        )

    return parsed_records


def _validate_record_count(
    name: str,
    expected: int,
    actual: int,
    warnings: list[str],
) -> bool:
    if expected == actual:
        return True

    warnings.append(
        f"DNS {name} count mismatch: header={expected}, parsed={actual}"
    )
    return False


def parse_dns(
    payload: bytes,
    transport_protocol: str,
) -> DnsParseResult:
    message, complete, remaining_bytes, warnings = _extract_dns_message(
        payload,
        transport_protocol,
    )

    if len(message) < 12:
        raise DnsParseError("DNS message is shorter than its 12-byte header")

    try:
        dns = DNS(message)
    except Exception as error:
        raise DnsParseError(f"Cannot decode DNS message: {error}") from error

    questions = _parse_questions(dns.qd)
    answers = _parse_resource_records(dns.an)
    authorities = _parse_resource_records(dns.ns)
    additionals = _parse_resource_records(dns.ar)

    expected_counts = {
        "question": int(dns.qdcount or 0),
        "answer": int(dns.ancount or 0),
        "authority": int(dns.nscount or 0),
        "additional": int(dns.arcount or 0),
    }
    actual_counts = {
        "question": len(questions),
        "answer": len(answers),
        "authority": len(authorities),
        "additional": len(additionals),
    }

    for name in expected_counts:
        complete = (
            _validate_record_count(
                name,
                expected_counts[name],
                actual_counts[name],
                warnings,
            )
            and complete
        )

    opcode = int(dns.opcode)
    rcode = int(dns.rcode)
    is_response = bool(dns.qr)

    fields: dict[str, Any] = {
        "transaction_id": int(dns.id),
        "opcode": DNS_OPCODE_NAMES.get(opcode, f"OPCODE{opcode}"),
        "opcode_code": opcode,
        "response_code": DNS_RCODE_NAMES.get(rcode, f"RCODE{rcode}"),
        "response_code_value": rcode,
        "flags": {
            "authoritative_answer": bool(dns.aa),
            "truncated": bool(dns.tc),
            "recursion_desired": bool(dns.rd),
            "recursion_available": bool(dns.ra),
            "authenticated_data": bool(dns.ad),
            "checking_disabled": bool(dns.cd),
        },
        "counts": expected_counts,
        "questions": questions,
        "answers": answers,
        "authorities": authorities,
        "additionals": additionals,
        "remaining_bytes": remaining_bytes,
        "message_complete": complete,
    }

    application = ApplicationInfo(
        protocol="DNS",
        kind="response" if is_response else "query",
        fields=fields,
    )

    return DnsParseResult(
        application=application,
        complete=complete,
        warnings=warnings,
    )
