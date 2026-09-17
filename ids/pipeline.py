import base64
from datetime import datetime, timezone

from scapy.packet import Packet

from ids.models import (
    CaptureSource,
    PacketEvent,
    ParseError,
    PayloadInfo,
)
from ids.parsers.network import (
    UnsupportedNetworkProtocol,
    parse_ipv4,
)
from ids.parsers.application.detector import detect_application_protocol
from ids.parsers.transport import (
    UnsupportedTransportProtocol,
    parse_transport,
)


def format_timestamp(packet: Packet) -> str:
    timestamp = float(packet.time)

    return (
        datetime.fromtimestamp(timestamp, tz=timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def create_payload_info(payload: bytes) -> PayloadInfo:
    if not payload:
        return PayloadInfo()

    return PayloadInfo(
        length=len(payload),
        base64=base64.b64encode(payload).decode("ascii"),
        preview=payload[:256].decode(
            "utf-8",
            errors="replace",
        ),
        truncated=False,
    )


def parse_packet(
    packet: Packet,
    packet_id: int,
    source: CaptureSource,
) -> PacketEvent:
    captured_length = len(bytes(packet))

    wire_length_value = getattr(packet, "wirelen", None)
    wire_length = (
        int(wire_length_value)
        if wire_length_value is not None
        else captured_length
    )

    event = PacketEvent(
        packet_id=packet_id,
        timestamp=format_timestamp(packet),
        source=source,
        captured_length=captured_length,
        wire_length=wire_length,
    )

    try:
        event.network = parse_ipv4(packet)
    except UnsupportedNetworkProtocol as error:
        event.parse_status = "unsupported"
        event.errors.append(
            ParseError(
                stage="network",
                message=str(error),
            )
        )
        return event
    except Exception as error:
        event.parse_status = "malformed"
        event.errors.append(
            ParseError(
                stage="network",
                message=f"{type(error).__name__}: {error}",
            )
        )
        return event

    try:
        result = parse_transport(packet)
        event.transport = result.info
        event.payload = create_payload_info(result.payload)
    except UnsupportedTransportProtocol as error:
        event.parse_status = "unsupported"
        event.errors.append(
            ParseError(
                stage="transport",
                message=str(error),
            )
        )
        return event
    except Exception as error:
        event.parse_status = "malformed"
        event.errors.append(
            ParseError(
                stage="transport",
                message=f"{type(error).__name__}: {error}",
            )
        )
        return event

    try:
        event.application.protocol = detect_application_protocol(
            payload=result.payload,
            transport_protocol=result.info.protocol,
            src_port=result.info.src_port,
            dst_port=result.info.dst_port,
        )
    except Exception as error:
        event.parse_status = "partial"
        event.errors.append(
            ParseError(
                stage="application_detector",
                message=f"{type(error).__name__}: {error}",
            )
        )

    return event
