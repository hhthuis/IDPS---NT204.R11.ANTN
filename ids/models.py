from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class CaptureSource:
    type: str
    name: str


@dataclass(slots=True)
class NetworkInfo:
    protocol: str
    src_ip: str
    dst_ip: str
    ttl: int | None = None
    packet_length: int | None = None
    identification: int | None = None
    flags: list[str] = field(default_factory=list)
    fragment_offset: int | None = None


@dataclass(slots=True)
class TransportInfo:
    protocol: str
    src_port: int
    dst_port: int
    fields: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ApplicationInfo:
    protocol: str = "UNKNOWN"
    kind: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class PayloadInfo:
    length: int = 0
    base64: str | None = None
    preview: str | None = None
    truncated: bool = False


@dataclass(slots=True)
class ParseError:
    stage: str
    message: str


@dataclass(slots=True)
class PacketEvent:
    packet_id: int
    timestamp: str
    source: CaptureSource
    captured_length: int

    schema_version: str = "1.0"
    wire_length: int | None = None
    network: NetworkInfo | None = None
    transport: TransportInfo | None = None
    application: ApplicationInfo = field(default_factory=ApplicationInfo)
    payload: PayloadInfo = field(default_factory=PayloadInfo)
    parse_status: str = "ok"
    errors: list[ParseError] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Chuyển event thành dictionary tương thích JSON."""
        return asdict(self)