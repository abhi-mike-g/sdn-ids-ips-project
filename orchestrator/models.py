"""Core data models for the SDN security orchestrator."""
from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_suricata(cls, sev: int) -> "Severity":
        # Suricata severity: 1 = most severe ... 3+ = least. Invert to our scale.
        return {1: cls.HIGH, 2: cls.MEDIUM, 3: cls.LOW}.get(sev, cls.LOW)


class Stride(enum.Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFO_DISCLOSURE = "Information Disclosure"
    DOS = "Denial of Service"
    ELEVATION = "Elevation of Privilege"
    UNKNOWN = "Unknown"


class IncidentState(enum.Enum):
    NEW = "new"
    TRIAGED = "triaged"
    MITIGATING = "mitigating"
    MITIGATED = "mitigated"
    SIMULATED = "simulated"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class ResponseAction(enum.Enum):
    NONE = "none"
    MONITOR = "monitor"
    RATE_LIMIT = "rate_limit"
    BLOCK = "block"


def _parse_ts(s: Optional[str]) -> datetime:
    """Parse a Suricata EVE timestamp, tolerating both '+0000' and '+00:00'."""
    if not s:
        return datetime.now(timezone.utc)
    # Normalise a trailing '+0000'/'-0530' into '+00:00'/'-05:30'.
    if len(s) >= 5 and s[-5] in "+-" and s[-3] != ":":
        s = s[:-2] + ":" + s[-2:]
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return datetime.now(timezone.utc)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@dataclass
class Alert:
    """A normalised, enriched alert derived from one Suricata EVE record."""
    src_ip: str
    dest_ip: str
    signature: str
    sid: int
    suricata_severity: int
    timestamp: datetime
    src_port: Optional[int] = None
    dest_port: Optional[int] = None
    proto: Optional[str] = None
    category: str = ""
    # Enriched fields (filled by the enrichment stage).
    severity: Severity = Severity.LOW
    stride: Stride = Stride.UNKNOWN
    mitre: list = field(default_factory=list)
    confidence: float = 0.5
    id: str = field(default_factory=lambda: uuid.uuid4().hex)

    @classmethod
    def from_eve(cls, rec: dict) -> Optional["Alert"]:
        if rec.get("event_type") != "alert":
            return None
        a = rec.get("alert", {})
        alert = cls(
            src_ip=rec.get("src_ip", ""),
            dest_ip=rec.get("dest_ip", ""),
            src_port=rec.get("src_port"),
            dest_port=rec.get("dest_port"),
            proto=rec.get("proto"),
            signature=a.get("signature", ""),
            sid=int(a.get("signature_id", 0) or 0),
            category=a.get("category", ""),
            suricata_severity=int(a.get("severity", 3) or 3),
            timestamp=_parse_ts(rec.get("timestamp")),
        )
        alert.severity = Severity.from_suricata(alert.suricata_severity)
        return alert


@dataclass
class Incident:
    """A correlated group of alerts from a single source ('actor')."""
    id: str
    src_ip: str
    created_at: datetime
    updated_at: datetime
    first_seen_ts: float
    last_seen_ts: float
    alert_count: int = 0
    signatures: set = field(default_factory=set)
    stride: set = field(default_factory=set)
    mitre: set = field(default_factory=set)
    dest_ips: set = field(default_factory=set)
    max_severity: Severity = Severity.INFO
    max_confidence: float = 0.0
    state: IncidentState = IncidentState.NEW
    action: ResponseAction = ResponseAction.NONE
    action_reason: str = ""
    mitigation_latency_ms: Optional[float] = None
    flow_rule: str = ""

    @classmethod
    def new(cls, src_ip: str, ts: datetime) -> "Incident":
        return cls(
            id=uuid.uuid4().hex, src_ip=src_ip,
            created_at=ts, updated_at=ts,
            first_seen_ts=ts.timestamp(), last_seen_ts=ts.timestamp(),
        )

    def fold(self, alert: Alert) -> None:
        """Merge a new alert into this incident."""
        self.alert_count += 1
        self.signatures.add(alert.signature)
        if alert.stride is not Stride.UNKNOWN:
            self.stride.add(alert.stride)
        self.mitre.update(alert.mitre)
        if alert.dest_ip:
            self.dest_ips.add(alert.dest_ip)
        if alert.severity > self.max_severity:
            self.max_severity = alert.severity
        if alert.confidence > self.max_confidence:
            self.max_confidence = alert.confidence
        self.updated_at = alert.timestamp
        self.last_seen_ts = max(self.last_seen_ts, alert.timestamp.timestamp())
