from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class Event:
    """Normalized record with a timezone-aware timestamp and source reference."""

    event_id: str
    timestamp: datetime
    event_type: str
    host: str
    source: str
    user: Optional[str] = None
    source_ip: Optional[str] = None


@dataclass(frozen=True)
class Finding:
    detector: str
    reason: str
    event_ids: tuple[str, ...]


@dataclass(frozen=True)
class Case:
    case_id: str
    findings: tuple[Finding, ...]
    events: tuple[Event, ...]
