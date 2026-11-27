"""Turn log events and evidence gaps into retrieval queries."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

_EVENT_FIELDS = (
    "log_type",
    "log_source",
    "event_id",
    "eventid",
    "event_type",
    "object",
    "action",
    "computer",
    "host",
    "user",
    "image",
    "process",
    "parent_image",
    "parent_process",
    "command_line",
    "script_block",
    "message",
    "destination_ip",
    "destination_hostname",
    "query",
    "file_name",
    "registry_key",
    "protocol",
    "status",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "method",
    "uri",
    "user_agent",
    "mime_type",
    "uid",
    "status_message",
)


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return " ".join(_stringify(item) for item in value if item is not None)
    if isinstance(value, Mapping):
        return " ".join(f"{key}={_stringify(item)}" for key, item in value.items())
    return str(value).strip()


def _truncate(text: str, max_chars: int) -> str:
    text = " ".join(text.split())
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3].rstrip() + "..."


def build_event_query(event: Mapping[str, Any] | Any, *, max_chars: int = 1200) -> str:
    if not isinstance(event, Mapping):
        try:
            event = vars(event)
        except TypeError:
            event = {"event": event}
    parts: list[str] = []
    for key in _EVENT_FIELDS:
        value = _stringify(event.get(key))
        if value:
            parts.append(f"{key}={value}")
    if not parts:
        parts.append(_stringify(json.dumps(event, ensure_ascii=False, default=str)))
    return _truncate(" ".join(parts), max_chars)


def build_gap_query(gap: Any, *, max_chars: int = 1200) -> str:
    if isinstance(gap, Mapping):
        text = " ".join(f"{key}={_stringify(value)}" for key, value in gap.items())
    elif isinstance(gap, Sequence) and not isinstance(gap, (str, bytes)):
        text = " ".join(_stringify(item) for item in gap)
    else:
        text = _stringify(gap)
    if not text:
        return "missing evidence"
    return _truncate("missing evidence: " + text, max_chars)


def build_technique_query(
    technique_id: str,
    behavior: str | None = None,
    *,
    max_chars: int = 1200,
) -> str:
    text = f"{technique_id} {behavior or ''}".strip()
    return _truncate(text or str(technique_id), max_chars)
