"""Deterministic log normalization & M3 formatter bridges reusing script/log_convert/lib (F03)."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import math
import re
import sys
import threading
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

import orjson
from dateutil import parser as dateutil_parser
from lxml import etree
from pydantic import BaseModel, ConfigDict, Field

from apt_agent.exceptions import ConfigError, InvalidArgumentError
from apt_agent.ingestion.store import RawEvidenceStore
from apt_agent.models import Event, RawRecord, RunContext

_LIB_LOCK = threading.Lock()
_CACHED_LIB: _LogConvertLib | None = None
_PRIVATE_PKG = "apt_agent.ingestion._log_convert_lib"

_FLEX_EPOCH_COMMENT_RE = re.compile(r"^#([0-9]+)$")
_XML_DECL_RE = re.compile(r"^\s*<\?xml[^?]*\?>\s*", re.IGNORECASE)

_KNOWN_WINXML_SYSTEM_KEYS = frozenset(
    {
        "Provider",
        "TimeCreated",
        "Execution",
        "Correlation",
        "Security",
        "EventID",
        "EventID_Qualifiers",
        "Version",
        "Level",
        "Task",
        "Opcode",
        "Keywords",
        "EventRecordID",
        "Channel",
        "Computer",
    }
)

_KNOWN_ECAR_TOP_KEYS = frozenset(
    {
        "id",
        "object",
        "action",
        "objectID",
        "actorID",
        "hostname",
        "principal",
        "pid",
        "ppid",
        "tid",
        "timestamp_ms",
        "timestamp",
        "properties",
    }
)


@dataclass(frozen=True)
class _LogConvertLib:
    common: ModuleType
    parsers: ModuleType
    formatters: ModuleType


def _find_log_convert_lib_dir() -> Path:
    candidates = [
        Path(__file__).resolve().parents[3] / "script" / "log_convert" / "lib",
        Path.cwd() / "script" / "log_convert" / "lib",
    ]
    for cand in candidates:
        if (cand / "common.py").is_file() and (cand / "parsers.py").is_file() and (
            cand / "formatters.py"
        ).is_file():
            return cand
    raise ConfigError(
        "Could not locate script/log_convert/lib directory.",
        details={"searched": [str(c) for c in candidates]},
    )


def _load_submodule(full_name: str, file_path: Path, *, is_pkg: bool = False) -> ModuleType:
    if full_name in sys.modules:
        return sys.modules[full_name]
    kwargs: dict[str, Any] = {}
    if is_pkg:
        kwargs["submodule_search_locations"] = [str(file_path.parent)]
    spec = importlib.util.spec_from_file_location(full_name, file_path, **kwargs)
    if spec is None or spec.loader is None:
        raise ConfigError(
            f"Failed to create module spec for {full_name} from {file_path}.",
            details={"module": full_name, "path": str(file_path)},
        )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[full_name] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        sys.modules.pop(full_name, None)
        raise
    return mod


def _load_log_convert_lib() -> _LogConvertLib:
    """Load script/log_convert/lib/* under a private namespace without touching sys.path or sys.modules['lib']."""
    global _CACHED_LIB
    if _CACHED_LIB is not None:
        return _CACHED_LIB
    with _LIB_LOCK:
        if _CACHED_LIB is not None:
            return _CACHED_LIB
        lib_dir = _find_log_convert_lib_dir()
        _load_submodule(_PRIVATE_PKG, lib_dir / "__init__.py", is_pkg=True)
        common_mod = _load_submodule(f"{_PRIVATE_PKG}.common", lib_dir / "common.py")
        parsers_mod = _load_submodule(f"{_PRIVATE_PKG}.parsers", lib_dir / "parsers.py")
        formatters_mod = _load_submodule(
            f"{_PRIVATE_PKG}.formatters", lib_dir / "formatters.py"
        )
        _CACHED_LIB = _LogConvertLib(
            common=common_mod,
            parsers=parsers_mod,
            formatters=formatters_mod,
        )
        return _CACHED_LIB


class NormalizationResult(BaseModel):
    """Batch normalization output returned by `Normalizer.normalize_batch`."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    events: list[Event] = Field(default_factory=list)
    gaps: list[dict[str, Any]] = Field(default_factory=list)
    source_type_counts: dict[str, int] = Field(default_factory=dict)
    event_to_physical: dict[str, str] = Field(default_factory=dict)


def _make_deterministic_event_id(case_id: str, physical_record_id: str, sub_index: int) -> str:
    payload = f"{case_id}|{physical_record_id}|{sub_index}".encode("utf-8")
    return "evt_" + hashlib.sha256(payload).hexdigest()[:16]


def _make_gap(
    raw: RawRecord,
    *,
    source: str,
    reason: str,
    detail: str,
) -> dict[str, Any]:
    return {
        "physical_record_id": raw.physical_record_id,
        "raw_id": raw.raw_id or raw.physical_record_id,
        "source": source,
        "reason": reason,
        "detail": detail,
    }


def _truncate_fractional_seconds(ts_str: str) -> str:
    s = ts_str.strip()
    if "." not in s:
        return s
    head, rest = s.split(".", 1)
    frac_chars: list[str] = []
    tz_part = ""
    for idx, ch in enumerate(rest):
        if ch.isdigit():
            frac_chars.append(ch)
        else:
            tz_part = rest[idx:]
            break
    frac = "".join(frac_chars)[:6].ljust(6, "0")
    return f"{head}.{frac}{tz_part}"


def _format_tz_offset(dt: datetime) -> str:
    offset = dt.utcoffset()
    if offset is None:
        return "unknown"
    total_seconds = int(offset.total_seconds())
    if total_seconds == 0:
        return "UTC"
    sign = "+" if total_seconds >= 0 else "-"
    total_seconds = abs(total_seconds)
    hours, rem = divmod(total_seconds, 3600)
    minutes = rem // 60
    return f"{sign}{hours:02d}:{minutes:02d}"


def _normalize_iso_utc_strict(
    ts_str: Any,
    lib_common: ModuleType,
) -> tuple[str | None, str | None, dict[str, Any]]:
    """Normalize ISO-8601 string to UTC Z; return `(None, warning, meta)` on naive/invalid input."""
    if ts_str is None:
        return None, "missing_timestamp", {"raw_timestamp": None}
    if not isinstance(ts_str, str):
        return None, "invalid_timestamp", {"raw_timestamp": ts_str}
    stripped = ts_str.strip()
    if not stripped:
        return None, "missing_timestamp", {"raw_timestamp": ts_str}

    sanitized = _truncate_fractional_seconds(stripped)
    try:
        parsed = dateutil_parser.isoparse(sanitized)
    except (ValueError, TypeError, OverflowError):
        return None, "invalid_timestamp", {"raw_timestamp": ts_str}

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return (
            None,
            "unknown_timezone",
            {"raw_timestamp": ts_str, "original_timezone": "unknown"},
        )

    orig_tz = _format_tz_offset(parsed)
    try:
        utc_iso = lib_common.normalize_iso_utc(stripped)
    except (ValueError, TypeError, OverflowError):
        return None, "invalid_timestamp", {"raw_timestamp": ts_str}

    return (
        utc_iso,
        None,
        {"raw_timestamp": ts_str, "original_timezone": orig_tz},
    )


def _normalize_epoch_seconds(
    val: Any,
    lib_common: ModuleType,
) -> tuple[str | None, str | None]:
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        return None, "invalid_timestamp"
    num = float(val)
    if not math.isfinite(num):
        return None, "invalid_timestamp"
    try:
        return lib_common.epoch_to_utc_iso(num), None
    except (ValueError, TypeError, OverflowError, OSError):
        return None, "invalid_timestamp"


def _normalize_epoch_ms(
    val: Any,
    lib_common: ModuleType,
) -> tuple[str | None, str | None]:
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        return None, "invalid_timestamp"
    num = float(val)
    if not math.isfinite(num):
        return None, "invalid_timestamp"
    try:
        return lib_common.epoch_ms_to_utc_iso(num), None
    except (ValueError, TypeError, OverflowError, OSError):
        return None, "invalid_timestamp"


def _infer_zeek_type_fallback(sample: Mapping[str, Any]) -> str:
    if "conn_state" in sample or ("proto" in sample and ("orig_bytes" in sample or "resp_bytes" in sample or "duration" in sample)):
        return "conn"
    if "query" in sample or "qtype_name" in sample or "rcode_name" in sample or "answers" in sample:
        return "dns"
    if "method" in sample or ("uri" in sample and "host" in sample) or ("status_code" in sample and "user_agent" in sample):
        return "http"
    if "server_name" in sample or "cipher" in sample or "ja3" in sample or ("version" in sample and "resumed" in sample):
        return "ssl"
    if "fuid" in sample or ("mime_type" in sample and ("sha256" in sample or "md5" in sample or "tx_hosts" in sample)):
        return "files"
    if "assigned_addr" in sample or "lease_time" in sample or ("mac" in sample and ("client_addr" in sample or "host_name" in sample or "msg_types" in sample)):
        return "dhcp"
    if "helo" in sample or "mailfrom" in sample or "rcptto" in sample or "last_reply" in sample:
        return "smtp"
    if "certificate.subject" in sample or "certificate.serial" in sample or "san.dns" in sample or "basic_constraints.ca" in sample:
        return "x509"
    if "certStatus" in sample or "serialNumber" in sample or "responderId" in sample:
        return "ocsp"
    if "machine" in sample or "section_names" in sample or "compile_ts" in sample or "subsystem" in sample:
        return "pe"
    return "unknown"


def _looks_like_ecar_dict(d: Mapping[str, Any]) -> bool:
    if "object" in d and "action" in d:
        return True
    if "timestamp_ms" in d or isinstance(d.get("properties"), Mapping):
        return True
    if "actorID" in d and "objectID" in d:
        return True
    if "principal" in d and "hostname" in d and "pid" in d:
        return True
    return False


def _looks_like_zeek_dict(d: Mapping[str, Any], lib_parsers: ModuleType) -> bool:
    if _infer_zeek_type_fallback(d) != "unknown":
        return True
    if "ts" in d or "id.orig_h" in d or "id.resp_h" in d:
        return True
    if "uid" in d and "proto" in d:
        return True
    inferred = lib_parsers.detect_zeek_log_type(Path("unknown.json"), dict(d))
    return inferred != "unknown"


def _classify_hint_label(hint: str, lib_parsers: ModuleType) -> tuple[str | None, str | None]:
    """Classify explicit format/type hint string; return `(log_format, zeek_subtype_or_none)`."""
    low = hint.strip().lower()
    if low in ("winxml", "winxml_sysmon", "winxml_security"):
        return "winxml", None
    if low in ("ecar", "ecar_json"):
        return "ecar_json", None
    if low == "syslog":
        return "syslog", None
    if low == "web_access":
        return "web_access", None
    if low == "bash_history":
        return "bash_history", None
    if low in ("zeek", "zeek_json"):
        return "zeek_json", None
    if low.startswith("zeek_"):
        subtype = low[5:]
        return "zeek_json", subtype

    # Treat hint as a filepath if it looks like a filename/path
    p = Path(hint)
    if lib_parsers.is_winxml_file(p):
        return "winxml", None
    if lib_parsers.is_ecar_json_file(p):
        return "ecar_json", None
    if p.suffix.lower() in (".json", ".jsonl", ".ndjson"):
        stem = p.stem.lower()
        if stem in lib_parsers.ZEEK_KNOWN_TYPES:
            return "zeek_json", stem
        return None, None  # Ambiguous .json filename -> inspect content
    if lib_parsers.is_bash_history_file(p) or any(
        "bash_history" in part.lower() for part in p.parts
    ):
        return "bash_history", None
    if lib_parsers.is_web_access_file(p):
        return "web_access", None
    if lib_parsers.is_syslog_file(p):
        return "syslog", None
    return None, None


def _classify_raw_record(
    raw: RawRecord,
    lib_parsers: ModuleType,
) -> tuple[str | None, str | None, bool, dict[str, Any] | None, dict[str, Any] | None]:
    """Determine `(log_format, zeek_hint, forced_by_metadata, parsed_json_obj, gap_or_none)`."""
    forced_format: str | None = None
    zeek_hint: str | None = None

    if raw.source_hint:
        forced_format, zeek_hint = _classify_hint_label(raw.source_hint, lib_parsers)
    if forced_format is None and raw.locator is not None:
        forced_format, zeek_hint = _classify_hint_label(raw.locator.filepath, lib_parsers)

    payload = raw.payload
    if forced_format is not None:
        return forced_format, zeek_hint, True, None, None

    # Content-based classification (locator is None or ambiguous .json filename)
    if "raw_text" in payload:
        raw_text = payload.get("raw_text")
        if not isinstance(raw_text, str):
            return (
                None,
                None,
                False,
                None,
                _make_gap(
                    raw,
                    source="unknown",
                    reason="invalid_payload",
                    detail="payload['raw_text'] must be a string.",
                ),
            )
        if "timestamp" in payload:
            ts_val = payload["timestamp"]
            if isinstance(ts_val, bool):
                return (
                    None,
                    None,
                    False,
                    None,
                    _make_gap(
                        raw,
                        source="bash_history",
                        reason="invalid_timestamp_type",
                        detail="bash_history timestamp must be int or None, not bool.",
                    ),
                )
            if ts_val is None or isinstance(ts_val, int):
                return "bash_history", None, False, None, None

        stripped = raw_text.strip()
        if not stripped:
            return (
                None,
                None,
                False,
                None,
                _make_gap(
                    raw,
                    source="unknown",
                    reason="empty_payload",
                    detail="raw_text is empty or whitespace-only.",
                ),
            )

        if stripped.startswith("<") and "<Event" in stripped:
            return "winxml", None, False, None, None

        if stripped.startswith("{"):
            try:
                parsed = orjson.loads(stripped)
            except (orjson.JSONDecodeError, ValueError) as exc:
                return (
                    None,
                    None,
                    False,
                    None,
                    _make_gap(
                        raw,
                        source="json",
                        reason="json_parse_error",
                        detail=f"Failed to parse JSON raw_text: {exc}",
                    ),
                )
            if not isinstance(parsed, dict):
                return (
                    None,
                    None,
                    False,
                    None,
                    _make_gap(
                        raw,
                        source="json",
                        reason="json_parse_error",
                        detail="JSON raw_text must decode to an object.",
                    ),
                )
            if _looks_like_ecar_dict(parsed):
                return "ecar_json", None, False, parsed, None
            if _looks_like_zeek_dict(parsed, lib_parsers):
                return "zeek_json", None, False, parsed, None
            return (
                None,
                None,
                False,
                None,
                _make_gap(
                    raw,
                    source="json",
                    reason="unrecognized_json_schema",
                    detail="JSON object matched neither ECAR nor Zeek schema.",
                ),
            )

        first_line = raw_text.splitlines()[0].rstrip("\r\n") if raw_text else ""
        if lib_parsers.RFC5424_RE.match(first_line) or lib_parsers.RFC3164_RE.match(first_line):
            return "syslog", None, False, None, None
        if lib_parsers.COMBINED_LOG_RE.match(first_line):
            return "web_access", None, False, None, None
        if _FLEX_EPOCH_COMMENT_RE.match(first_line):
            return "bash_history", None, False, None, None

        return (
            None,
            None,
            False,
            None,
            _make_gap(
                raw,
                source="unknown",
                reason="unrecognized_format",
                detail="Could not identify log format from raw_text.",
            ),
        )

    # Structured dict payload (no raw_text wrapper)
    if not payload:
        return (
            None,
            None,
            False,
            None,
            _make_gap(
                raw,
                source="unknown",
                reason="empty_payload",
                detail="Payload dictionary is empty.",
            ),
        )
    if "parse_error" in payload and "ts" not in payload and "object" not in payload:
        return (
            None,
            None,
            False,
            None,
            _make_gap(
                raw,
                source="json",
                reason="json_parse_error",
                detail=str(payload.get("parse_error")),
            ),
        )
    if _looks_like_ecar_dict(payload):
        return "ecar_json", None, False, dict(payload), None
    if _looks_like_zeek_dict(payload, lib_parsers):
        return "zeek_json", None, False, dict(payload), None

    return (
        None,
        None,
        False,
        None,
        _make_gap(
            raw,
            source="json",
            reason="unrecognized_json_schema",
            detail="Structured dict payload matched neither ECAR nor Zeek schema.",
        ),
    )


def _extract_json_dict(
    raw: RawRecord,
    preparsed: dict[str, Any] | None,
    *,
    source_label: str,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if preparsed is not None:
        return preparsed, None
    payload = raw.payload
    if "raw_text" in payload:
        raw_text = payload.get("raw_text")
        if not isinstance(raw_text, str) or not raw_text.strip():
            return None, _make_gap(
                raw,
                source=source_label,
                reason="empty_payload",
                detail="Blank or missing JSONL line.",
            )
        try:
            decoded = orjson.loads(raw_text)
        except (orjson.JSONDecodeError, ValueError) as exc:
            return None, _make_gap(
                raw,
                source=source_label,
                reason="json_parse_error",
                detail=f"Malformed JSON: {exc}",
            )
        if not isinstance(decoded, dict):
            return None, _make_gap(
                raw,
                source=source_label,
                reason="json_parse_error",
                detail="Decoded JSON value is not an object.",
            )
        return decoded, None
    if not payload:
        return None, _make_gap(
            raw,
            source=source_label,
            reason="empty_payload",
            detail="Payload dictionary is empty.",
        )
    if "parse_error" in payload and len(payload) <= 2:
        return None, _make_gap(
            raw,
            source=source_label,
            reason="json_parse_error",
            detail=str(payload["parse_error"]),
        )
    return dict(payload), None


def _source_meta(raw: RawRecord) -> tuple[str, int]:
    if raw.locator is not None:
        return Path(raw.locator.filepath).name, raw.locator.linenumber
    if raw.source_hint:
        return Path(raw.source_hint).name, 1
    return "", 1


def _normalize_winxml(
    ctx: RunContext,
    raw: RawRecord,
    lib: _LogConvertLib,
) -> tuple[list[Event], list[dict[str, Any]]]:
    raw_text = raw.payload.get("raw_text")
    if not isinstance(raw_text, str) or not raw_text.strip():
        return [], [
            _make_gap(
                raw,
                source="winxml",
                reason="empty_payload",
                detail="Windows XML raw_text is empty or missing.",
            )
        ]

    cleaned_xml = _XML_DECL_RE.sub("", raw_text.strip(), count=1)
    wrapped = f"<_AptRoot>{cleaned_xml}</_AptRoot>".encode("utf-8", errors="replace")
    parser = etree.XMLParser(resolve_entities=False, no_network=True, recover=True)
    try:
        root = etree.fromstring(wrapped, parser=parser)
    except etree.XMLSyntaxError as exc:
        return [], [
            _make_gap(
                raw,
                source="winxml",
                reason="xml_parse_error",
                detail=f"Failed to parse XML: {exc}",
            )
        ]

    if root is None:
        return [], [
            _make_gap(
                raw,
                source="winxml",
                reason="xml_parse_error",
                detail="XML parser returned empty document.",
            )
        ]

    event_elems = [
        el
        for el in root.iter()
        if isinstance(el.tag, str) and lib.parsers._local_tag(el.tag) == "Event"
    ]
    if not event_elems:
        return [], [
            _make_gap(
                raw,
                source="winxml",
                reason="xml_parse_error",
                detail="No <Event> elements found in XML payload.",
            )
        ]

    source_file, record_index = _source_meta(raw)
    events: list[Event] = []
    gaps: list[dict[str, Any]] = []

    for sub_index, elem in enumerate(event_elems):
        xmlns = elem.nsmap.get(None) or "http://schemas.microsoft.com/win/2004/08/events/event"
        system: dict[str, Any] = {}
        event_data: dict[str, Any] = {}
        user_data: dict[str, Any] = {}
        extra_sections: dict[str, Any] = {}

        for child in elem:
            if not isinstance(child.tag, str):
                continue
            ctag = lib.parsers._local_tag(child.tag)
            if ctag == "System":
                for sc in child:
                    if not isinstance(sc.tag, str):
                        continue
                    stag = lib.parsers._local_tag(sc.tag)
                    text = sc.text.strip() if sc.text else None
                    attrs = dict(sc.attrib)
                    if stag == "Provider":
                        system["Provider"] = attrs
                    elif stag == "TimeCreated":
                        system["TimeCreated"] = attrs
                    elif stag == "Execution":
                        exec_attrs: dict[str, Any] = {}
                        for k, v in attrs.items():
                            exec_attrs[k] = lib.parsers._try_int(v)
                        system["Execution"] = exec_attrs
                    elif stag == "Correlation":
                        system["Correlation"] = attrs if attrs else None
                    elif stag == "Security":
                        system["Security"] = attrs if attrs else None
                    elif stag == "EventID":
                        ev_id = lib.parsers._try_int(text)
                        if attrs:
                            system["EventID"] = ev_id
                            system["EventID_Qualifiers"] = lib.parsers._try_int(
                                attrs.get("Qualifiers")
                            )
                        else:
                            system["EventID"] = ev_id
                    elif stag in lib.parsers.WIN_XML_INT_SYSTEM_TAGS:
                        system[stag] = lib.parsers._try_int(text)
                    else:
                        system[stag] = text
            elif ctag == "EventData":
                unnamed_idx = 0
                for dc in child:
                    if not isinstance(dc.tag, str):
                        continue
                    dtag = lib.parsers._local_tag(dc.tag)
                    dval = dc.text if dc.text is not None else ""
                    if dtag == "Data":
                        dname = dc.attrib.get("Name")
                        if not dname:
                            dname = f"Data_{unnamed_idx}"
                            unnamed_idx += 1
                        event_data[dname] = dval
                    else:
                        event_data[dtag] = dval
            elif ctag == "UserData":
                for uc in child:
                    if not isinstance(uc.tag, str):
                        continue
                    for sub in uc:
                        if not isinstance(sub.tag, str):
                            continue
                        user_data[lib.parsers._local_tag(sub.tag)] = (
                            sub.text if sub.text is not None else ""
                        )
            else:
                extra_sections[ctag] = (child.text or "").strip()

        if not system and not event_data and not user_data:
            gaps.append(
                _make_gap(
                    raw,
                    source="winxml",
                    reason="xml_parse_error",
                    detail=f"<Event> sub-index {sub_index} contained no System/EventData/UserData.",
                )
            )
            continue

        sys_time_raw = (system.get("TimeCreated") or {}).get("SystemTime", "")
        event_time, ts_warn, tz_meta = _normalize_iso_utc_strict(sys_time_raw, lib.common)
        warnings: list[str] = [ts_warn] if ts_warn else []

        provider_name = str((system.get("Provider") or {}).get("Name") or "").lower()
        channel = str(system.get("Channel") or "").lower()
        hint_or_path = (
            f"{raw.source_hint or ''} {raw.locator.filepath if raw.locator else ''}".lower()
        )
        if "sysmon" in channel or "sysmon" in provider_name or "sysmon" in hint_or_path:
            source_type = "winxml_sysmon"
        elif (
            channel == "security"
            or "security-auditing" in provider_name
            or "security" in hint_or_path
        ):
            source_type = "winxml_security"
        else:
            source_type = "winxml"

        event_id = _make_deterministic_event_id(ctx.case_id, raw.physical_record_id, sub_index)
        raw_id = raw.raw_id or raw.physical_record_id
        parsed_stub = {
            "event_id": event_id,
            "raw_id": raw_id,
            "source_file": source_file,
            "record_index": record_index,
            "xmlns": xmlns,
            "utc_timestamp": event_time or "",
            "system_time_raw": sys_time_raw,
            "system": system,
            "event_data": event_data,
            "user_data": user_data,
        }
        flat = lib.formatters._build_flat_winxml_record(parsed_stub)
        fields: dict[str, Any] = {
            k: v
            for k, v in flat.items()
            if k not in ("event_id", "raw_id", "source_file", "record_index", "@timestamp")
        }
        unknown_fields: list[str] = []
        existing_lower = {k.lower() for k in fields}
        for sk, sv in system.items():
            if sk not in _KNOWN_WINXML_SYSTEM_KEYS:
                unknown_fields.append(sk)
                out_k = sk if sk.lower() not in existing_lower else f"System_{sk}"
                fields[out_k] = sv
                existing_lower.add(out_k.lower())
        for ek, ev in extra_sections.items():
            unknown_fields.append(ek)
            out_k = ek if ek.lower() not in existing_lower else f"Event_{ek}"
            fields[out_k] = ev
            existing_lower.add(out_k.lower())

        parse_metadata: dict[str, Any] = {
            "log_format": "winxml",
            "source_file": source_file,
            "record_index": record_index,
            "sub_index": sub_index,
            "raw_timestamp": tz_meta.get("raw_timestamp"),
            "original_timezone": tz_meta.get("original_timezone"),
            "warnings": warnings,
            "unknown_fields": unknown_fields,
            "_winxml": {
                "xmlns": xmlns,
                "system": system,
                "event_data": event_data,
                "user_data": user_data,
                "system_time_raw": sys_time_raw,
            },
        }
        events.append(
            Event(
                event_id=event_id,
                physical_record_id=raw.physical_record_id,
                raw_id=raw_id,
                source_type=source_type,
                event_time=event_time,
                fields=fields,
                host=system.get("Computer") if isinstance(system.get("Computer"), str) else None,
                parse_metadata=parse_metadata,
            )
        )

    return events, gaps


def _normalize_zeek(
    ctx: RunContext,
    raw: RawRecord,
    lib: _LogConvertLib,
    preparsed: dict[str, Any] | None,
    zeek_hint: str | None,
) -> tuple[list[Event], list[dict[str, Any]]]:
    obj, gap = _extract_json_dict(raw, preparsed, source_label="zeek_json")
    if gap is not None or obj is None:
        return [], [gap] if gap is not None else []

    source_file, record_index = _source_meta(raw)
    path_for_detect = Path(raw.locator.filepath) if raw.locator is not None else Path("unknown.json")
    if zeek_hint and zeek_hint != "unknown":
        zeek_type = zeek_hint
    else:
        zeek_type = lib.parsers.detect_zeek_log_type(path_for_detect, obj)
        if zeek_type not in lib.parsers.ZEEK_KNOWN_TYPES:
            inferred = _infer_zeek_type_fallback(obj)
            if inferred != "unknown":
                zeek_type = inferred

    source_type = f"zeek_{zeek_type}" if zeek_type and zeek_type != "unknown" else "zeek"

    ts_val = obj.get("ts")
    warnings: list[str] = []
    if ts_val is not None:
        event_time, ts_warn = _normalize_epoch_seconds(ts_val, lib.common)
        if ts_warn:
            warnings.append(ts_warn)
    else:
        event_time = None
        warnings.append("missing_timestamp")

    fields: dict[str, Any] = {
        "log_source": "zeek",
        "zeek_log_type": zeek_type,
    }
    fields.update(lib.formatters._zeek_sigma_aliases(obj))
    for k, v in obj.items():
        fields[k] = copy.deepcopy(v)
        if "." in k:
            underscore_key = k.replace(".", "_")
            if underscore_key not in fields:
                fields[underscore_key] = copy.deepcopy(v)

    host_val = obj.get("id.orig_h")
    host = host_val if isinstance(host_val, str) and host_val.strip() else None

    raw_id = raw.raw_id or raw.physical_record_id
    event_id = _make_deterministic_event_id(ctx.case_id, raw.physical_record_id, 0)
    parse_metadata: dict[str, Any] = {
        "log_format": "zeek_json",
        "zeek_log_type": zeek_type,
        "source_file": source_file,
        "record_index": record_index,
        "sub_index": 0,
        "raw_timestamp": ts_val,
        "original_timezone": "epoch_utc" if event_time else None,
        "warnings": warnings,
        "_zeek_raw": copy.deepcopy(obj),
    }

    return [
        Event(
            event_id=event_id,
            physical_record_id=raw.physical_record_id,
            raw_id=raw_id,
            source_type=source_type,
            event_time=event_time,
            fields=fields,
            host=host,
            parse_metadata=parse_metadata,
        )
    ], []


def _normalize_ecar(
    ctx: RunContext,
    raw: RawRecord,
    lib: _LogConvertLib,
    preparsed: dict[str, Any] | None,
) -> tuple[list[Event], list[dict[str, Any]]]:
    obj, gap = _extract_json_dict(raw, preparsed, source_label="ecar")
    if gap is not None or obj is None:
        return [], [gap] if gap is not None else []

    source_file, record_index = _source_meta(raw)
    warnings: list[str] = []
    raw_ts: Any = None
    orig_tz: str | None = None

    if "timestamp_ms" in obj and obj["timestamp_ms"] is not None:
        raw_ts = obj["timestamp_ms"]
        orig_tz = "epoch_ms_utc"
        event_time, ts_warn = _normalize_epoch_ms(raw_ts, lib.common)
        if ts_warn:
            warnings.append(ts_warn)
    elif obj.get("timestamp") not in (None, ""):
        raw_ts = obj["timestamp"]
        event_time, ts_warn, tz_meta = _normalize_iso_utc_strict(str(raw_ts), lib.common)
        orig_tz = tz_meta.get("original_timezone")
        if ts_warn:
            warnings.append(ts_warn)
    else:
        event_time = None
        warnings.append("missing_timestamp")

    raw_props = obj.get("properties")
    if "properties" in obj and raw_props is not None and not isinstance(raw_props, Mapping):
        warnings.append("invalid_properties")
        sanitized_obj = {**obj, "properties": {}}
    else:
        sanitized_obj = obj

    fields: dict[str, Any] = lib.formatters._ecar_sigma_fields(sanitized_obj)
    if "properties" in obj:
        fields["properties"] = copy.deepcopy(raw_props)

    unknown_fields: list[str] = []
    for k, v in obj.items():
        if k not in _KNOWN_ECAR_TOP_KEYS:
            unknown_fields.append(k)
            if k not in fields:
                fields[k] = copy.deepcopy(v)

    host_val = obj.get("hostname")
    host = host_val if isinstance(host_val, str) and host_val.strip() else None

    raw_id = raw.raw_id or raw.physical_record_id
    event_id = _make_deterministic_event_id(ctx.case_id, raw.physical_record_id, 0)
    parse_metadata: dict[str, Any] = {
        "log_format": "ecar_json",
        "source_file": source_file,
        "record_index": record_index,
        "sub_index": 0,
        "raw_timestamp": raw_ts,
        "original_timezone": orig_tz,
        "warnings": warnings,
        "unknown_fields": unknown_fields,
        "_ecar_raw": copy.deepcopy(sanitized_obj),
    }

    return [
        Event(
            event_id=event_id,
            physical_record_id=raw.physical_record_id,
            raw_id=raw_id,
            source_type="ecar",
            event_time=event_time,
            fields=fields,
            host=host,
            parse_metadata=parse_metadata,
        )
    ], []


def _normalize_syslog(
    ctx: RunContext,
    raw: RawRecord,
    lib: _LogConvertLib,
    *,
    forced: bool,
) -> tuple[list[Event], list[dict[str, Any]]]:
    raw_text = raw.payload.get("raw_text")
    if not isinstance(raw_text, str):
        return [], [
            _make_gap(
                raw,
                source="syslog",
                reason="invalid_payload",
                detail="Syslog payload must contain string 'raw_text'.",
            )
        ]
    line = raw_text.rstrip("\r\n")
    if not line.strip():
        return [], [
            _make_gap(
                raw,
                source="syslog",
                reason="empty_payload",
                detail="Syslog line is blank.",
            )
        ]

    source_file, record_index = _source_meta(raw)
    raw_id = raw.raw_id or raw.physical_record_id
    event_id = _make_deterministic_event_id(ctx.case_id, raw.physical_record_id, 0)
    warnings: list[str] = []

    m5424 = lib.parsers.RFC5424_RE.match(line)
    if m5424:
        pri = int(m5424.group(1))
        version = int(m5424.group(2))
        ts_raw = m5424.group(3)
        hostname = None if m5424.group(4) == "-" else m5424.group(4)
        app_name = None if m5424.group(5) == "-" else m5424.group(5)
        procid_raw = None if m5424.group(6) == "-" else m5424.group(6)
        pid = lib.parsers._try_int(procid_raw) if procid_raw is not None else None
        msgid = None if m5424.group(7) == "-" else m5424.group(7)
        sd = None if m5424.group(8) == "-" else m5424.group(8)
        message = m5424.group(9) or ""
        if ts_raw != "-":
            event_time, ts_warn, tz_meta = _normalize_iso_utc_strict(ts_raw, lib.common)
            if ts_warn:
                warnings.append(ts_warn)
        else:
            event_time = None
            tz_meta = {"raw_timestamp": None, "original_timezone": None}
            warnings.append("missing_timestamp")
        fac = pri >> 3
        sev = pri & 0x07
        fields: dict[str, Any] = {
            "log_source": "syslog",
            "rfc": "5424",
            "priority": pri,
            "facility": fac,
            "facility_name": lib.parsers.SYSLOG_FACILITIES.get(fac, f"facility_{fac}"),
            "severity": sev,
            "severity_name": lib.parsers.SYSLOG_SEVERITIES.get(sev, f"severity_{sev}"),
            "syslog_version": version,
            "hostname": hostname,
            "Computer": hostname,
            "app_name": app_name,
            "ProcessName": app_name,
            "pid": pid,
            "msgid": msgid,
            "structured_data": sd,
            "message": message,
            "raw_line": line,
        }
        return [
            Event(
                event_id=event_id,
                physical_record_id=raw.physical_record_id,
                raw_id=raw_id,
                source_type="syslog",
                event_time=event_time,
                fields=fields,
                host=hostname,
                parse_metadata={
                    "log_format": "syslog",
                    "source_file": source_file,
                    "record_index": record_index,
                    "sub_index": 0,
                    "raw_timestamp": tz_meta.get("raw_timestamp"),
                    "original_timezone": tz_meta.get("original_timezone"),
                    "warnings": warnings,
                },
            )
        ], []

    m3164 = lib.parsers.RFC3164_RE.match(line)
    if m3164:
        pri = int(m3164.group(1))
        ts_raw = m3164.group(2)
        hostname = m3164.group(3)
        app_name = m3164.group(4)
        pid = lib.parsers._try_int(m3164.group(5))
        message = m3164.group(6)
        fac = pri >> 3
        sev = pri & 0x07
        warnings.append("rfc3164_missing_year_and_timezone")
        fields = {
            "log_source": "syslog",
            "rfc": "3164",
            "priority": pri,
            "facility": fac,
            "facility_name": lib.parsers.SYSLOG_FACILITIES.get(fac, f"facility_{fac}"),
            "severity": sev,
            "severity_name": lib.parsers.SYSLOG_SEVERITIES.get(sev, f"severity_{sev}"),
            "syslog_version": 0,
            "hostname": hostname,
            "Computer": hostname,
            "app_name": app_name,
            "ProcessName": app_name,
            "pid": pid,
            "msgid": None,
            "structured_data": None,
            "message": message,
            "raw_line": line,
        }
        return [
            Event(
                event_id=event_id,
                physical_record_id=raw.physical_record_id,
                raw_id=raw_id,
                source_type="syslog",
                event_time=None,
                fields=fields,
                host=hostname,
                parse_metadata={
                    "log_format": "syslog",
                    "source_file": source_file,
                    "record_index": record_index,
                    "sub_index": 0,
                    "raw_timestamp": ts_raw,
                    "original_timezone": "unknown",
                    "warnings": warnings,
                },
            )
        ], []

    if not forced:
        return [], [
            _make_gap(
                raw,
                source="syslog",
                reason="syslog_unmatched_format",
                detail="Line did not match RFC 5424 or RFC 3164 syslog format.",
            )
        ]

    # Forced syslog file with non-standard line: preserve partial Event per parsers.py
    fields = {
        "log_source": "syslog",
        "rfc": "unknown",
        "priority": None,
        "facility": None,
        "facility_name": None,
        "severity": None,
        "severity_name": None,
        "syslog_version": None,
        "hostname": None,
        "Computer": None,
        "app_name": None,
        "ProcessName": None,
        "pid": None,
        "msgid": None,
        "structured_data": None,
        "message": line,
        "raw_line": line,
    }
    return [
        Event(
            event_id=event_id,
            physical_record_id=raw.physical_record_id,
            raw_id=raw_id,
            source_type="syslog",
            event_time=None,
            fields=fields,
            host=None,
            parse_metadata={
                "log_format": "syslog",
                "source_file": source_file,
                "record_index": record_index,
                "sub_index": 0,
                "raw_timestamp": None,
                "original_timezone": None,
                "partial_parse": True,
                "warnings": ["syslog_unmatched_format"],
            },
        )
    ], []


def _normalize_web_access(
    ctx: RunContext,
    raw: RawRecord,
    lib: _LogConvertLib,
) -> tuple[list[Event], list[dict[str, Any]]]:
    raw_text = raw.payload.get("raw_text")
    if not isinstance(raw_text, str):
        return [], [
            _make_gap(
                raw,
                source="web_access",
                reason="invalid_payload",
                detail="web_access payload must contain string 'raw_text'.",
            )
        ]
    line = raw_text.rstrip("\r\n")
    if not line.strip():
        return [], [
            _make_gap(
                raw,
                source="web_access",
                reason="empty_payload",
                detail="web_access line is blank.",
            )
        ]

    m = lib.parsers.COMBINED_LOG_RE.match(line)
    if not m:
        return [], [
            _make_gap(
                raw,
                source="web_access",
                reason="web_access_unmatched_line",
                detail="Line did not match Apache/Nginx Combined or Common Log Format.",
            )
        ]

    client_ip = m.group(1)
    ident = None if m.group(2) == "-" else m.group(2)
    username = None if m.group(3) == "-" else m.group(3)
    raw_ts = m.group(4)
    warnings: list[str] = []
    try:
        event_time: str | None = lib.common.clf_time_to_utc_iso(raw_ts)
    except (ValueError, TypeError):
        event_time = None
        warnings.append("invalid_timestamp")
    tz_part = raw_ts.rsplit(" ", 1)[-1] if " " in raw_ts else "unknown"

    request = m.group(5)
    status = int(m.group(6))
    bytes_str = m.group(7)
    if bytes_str == "-":
        sc_bytes: int | None = None
    else:
        try:
            sc_bytes = int(bytes_str)
        except ValueError:
            sc_bytes = None
            warnings.append("invalid_bytes")
    referer = None if m.group(8) == "-" else m.group(8)
    user_agent = None if m.group(9) == "-" else m.group(9)

    req_parts = request.split(" ")
    method = req_parts[0] if len(req_parts) >= 1 else ""
    uri = req_parts[1] if len(req_parts) >= 2 else ""
    version = req_parts[2] if len(req_parts) >= 3 else ""
    if "?" in uri:
        uri_stem, uri_query = uri.split("?", 1)
    else:
        uri_stem, uri_query = uri, ""

    source_file, record_index = _source_meta(raw)
    raw_id = raw.raw_id or raw.physical_record_id
    event_id = _make_deterministic_event_id(ctx.case_id, raw.physical_record_id, 0)
    fields: dict[str, Any] = {
        "log_source": "web_access",
        "raw_timestamp": raw_ts,
        "c-ip": client_ip,
        "ident": ident,
        "cs-username": username,
        "cs-method": method,
        "cs-uri": uri,
        "cs-uri-stem": uri_stem,
        "cs-uri-query": uri_query,
        "cs-version": version,
        "sc-status": status,
        "sc-bytes": sc_bytes,
        "cs-Referer": referer,
        "cs-User-Agent": user_agent,
        "request": request,
        "raw_line": line,
    }
    return [
        Event(
            event_id=event_id,
            physical_record_id=raw.physical_record_id,
            raw_id=raw_id,
            source_type="web_access",
            event_time=event_time,
            fields=fields,
            host=None,
            parse_metadata={
                "log_format": "web_access",
                "source_file": source_file,
                "record_index": record_index,
                "sub_index": 0,
                "raw_timestamp": raw_ts,
                "original_timezone": tz_part,
                "warnings": warnings,
            },
        )
    ], []


def _normalize_bash_history(
    ctx: RunContext,
    raw: RawRecord,
    lib: _LogConvertLib,
) -> tuple[list[Event], list[dict[str, Any]]]:
    payload = raw.payload
    raw_text = payload.get("raw_text")
    if not isinstance(raw_text, str):
        return [], [
            _make_gap(
                raw,
                source="bash_history",
                reason="invalid_payload",
                detail="bash_history payload must contain string 'raw_text'.",
            )
        ]

    epoch_ts = payload.get("timestamp")
    if isinstance(epoch_ts, bool):
        return [], [
            _make_gap(
                raw,
                source="bash_history",
                reason="invalid_timestamp_type",
                detail="bash_history timestamp must be int or None, not bool.",
            )
        ]
    if epoch_ts is not None and not isinstance(epoch_ts, int):
        return [], [
            _make_gap(
                raw,
                source="bash_history",
                reason="invalid_timestamp_type",
                detail=f"bash_history timestamp has invalid type {type(epoch_ts).__name__}.",
            )
        ]

    command_text = raw_text
    if epoch_ts is None and raw_text:
        lines = raw_text.splitlines()
        marker = _FLEX_EPOCH_COMMENT_RE.match(lines[0].strip()) if lines else None
        if marker is not None:
            epoch_ts = int(marker.group(1))
            command_text = "\n".join(lines[1:])

    if not command_text.strip():
        return [], [
            _make_gap(
                raw,
                source="bash_history",
                reason="empty_payload",
                detail="bash_history command text is empty.",
            )
        ]

    warnings: list[str] = []
    if epoch_ts is not None:
        event_time, ts_warn = _normalize_epoch_seconds(epoch_ts, lib.common)
        if ts_warn:
            warnings.append(ts_warn)
    else:
        event_time = None
        warnings.append("missing_timestamp")

    user_val = payload.get("user")
    if not isinstance(user_val, str) or not user_val.strip():
        user_val = (
            lib.parsers.infer_user_from_bash_history(Path(raw.locator.filepath))
            if raw.locator is not None
            else None
        )

    executable = lib.parsers.extract_command_executable(command_text)
    source_file, record_index = _source_meta(raw)
    raw_id = raw.raw_id or raw.physical_record_id
    event_id = _make_deterministic_event_id(ctx.case_id, raw.physical_record_id, 0)
    host_val = payload.get("host")
    host = host_val if isinstance(host_val, str) and host_val.strip() else None

    fields: dict[str, Any] = {
        "log_source": "bash_history",
        "epoch_ts": epoch_ts,
        "User": user_val,
        "user": user_val,
        "Image": executable,
        "CommandLine": command_text,
        "command": command_text,
    }
    return [
        Event(
            event_id=event_id,
            physical_record_id=raw.physical_record_id,
            raw_id=raw_id,
            source_type="bash_history",
            event_time=event_time,
            fields=fields,
            host=host,
            parse_metadata={
                "log_format": "bash_history",
                "source_file": source_file,
                "record_index": record_index,
                "sub_index": 0,
                "raw_timestamp": epoch_ts,
                "original_timezone": "epoch_utc" if epoch_ts is not None else None,
                "warnings": warnings,
            },
        )
    ], []


class Normalizer:
    """Deterministic log normalizer wrapping `script/log_convert/lib/*`."""

    @classmethod
    def normalize(cls, ctx: RunContext, raw: RawRecord) -> dict[str, Any]:
        """Normalize one `RawRecord` into 0..N `Event`s plus structured `gaps`."""
        if not isinstance(ctx, RunContext):
            raise InvalidArgumentError(
                "ctx must be a RunContext instance.",
                details={"type": type(ctx).__name__},
            )
        if not isinstance(raw, RawRecord):
            raise InvalidArgumentError(
                "raw must be a RawRecord instance.",
                details={"type": type(raw).__name__},
            )

        lib = _load_log_convert_lib()
        log_format, zeek_hint, forced, preparsed, gap = _classify_raw_record(
            raw, lib.parsers
        )
        if gap is not None or log_format is None:
            return {"events": [], "gaps": [gap] if gap is not None else []}

        if log_format == "winxml":
            events, gaps = _normalize_winxml(ctx, raw, lib)
        elif log_format == "zeek_json":
            events, gaps = _normalize_zeek(ctx, raw, lib, preparsed, zeek_hint)
        elif log_format == "ecar_json":
            events, gaps = _normalize_ecar(ctx, raw, lib, preparsed)
        elif log_format == "syslog":
            events, gaps = _normalize_syslog(ctx, raw, lib, forced=forced)
        elif log_format == "web_access":
            events, gaps = _normalize_web_access(ctx, raw, lib)
        elif log_format == "bash_history":
            events, gaps = _normalize_bash_history(ctx, raw, lib)
        else:
            events, gaps = (
                [],
                [
                    _make_gap(
                        raw,
                        source=log_format,
                        reason="unsupported_format",
                        detail=f"Unsupported log format {log_format!r}.",
                    )
                ],
            )
        return {"events": events, "gaps": gaps}

    @classmethod
    def normalize_batch(
        cls,
        ctx: RunContext,
        store: RawEvidenceStore | Iterable[RawRecord],
    ) -> NormalizationResult:
        """Normalize all `RawRecord`s in `store` into a `NormalizationResult`."""
        if not isinstance(ctx, RunContext):
            raise InvalidArgumentError(
                "ctx must be a RunContext instance.",
                details={"type": type(ctx).__name__},
            )
        if isinstance(store, RawEvidenceStore):
            record_iter = store.iter_records()
        else:
            if store is None or isinstance(store, (str, bytes, bytearray, dict)):
                raise InvalidArgumentError(
                    "store must be a RawEvidenceStore or iterable of RawRecord.",
                    details={"type": type(store).__name__},
                )
            record_iter = iter(store)

        events: list[Event] = []
        gaps: list[dict[str, Any]] = []
        counts: Counter[str] = Counter()
        event_to_physical: dict[str, str] = {}

        for raw in record_iter:
            res = cls.normalize(ctx, raw)
            for ev in res["events"]:
                events.append(ev)
                counts[ev.source_type or "unknown"] += 1
                event_to_physical[ev.event_id] = ev.physical_record_id
            gaps.extend(res["gaps"])

        return NormalizationResult(
            events=events,
            gaps=gaps,
            source_type_counts=dict(sorted(counts.items())),
            event_to_physical=event_to_physical,
        )


# ---------------------------------------------------------------------------
# M3 Formatter Bridges (reusing script/log_convert/lib/formatters.py)
# ---------------------------------------------------------------------------


def _infer_event_log_format(event: Event) -> str:
    fmt = event.parse_metadata.get("log_format")
    if isinstance(fmt, str) and fmt:
        return fmt
    st = (event.source_type or "").lower()
    if st.startswith("winxml"):
        return "winxml"
    if st.startswith("zeek"):
        return "zeek_json"
    if st == "ecar":
        return "ecar_json"
    if st in ("syslog", "web_access", "bash_history"):
        return st
    ls = str(event.fields.get("log_source") or "").lower()
    if ls == "zeek":
        return "zeek_json"
    if ls in ("ecar",):
        return "ecar_json"
    if ls in ("syslog", "web_access", "bash_history"):
        return ls
    return "winxml" if "EventID" in event.fields and "Channel" in event.fields else "unknown"


def event_to_parsed_dict(event: Event) -> dict[str, Any]:
    """Reconstruct the `parsed` dict expected by `script/log_convert/lib/formatters.py`."""
    if not isinstance(event, Event):
        raise InvalidArgumentError(
            "event must be an Event instance.",
            details={"type": type(event).__name__},
        )
    fmt = _infer_event_log_format(event)
    base: dict[str, Any] = {
        "event_id": event.event_id,
        "raw_id": event.raw_id or event.physical_record_id,
        "source_file": event.parse_metadata.get("source_file", ""),
        "record_index": event.parse_metadata.get("record_index", 1),
        "utc_timestamp": event.event_time or "",
        "_log_format": fmt,
    }

    if fmt == "winxml":
        win_meta = event.parse_metadata.get("_winxml")
        if isinstance(win_meta, dict):
            base["xmlns"] = win_meta.get(
                "xmlns", "http://schemas.microsoft.com/win/2004/08/events/event"
            )
            base["system_time_raw"] = win_meta.get("system_time_raw", "")
            base["system"] = copy.deepcopy(win_meta.get("system", {}))
            base["event_data"] = copy.deepcopy(win_meta.get("event_data", {}))
            base["user_data"] = copy.deepcopy(win_meta.get("user_data", {}))
        else:
            f = event.fields
            system = {
                "Provider": {
                    "Name": f.get("Provider_Name"),
                    "Guid": f.get("Provider_Guid"),
                },
                "TimeCreated": {"SystemTime": f.get("SystemTime") or (event.event_time or "")},
                "Execution": {
                    "ProcessID": f.get("Execution_ProcessID"),
                    "ThreadID": f.get("Execution_ThreadID"),
                },
                "EventID": f.get("EventID"),
                "Version": f.get("Version"),
                "Level": f.get("Level"),
                "Task": f.get("Task"),
                "Opcode": f.get("Opcode"),
                "Keywords": f.get("Keywords"),
                "EventRecordID": f.get("EventRecordID"),
                "Channel": f.get("Channel"),
                "Computer": f.get("Computer") or event.host,
            }
            if f.get("Security_UserID") is not None:
                system["Security"] = {"UserID": f["Security_UserID"]}
            std_keys = {
                "SystemTime", "EventID", "Version", "Level", "Task", "Opcode",
                "Keywords", "EventRecordID", "Channel", "Computer",
                "Provider_Name", "Provider_Guid", "Execution_ProcessID",
                "Execution_ThreadID", "Security_UserID",
            }
            event_data = {k: v for k, v in f.items() if k not in std_keys}
            base["xmlns"] = "http://schemas.microsoft.com/win/2004/08/events/event"
            base["system_time_raw"] = str(f.get("SystemTime") or (event.event_time or ""))
            base["system"] = system
            base["event_data"] = event_data
            base["user_data"] = {}
        return base

    if fmt == "zeek_json":
        zeek_type = event.parse_metadata.get("zeek_log_type") or event.fields.get(
            "zeek_log_type"
        )
        if not zeek_type:
            st = event.source_type or ""
            zeek_type = st[5:] if st.startswith("zeek_") else "unknown"
        zeek_raw = event.parse_metadata.get("_zeek_raw")
        if isinstance(zeek_raw, dict):
            data = copy.deepcopy(zeek_raw)
        else:
            skip = {"log_source", "zeek_log_type", "src_ip", "src_port", "dst_ip", "dst_port"}
            data = {k: copy.deepcopy(v) for k, v in event.fields.items() if k not in skip}
        base["zeek_log_type"] = zeek_type
        base["data"] = data
        return base

    if fmt == "ecar_json":
        ecar_raw = event.parse_metadata.get("_ecar_raw")
        if isinstance(ecar_raw, dict):
            data = copy.deepcopy(ecar_raw)
        else:
            data = copy.deepcopy(event.fields)
        if (
            "properties" in data
            and data["properties"] is not None
            and not isinstance(data["properties"], Mapping)
        ):
            data["properties"] = {}
        base["data"] = data
        return base

    if fmt == "syslog":
        for k in (
            "rfc", "priority", "facility", "facility_name", "severity",
            "severity_name", "syslog_version", "hostname", "app_name",
            "pid", "msgid", "structured_data", "message", "raw_line",
        ):
            base[k] = event.fields.get(k)
        return base

    if fmt == "web_access":
        for k in (
            "raw_timestamp", "c-ip", "ident", "cs-username", "cs-method",
            "cs-uri", "cs-uri-stem", "cs-uri-query", "cs-version",
            "sc-status", "sc-bytes", "cs-Referer", "cs-User-Agent", "request",
            "parse_error", "raw_line",
        ):
            if k in event.fields:
                base[k] = event.fields[k]
        return base

    if fmt == "bash_history":
        base["epoch_ts"] = event.fields.get("epoch_ts")
        base["user"] = event.fields.get("user") if "user" in event.fields else event.fields.get("User")
        base["executable"] = event.fields.get("Image", "")
        base["command"] = event.fields.get("command", event.fields.get("CommandLine", ""))
        return base

    raise InvalidArgumentError(
        f"Cannot format Event {event.event_id!r} with unsupported log format {fmt!r}.",
        details={"event_id": event.event_id, "source_type": event.source_type},
    )


def format_for_zircolite(events: Sequence[Event]) -> list[dict[str, Any]]:
    """Format normalized `Event`s into SQLite-safe Zircolite JSONL records."""
    lib = _load_log_convert_lib()
    fn_map = {
        "winxml": lib.formatters.format_zircolite_winxml,
        "zeek_json": lib.formatters.format_zircolite_zeek,
        "ecar_json": lib.formatters.format_zircolite_ecar,
        "syslog": lib.formatters.format_zircolite_syslog,
        "web_access": lib.formatters.format_zircolite_web_access,
        "bash_history": lib.formatters.format_zircolite_bash_history,
    }
    out: list[dict[str, Any]] = []
    for ev in events:
        parsed = event_to_parsed_dict(ev)
        fmt = parsed.pop("_log_format")
        out.append(fn_map[fmt](parsed))
    return out


def format_for_hayabusa(
    events: Sequence[Event],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Format Windows XML `Event`s for Hayabusa `-J` and return `(records, index_records)`."""
    lib = _load_log_convert_lib()
    hayabusa_records: list[dict[str, Any]] = []
    index_records: list[dict[str, Any]] = []
    for ev in events:
        parsed = event_to_parsed_dict(ev)
        if parsed.pop("_log_format") != "winxml":
            continue
        h_rec, idx_rec = lib.formatters.format_hayabusa_winxml(parsed)
        hayabusa_records.append(h_rec)
        index_records.append(idx_rec)
    return hayabusa_records, index_records


_UTC_MIN_DT = datetime.min.replace(tzinfo=timezone.utc)


def _rsigma_sort_key(record: Mapping[str, Any]) -> tuple[int, datetime, str]:
    ts = record.get("@timestamp")
    event_id = str(record.get("event_id") or "")
    if isinstance(ts, str):
        stripped = ts.strip()
        if stripped:
            try:
                dt = datetime.fromisoformat(stripped.replace("Z", "+00:00"))
            except ValueError:
                try:
                    dt = datetime.fromisoformat(
                        _truncate_fractional_seconds(stripped).replace("Z", "+00:00")
                    )
                except ValueError:
                    dt = None
            if dt is not None and dt.tzinfo is not None and dt.utcoffset() is not None:
                return (0, dt.astimezone(timezone.utc), event_id)
    return (1, _UTC_MIN_DT, event_id)


def format_for_rsigma(
    events: Sequence[Event], *, sort_utc: bool = True
) -> list[dict[str, Any]]:
    """Format normalized `Event`s for RSigma NDJSON, sorted chronologically in UTC by default."""
    lib = _load_log_convert_lib()
    fn_map = {
        "winxml": lib.formatters.format_rsigma_winxml,
        "zeek_json": lib.formatters.format_rsigma_zeek,
        "ecar_json": lib.formatters.format_rsigma_ecar,
        "syslog": lib.formatters.format_rsigma_syslog,
        "web_access": lib.formatters.format_rsigma_web_access,
        "bash_history": lib.formatters.format_rsigma_bash_history,
    }
    out: list[dict[str, Any]] = []
    for ev in events:
        parsed = event_to_parsed_dict(ev)
        fmt = parsed.pop("_log_format")
        out.append(fn_map[fmt](parsed))

    if sort_utc:
        out.sort(key=_rsigma_sort_key)
    return out


def format_for_chainsaw(events: Sequence[Event]) -> list[dict[str, Any]]:
    """Format normalized `Event`s into Chainsaw `kind: json` records."""
    lib = _load_log_convert_lib()
    fn_map = {
        "winxml": lib.formatters.format_chainsaw_winxml,
        "zeek_json": lib.formatters.format_chainsaw_zeek,
        "ecar_json": lib.formatters.format_chainsaw_ecar,
        "syslog": lib.formatters.format_chainsaw_syslog,
        "web_access": lib.formatters.format_chainsaw_web_access,
        "bash_history": lib.formatters.format_chainsaw_bash_history,
    }
    out: list[dict[str, Any]] = []
    for ev in events:
        parsed = event_to_parsed_dict(ev)
        fmt = parsed.pop("_log_format")
        out.append(fn_map[fmt](parsed))
    return out


__all__ = [
    "NormalizationResult",
    "Normalizer",
    "event_to_parsed_dict",
    "format_for_chainsaw",
    "format_for_hayabusa",
    "format_for_rsigma",
    "format_for_zircolite",
]
