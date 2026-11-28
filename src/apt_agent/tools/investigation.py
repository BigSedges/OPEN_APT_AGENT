"""Typed, case-scoped forensic investigation query tools (F08)."""

from __future__ import annotations

import base64
import hashlib
import json
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from apt_agent.exceptions import InvalidArgumentError, OutOfScopeError
from apt_agent.ingestion.store import RawEvidenceStore
from apt_agent.models import Edge, Event, RunContext

_UTC_MAX_DT = datetime.max.replace(tzinfo=timezone.utc)
_MAX_QUERY_LIMIT = 500

_ALLOWED_FILTER_KEYS: frozenset[str] = frozenset(
    {
        "event_id",
        "event_ids",
        "physical_record_id",
        "physical_record_ids",
        "source_type",
        "source_types",
        "host",
        "hosts",
        "ip",
        "ips",
        "src_ip",
        "dst_ip",
        "port",
        "src_port",
        "dst_port",
        "protocol",
        "process_guid",
        "parent_process_guid",
        "pid",
        "ppid",
        "image",
        "command_line",
        "user",
        "logon_id",
        "session_id",
        "entity",
        "time_window",
        "start_time",
        "end_time",
        "keyword",
        "fields",
    }
)


def _require_non_blank_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidArgumentError(
            f"{field_name} must be a non-blank string.",
            details={"field": field_name, "value": value},
        )
    return value


def _parse_utc_datetime(value: Any, *, field_name: str = "timestamp") -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise InvalidArgumentError(
            f"{field_name} must be a non-blank UTC ISO-8601 string.",
            details={"field": field_name, "value": value},
        )
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError as exc:
        raise InvalidArgumentError(
            f"Invalid ISO-8601 timestamp for {field_name}: {value!r}",
            details={"field": field_name, "value": value, "reason": str(exc)},
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise InvalidArgumentError(
            f"{field_name} must be timezone-aware UTC ISO-8601: {value!r}",
            details={"field": field_name, "value": value},
        )
    return parsed.astimezone(timezone.utc)


def _format_utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _event_sort_key(event: Event) -> tuple[int, datetime, str, str]:
    """Chronological UTC datetime sort key (null timestamps sort deterministically last)."""
    if event.event_time is None:
        return (1, _UTC_MAX_DT, event.physical_record_id, event.event_id)
    parsed = _parse_utc_datetime(event.event_time, field_name="event_time")
    return (0, parsed, event.physical_record_id, event.event_id)


def _as_str_set(value: Any, *, field_name: str) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            raise InvalidArgumentError(f"{field_name} must not be blank.")
        return {stripped}
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return {str(value)}
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, Mapping)):
        out: set[str] = set()
        for item in value:
            if isinstance(item, bool) or not isinstance(item, (str, int, float)):
                raise InvalidArgumentError(
                    f"{field_name} items must be non-blank strings or numbers.",
                    details={"field": field_name, "item": item},
                )
            text = str(item).strip()
            if not text:
                raise InvalidArgumentError(f"{field_name} must not contain blank items.")
            out.add(text)
        return out
    raise InvalidArgumentError(
        f"{field_name} must be a string or sequence of strings.",
        details={"field": field_name, "type": type(value).__name__},
    )


def _as_lower_str_set(value: Any, *, field_name: str) -> set[str]:
    return {item.lower() for item in _as_str_set(value, field_name=field_name)}


def _as_port_set(value: Any, *, field_name: str) -> set[int]:
    if value is None:
        return set()
    items = (
        [value]
        if (isinstance(value, (int, str)) and not isinstance(value, bool))
        else list(value)
        if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, Mapping))
        else None
    )
    if items is None:
        raise InvalidArgumentError(f"{field_name} must be a port integer or sequence of ports.")
    ports: set[int] = set()
    for item in items:
        if isinstance(item, bool):
            raise InvalidArgumentError(f"{field_name} cannot contain booleans.")
        try:
            port = int(item)
        except (TypeError, ValueError) as exc:
            raise InvalidArgumentError(
                f"Invalid port value in {field_name}: {item!r}",
                details={"field": field_name, "value": item},
            ) from exc
        if not (0 <= port <= 65535):
            raise InvalidArgumentError(
                f"Port out of range (0..65535) in {field_name}: {port}",
                details={"field": field_name, "value": port},
            )
        ports.add(port)
    return ports


def _first_non_empty(fields: Mapping[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        val = fields.get(key)
        if val is not None and str(val).strip() != "":
            return val
    return None


def _all_non_empty_strs(fields: Mapping[str, Any], keys: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    for key in keys:
        val = fields.get(key)
        if val is not None:
            text = str(val).strip()
            if text:
                values.append(text)
    return values


def _extract_host(event: Event) -> str | None:
    if event.host and event.host.strip():
        return event.host.strip()
    val = _first_non_empty(event.fields, ("Computer", "hostname", "host"))
    return str(val).strip() if val is not None else None


def _extract_src_ips(event: Event) -> list[str]:
    return _all_non_empty_strs(event.fields, ("src_ip", "SourceIp", "id.orig_h", "c-ip"))


def _extract_dst_ips(event: Event) -> list[str]:
    return _all_non_empty_strs(event.fields, ("dst_ip", "DestinationIp", "id.resp_h", "s-ip"))


def _extract_ports(event: Event, keys: tuple[str, ...]) -> list[int]:
    ports: list[int] = []
    for key in keys:
        val = event.fields.get(key)
        if val is None or isinstance(val, bool):
            continue
        try:
            ports.append(int(val))
        except (TypeError, ValueError):
            continue
    return ports


def _extract_src_ports(event: Event) -> list[int]:
    return _extract_ports(event, ("src_port", "SourcePort", "id.orig_p", "c-port"))


def _extract_dst_ports(event: Event) -> list[int]:
    return _extract_ports(event, ("dst_port", "DestinationPort", "id.resp_p", "s-port"))


def _extract_protocols(event: Event) -> list[str]:
    return _all_non_empty_strs(event.fields, ("Protocol", "proto", "protocol"))


def _extract_process_guids(event: Event) -> list[str]:
    values = _all_non_empty_strs(event.fields, ("ProcessGuid", "ProcessGUID", "process_guid"))
    properties = event.fields.get("properties")
    if isinstance(properties, Mapping):
        values.extend(_all_non_empty_strs(properties, ("process_guid",)))
    return list(dict.fromkeys(values))


def _extract_parent_process_guids(event: Event) -> list[str]:
    values = _all_non_empty_strs(
        event.fields, ("ParentProcessGuid", "ParentProcessGUID", "parent_process_guid")
    )
    properties = event.fields.get("properties")
    if isinstance(properties, Mapping):
        values.extend(_all_non_empty_strs(properties, ("parent_process_guid",)))
    return list(dict.fromkeys(values))


def _extract_pids(event: Event) -> list[str]:
    return _all_non_empty_strs(event.fields, ("ProcessId", "pid"))


def _extract_ppids(event: Event) -> list[str]:
    return _all_non_empty_strs(event.fields, ("ParentProcessId", "ppid"))


def _extract_images(event: Event) -> list[str]:
    return _all_non_empty_strs(
        event.fields,
        ("Image", "ParentImage", "image_path", "ProcessName", "app_name"),
    )


def _extract_commands(event: Event) -> list[str]:
    return _all_non_empty_strs(event.fields, ("CommandLine", "command", "command_line"))


def _extract_users(event: Event) -> list[str]:
    return _all_non_empty_strs(
        event.fields, ("User", "principal", "Security_UserID", "cs-username", "user")
    )


def _extract_logon_ids(event: Event) -> list[str]:
    return _all_non_empty_strs(event.fields, ("LogonId", "LogonGuid"))


def _extract_session_ids(event: Event) -> list[str]:
    return _all_non_empty_strs(event.fields, ("SessionId", "session_id"))


def _parse_time_bounds(
    filters: Mapping[str, Any],
) -> tuple[datetime | None, datetime | None, tuple[str, str] | None]:
    start_dt: datetime | None = None
    end_dt: datetime | None = None

    if "time_window" in filters and filters["time_window"] is not None:
        tw = filters["time_window"]
        if (
            not isinstance(tw, Sequence)
            or isinstance(tw, (str, bytes, bytearray, Mapping))
            or len(tw) != 2
        ):
            raise InvalidArgumentError(
                "time_window must be a 2-element sequence [start, end).",
                details={"time_window": tw},
            )
        start_dt = _parse_utc_datetime(tw[0], field_name="time_window[0]")
        end_dt = _parse_utc_datetime(tw[1], field_name="time_window[1]")
        if start_dt > end_dt:
            raise InvalidArgumentError(
                "time_window start must be <= end.",
                details={"start": tw[0], "end": tw[1]},
            )

    if "start_time" in filters and filters["start_time"] is not None:
        s_dt = _parse_utc_datetime(filters["start_time"], field_name="start_time")
        start_dt = max(start_dt, s_dt) if start_dt is not None else s_dt

    if "end_time" in filters and filters["end_time"] is not None:
        e_dt = _parse_utc_datetime(filters["end_time"], field_name="end_time")
        end_dt = min(end_dt, e_dt) if end_dt is not None else e_dt

    if start_dt is not None and end_dt is not None and start_dt > end_dt:
        raise InvalidArgumentError(
            "Effective time_window start must be <= end.",
            details={"start": _format_utc_iso(start_dt), "end": _format_utc_iso(end_dt)},
        )

    window_tuple = (
        (_format_utc_iso(start_dt), _format_utc_iso(end_dt))
        if start_dt is not None and end_dt is not None
        else None
    )
    return start_dt, end_dt, window_tuple


def _normalize_filters(filters: Mapping[str, Any] | None) -> tuple[dict[str, Any], datetime | None, datetime | None, tuple[str, str] | None]:
    if filters is None:
        return {}, None, None, None
    if not isinstance(filters, Mapping):
        raise InvalidArgumentError(
            "filters must be a mapping.",
            details={"type": type(filters).__name__},
        )
    unknown = sorted(str(k) for k in filters.keys() if k not in _ALLOWED_FILTER_KEYS)
    if unknown:
        raise InvalidArgumentError(
            f"Unsupported filter key(s): {unknown}",
            details={"unknown_keys": unknown, "allowed_keys": sorted(_ALLOWED_FILTER_KEYS)},
        )

    start_dt, end_dt, window_tuple = _parse_time_bounds(filters)
    normalized: dict[str, Any] = {}

    if filters.get("event_id") is not None or filters.get("event_ids") is not None:
        ids = _as_str_set(filters.get("event_id"), field_name="event_id") | _as_str_set(
            filters.get("event_ids"), field_name="event_ids"
        )
        normalized["event_ids"] = sorted(ids)

    if (
        filters.get("physical_record_id") is not None
        or filters.get("physical_record_ids") is not None
    ):
        pids = _as_str_set(
            filters.get("physical_record_id"), field_name="physical_record_id"
        ) | _as_str_set(filters.get("physical_record_ids"), field_name="physical_record_ids")
        normalized["physical_record_ids"] = sorted(pids)

    if filters.get("source_type") is not None or filters.get("source_types") is not None:
        sts = _as_lower_str_set(filters.get("source_type"), field_name="source_type") | _as_lower_str_set(
            filters.get("source_types"), field_name="source_types"
        )
        normalized["source_types"] = sorted(sts)

    if filters.get("host") is not None or filters.get("hosts") is not None:
        hosts = _as_lower_str_set(filters.get("host"), field_name="host") | _as_lower_str_set(
            filters.get("hosts"), field_name="hosts"
        )
        normalized["hosts"] = sorted(hosts)

    if filters.get("ip") is not None or filters.get("ips") is not None:
        ips = _as_str_set(filters.get("ip"), field_name="ip") | _as_str_set(
            filters.get("ips"), field_name="ips"
        )
        normalized["ips"] = sorted(ips)

    if filters.get("src_ip") is not None:
        normalized["src_ips"] = sorted(_as_str_set(filters.get("src_ip"), field_name="src_ip"))
    if filters.get("dst_ip") is not None:
        normalized["dst_ips"] = sorted(_as_str_set(filters.get("dst_ip"), field_name="dst_ip"))

    if filters.get("port") is not None:
        normalized["ports"] = sorted(_as_port_set(filters.get("port"), field_name="port"))
    if filters.get("src_port") is not None:
        normalized["src_ports"] = sorted(
            _as_port_set(filters.get("src_port"), field_name="src_port")
        )
    if filters.get("dst_port") is not None:
        normalized["dst_ports"] = sorted(
            _as_port_set(filters.get("dst_port"), field_name="dst_port")
        )

    if filters.get("protocol") is not None:
        normalized["protocols"] = sorted(
            _as_lower_str_set(filters.get("protocol"), field_name="protocol")
        )

    if filters.get("process_guid") is not None:
        normalized["process_guids"] = sorted(
            _as_lower_str_set(filters.get("process_guid"), field_name="process_guid")
        )
    if filters.get("parent_process_guid") is not None:
        normalized["parent_process_guids"] = sorted(
            _as_lower_str_set(
                filters.get("parent_process_guid"), field_name="parent_process_guid"
            )
        )
    if filters.get("pid") is not None:
        normalized["pids"] = sorted(_as_str_set(filters.get("pid"), field_name="pid"))
    if filters.get("ppid") is not None:
        normalized["ppids"] = sorted(_as_str_set(filters.get("ppid"), field_name="ppid"))

    if filters.get("image") is not None:
        normalized["images"] = sorted(
            _as_lower_str_set(filters.get("image"), field_name="image")
        )
    if filters.get("command_line") is not None:
        normalized["command_lines"] = sorted(
            _as_lower_str_set(filters.get("command_line"), field_name="command_line")
        )

    if filters.get("user") is not None:
        normalized["users"] = sorted(_as_lower_str_set(filters.get("user"), field_name="user"))
    if filters.get("logon_id") is not None:
        normalized["logon_ids"] = sorted(
            _as_lower_str_set(filters.get("logon_id"), field_name="logon_id")
        )
    if filters.get("session_id") is not None:
        normalized["session_ids"] = sorted(
            _as_lower_str_set(filters.get("session_id"), field_name="session_id")
        )

    if filters.get("entity") is not None:
        normalized["entities"] = sorted(
            _as_lower_str_set(filters.get("entity"), field_name="entity")
        )

    if filters.get("keyword") is not None:
        normalized["keyword"] = _require_non_blank_str(
            filters.get("keyword"), "keyword"
        ).strip().lower()

    if filters.get("fields") is not None:
        fmap = filters.get("fields")
        if not isinstance(fmap, Mapping):
            raise InvalidArgumentError("filters['fields'] must be a mapping.")
        normalized["fields"] = dict(fmap)

    if start_dt is not None:
        normalized["start_time"] = _format_utc_iso(start_dt)
    if end_dt is not None:
        normalized["end_time"] = _format_utc_iso(end_dt)

    return normalized, start_dt, end_dt, window_tuple


def _matches_filters(
    event: Event,
    norm: Mapping[str, Any],
    start_dt: datetime | None,
    end_dt: datetime | None,
) -> bool:
    if start_dt is not None or end_dt is not None:
        if event.event_time is None:
            return False
        ev_dt = _parse_utc_datetime(event.event_time, field_name="event_time")
        if start_dt is not None and ev_dt < start_dt:
            return False
        if end_dt is not None and ev_dt >= end_dt:
            return False

    if "event_ids" in norm and event.event_id not in norm["event_ids"]:
        return False

    if "physical_record_ids" in norm and event.physical_record_id not in norm["physical_record_ids"]:
        return False

    if "source_types" in norm:
        st = (event.source_type or "").strip().lower()
        wanted = norm["source_types"]
        if not st or not any(st == w or (w == "zeek" and st.startswith("zeek_")) for w in wanted):
            return False

    if "hosts" in norm:
        host = (_extract_host(event) or "").lower()
        if host not in norm["hosts"]:
            return False

    if "ips" in norm:
        all_ips = set(_extract_src_ips(event) + _extract_dst_ips(event))
        if not all_ips.intersection(norm["ips"]):
            return False

    if "src_ips" in norm and not set(_extract_src_ips(event)).intersection(norm["src_ips"]):
        return False

    if "dst_ips" in norm and not set(_extract_dst_ips(event)).intersection(norm["dst_ips"]):
        return False

    if "ports" in norm:
        all_ports = set(_extract_src_ports(event) + _extract_dst_ports(event))
        if not all_ports.intersection(norm["ports"]):
            return False

    if "src_ports" in norm and not set(_extract_src_ports(event)).intersection(norm["src_ports"]):
        return False

    if "dst_ports" in norm and not set(_extract_dst_ports(event)).intersection(norm["dst_ports"]):
        return False

    if "protocols" in norm:
        protos = {p.lower() for p in _extract_protocols(event)}
        if not protos.intersection(norm["protocols"]):
            return False

    if "process_guids" in norm:
        guids = {g.lower() for g in _extract_process_guids(event)}
        if not guids.intersection(norm["process_guids"]):
            return False

    if "parent_process_guids" in norm:
        pguids = {g.lower() for g in _extract_parent_process_guids(event)}
        if not pguids.intersection(norm["parent_process_guids"]):
            return False

    if "pids" in norm and not set(_extract_pids(event)).intersection(norm["pids"]):
        return False

    if "ppids" in norm and not set(_extract_ppids(event)).intersection(norm["ppids"]):
        return False

    if "images" in norm:
        imgs = [img.lower() for img in _extract_images(event)]
        if not any(want in img for want in norm["images"] for img in imgs):
            return False

    if "command_lines" in norm:
        cmds = [cmd.lower() for cmd in _extract_commands(event)]
        if not any(want in cmd for want in norm["command_lines"] for cmd in cmds):
            return False

    if "users" in norm:
        users = [u.lower() for u in _extract_users(event)]
        if not any(want == u or want in u for want in norm["users"] for u in users):
            return False

    if "logon_ids" in norm:
        lids = {lid.lower() for lid in _extract_logon_ids(event)}
        if not lids.intersection(norm["logon_ids"]):
            return False

    if "session_ids" in norm:
        sids = {sid.lower() for sid in _extract_session_ids(event)}
        if not sids.intersection(norm["session_ids"]):
            return False

    if "entities" in norm:
        candidates: list[str] = []
        host = _extract_host(event)
        if host:
            candidates.append(host)
        candidates.extend(_extract_src_ips(event))
        candidates.extend(_extract_dst_ips(event))
        candidates.extend(_extract_users(event))
        candidates.extend(_extract_images(event))
        candidates.extend(_extract_commands(event))
        candidates.extend(_extract_process_guids(event))
        candidates.extend(_extract_parent_process_guids(event))
        candidates.extend(_extract_pids(event))
        candidates.extend(
            _all_non_empty_strs(
                event.fields,
                ("query", "TargetFilename", "DestinationHostname", "uid", "TargetObject"),
            )
        )
        lowered = [c.lower() for c in candidates]
        if not any(ent in cand for ent in norm["entities"] for cand in lowered):
            return False

    if "fields" in norm:
        for k, expected in norm["fields"].items():
            if k not in event.fields or event.fields[k] != expected:
                return False

    if "keyword" in norm:
        kw = norm["keyword"]
        haystack = " ".join(
            [
                event.event_id,
                event.physical_record_id,
                event.source_type or "",
                _extract_host(event) or "",
                json.dumps(event.fields, ensure_ascii=False, sort_keys=True, default=str),
            ]
        ).lower()
        if kw not in haystack:
            return False

    return True


def _compute_filter_signature(
    case_id: str,
    run_id: str,
    norm_filters: Mapping[str, Any],
) -> str:
    payload = {
        "case_id": case_id,
        "run_id": run_id,
        "filters": dict(norm_filters),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def _encode_cursor(offset: int, filter_sig: str) -> str:
    payload = json.dumps({"offset": offset, "filter_sig": filter_sig}, separators=(",", ":"))
    return base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii")


def _decode_cursor(cursor: str, expected_sig: str) -> int:
    if not isinstance(cursor, str) or not cursor.strip():
        raise InvalidArgumentError("cursor must be a non-blank string.")
    try:
        decoded = base64.urlsafe_b64decode(cursor.encode("ascii"))
        obj = json.loads(decoded.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise InvalidArgumentError(
            "Invalid or malformed query cursor.",
            details={"reason": str(exc)},
        ) from exc
    if not isinstance(obj, dict) or set(obj.keys()) != {"offset", "filter_sig"}:
        raise InvalidArgumentError("Invalid query cursor structure.")
    offset = obj["offset"]
    sig = obj["filter_sig"]
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise InvalidArgumentError("Query cursor offset must be an integer >= 0.")
    if sig != expected_sig:
        raise InvalidArgumentError("Query cursor does not match current query filters or case.")
    return offset


def correlate_lineage_and_flows(
    events: Sequence[Event],
    *,
    max_flow_skew_s: float = 5.0,
) -> list[Edge]:
    """Deterministically derive candidate process-lineage and cross-source flow `Edge`s."""
    ordered = sorted(events, key=_event_sort_key)
    edges_by_key: dict[tuple[str, str, str], Edge] = {}

    def _add_edge(edge: Edge) -> None:
        if edge.dedup_key not in edges_by_key:
            edges_by_key[edge.dedup_key] = edge

    by_host_guid: dict[tuple[str, str], list[Event]] = defaultdict(list)
    by_host_pid: dict[tuple[str, str], list[Event]] = defaultdict(list)
    flow_buckets: dict[tuple[str, int, str, int, str], list[Event]] = defaultdict(list)

    for ev in ordered:
        host = (_extract_host(ev) or "").lower()
        for guid in _extract_process_guids(ev):
            by_host_guid[(host, guid.lower())].append(ev)
        for pid in _extract_pids(ev):
            by_host_pid[(host, pid)].append(ev)

        src_ips = _extract_src_ips(ev)
        dst_ips = _extract_dst_ips(ev)
        src_ports = _extract_src_ports(ev)
        dst_ports = _extract_dst_ports(ev)
        protos = _extract_protocols(ev)
        if src_ips and dst_ips and src_ports and dst_ports and protos:
            five_tuple = (
                src_ips[0],
                src_ports[0],
                dst_ips[0],
                dst_ports[0],
                protos[0].lower(),
            )
            flow_buckets[five_tuple].append(ev)

    # 1) Same-host process lineage (ProcessGuid first, then pid/ppid fallback)
    for ev in ordered:
        host_raw = _extract_host(ev)
        host = (host_raw or "").lower()
        if not host:
            continue
        ev_dt = _parse_utc_datetime(ev.event_time) if ev.event_time else None

        parent_matched = False
        for pguid in _extract_parent_process_guids(ev):
            parents: list[Event] = []
            for p in by_host_guid.get((host, pguid.lower()), ()):
                if p.event_id == ev.event_id:
                    continue
                if ev_dt is not None and p.event_time is not None:
                    p_dt = _parse_utc_datetime(p.event_time)
                    if p_dt > ev_dt:
                        continue
                parents.append(p)
            if parents:
                parent = parents[0]
                parent_matched = True
                _add_edge(
                    Edge(
                        from_event_id=parent.event_id,
                        to_event_id=ev.event_id,
                        relation="spawned",
                        join_keys={"host": host_raw, "process_guid": pguid},
                        evidence_event_ids=[parent.event_id, ev.event_id],
                        status="proposed",
                        sources=["query_events"],
                        ambiguity_reason=None,
                    )
                )

        if not parent_matched:
            for ppid in _extract_ppids(ev):
                candidates = []
                for p in by_host_pid.get((host, ppid), ()):
                    if p.event_id == ev.event_id:
                        continue
                    if ev_dt is not None and p.event_time is not None:
                        p_dt = _parse_utc_datetime(p.event_time)
                        if p_dt > ev_dt:
                            continue
                    candidates.append(p)
                if candidates:
                    parent = candidates[-1]
                    reason = (
                        "missing_process_guid_multiple_pid_candidates"
                        if len(candidates) > 1
                        else "missing_process_guid_pid_fallback"
                    )
                    _add_edge(
                        Edge(
                            from_event_id=parent.event_id,
                            to_event_id=ev.event_id,
                            relation="spawned",
                            join_keys={"host": host_raw, "pid": ppid},
                            evidence_event_ids=[parent.event_id, ev.event_id],
                            status="proposed",
                            sources=["query_events"],
                            ambiguity_reason=reason,
                        )
                    )

        # 2) Same-host process-to-network flow initiation
        if _extract_src_ips(ev) and _extract_dst_ips(ev):
            linked_proc = False
            for guid in _extract_process_guids(ev):
                procs = [
                    p
                    for p in by_host_guid.get((host, guid.lower()), ())
                    if p.event_id != ev.event_id
                ]
                if procs:
                    proc = procs[0]
                    linked_proc = True
                    _add_edge(
                        Edge(
                            from_event_id=proc.event_id,
                            to_event_id=ev.event_id,
                            relation="initiated_flow",
                            join_keys={"host": host_raw, "process_guid": guid},
                            evidence_event_ids=[proc.event_id, ev.event_id],
                            status="proposed",
                            sources=["query_events"],
                            ambiguity_reason=None,
                        )
                    )
            if not linked_proc:
                for pid in _extract_pids(ev):
                    valid_candidates: list[Event] = []
                    for p in by_host_pid.get((host, pid), ()):
                        if p.event_id == ev.event_id:
                            continue
                        if _extract_src_ips(p) and _extract_dst_ips(p):
                            continue
                        if ev_dt is not None and p.event_time is not None:
                            p_dt = _parse_utc_datetime(p.event_time)
                            if p_dt > ev_dt:
                                continue
                        valid_candidates.append(p)
                    if valid_candidates:
                        proc = valid_candidates[-1]
                        reason = (
                            "missing_process_guid_multiple_pid_candidates"
                            if len(valid_candidates) > 1
                            else "missing_process_guid_pid_fallback"
                        )
                        _add_edge(
                            Edge(
                                from_event_id=proc.event_id,
                                to_event_id=ev.event_id,
                                relation="initiated_flow",
                                join_keys={"host": host_raw, "pid": pid},
                                evidence_event_ids=[proc.event_id, ev.event_id],
                                status="proposed",
                                sources=["query_events"],
                                ambiguity_reason=reason,
                            )
                        )

    # 3) Cross-source network 5-tuple joins
    for five_tuple, bucket in flow_buckets.items():
        if len(bucket) < 2:
            continue
        ambiguous_bucket = len(bucket) > 2
        for i in range(len(bucket)):
            for j in range(i + 1, len(bucket)):
                e1, e2 = bucket[i], bucket[j]
                if (e1.source_type or "") == (e2.source_type or ""):
                    continue
                if e1.event_time is not None and e2.event_time is not None:
                    dt1 = _parse_utc_datetime(e1.event_time)
                    dt2 = _parse_utc_datetime(e2.event_time)
                    if abs((dt2 - dt1).total_seconds()) > max_flow_skew_s:
                        continue
                _add_edge(
                    Edge(
                        from_event_id=e1.event_id,
                        to_event_id=e2.event_id,
                        relation="corroborates_flow",
                        join_keys={
                            "src_ip": five_tuple[0],
                            "src_port": five_tuple[1],
                            "dst_ip": five_tuple[2],
                            "dst_port": five_tuple[3],
                            "protocol": five_tuple[4],
                        },
                        evidence_event_ids=[e1.event_id, e2.event_id],
                        status="proposed",
                        sources=["query_events"],
                        ambiguity_reason=(
                            "ambiguous_multi_flow_5tuple" if ambiguous_bucket else None
                        ),
                    )
                )

    return list(edges_by_key.values())


def fetch_raw_evidence(
    ctx: RunContext,
    store: RawEvidenceStore,
    physical_ids: Sequence[str],
    *,
    task_id: str | None = None,
    query_id: str | None = None,
    strict_scope: bool = False,
) -> dict[str, Any]:
    """Fetch unmodified `RawRecord`s by `physical_record_id` strictly within `ctx.case_id`."""
    if not isinstance(ctx, RunContext):
        raise InvalidArgumentError("ctx must be a RunContext instance.")
    if not isinstance(store, RawEvidenceStore):
        raise InvalidArgumentError("store must be a RawEvidenceStore instance.")
    if task_id is not None:
        _require_non_blank_str(task_id, "task_id")
    if query_id is not None:
        _require_non_blank_str(query_id, "query_id")
    if not isinstance(strict_scope, bool):
        raise InvalidArgumentError("strict_scope must be a boolean.")

    if store.case_id != ctx.case_id:
        raise OutOfScopeError(
            f"RawEvidenceStore case_id {store.case_id!r} does not match ctx.case_id {ctx.case_id!r}.",
            details={"store_case_id": store.case_id, "ctx_case_id": ctx.case_id},
        )

    records, missing_ids = store.fetch_raw_evidence(physical_ids)

    if ctx.valid_physical_ids is not None:
        for rec in records:
            if rec.physical_record_id not in ctx.valid_physical_ids:
                raise OutOfScopeError(
                    f"Record {rec.physical_record_id!r} is outside ctx.valid_physical_ids.",
                    details={"physical_record_id": rec.physical_record_id, "case_id": ctx.case_id},
                )
        if strict_scope:
            out_of_scope_missing = [
                pid for pid in missing_ids if pid not in ctx.valid_physical_ids
            ]
            if out_of_scope_missing:
                raise OutOfScopeError(
                    f"Requested physical_ids outside ctx.valid_physical_ids: {out_of_scope_missing}",
                    details={"physical_ids": out_of_scope_missing, "case_id": ctx.case_id},
                )

    resolved_query_id = query_id or f"qry_{uuid4().hex[:16]}"
    return {
        "query_id": resolved_query_id,
        "case_id": ctx.case_id,
        "run_id": ctx.run_id,
        "task_id": task_id,
        "records": records,
        "missing_ids": missing_ids,
        "evidence_ids": [rec.physical_record_id for rec in records],
    }


def query_events(
    ctx: RunContext,
    events: Sequence[Event],
    task_id: str,
    filters: Mapping[str, Any] | None = None,
    limit: int = 50,
    cursor: str | None = None,
    *,
    include_edges: bool = False,
    query_id: str | None = None,
) -> dict[str, Any]:
    """Query normalized events with deterministic UTC sort, cursor pagination, and scope coverage."""
    if not isinstance(ctx, RunContext):
        raise InvalidArgumentError("ctx must be a RunContext instance.")
    _require_non_blank_str(task_id, "task_id")
    if query_id is not None:
        _require_non_blank_str(query_id, "query_id")
    if isinstance(limit, bool) or not isinstance(limit, int) or not (1 <= limit <= _MAX_QUERY_LIMIT):
        raise InvalidArgumentError(
            f"limit must be an integer between 1 and {_MAX_QUERY_LIMIT}.",
            details={"limit": limit},
        )
    if not isinstance(include_edges, bool):
        raise InvalidArgumentError("include_edges must be a boolean.")
    if events is None or isinstance(events, (str, bytes, bytearray, Mapping)):
        raise InvalidArgumentError("events must be a sequence of Event objects.")

    event_list = list(events)
    for idx, ev in enumerate(event_list):
        if not isinstance(ev, Event):
            raise InvalidArgumentError(
                "Each item in events must be an Event instance.",
                details={"index": idx, "type": type(ev).__name__},
            )

    norm_filters, start_dt, end_dt, window_tuple = _normalize_filters(filters)
    filter_sig = _compute_filter_signature(ctx.case_id, ctx.run_id, norm_filters)

    offset = 0
    if cursor is not None:
        offset = _decode_cursor(cursor, filter_sig)

    matched = [
        ev for ev in event_list if _matches_filters(ev, norm_filters, start_dt, end_dt)
    ]
    matched.sort(key=_event_sort_key)

    if offset > len(matched) or (offset == len(matched) and len(matched) > 0 and cursor is not None):
        raise InvalidArgumentError(
            f"Query cursor offset {offset} is out of range for {len(matched)} matched events.",
            details={"offset": offset, "total_matched": len(matched)},
        )

    page = matched[offset : offset + limit]
    next_offset = offset + len(page)
    next_cursor = _encode_cursor(next_offset, filter_sig) if next_offset < len(matched) else None

    edges = correlate_lineage_and_flows(page) if include_edges and page else []
    resolved_query_id = query_id or f"qry_{uuid4().hex[:16]}"

    return {
        "query_id": resolved_query_id,
        "case_id": ctx.case_id,
        "run_id": ctx.run_id,
        "task_id": task_id,
        "events": page,
        "edges": edges,
        "next_cursor": next_cursor,
        "total_matched": len(matched),
        "evidence_ids": list(dict.fromkeys(ev.physical_record_id for ev in page)),
        "event_ids": [ev.event_id for ev in page],
        "covered_scope": {
            "case_id": ctx.case_id,
            "run_id": ctx.run_id,
            "task_id": task_id,
            "filters": dict(filters) if filters else {},
            "time_window": list(window_tuple) if window_tuple else None,
            "total_scanned": len(event_list),
            "total_matched": len(matched),
            "returned_count": len(page),
            "empty": len(matched) == 0,
        },
    }


__all__ = [
    "correlate_lineage_and_flows",
    "fetch_raw_evidence",
    "query_events",
]
