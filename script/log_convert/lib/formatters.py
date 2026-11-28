"""Tool-specific record formatters for Zircolite, Hayabusa, RSigma, and Chainsaw."""

from __future__ import annotations

from ipaddress import IPv6Address
from typing import Any


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# These are address fields, not command lines or arbitrary strings containing IPs.
_WINDOWS_IP_FIELDS = frozenset({
    "IpAddress", "SourceIp", "DestinationIp", "ClientAddress", "ClientIP",
    "SourceAddress", "DestAddress",
})


def _canonical_windows_addresses(fields: dict[str, Any]) -> dict[str, Any]:
    """Represent IPv4-mapped IPv6 as IPv4 for IPv4 Sigma CIDR predicates.

    The parser's dictionaries and raw evidence remain unchanged. Native IPv6,
    missing values and unparseable values retain their original representation.
    """
    result = dict(fields)
    for key in _WINDOWS_IP_FIELDS & fields.keys():
        value = fields[key]
        if not isinstance(value, str) or ":" not in value:
            continue
        try:
            mapped = IPv6Address(value.strip()).ipv4_mapped
        except ValueError:
            continue
        if mapped is not None:
            result[key] = str(mapped)
    return result


def _flatten_value_for_sqlite(val: Any) -> Any:
    """Convert lists/dicts into SQLite-friendly scalar strings for Zircolite."""
    if isinstance(val, list):
        if all(isinstance(x, (str, int, float, bool)) or x is None for x in val):
            return ", ".join("" if x is None else str(x) for x in val)
        return str(val)
    if isinstance(val, dict):
        return str(val)
    return val


def _build_evtx_dump_event(parsed: dict[str, Any]) -> dict[str, Any]:
    """Build Rust `evtx` crate / `evtx_dump -o jsonl` structure used by Hayabusa -J and Chainsaw."""
    sys_raw = parsed["system"]
    provider = sys_raw.get("Provider") or {}
    time_created = sys_raw.get("TimeCreated") or {}
    execution = sys_raw.get("Execution") or {}
    correlation = sys_raw.get("Correlation")
    security = sys_raw.get("Security")

    system_obj: dict[str, Any] = {
        "Provider": {"#attributes": provider} if provider else {},
        "EventID": sys_raw.get("EventID"),
        "Version": sys_raw.get("Version"),
        "Level": sys_raw.get("Level"),
        "Task": sys_raw.get("Task"),
        "Opcode": sys_raw.get("Opcode"),
        "Keywords": sys_raw.get("Keywords"),
        "TimeCreated": {"#attributes": time_created} if time_created else {},
        "EventRecordID": sys_raw.get("EventRecordID"),
        "Correlation": {"#attributes": correlation} if correlation else None,
        "Execution": {"#attributes": execution} if execution else {},
        "Channel": sys_raw.get("Channel"),
        "Computer": sys_raw.get("Computer"),
        "Security": {"#attributes": security} if security else None,
    }
    if "EventID_Qualifiers" in sys_raw and sys_raw["EventID_Qualifiers"] is not None:
        system_obj["EventID"] = {
            "#attributes": {"Qualifiers": sys_raw["EventID_Qualifiers"]},
            "#text": sys_raw.get("EventID"),
        }

    event_obj: dict[str, Any] = {
        "#attributes": {"xmlns": parsed["xmlns"]},
        "System": system_obj,
    }
    if parsed["event_data"]:
        event_obj["EventData"] = _canonical_windows_addresses(parsed["event_data"])
    elif parsed["user_data"]:
        event_obj["UserData"] = _canonical_windows_addresses(parsed["user_data"])
    else:
        event_obj["EventData"] = None

    return {"Event": event_obj}


def _build_flat_winxml_record(parsed: dict[str, Any]) -> dict[str, Any]:
    """Build flattened Windows Event record with Sigma-standard field names and no SQLite case collisions."""
    sys_raw = parsed["system"]
    provider = sys_raw.get("Provider") or {}
    execution = sys_raw.get("Execution") or {}
    security = sys_raw.get("Security") or {}

    rec: dict[str, Any] = {
        "event_id": parsed["event_id"],
        "raw_id": parsed["raw_id"],
        "source_file": parsed["source_file"],
        "record_index": parsed["record_index"],
        "@timestamp": parsed["utc_timestamp"],
        "SystemTime": parsed["system_time_raw"] or parsed["utc_timestamp"],
        "EventID": sys_raw.get("EventID"),
        "Version": sys_raw.get("Version"),
        "Level": sys_raw.get("Level"),
        "Task": sys_raw.get("Task"),
        "Opcode": sys_raw.get("Opcode"),
        "Keywords": sys_raw.get("Keywords"),
        "EventRecordID": sys_raw.get("EventRecordID"),
        "Channel": sys_raw.get("Channel"),
        "Computer": sys_raw.get("Computer"),
        "Provider_Name": provider.get("Name"),
        "Provider_Guid": provider.get("Guid"),
        "Execution_ProcessID": execution.get("ProcessID"),
        "Execution_ThreadID": execution.get("ThreadID"),
    }
    if security.get("UserID") is not None:
        rec["Security_UserID"] = security["UserID"]

    existing_lower = {k.lower() for k in rec}
    for k, v in _canonical_windows_addresses(parsed["event_data"]).items():
        key = k if k.lower() not in existing_lower else f"EventData_{k}"
        rec[key] = v
        existing_lower.add(key.lower())
    for k, v in _canonical_windows_addresses(parsed["user_data"]).items():
        key = k if k.lower() not in existing_lower else f"UserData_{k}"
        rec[key] = v
        existing_lower.add(key.lower())
    return rec


def _ecar_sigma_fields(data: dict[str, Any]) -> dict[str, Any]:
    """Map ECAR fields + properties to standard Sigma fields."""
    props = data.get("properties") or {}
    obj_type = data.get("object") or ""
    action = data.get("action") or ""

    mapped: dict[str, Any] = {
        "log_source": "ecar",
        "ecar_id": data.get("id"),
        "event_type": f"{obj_type}_{action}" if obj_type and action else obj_type or action,
        "object": obj_type,
        "action": action,
        "objectID": data.get("objectID"),
        "actorID": data.get("actorID"),
        "hostname": data.get("hostname"),
        "Computer": data.get("hostname"),
        "principal": data.get("principal"),
        "User": data.get("principal"),
        "pid": data.get("pid"),
        "ProcessId": data.get("pid"),
        "ppid": data.get("ppid"),
        "ParentProcessId": data.get("ppid"),
        "tid": data.get("tid"),
        "ThreadId": data.get("tid"),
        "timestamp_ms": data.get("timestamp_ms"),
    }

    prop_to_sigma = {
        "process_guid": "ProcessGuid",
        "parent_process_guid": "ParentProcessGuid",
        "image_path": "Image",
        "parent_image_path": "ParentImage",
        "command_line": "CommandLine",
        "file_path": "TargetFilename",
        "src_ip": "SourceIp",
        "src_port": "SourcePort",
        "dst_ip": "DestinationIp",
        "dst_port": "DestinationPort",
        "protocol": "Protocol",
        "direction": "Direction",
        "logon_id": "LogonId",
        "logon_guid": "LogonGuid",
        "session_id": "SessionId",
        "session_type": "LogonType",
        "session_lifecycle": "SessionLifecycle",
        "outcome": "Outcome",
        "failure_reason": "FailureReason",
        "icmp_type": "IcmpType",
        "icmp_code": "IcmpCode",
    }

    # ECAR object IDs have different meanings for different event kinds.
    # Only process lifecycle records identify the process with objectID.
    kind = (str(obj_type).upper(), str(action).upper())
    categories = {
        ("PROCESS", "CREATE"): ["process_creation"],
        ("PROCESS", "TERMINATE"): ["process_termination"],
        ("PROCESS", "OPEN"): ["process_access"],
        ("FLOW", "CONNECT"): ["network_connection"],
        ("MODULE", "LOAD"): ["image_load"],
        ("FILE", "READ"): ["file_access"],
        ("FILE", "CREATE"): ["file_event"],
        ("FILE", "WRITE"): ["file_event"],
        ("FILE", "DELETE"): ["file_delete"],
        ("REGISTRY", "MODIFY"): ["registry_event", "registry_set"],
        ("THREAD", "REMOTE_CREATE"): ["create_remote_thread"],
    }
    mapped["event_categories"] = categories.get(kind, [])
    if kind in {("PROCESS", "CREATE"), ("PROCESS", "TERMINATE")}:
        if data.get("objectID"):
            mapped["ProcessGuid"] = data["objectID"]
        if kind == ("PROCESS", "CREATE") and data.get("actorID"):
            mapped["ParentProcessGuid"] = data["actorID"]
    elif kind in categories:
        if data.get("actorID"):
            mapped["ProcessGuid"] = data["actorID"]
    if kind == ("FILE", "READ"):
        path = props.get("file_path")
        if isinstance(path, str) and path.strip():
            mapped["FileName"] = path
    if kind == ("MODULE", "LOAD") and props.get("file_path") is not None:
        mapped["ImageLoaded"] = props["file_path"]
    if kind == ("REGISTRY", "MODIFY"):
        if props.get("registry_key") is not None:
            mapped["TargetObject"] = props["registry_key"]
        if props.get("registry_value") is not None:
            mapped["Details"] = props["registry_value"]
    if kind in {("PROCESS", "OPEN"), ("THREAD", "REMOTE_CREATE")}:
        for source, target in {
            "image_path": "SourceImage", "target_image_path": "TargetImage",
            "granted_access": "GrantedAccess", "call_trace": "CallTrace",
            "target_process_uuid": "TargetProcessGUID",
        }.items():
            if props.get(source) is not None:
                mapped[target] = props[source]
        if data.get("actorID"):
            mapped["SourceProcessGUID"] = data["actorID"]

    for pk, pv in props.items():
        mapped[f"properties_{pk}"] = pv
        sigma_key = prop_to_sigma.get(pk)
        if sigma_key:
            if sigma_key in ("SourcePort", "DestinationPort") and isinstance(pv, str) and pv.isdigit():
                mapped[sigma_key] = int(pv)
            else:
                mapped[sigma_key] = pv
    return mapped


def _zeek_sigma_aliases(data: dict[str, Any]) -> dict[str, Any]:
    """Extract common Sigma network aliases from a Zeek record."""
    aliases: dict[str, Any] = {}
    if "id.orig_h" in data:
        aliases["src_ip"] = data["id.orig_h"]
    if "id.orig_p" in data:
        aliases["src_port"] = data["id.orig_p"]
    if "id.resp_h" in data:
        aliases["dst_ip"] = data["id.resp_h"]
    if "id.resp_p" in data:
        aliases["dst_port"] = data["id.resp_p"]
    return aliases


# ===========================================================================
# 1. Zircolite Formatters (flat SQLite-safe JSONL + event_id + @timestamp)
# ===========================================================================

def format_zircolite_winxml(parsed: dict[str, Any]) -> dict[str, Any]:
    return _build_flat_winxml_record(parsed)


def format_zircolite_zeek(parsed: dict[str, Any]) -> dict[str, Any]:
    data = parsed["data"]
    rec: dict[str, Any] = {
        "event_id": parsed["event_id"],
        "raw_id": parsed["raw_id"],
        "source_file": parsed["source_file"],
        "record_index": parsed["record_index"],
        "@timestamp": parsed["utc_timestamp"],
        "log_source": "zeek",
        "zeek_log_type": parsed["zeek_log_type"],
    }
    rec.update(_zeek_sigma_aliases(data))
    existing_lower = {k.lower() for k in rec}
    for k, v in data.items():
        flat_key = k.replace(".", "_")
        if flat_key.lower() in existing_lower:
            flat_key = f"zeek_{flat_key}"
        rec[flat_key] = _flatten_value_for_sqlite(v)
        existing_lower.add(flat_key.lower())
    return rec


def format_zircolite_ecar(parsed: dict[str, Any]) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "event_id": parsed["event_id"],
        "raw_id": parsed["raw_id"],
        "source_file": parsed["source_file"],
        "record_index": parsed["record_index"],
        "@timestamp": parsed["utc_timestamp"],
    }
    for k, v in _ecar_sigma_fields(parsed["data"]).items():
        rec[k] = _flatten_value_for_sqlite(v)
    return rec


def format_zircolite_syslog(parsed: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_id": parsed["event_id"],
        "raw_id": parsed["raw_id"],
        "source_file": parsed["source_file"],
        "record_index": parsed["record_index"],
        "@timestamp": parsed["utc_timestamp"],
        "log_source": "syslog",
        "rfc": parsed["rfc"],
        "priority": parsed["priority"],
        "facility": parsed["facility"],
        "facility_name": parsed["facility_name"],
        "severity": parsed["severity"],
        "severity_name": parsed["severity_name"],
        "syslog_version": parsed["syslog_version"],
        "hostname": parsed["hostname"],
        "Computer": parsed["hostname"],
        "app_name": parsed["app_name"],
        "ProcessName": parsed["app_name"],
        "pid": parsed["pid"],
        "msgid": parsed["msgid"],
        "structured_data": parsed["structured_data"],
        "message": parsed["message"],
    }


def format_zircolite_web_access(parsed: dict[str, Any]) -> dict[str, Any]:
    rec = {
        "event_id": parsed["event_id"],
        "raw_id": parsed["raw_id"],
        "source_file": parsed["source_file"],
        "record_index": parsed["record_index"],
        "@timestamp": parsed["utc_timestamp"],
        "log_source": "web_access",
    }
    for k in (
        "raw_timestamp", "c-ip", "ident", "cs-username", "cs-method",
        "cs-uri", "cs-uri-stem", "cs-uri-query", "cs-version",
        "sc-status", "sc-bytes", "cs-Referer", "cs-User-Agent", "request",
        "parse_error", "raw_line",
    ):
        if k in parsed:
            rec[k] = parsed[k]
    return rec


def format_zircolite_bash_history(parsed: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_id": parsed["event_id"],
        "raw_id": parsed["raw_id"],
        "source_file": parsed["source_file"],
        "record_index": parsed["record_index"],
        "@timestamp": parsed["utc_timestamp"],
        "epoch_ts": parsed["epoch_ts"],
        "log_source": "bash_history",
        "User": parsed["user"],
        "Image": parsed["executable"],
        "CommandLine": parsed["command"],
        "command": parsed["command"],
    }


# ===========================================================================
# 2. Hayabusa Formatter (flat JSONL for `hayabusa dfir-timeline -J`)
# ===========================================================================

def format_hayabusa_winxml(parsed: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (hayabusa_json_input_record, reverse_lookup_index_record).

    Hayabusa v4 `-J` (`--json-input`) ingests flat Windows Event JSONL with
    `@timestamp`, `Hostname`, `Channel`, `EventID`, `RecordNumber`, `SourceName`,
    and top-level EventData fields (preserving extra metadata such as `event_id`
    inside `ExtraFieldInfo` when run with `-p super-verbose`).
    """
    sys_raw = parsed["system"]
    provider = sys_raw.get("Provider") or {}
    execution = sys_raw.get("Execution") or {}
    security = sys_raw.get("Security") or {}

    hayabusa_rec: dict[str, Any] = {
        "@timestamp": parsed["system_time_raw"] or parsed["utc_timestamp"],
        "Hostname": sys_raw.get("Computer"),
        "Channel": sys_raw.get("Channel"),
        "EventID": sys_raw.get("EventID"),
        "RecordNumber": sys_raw.get("EventRecordID"),
        "SourceName": provider.get("Name"),
        "ProviderGuid": provider.get("Guid"),
        "Version": sys_raw.get("Version"),
        "Level": sys_raw.get("Level"),
        "Task": sys_raw.get("Task"),
        "Opcode": sys_raw.get("Opcode"),
        "Keywords": sys_raw.get("Keywords"),
        "event_id": parsed["event_id"],
        "raw_id": parsed["raw_id"],
    }
    if execution.get("ProcessID") is not None:
        hayabusa_rec["ExecutionProcessID"] = execution["ProcessID"]
    if execution.get("ThreadID") is not None:
        hayabusa_rec["ExecutionThreadID"] = execution["ThreadID"]
    if security.get("UserID") is not None:
        hayabusa_rec["SecurityUserID"] = security["UserID"]

    for k, v in _canonical_windows_addresses(parsed["event_data"]).items():
        if k not in hayabusa_rec:
            hayabusa_rec[k] = v
    for k, v in _canonical_windows_addresses(parsed["user_data"]).items():
        if k not in hayabusa_rec:
            hayabusa_rec[k] = v

    index_rec = {
        "Computer": sys_raw.get("Computer"),
        "Channel": sys_raw.get("Channel"),
        "RecordID": sys_raw.get("EventRecordID"),
        "EventID": sys_raw.get("EventID"),
        "Timestamp": parsed["utc_timestamp"],
        "event_id": parsed["event_id"],
        "raw_id": parsed["raw_id"],
        "source_file": parsed["source_file"],
        "record_index": parsed["record_index"],
    }
    return hayabusa_rec, index_rec


# ===========================================================================
# 3. RSigma Formatters (UTC-sorted NDJSON with @timestamp & event_id)
# ===========================================================================

def format_rsigma_winxml(parsed: dict[str, Any]) -> dict[str, Any]:
    return _build_flat_winxml_record(parsed)


def format_rsigma_zeek(parsed: dict[str, Any]) -> dict[str, Any]:
    data = parsed["data"]
    rec: dict[str, Any] = {
        "event_id": parsed["event_id"],
        "raw_id": parsed["raw_id"],
        "source_file": parsed["source_file"],
        "record_index": parsed["record_index"],
        "@timestamp": parsed["utc_timestamp"],
        "log_source": "zeek",
        "zeek_log_type": parsed["zeek_log_type"],
    }
    rec.update(_zeek_sigma_aliases(data))
    # Preserve native Zeek keys (including lists & dotted keys) plus underscore aliases for pipelines
    for k, v in data.items():
        rec[k] = v
        if "." in k:
            rec[k.replace(".", "_")] = v
    return rec


def format_rsigma_ecar(parsed: dict[str, Any]) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "event_id": parsed["event_id"],
        "raw_id": parsed["raw_id"],
        "source_file": parsed["source_file"],
        "record_index": parsed["record_index"],
        "@timestamp": parsed["utc_timestamp"],
    }
    rec.update(_ecar_sigma_fields(parsed["data"]))
    if "properties" in parsed["data"]:
        rec["properties"] = parsed["data"]["properties"]
    return rec


def format_rsigma_syslog(parsed: dict[str, Any]) -> dict[str, Any]:
    return format_zircolite_syslog(parsed)


def format_rsigma_web_access(parsed: dict[str, Any]) -> dict[str, Any]:
    return format_zircolite_web_access(parsed)


def format_rsigma_bash_history(parsed: dict[str, Any]) -> dict[str, Any]:
    return format_zircolite_bash_history(parsed)


# ===========================================================================
# 4. Chainsaw Formatters (JSON Array for Chainsaw 2.18 `kind: json`)
# ===========================================================================

def format_chainsaw_winxml(parsed: dict[str, Any]) -> dict[str, Any]:
    """Build Chainsaw sigma-event-logs-json.yml compatible Windows Event JSON record.

    Chainsaw's `sigma-event-logs-json.yml` maps `Event.System.Provider` and
    `Event.System.TimeCreated` as plain strings (with `*_attributes` alongside).
    """
    sys_raw = parsed["system"]
    provider = sys_raw.get("Provider") or {}
    time_created = sys_raw.get("TimeCreated") or {}
    execution = sys_raw.get("Execution") or {}
    correlation = sys_raw.get("Correlation")
    security = sys_raw.get("Security")

    system_obj: dict[str, Any] = {
        "Provider": provider.get("Name", ""),
        "Provider_attributes": provider,
        "EventID": sys_raw.get("EventID"),
        "Version": sys_raw.get("Version"),
        "Level": sys_raw.get("Level"),
        "Task": sys_raw.get("Task"),
        "Opcode": sys_raw.get("Opcode"),
        "Keywords": sys_raw.get("Keywords"),
        "TimeCreated": time_created.get("SystemTime") or parsed["utc_timestamp"],
        "TimeCreated_attributes": time_created,
        "EventRecordID": sys_raw.get("EventRecordID"),
        "Channel": sys_raw.get("Channel"),
        "Computer": sys_raw.get("Computer"),
    }
    if execution:
        system_obj["Execution_attributes"] = execution
    if correlation:
        system_obj["Correlation_attributes"] = correlation
    if security:
        system_obj["Security_attributes"] = security

    event_obj: dict[str, Any] = {"System": system_obj}
    if parsed["event_data"]:
        event_obj["EventData"] = _canonical_windows_addresses(parsed["event_data"])
    elif parsed["user_data"]:
        event_obj["UserData"] = _canonical_windows_addresses(parsed["user_data"])
    else:
        event_obj["EventData"] = {}

    return {
        "Event": event_obj,
        "event_id": parsed["event_id"],
        "raw_id": parsed["raw_id"],
        "source_file": parsed["source_file"],
        "record_index": parsed["record_index"],
    }


def format_chainsaw_zeek(parsed: dict[str, Any]) -> dict[str, Any]:
    rec = format_rsigma_zeek(parsed)
    rec["timestamp"] = parsed["utc_timestamp"]
    return rec


def format_chainsaw_ecar(parsed: dict[str, Any]) -> dict[str, Any]:
    rec = format_rsigma_ecar(parsed)
    rec["timestamp"] = parsed["utc_timestamp"]
    return rec


def format_chainsaw_syslog(parsed: dict[str, Any]) -> dict[str, Any]:
    rec = format_zircolite_syslog(parsed)
    rec["timestamp"] = parsed["utc_timestamp"]
    return rec


def format_chainsaw_web_access(parsed: dict[str, Any]) -> dict[str, Any]:
    rec = format_zircolite_web_access(parsed)
    rec["timestamp"] = parsed["utc_timestamp"]
    return rec


def format_chainsaw_bash_history(parsed: dict[str, Any]) -> dict[str, Any]:
    rec = format_zircolite_bash_history(parsed)
    rec["timestamp"] = parsed["utc_timestamp"]
    return rec
