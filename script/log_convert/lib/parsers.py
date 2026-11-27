"""Streaming parsers for all 6 log types present in log_example."""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any, Iterator

import orjson
from lxml import etree

from .common import (
    clf_time_to_utc_iso,
    epoch_ms_to_utc_iso,
    epoch_to_utc_iso,
    make_event_id,
    make_raw_id,
    normalize_iso_utc,
)

# ---------------------------------------------------------------------------
# File matchers (for directory input auto-discovery)
# ---------------------------------------------------------------------------

ZEEK_KNOWN_TYPES = {
    "conn",
    "dhcp",
    "dns",
    "files",
    "http",
    "ocsp",
    "pe",
    "smtp",
    "ssl",
    "x509",
    "kerberos",
    "ntlm",
    "smb_files",
    "smb_mapping",
    "rdp",
    "ssh",
    "notice",
    "weird",
    "dpd",
    "ftp",
    "irc",
    "mysql",
    "sip",
    "snmp",
    "socks",
    "tunnel",
}


def is_winxml_file(path: Path) -> bool:
    return path.suffix.lower() == ".xml"


def is_zeek_json_file(path: Path) -> bool:
    if path.suffix.lower() not in (".json", ".jsonl", ".ndjson"):
        return False
    stem = path.stem.lower()
    if stem == "ecar" or stem.startswith("ecar_"):
        return False
    return stem in ZEEK_KNOWN_TYPES or not stem.startswith("ecar")


def is_ecar_json_file(path: Path) -> bool:
    return path.suffix.lower() in (".json", ".jsonl", ".ndjson") and "ecar" in path.stem.lower()


def is_syslog_file(path: Path) -> bool:
    name = path.name.lower()
    return "syslog" in name or name in ("messages", "auth.log", "secure")


def is_web_access_file(path: Path) -> bool:
    name = path.name.lower()
    return "access" in name and name.endswith(".log")


def is_bash_history_file(path: Path) -> bool:
    name = path.name.lower()
    return "bash_history" in name or name == ".bash_history"


# ---------------------------------------------------------------------------
# 1. Windows Event XML Parser (Security, Sysmon, etc.)
# ---------------------------------------------------------------------------

WIN_XML_INT_SYSTEM_TAGS = {"EventID", "Version", "Level", "Task", "Opcode", "EventRecordID"}


def _local_tag(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def _try_int(val: str | None) -> int | str | None:
    if val is None:
        return None
    s = val.strip()
    if not s:
        return None
    try:
        return int(s)
    except ValueError:
        return s


def parse_winxml_file(path: Path, case_id: str = "default") -> Iterator[dict[str, Any]]:
    """Stream-parse a Windows Event XML file (<Events><Event>...</Event></Events>)."""
    source_file = path.name
    record_index = 0

    context = etree.iterparse(
        str(path),
        events=("end",),
        recover=True,
    )
    for _, elem in context:
        if _local_tag(elem.tag) != "Event":
            continue
        record_index += 1

        xmlns = elem.nsmap.get(None) or "http://schemas.microsoft.com/win/2004/08/events/event"
        system: dict[str, Any] = {}
        event_data: dict[str, Any] = {}
        user_data: dict[str, Any] = {}

        for child in elem:
            ctag = _local_tag(child.tag)
            if ctag == "System":
                for sc in child:
                    stag = _local_tag(sc.tag)
                    text = sc.text.strip() if sc.text else None
                    attrs = dict(sc.attrib)
                    if stag == "Provider":
                        system["Provider"] = attrs
                    elif stag == "TimeCreated":
                        system["TimeCreated"] = attrs
                    elif stag == "Execution":
                        exec_attrs: dict[str, Any] = {}
                        for k, v in attrs.items():
                            exec_attrs[k] = _try_int(v)
                        system["Execution"] = exec_attrs
                    elif stag == "Correlation":
                        system["Correlation"] = attrs if attrs else None
                    elif stag == "Security":
                        system["Security"] = attrs if attrs else None
                    elif stag == "EventID":
                        ev_id = _try_int(text)
                        if attrs:
                            system["EventID"] = ev_id
                            system["EventID_Qualifiers"] = _try_int(attrs.get("Qualifiers"))
                        else:
                            system["EventID"] = ev_id
                    elif stag in WIN_XML_INT_SYSTEM_TAGS:
                        system[stag] = _try_int(text)
                    else:
                        system[stag] = text
            elif ctag == "EventData":
                unnamed_idx = 0
                for dc in child:
                    dtag = _local_tag(dc.tag)
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
                    for sub in uc:
                        user_data[_local_tag(sub.tag)] = sub.text if sub.text is not None else ""

        sys_time_raw = (system.get("TimeCreated") or {}).get("SystemTime", "")
        utc_ts = normalize_iso_utc(sys_time_raw) if sys_time_raw else ""
        rec_id = system.get("EventRecordID")
        locator = f"rec:{rec_id}" if rec_id is not None else f"idx:{record_index}"
        raw_id = make_raw_id(case_id, source_file, locator)
        event_id = make_event_id(raw_id, 0)

        yield {
            "event_id": event_id,
            "raw_id": raw_id,
            "source_file": source_file,
            "record_index": record_index,
            "xmlns": xmlns,
            "utc_timestamp": utc_ts,
            "system_time_raw": sys_time_raw,
            "system": system,
            "event_data": event_data,
            "user_data": user_data,
        }

        # Free memory for streaming large XML files
        elem.clear()
        while elem.getprevious() is not None:
            del elem.getparent()[0]


# ---------------------------------------------------------------------------
# 2. Zeek JSONL Parser (conn, dhcp, dns, files, http, ocsp, pe, smtp, ssl, x509)
# ---------------------------------------------------------------------------

def detect_zeek_log_type(path: Path, sample: dict[str, Any]) -> str:
    stem = path.stem.lower()
    if stem in ZEEK_KNOWN_TYPES:
        return stem
    if "conn_state" in sample:
        return "conn"
    if "query" in sample and "qtype_name" in sample:
        return "dns"
    if "method" in sample and "uri" in sample:
        return "http"
    if "server_name" in sample or "cipher" in sample:
        return "ssl"
    if "fuid" in sample and "mime_type" in sample:
        return "files"
    if "assigned_addr" in sample or "lease_time" in sample:
        return "dhcp"
    if "helo" in sample or "mailfrom" in sample:
        return "smtp"
    if "fingerprint" in sample and "certificate.subject" in sample:
        return "x509"
    if "certStatus" in sample and "serialNumber" in sample:
        return "ocsp"
    if "machine" in sample and "section_names" in sample:
        return "pe"
    return stem


def parse_zeek_json_file(path: Path, case_id: str = "default") -> Iterator[dict[str, Any]]:
    """Stream-parse a Zeek JSONL file."""
    source_file = path.name
    zeek_type: str | None = None
    with path.open("rb") as fh:
        for line_no, raw_line in enumerate(fh, 1):
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            obj = orjson.loads(raw_line)
            if zeek_type is None:
                zeek_type = detect_zeek_log_type(path, obj)

            ts_val = obj.get("ts")
            utc_ts = epoch_to_utc_iso(ts_val) if ts_val is not None else ""
            raw_id = make_raw_id(case_id, source_file, line_no)
            event_id = make_event_id(raw_id, 0)

            yield {
                "event_id": event_id,
                "raw_id": raw_id,
                "source_file": source_file,
                "record_index": line_no,
                "zeek_log_type": zeek_type,
                "utc_timestamp": utc_ts,
                "data": obj,
            }


# ---------------------------------------------------------------------------
# 3. ECAR JSONL Parser (ecar.json)
# ---------------------------------------------------------------------------

def parse_ecar_json_file(path: Path, case_id: str = "default") -> Iterator[dict[str, Any]]:
    """Stream-parse an ECAR JSONL file."""
    source_file = path.name
    with path.open("rb") as fh:
        for line_no, raw_line in enumerate(fh, 1):
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            obj = orjson.loads(raw_line)
            ts_ms = obj.get("timestamp_ms")
            if ts_ms is not None:
                utc_ts = epoch_ms_to_utc_iso(ts_ms)
            elif obj.get("timestamp"):
                utc_ts = normalize_iso_utc(str(obj["timestamp"]))
            else:
                utc_ts = ""

            ecar_uid = obj.get("id")
            locator = f"id:{ecar_uid}" if ecar_uid else f"line:{line_no}"
            raw_id = make_raw_id(case_id, source_file, locator)
            event_id = make_event_id(raw_id, 0)

            yield {
                "event_id": event_id,
                "raw_id": raw_id,
                "source_file": source_file,
                "record_index": line_no,
                "utc_timestamp": utc_ts,
                "data": obj,
            }


# ---------------------------------------------------------------------------
# 4. Syslog RFC 5424 (with RFC 3164 fallback) Parser
# ---------------------------------------------------------------------------

SYSLOG_FACILITIES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth", 5: "syslog",
    6: "lpr", 7: "news", 8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    12: "ntp", 13: "security", 14: "console", 15: "solaris-cron",
    16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7",
}

SYSLOG_SEVERITIES = {
    0: "emerg", 1: "alert", 2: "crit", 3: "err",
    4: "warning", 5: "notice", 6: "info", 7: "debug",
}

RFC5424_RE = re.compile(
    r"^<(\d{1,3})>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\-|(?:\[[^\]]+\])+)(?:\s+(.*))?$"
)
RFC3164_RE = re.compile(
    r"^<(\d{1,3})>([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\s:\[]+)(?:\[(\d+)\])?:\s*(.*)$"
)


def parse_syslog_file(path: Path, case_id: str = "default") -> Iterator[dict[str, Any]]:
    """Stream-parse an RFC 5424 (or RFC 3164) syslog file."""
    source_file = path.name
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line_no, raw in enumerate(fh, 1):
            line = raw.rstrip("\r\n")
            if not line:
                continue

            raw_id = make_raw_id(case_id, source_file, line_no)
            event_id = make_event_id(raw_id, 0)

            m = RFC5424_RE.match(line)
            if m:
                pri = int(m.group(1))
                version = int(m.group(2))
                ts_raw = m.group(3)
                hostname = None if m.group(4) == "-" else m.group(4)
                app_name = None if m.group(5) == "-" else m.group(5)
                procid_raw = None if m.group(6) == "-" else m.group(6)
                pid = _try_int(procid_raw) if procid_raw is not None else None
                msgid = None if m.group(7) == "-" else m.group(7)
                sd = None if m.group(8) == "-" else m.group(8)
                message = m.group(9) or ""
                utc_ts = normalize_iso_utc(ts_raw) if ts_raw != "-" else ""
                fac = pri >> 3
                sev = pri & 0x07

                yield {
                    "event_id": event_id,
                    "raw_id": raw_id,
                    "source_file": source_file,
                    "record_index": line_no,
                    "utc_timestamp": utc_ts,
                    "rfc": "5424",
                    "priority": pri,
                    "facility": fac,
                    "facility_name": SYSLOG_FACILITIES.get(fac, f"facility_{fac}"),
                    "severity": sev,
                    "severity_name": SYSLOG_SEVERITIES.get(sev, f"severity_{sev}"),
                    "syslog_version": version,
                    "hostname": hostname,
                    "app_name": app_name,
                    "pid": pid,
                    "msgid": msgid,
                    "structured_data": sd,
                    "message": message,
                    "raw_line": line,
                }
                continue

            m3164 = RFC3164_RE.match(line)
            if m3164:
                pri = int(m3164.group(1))
                fac = pri >> 3
                sev = pri & 0x07
                yield {
                    "event_id": event_id,
                    "raw_id": raw_id,
                    "source_file": source_file,
                    "record_index": line_no,
                    "utc_timestamp": "",
                    "rfc": "3164",
                    "priority": pri,
                    "facility": fac,
                    "facility_name": SYSLOG_FACILITIES.get(fac, f"facility_{fac}"),
                    "severity": sev,
                    "severity_name": SYSLOG_SEVERITIES.get(sev, f"severity_{sev}"),
                    "syslog_version": 0,
                    "hostname": m3164.group(3),
                    "app_name": m3164.group(4),
                    "pid": _try_int(m3164.group(5)),
                    "msgid": None,
                    "structured_data": None,
                    "message": m3164.group(6),
                    "raw_line": line,
                }
                continue

            yield {
                "event_id": event_id,
                "raw_id": raw_id,
                "source_file": source_file,
                "record_index": line_no,
                "utc_timestamp": "",
                "rfc": "unknown",
                "priority": None,
                "facility": None,
                "facility_name": None,
                "severity": None,
                "severity_name": None,
                "syslog_version": None,
                "hostname": None,
                "app_name": None,
                "pid": None,
                "msgid": None,
                "structured_data": None,
                "message": line,
                "raw_line": line,
            }


# ---------------------------------------------------------------------------
# 5. Web Access Log (Apache / Nginx Combined & Common Log Format) Parser
# ---------------------------------------------------------------------------

COMBINED_LOG_RE = re.compile(
    r'^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?$'
)


def parse_web_access_file(path: Path, case_id: str = "default") -> Iterator[dict[str, Any]]:
    """Stream-parse an Apache/Nginx Combined (or Common) access log file."""
    source_file = path.name
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line_no, raw in enumerate(fh, 1):
            line = raw.rstrip("\r\n")
            if not line:
                continue

            raw_id = make_raw_id(case_id, source_file, line_no)
            event_id = make_event_id(raw_id, 0)

            m = COMBINED_LOG_RE.match(line)
            if not m:
                yield {
                    "event_id": event_id,
                    "raw_id": raw_id,
                    "source_file": source_file,
                    "record_index": line_no,
                    "utc_timestamp": "",
                    "parse_error": "unmatched_line",
                    "raw_line": line,
                }
                continue

            client_ip = m.group(1)
            ident = None if m.group(2) == "-" else m.group(2)
            username = None if m.group(3) == "-" else m.group(3)
            raw_ts = m.group(4)
            utc_ts = clf_time_to_utc_iso(raw_ts)
            request = m.group(5)
            status = int(m.group(6))
            bytes_str = m.group(7)
            sc_bytes = None if bytes_str == "-" else int(bytes_str)
            referer = m.group(8)
            if referer == "-":
                referer = None
            user_agent = m.group(9)
            if user_agent == "-":
                user_agent = None

            req_parts = request.split(" ")
            method = req_parts[0] if len(req_parts) >= 1 else ""
            uri = req_parts[1] if len(req_parts) >= 2 else ""
            version = req_parts[2] if len(req_parts) >= 3 else ""
            if "?" in uri:
                uri_stem, uri_query = uri.split("?", 1)
            else:
                uri_stem, uri_query = uri, ""

            yield {
                "event_id": event_id,
                "raw_id": raw_id,
                "source_file": source_file,
                "record_index": line_no,
                "utc_timestamp": utc_ts,
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
            }


# ---------------------------------------------------------------------------
# 6. Bash History Parser (#<epoch>\n<command>)
# ---------------------------------------------------------------------------

EPOCH_COMMENT_RE = re.compile(r"^#(\d{9,12})$")
ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")


def infer_user_from_bash_history(path: Path) -> str | None:
    name = path.name
    if name.endswith(".bash_history") and name != ".bash_history":
        return name[: -len(".bash_history")]
    return None


def extract_command_executable(cmd: str) -> str:
    """Extract the leading command/binary token from a shell command line."""
    try:
        tokens = shlex.split(cmd, posix=True)
    except ValueError:
        tokens = cmd.strip().split()
    for tok in tokens:
        if tok in ("sudo", "env", "nohup", "time", "exec"):
            continue
        if ENV_ASSIGN_RE.match(tok):
            continue
        return tok
    return tokens[0] if tokens else ""


def parse_bash_history_file(
    path: Path,
    case_id: str = "default",
    user_override: str | None = None,
) -> Iterator[dict[str, Any]]:
    """Parse GNU bash history file supporting optional '#<unix_epoch>' timestamp lines."""
    source_file = path.name
    username = user_override or infer_user_from_bash_history(path)
    pending_epoch: int | None = None

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line_no, raw in enumerate(fh, 1):
            line = raw.rstrip("\r\n")
            if not line:
                continue

            m = EPOCH_COMMENT_RE.match(line)
            if m:
                pending_epoch = int(m.group(1))
                continue

            utc_ts = epoch_to_utc_iso(pending_epoch) if pending_epoch is not None else None
            raw_id = make_raw_id(case_id, source_file, line_no)
            event_id = make_event_id(raw_id, 0)
            executable = extract_command_executable(line)

            yield {
                "event_id": event_id,
                "raw_id": raw_id,
                "source_file": source_file,
                "record_index": line_no,
                "utc_timestamp": utc_ts,
                "epoch_ts": pending_epoch,
                "user": username,
                "command": line,
                "executable": executable,
            }
            pending_epoch = None
