"""Read-only adapters from anomaly rankings to RAG log-event queries.

The benchmark writes ranked ``pr-*`` IDs.  ``Label_Index.json`` maps each ID to
``{linenumber, filepath}``; this module resolves a few candidates and extracts
common fields without modifying the benchmark or the raw corpus.

The mapping is heuristic and intentionally conservative: unsupported layouts
produce a minimal event rather than fabricated fields.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from html import unescape
from pathlib import Path
from typing import Any, Mapping

XML_EVENT = re.compile(r"<Event\b.*?</Event>", re.DOTALL)
XML_EVENT_ID = re.compile(r"<EventID\b[^>]*>(\d+)</EventID>", re.I)
XML_COMPUTER = re.compile(r"<Computer>([^<]*)</Computer>", re.I)
XML_DATA = re.compile(
    r'<Data\s+Name=["\']([^"\']+)["\'][^>]*>([^<]*)</Data>',
    re.I,
)
BASH_TIMESTAMP = re.compile(r"#\d+")


class CandidateError(ValueError):
    pass


@dataclass(frozen=True)
class CandidateRef:
    scene: str
    physical_record_id: str
    filepath: str
    linenumber: int
    rank: int | None = None
    score: float | None = None
    model: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scene": self.scene,
            "physical_record_id": self.physical_record_id,
            "filepath": self.filepath,
            "linenumber": self.linenumber,
            "rank": self.rank,
            "score": self.score,
            "model": self.model,
        }


def load_scene_index(scene_dir: str | Path) -> dict[str, Any]:
    scene_dir = Path(scene_dir)
    path = scene_dir / "Label_Index.json"
    data = json.loads(path.read_bytes())
    if not isinstance(data, dict):
        raise CandidateError(f"Label_Index.json is not an object: {path}")
    return data


def _safe_target(scene_dir: Path, filepath: str) -> Path:
    relative = Path(filepath)
    if relative.is_absolute() or not relative.parts or relative.parts[0] != "data":
        raise CandidateError(f"unsafe filepath: {filepath}")
    if ".." in relative.parts:
        raise CandidateError(f"unsafe filepath: {filepath}")
    base = scene_dir.resolve()
    target = (scene_dir / relative).resolve()
    if target != base and base not in target.parents:
        raise CandidateError(f"filepath escapes scene: {filepath}")
    return target


def resolve_candidate(
    scene_dir: str | Path,
    physical_record_id: str,
    *,
    index: Mapping[str, Any] | None = None,
    rank: int | None = None,
    score: float | None = None,
    model: str | None = None,
) -> CandidateRef:
    scene_dir = Path(scene_dir)
    index = index if index is not None else load_scene_index(scene_dir)
    entry = index.get(physical_record_id)
    if not isinstance(entry, Mapping):
        raise CandidateError(f"unknown physical record ID: {physical_record_id}")
    filepath = entry.get("filepath")
    linenumber = entry.get("linenumber")
    if not isinstance(filepath, str) or not isinstance(linenumber, int) or linenumber < 1:
        raise CandidateError(f"invalid index entry for {physical_record_id}")
    _safe_target(scene_dir, filepath)
    return CandidateRef(
        scene=scene_dir.name,
        physical_record_id=physical_record_id,
        filepath=filepath,
        linenumber=linenumber,
        rank=rank,
        score=score,
        model=model,
    )


def read_record(scene_dir: str | Path, ref: CandidateRef) -> dict[str, Any]:
    scene_dir = Path(scene_dir)
    target = _safe_target(scene_dir, ref.filepath)
    suffix = target.suffix.lower()
    if suffix == ".xml":
        events = list(XML_EVENT.finditer(target.read_text(encoding="utf-8", errors="replace")))
        if ref.linenumber > len(events):
            raise CandidateError(f"event number {ref.linenumber} exceeds XML events in {ref.filepath}")
        event_text = events[ref.linenumber - 1].group()
        event_match = XML_EVENT_ID.search(event_text)
        computer_match = XML_COMPUTER.search(event_text)
        fields = {
            name.lower(): unescape(value)
            for name, value in XML_DATA.findall(event_text)
        }
        return {
            "log_type": target.stem,
            "event_id": event_match.group(1) if event_match else "",
            "computer": unescape(computer_match.group(1)) if computer_match else "",
            "fields": fields,
            "_source_file": ref.filepath,
        }

    if suffix == ".json":
        with target.open(encoding="utf-8", errors="replace") as stream:
            for line_number, line in enumerate(stream, start=1):
                if line_number != ref.linenumber:
                    continue
                if not line.strip():
                    raise CandidateError(f"empty JSONL record at {ref.filepath}:{ref.linenumber}")
                record = json.loads(line)
                if isinstance(record, dict):
                    payload = dict(record)
                    payload.setdefault("_source_file", ref.filepath)
                    return payload
                return {"log_type": target.stem, "value": record, "_source_file": ref.filepath}
        raise CandidateError(f"line {ref.linenumber} exceeds {ref.filepath}")

    if suffix == ".bash_history":
        records: list[str] = []
        current: list[str] | None = None
        with target.open(encoding="utf-8", errors="replace") as stream:
            for line in stream:
                text = line.rstrip("\r\n")
                if BASH_TIMESTAMP.fullmatch(text):
                    if current is not None:
                        records.append("".join(current))
                    current = [text]
                elif current is not None:
                    current.append("\n" + text)
        if current is not None:
            records.append("".join(current))
        if ref.linenumber > len(records):
            raise CandidateError(f"command number {ref.linenumber} exceeds {ref.filepath}")
        return {
            "log_type": "bash_history",
            "command": records[ref.linenumber - 1].strip(),
            "_source_file": ref.filepath,
        }

    with target.open(encoding="utf-8", errors="replace") as stream:
        for line_number, line in enumerate(stream, start=1):
            if line_number == ref.linenumber:
                return {
                    "log_type": target.stem,
                    "message": line.strip(),
                    "_source_file": ref.filepath,
                }
    raise CandidateError(f"line {ref.linenumber} exceeds {ref.filepath}")


def _first(values: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        value = values.get(key)
        if value is None:
            continue
        if isinstance(value, (dict, list, tuple)):
            continue
        text = str(value).strip()
        if text and text != "-":
            return text
    return ""


def _log_type(ref: CandidateRef) -> str:
    name = Path(ref.filepath).name.lower()
    if "windows_event_sysmon" in name:
        return "windows_sysmon"
    if "windows_event_security" in name:
        return "windows_security"
    if name.endswith("ecar.json"):
        return "ecar"
    for stem in ("conn", "dns", "http", "ssl", "files", "x509"):
        if name == f"{stem}.json":
            return f"zeek_{stem}"
    if name.endswith("syslog.log"):
        return "syslog"
    if name.endswith("web_access.log"):
        return "web_access"
    if name.endswith(".bash_history"):
        return "bash_history"
    return Path(name).stem


def _collect(fields: dict[str, Any], key: str, value: Any) -> None:
    if isinstance(value, (dict,)):
        return
    if isinstance(value, (list, tuple)):
        if all(not isinstance(item, (dict, list, tuple)) for item in value):
            fields[key.lower()] = ", ".join(str(item) for item in value)
        return
    fields[key.lower()] = value


def candidate_to_event(ref: CandidateRef, record: Mapping[str, Any]) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for key, value in record.items():
        _collect(fields, str(key), value)
    for nested_name in ("properties", "fields"):
        nested = record.get(nested_name)
        if isinstance(nested, Mapping):
            for key, value in nested.items():
                _collect(fields, str(key), value)

    event: dict[str, Any] = {
        "log_type": _log_type(ref),
        "physical_record_id": ref.physical_record_id,
        "scene": ref.scene,
    }
    event_id = _first(fields, "event_id", "eventid")
    object_name = _first(fields, "object")
    action = _first(fields, "action")
    if event_id:
        event["event_id"] = event_id
    if object_name or action:
        event["event_type"] = "/".join(part for part in (object_name, action) if part)
    mapping = {
        "computer": ("computer", "host", "hostname"),
        "user": ("user", "targetusername", "subjectusername", "username"),
        "image": ("image", "image_path", "newprocessname", "processname", "application"),
        "parent_image": ("parentimage", "parent_image_path", "parentprocessname"),
        "command_line": ("commandline", "command_line", "command"),
        "destination_ip": ("destinationip", "dst_ip", "id.resp_h", "remote_ip"),
        "destination_hostname": ("destinationhostname", "server_name", "host", "query"),
        "query": ("query",),
        "file_name": ("targetfilename", "file_path", "file_name"),
        "registry_key": ("targetobject", "registry_key"),
        "protocol": ("protocol", "proto"),
        "status": ("status", "status_code", "conn_state", "rcode_name"),
        "src_ip": ("sourceip", "src_ip", "id.orig_h"),
        "src_port": ("sourceport", "src_port", "id.orig_p"),
        "dst_port": ("destinationport", "dst_port", "id.resp_p"),
        "method": ("method",),
        "uri": ("uri", "request_uri"),
        "user_agent": ("user_agent",),
        "mime_type": ("resp_mime_types", "mime_type"),
        "uid": ("uid",),
        "status_message": ("status_msg",),
        "message": ("message", "command"),
    }
    for target_key, source_keys in mapping.items():
        value = _first(fields, *source_keys)
        if value:
            event[target_key] = value
    if ref.rank is not None:
        event["rank"] = ref.rank
    if ref.score is not None:
        event["score"] = ref.score
    if ref.model:
        event["model"] = ref.model
    return event


def read_ranking_ids(path: str | Path, *, limit: int = 5) -> list[str]:
    ids: list[str] = []
    with Path(path).open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            if not text.startswith("pr-"):
                raise CandidateError(f"unexpected ranking line: {text[:80]}")
            ids.append(text)
            if len(ids) >= limit:
                break
    return ids


def explain_candidate(tools: Any, ref: CandidateRef, record: Mapping[str, Any], *, top_k: int = 5):
    event = candidate_to_event(ref, record)
    response = tools.explain_log_event(event, top_k=top_k)
    return event, response
