"""Raw evidence ingestion, replayable store, and Label_Index multi-format loader (F02)."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
from collections.abc import Set as AbstractSet
from pathlib import Path, PureWindowsPath
from typing import Any, Literal

import orjson

from apt_agent.exceptions import InvalidArgumentError, OutOfScopeError
from apt_agent.models import Locator, RawRecord

PR_ID_PATTERN = re.compile(r"\Apr-\S+\Z")
BASH_EPOCH_RE = re.compile(r"^#([0-9]+)$")
XML_COMMENT_OR_EVENT_RE = re.compile(
    r"(<!--.*?-->)|(<Event(?:\s[^>]*)?>(?:<!--.*?-->|(?!</Event>).)*</Event>)",
    re.DOTALL,
)
JSONL_EXTENSIONS = frozenset({".json", ".jsonl", ".ndjson"})

IndexedLogFormat = Literal["jsonl", "winxml", "bash_history", "text"]


def _require_non_blank_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidArgumentError(
            f"{field_name} must be a non-blank string.",
            details={"field": field_name, "value": value},
        )
    return value


def _clone_record(record: RawRecord) -> RawRecord:
    """Return a deep-isolated copy of a RawRecord so caller mutations cannot corrupt the store."""
    return record.model_copy(update={"payload": copy.deepcopy(record.payload)})


def _compute_payload_digest(payload: Mapping[str, Any]) -> str:
    """Compute a deterministic SHA-256 hex digest of a payload mapping."""
    try:
        raw_bytes = orjson.dumps(dict(payload), option=orjson.OPT_SORT_KEYS)
    except TypeError:
        raw_text = json.dumps(
            dict(payload),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        )
        raw_bytes = raw_text.encode("utf-8")
    return hashlib.sha256(raw_bytes).hexdigest()


class RawEvidenceStore:
    """In-memory replayable store of immutable raw records keyed by physical_record_id."""

    def __init__(
        self,
        *,
        case_id: str,
        run_id: str,
        records: Mapping[str, RawRecord],
        valid_physical_ids: frozenset[str] | None = None,
    ) -> None:
        self._case_id = _require_non_blank_str(case_id, "case_id")
        self._run_id = _require_non_blank_str(run_id, "run_id")
        self._records: dict[str, RawRecord] = {
            pid: _clone_record(rec) for pid, rec in records.items()
        }
        self._valid_physical_ids = valid_physical_ids

    @property
    def case_id(self) -> str:
        return self._case_id

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def valid_physical_ids(self) -> frozenset[str] | None:
        return self._valid_physical_ids

    def __len__(self) -> int:
        return len(self._records)

    def __contains__(self, physical_record_id: object) -> bool:
        if not isinstance(physical_record_id, str):
            return False
        return physical_record_id in self._records

    def __iter__(self) -> Iterator[RawRecord]:
        for record in self._records.values():
            yield _clone_record(record)

    def iter_records(self) -> Iterator[RawRecord]:
        """Return a fresh replayable iterator over isolated RawRecord copies."""
        return iter(self)

    def records(self) -> list[RawRecord]:
        """Return a list of deep-isolated RawRecord copies in ingestion order."""
        return list(self)

    def physical_ids(self) -> list[str]:
        """Return ingested physical_record_ids in ingestion order."""
        return list(self._records.keys())

    def physical_id_frozenset(self) -> frozenset[str]:
        """Return an immutable frozenset of all ingested physical_record_ids."""
        return frozenset(self._records.keys())

    def get(self, physical_record_id: str) -> RawRecord | None:
        """Retrieve a deep-isolated RawRecord by physical_record_id, or None if missing."""
        pid = _require_non_blank_str(physical_record_id, "physical_record_id")
        rec = self._records.get(pid)
        return _clone_record(rec) if rec is not None else None

    def get_by_raw_id(self, raw_id: str) -> RawRecord | None:
        """Retrieve a deep-isolated RawRecord by raw_id (bound 1:1 to physical_record_id)."""
        rid = _require_non_blank_str(raw_id, "raw_id")
        return self.get(rid)

    def get_locator(self, physical_record_id: str) -> Locator | None:
        """Return the Locator for a stored physical_record_id, or None."""
        pid = _require_non_blank_str(physical_record_id, "physical_record_id")
        rec = self._records.get(pid)
        return rec.locator if rec is not None else None

    def fetch_raw_evidence(
        self, physical_ids: Sequence[str]
    ) -> tuple[list[RawRecord], list[str]]:
        """Lookup physical_ids preserving first-seen deduplicated order.

        Returns `(found_records, missing_ids)` with deep-isolated `RawRecord` copies.
        """
        if physical_ids is None or isinstance(
            physical_ids, (str, bytes, bytearray, Mapping)
        ):
            raise InvalidArgumentError(
                "physical_ids must be a sequence/iterable of physical_record_id strings.",
                details={"type": type(physical_ids).__name__},
            )
        try:
            iterator = iter(physical_ids)
        except TypeError as exc:
            raise InvalidArgumentError(
                "physical_ids must be iterable.",
                details={"type": type(physical_ids).__name__},
            ) from exc

        seen: set[str] = set()
        found: list[RawRecord] = []
        missing: list[str] = []

        for pid in iterator:
            _require_non_blank_str(pid, "physical_ids item")
            if pid in seen:
                continue
            seen.add(pid)
            rec = self._records.get(pid)
            if rec is not None:
                found.append(_clone_record(rec))
            else:
                missing.append(pid)

        return found, missing

    def summary(self) -> dict[str, Any]:
        """Return concise metadata summary for diagnostics and investigation ledgers."""
        return {
            "case_id": self._case_id,
            "run_id": self._run_id,
            "record_count": len(self._records),
            "has_scope_filter": self._valid_physical_ids is not None,
        }


def ingest_records(
    records: Iterable[tuple[str, dict[str, Any]]],
    *,
    case_id: str | None,
    run_id: str,
    locator_map: Mapping[str, Locator] | None = None,
    valid_physical_ids: AbstractSet[str] | None = None,
) -> RawEvidenceStore:
    """Consume an input `(physical_record_id, payload)` stream in a single pass.

    Builds an immutable, replayable `RawEvidenceStore` binding `raw_id == physical_record_id`.
    """
    if case_id is not None:
        _require_non_blank_str(case_id, "case_id")
    _require_non_blank_str(run_id, "run_id")

    if records is None or isinstance(records, (str, bytes, bytearray, Mapping)):
        raise InvalidArgumentError(
            "records must be an iterable of (physical_record_id, payload) pairs.",
            details={"type": type(records).__name__},
        )
    try:
        iterator = iter(records)
    except TypeError as exc:
        raise InvalidArgumentError(
            "records must be iterable.",
            details={"type": type(records).__name__},
        ) from exc

    loc_copy: dict[str, Locator] | None = None
    if locator_map is not None:
        if not isinstance(locator_map, Mapping):
            raise InvalidArgumentError(
                "locator_map must be a Mapping of physical_record_id -> Locator.",
                details={"type": type(locator_map).__name__},
            )
        loc_copy = {}
        for k, v in locator_map.items():
            _require_non_blank_str(k, "locator_map key")
            if not isinstance(v, Locator):
                raise InvalidArgumentError(
                    "locator_map values must be Locator instances.",
                    details={"key": k, "value_type": type(v).__name__},
                )
            loc_copy[k] = v

    scoped_ids: frozenset[str] | None = None
    if valid_physical_ids is not None:
        if isinstance(valid_physical_ids, (str, bytes, bytearray, Mapping)):
            raise InvalidArgumentError(
                "valid_physical_ids must be a set/iterable of non-blank strings.",
                details={"type": type(valid_physical_ids).__name__},
            )
        try:
            valid_iter = iter(valid_physical_ids)
        except TypeError as exc:
            raise InvalidArgumentError(
                "valid_physical_ids must be iterable.",
                details={"type": type(valid_physical_ids).__name__},
            ) from exc
        cleaned_ids: list[str] = []
        for item in valid_iter:
            cleaned_ids.append(_require_non_blank_str(item, "valid_physical_ids item"))
        scoped_ids = frozenset(cleaned_ids)

    stored: dict[str, RawRecord] = {}
    for idx, item in enumerate(iterator):
        if (
            not isinstance(item, Sequence)
            or isinstance(item, (str, bytes, bytearray, Mapping))
            or len(item) != 2
        ):
            raise InvalidArgumentError(
                "Each record must be a 2-tuple of (physical_record_id, payload).",
                details={"record_index": idx, "item_type": type(item).__name__},
            )

        pid, payload = item
        _require_non_blank_str(pid, "physical_record_id")
        if not isinstance(payload, Mapping):
            raise InvalidArgumentError(
                "Record payload must be a Mapping.",
                details={
                    "physical_record_id": pid,
                    "record_index": idx,
                    "payload_type": type(payload).__name__,
                },
            )

        if scoped_ids is not None and pid not in scoped_ids:
            raise OutOfScopeError(
                f"physical_record_id {pid!r} is outside valid_physical_ids scope.",
                details={
                    "case_id": case_id,
                    "run_id": run_id,
                    "physical_record_id": pid,
                },
            )

        if pid in stored:
            raise InvalidArgumentError(
                f"Duplicate physical_record_id encountered: {pid!r}.",
                details={"physical_record_id": pid, "record_index": idx},
            )

        locator = loc_copy.get(pid) if loc_copy is not None else None
        payload_dict = copy.deepcopy(dict(payload))
        digest = _compute_payload_digest(payload_dict)

        stored[pid] = RawRecord(
            physical_record_id=pid,
            payload=payload_dict,
            locator=locator,
            raw_id=pid,
            source_hint=locator.filepath if locator is not None else None,
            content_digest=digest,
        )

    if case_id is None:
        identity = [
            (pid, rec.content_digest, rec.locator.model_dump() if rec.locator else None)
            for pid, rec in sorted(stored.items())
        ]
        case_id = "case-" + hashlib.sha256(orjson.dumps(identity)).hexdigest()

    return RawEvidenceStore(
        case_id=case_id,
        run_id=run_id,
        records=stored,
        valid_physical_ids=scoped_ids,
    )


def detect_indexed_log_format(filepath: str | Path) -> IndexedLogFormat:
    """Classify an indexed log file into one of the 4 Label_Index extraction formats."""
    path = Path(filepath)
    suffix = path.suffix.lower()
    name = path.name.lower()

    if suffix == ".xml":
        return "winxml"
    if suffix in JSONL_EXTENSIONS:
        return "jsonl"
    if (
        "bash_history" in name
        or name == ".bash_history"
        or any("bash_history" in part.lower() for part in path.parts)
    ):
        return "bash_history"
    return "text"


def _resolve_indexed_filepath(filepath: Any, data_dir: Path | None) -> Path | None:
    """Validate a Label_Index filepath and optionally resolve it safely inside data_dir."""
    if not isinstance(filepath, str) or not filepath.strip():
        raise InvalidArgumentError(
            "Label_Index entry filepath must be a non-blank string.",
            details={"filepath": filepath},
        )
    if "\x00" in filepath:
        raise OutOfScopeError(
            "Null byte is forbidden in Label_Index filepath.",
            details={"filepath": filepath},
        )
    if "\\" in filepath:
        raise OutOfScopeError(
            "Backslash path separator is forbidden in Label_Index filepath.",
            details={"filepath": filepath},
        )
    if (
        filepath.startswith("/")
        or Path(filepath).is_absolute()
        or bool(PureWindowsPath(filepath).drive)
    ):
        raise OutOfScopeError(
            "Absolute paths and drive prefixes are forbidden in Label_Index filepath.",
            details={"filepath": filepath},
        )

    segments = filepath.split("/")
    if ".." in segments:
        raise OutOfScopeError(
            "Path traversal '..' is forbidden in Label_Index filepath.",
            details={"filepath": filepath},
        )
    if "" in segments:
        raise InvalidArgumentError(
            "Label_Index filepath contains empty path segments.",
            details={"filepath": filepath},
        )

    rel = filepath[5:] if filepath.startswith("data/") else filepath
    if not rel or rel in (".", "./"):
        raise InvalidArgumentError(
            "Label_Index filepath does not point to a file inside data_dir.",
            details={"filepath": filepath},
        )

    if data_dir is None:
        return None

    data_root = Path(data_dir).resolve()
    target = (data_root / rel).resolve()
    if not target.is_relative_to(data_root) or target == data_root:
        raise OutOfScopeError(
            "Resolved Label_Index filepath escapes data_dir.",
            details={
                "filepath": filepath,
                "resolved": str(target),
                "data_dir": str(data_root),
            },
        )
    return target


def load_label_index(
    index_path: Path | str,
    *,
    data_dir: Path | str | None = None,
) -> dict[str, Locator]:
    """Load and strictly validate a `Label_Index.json` file into `pid -> Locator`."""
    index, _ = _load_label_index(index_path, data_dir)
    return index


def _load_label_index(
    index_path: Path | str, data_dir: Path | str | None,
) -> tuple[dict[str, Locator], dict[str, Path | None]]:
    if not isinstance(index_path, (str, Path)):
        raise InvalidArgumentError(
            "index_path must be a str or Path.",
            details={"type": type(index_path).__name__},
        )
    idx_file = Path(index_path)
    if not idx_file.is_file():
        raise InvalidArgumentError(
            f"Label_Index file does not exist: {idx_file}",
            details={"index_path": str(idx_file)},
        )

    resolved_data_dir: Path | None = None
    if data_dir is not None:
        if not isinstance(data_dir, (str, Path)):
            raise InvalidArgumentError(
                "data_dir must be a str or Path.",
                details={"type": type(data_dir).__name__},
            )
        resolved_data_dir = Path(data_dir)
        if not resolved_data_dir.is_dir():
            raise InvalidArgumentError(
                f"data_dir is not an existing directory: {resolved_data_dir}",
                details={"data_dir": str(resolved_data_dir)},
            )

    try:
        raw_text = idx_file.read_text(encoding="utf-8")
        raw_index = json.loads(raw_text)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidArgumentError(
            f"Failed to read or parse Label_Index JSON: {exc}",
            details={"index_path": str(idx_file), "reason": str(exc)},
        ) from exc

    if not isinstance(raw_index, dict):
        raise InvalidArgumentError(
            "Label_Index root must be a JSON object.",
            details={"index_path": str(idx_file), "root_type": type(raw_index).__name__},
        )

    result: dict[str, Locator] = {}
    resolved_paths: dict[str, Path | None] = {}
    for pid, entry in raw_index.items():
        if not isinstance(pid, str) or not PR_ID_PATTERN.fullmatch(pid):
            raise InvalidArgumentError(
                f"Invalid physical record ID in Label_Index: {pid!r}",
                details={"physical_record_id": pid},
            )
        if not isinstance(entry, dict) or "filepath" not in entry or "linenumber" not in entry:
            raise InvalidArgumentError(
                f"Label_Index entry for {pid!r} must be an object with 'filepath' and 'linenumber'.",
                details={"physical_record_id": pid},
            )
        ln = entry["linenumber"]
        if isinstance(ln, bool) or not isinstance(ln, int) or ln < 1:
            raise InvalidArgumentError(
                f"Label_Index linenumber for {pid!r} must be an integer >= 1 (booleans rejected).",
                details={"physical_record_id": pid, "linenumber": ln},
            )

        filepath = entry["filepath"]
        # Many index rows refer to the same file. Resolve it once per load.
        if not isinstance(filepath, str) or filepath not in resolved_paths:
            resolved_paths[filepath] = _resolve_indexed_filepath(filepath, resolved_data_dir)
        result[pid] = Locator(filepath=filepath, linenumber=ln)

    return result, resolved_paths


def _read_jsonl_records(
    file_path: Path,
    *,
    logical_filepath: str,
    strict_json: bool,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    try:
        with file_path.open("r", encoding="utf-8") as fh:
            for line_no, raw_line in enumerate(fh, 1):
                text = raw_line.rstrip("\r\n")
                if not text.strip():
                    records.append({"raw_text": text})
                    continue
                try:
                    parsed = orjson.loads(text)
                except (orjson.JSONDecodeError, ValueError) as exc:
                    if strict_json:
                        raise InvalidArgumentError(
                            f"Malformed JSON at {logical_filepath}:{line_no}: {exc}",
                            details={
                                "filepath": logical_filepath,
                                "linenumber": line_no,
                                "reason": str(exc),
                            },
                        ) from exc
                    records.append({"raw_text": text, "parse_error": str(exc)})
                    continue

                if isinstance(parsed, dict):
                    records.append(parsed)
                else:
                    records.append({"raw_text": text, "json_value": parsed})
    except (OSError, UnicodeDecodeError) as exc:
        raise InvalidArgumentError(
            f"Failed to read JSONL file {logical_filepath}: {exc}",
            details={"filepath": logical_filepath, "reason": str(exc)},
        ) from exc
    return records


def _find_xml_tag_end(content: str, start: int) -> int:
    quote: str | None = None
    n = len(content)
    i = start
    while i < n:
        ch = content[i]
        if quote is not None:
            if ch == quote:
                quote = None
        else:
            if ch in ('"', "'"):
                quote = ch
            elif ch == ">":
                return i
        i += 1
    return -1


def _extract_winxml_events(content: str) -> list[str]:
    events: list[str] = []
    n = len(content)
    pos = 0
    while pos < n:
        next_lt = content.find("<", pos)
        if next_lt == -1:
            break
        if content.startswith("<!--", next_lt):
            end_comment = content.find("-->", next_lt + 4)
            if end_comment == -1:
                break
            pos = end_comment + 3
            continue
        if content.startswith("<![CDATA[", next_lt):
            end_cdata = content.find("]]>", next_lt + 9)
            if end_cdata == -1:
                break
            pos = end_cdata + 3
            continue
        if content.startswith("<Event", next_lt):
            after_idx = next_lt + 6
            if after_idx < n and (content[after_idx] == ">" or content[after_idx].isspace()):
                tag_end = _find_xml_tag_end(content, after_idx)
                if tag_end == -1:
                    break
                if content[tag_end - 1] == "/":
                    pos = tag_end + 1
                    continue
                inner_pos = tag_end + 1
                found_close = False
                while inner_pos < n:
                    inner_lt = content.find("<", inner_pos)
                    if inner_lt == -1:
                        break
                    if content.startswith("<!--", inner_lt):
                        end_c = content.find("-->", inner_lt + 4)
                        if end_c == -1:
                            inner_pos = n
                            break
                        inner_pos = end_c + 3
                        continue
                    if content.startswith("<![CDATA[", inner_lt):
                        end_cd = content.find("]]>", inner_lt + 9)
                        if end_cd == -1:
                            inner_pos = n
                            break
                        inner_pos = end_cd + 3
                        continue
                    if content.startswith("</Event>", inner_lt):
                        events.append(content[next_lt : inner_lt + 8])
                        pos = inner_lt + 8
                        found_close = True
                        break
                    if content.startswith("</Event", inner_lt):
                        close_after = inner_lt + 7
                        while close_after < n and content[close_after].isspace():
                            close_after += 1
                        if close_after < n and content[close_after] == ">":
                            events.append(content[next_lt : close_after + 1])
                            pos = close_after + 1
                            found_close = True
                            break
                    inner_pos = inner_lt + 1
                if not found_close:
                    break
                continue
        pos = next_lt + 1
    return events


def _read_winxml_records(
    file_path: Path,
    *,
    logical_filepath: str,
) -> list[dict[str, Any]]:
    try:
        content = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise InvalidArgumentError(
            f"Failed to read XML file {logical_filepath}: {exc}",
            details={"filepath": logical_filepath, "reason": str(exc)},
        ) from exc

    return [{"raw_text": event_xml} for event_xml in _extract_winxml_events(content)]


def _trim_blank_edges(lines: list[str]) -> list[str]:
    start = 0
    end = len(lines)
    while start < end and not lines[start].strip():
        start += 1
    while end > start and not lines[end - 1].strip():
        end -= 1
    return lines[start:end]


def _read_bash_history_records(
    file_path: Path,
    *,
    logical_filepath: str,
) -> list[dict[str, Any]]:
    try:
        raw_lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise InvalidArgumentError(
            f"Failed to read bash_history file {logical_filepath}: {exc}",
            details={"filepath": logical_filepath, "reason": str(exc)},
        ) from exc

    has_markers = any(BASH_EPOCH_RE.match(line.rstrip()) is not None for line in raw_lines)
    if not has_markers:
        return [
            {"raw_text": line, "timestamp": None}
            for line in raw_lines
            if line.strip()
        ]

    preamble: list[str] = []
    groups: list[tuple[int, list[str]]] = []
    current_epoch: int | None = None
    current_lines: list[str] = []

    for line in raw_lines:
        marker = BASH_EPOCH_RE.match(line.rstrip())
        if marker is not None:
            if current_epoch is not None:
                groups.append((current_epoch, current_lines))
            current_epoch = int(marker.group(1))
            current_lines = []
        elif current_epoch is None:
            if line.strip():
                preamble.append(line)
        else:
            current_lines.append(line)

    if current_epoch is not None:
        groups.append((current_epoch, current_lines))

    records: list[dict[str, Any]] = []
    for idx, (epoch, cmd_lines) in enumerate(groups):
        combined = (preamble + cmd_lines) if idx == 0 else cmd_lines
        trimmed = _trim_blank_edges(combined)
        records.append({"raw_text": "\n".join(trimmed), "timestamp": epoch})
    return records


def _read_text_records(
    file_path: Path,
    *,
    logical_filepath: str,
) -> list[dict[str, Any]]:
    try:
        with file_path.open("r", encoding="utf-8", errors="replace") as fh:
            return [{"raw_text": raw_line.rstrip("\r\n")} for raw_line in fh]
    except (OSError, UnicodeDecodeError) as exc:
        raise InvalidArgumentError(
            f"Failed to read text log file {logical_filepath}: {exc}",
            details={"filepath": logical_filepath, "reason": str(exc)},
        ) from exc


def _load_file_records(
    resolved_path: Path,
    *,
    logical_filepath: str,
    strict_json: bool,
) -> list[dict[str, Any]]:
    if not resolved_path.is_file():
        raise InvalidArgumentError(
            f"Indexed log file does not exist: {logical_filepath}",
            details={"filepath": logical_filepath, "resolved": str(resolved_path)},
        )

    fmt = detect_indexed_log_format(logical_filepath)
    if fmt == "jsonl":
        return _read_jsonl_records(
            resolved_path, logical_filepath=logical_filepath, strict_json=strict_json
        )
    if fmt == "winxml":
        return _read_winxml_records(resolved_path, logical_filepath=logical_filepath)
    if fmt == "bash_history":
        return _read_bash_history_records(resolved_path, logical_filepath=logical_filepath)
    return _read_text_records(resolved_path, logical_filepath=logical_filepath)


def load_indexed_records(
    index_path: Path | str,
    data_dir: Path | str,
    *,
    strict_json: bool = True,
) -> Iterator[tuple[str, dict[str, Any]]]:
    """Validate `Label_Index.json` and yield `(physical_record_id, payload)` in index order."""
    index_map, resolved_paths = _load_label_index(index_path, data_dir)

    def _iter_records() -> Iterator[tuple[str, dict[str, Any]]]:
        file_cache: dict[Path, list[dict[str, Any]]] = {}
        for pid, locator in index_map.items():
            target = resolved_paths[locator.filepath]
            assert target is not None
            if target not in file_cache:
                file_cache[target] = _load_file_records(
                    target,
                    logical_filepath=locator.filepath,
                    strict_json=strict_json,
                )
            entries = file_cache[target]
            if locator.linenumber > len(entries):
                raise InvalidArgumentError(
                    f"linenumber {locator.linenumber} out of range (1..{len(entries)}) "
                    f"for {locator.filepath}",
                    details={
                        "physical_record_id": pid,
                        "filepath": locator.filepath,
                        "linenumber": locator.linenumber,
                        "record_count": len(entries),
                    },
                )
            yield (pid, copy.deepcopy(entries[locator.linenumber - 1]))

    return _iter_records()


__all__ = [
    "BASH_EPOCH_RE",
    "IndexedLogFormat",
    "PR_ID_PATTERN",
    "RawEvidenceStore",
    "XML_COMMENT_OR_EVENT_RE",
    "detect_indexed_log_format",
    "ingest_records",
    "load_indexed_records",
    "load_label_index",
]
