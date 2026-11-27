"""Common utilities: deterministic IDs, UTC timestamps, file discovery, and JSONL I/O."""

from __future__ import annotations

import argparse
import hashlib
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Sequence

import orjson
from dateutil import parser as dateutil_parser


def make_raw_id(case_id: str, source_file: str, locator: str | int) -> str:
    """Return a deterministic raw_id for reproducible case replay."""
    payload = f"{case_id}|{source_file}|{locator}".encode("utf-8")
    return "raw_" + hashlib.sha256(payload).hexdigest()[:16]


def make_event_id(raw_id: str, sub_index: int = 0) -> str:
    """Return a deterministic event_id linked to raw_id."""
    payload = f"{raw_id}|{sub_index}".encode("utf-8")
    return "evt_" + hashlib.sha256(payload).hexdigest()[:16]


def epoch_to_utc_iso(epoch_seconds: float | int) -> str:
    """Convert Unix epoch seconds to RFC3339/ISO-8601 UTC string with microsecond precision."""
    dt = datetime.fromtimestamp(float(epoch_seconds), tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def epoch_ms_to_utc_iso(epoch_ms: int | float) -> str:
    """Convert Unix epoch milliseconds to RFC3339/ISO-8601 UTC string."""
    return epoch_to_utc_iso(float(epoch_ms) / 1000.0)


def normalize_iso_utc(ts_str: str) -> str:
    """Parse an ISO-8601 / RFC3339 timestamp string (including 7-digit Windows ticks) to UTC ISO-8601."""
    if not ts_str:
        return ""
    s = ts_str.strip()
    # Handle Windows 7-digit fractional seconds cleanly (truncate to 6 digits for Python datetime)
    if "." in s:
        head, rest = s.split(".", 1)
        frac_chars = []
        tz_part = ""
        for idx, ch in enumerate(rest):
            if ch.isdigit():
                frac_chars.append(ch)
            else:
                tz_part = rest[idx:]
                break
        frac = "".join(frac_chars)[:6].ljust(6, "0")
        s = f"{head}.{frac}{tz_part}"
    dt = dateutil_parser.isoparse(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def clf_time_to_utc_iso(clf_ts: str) -> str:
    """Parse Apache/Nginx CLF timestamp like '29/May/2024:16:07:18 +0000' into UTC ISO-8601."""
    dt = datetime.strptime(clf_ts.strip(), "%d/%b/%Y:%H:%M:%S %z")
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def is_ignored_file(path: Path) -> bool:
    """Skip NTFS Zone.Identifier ADS artifacts and hidden metadata files."""
    name = path.name
    return name.endswith(":Zone.Identifier") or name.startswith(".")


def collect_input_files(
    inputs: Sequence[str | Path],
    matcher: Callable[[Path], bool],
) -> list[Path]:
    """Resolve files or directories into a sorted list of matching input files."""
    resolved: list[Path] = []
    for item in inputs:
        p = Path(item)
        if not p.exists():
            raise FileNotFoundError(f"Input path does not exist: {p}")
        if p.is_file():
            if not is_ignored_file(p):
                resolved.append(p)
        elif p.is_dir():
            for child in sorted(p.iterdir()):
                if child.is_file() and not is_ignored_file(child) and matcher(child):
                    resolved.append(child)
    if not resolved:
        raise FileNotFoundError(f"No matching log files found in: {', '.join(str(x) for x in inputs)}")
    return resolved


def write_jsonl(
    records: Iterable[dict[str, Any]],
    output_path: str | Path,
    *,
    sort_by_timestamp: bool = False,
    timestamp_key: str = "@timestamp",
) -> int:
    """Serialize records as newline-delimited JSON using orjson."""
    if sort_by_timestamp:
        buf = list(records)
        buf.sort(key=lambda r: (r.get(timestamp_key) is None, str(r.get(timestamp_key) or ""), str(r.get("event_id") or "")))
        records = buf

    count = 0
    if str(output_path) == "-":
        out_stream = sys.stdout.buffer
        for rec in records:
            out_stream.write(orjson.dumps(rec) + b"\n")
            count += 1
        out_stream.flush()
    else:
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with out_file.open("wb") as fh:
            for rec in records:
                fh.write(orjson.dumps(rec) + b"\n")
                count += 1
    return count


def write_json_array(
    records: Iterable[dict[str, Any]],
    output_path: str | Path,
) -> int:
    """Stream-serialize records as a JSON array ([...]) using orjson (required by Chainsaw kind: json)."""
    count = 0
    if str(output_path) == "-":
        out_stream = sys.stdout.buffer
        out_stream.write(b"[\n")
        for rec in records:
            if count > 0:
                out_stream.write(b",\n")
            out_stream.write(orjson.dumps(rec))
            count += 1
        out_stream.write(b"\n]\n")
        out_stream.flush()
    else:
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with out_file.open("wb") as fh:
            fh.write(b"[\n")
            for rec in records:
                if count > 0:
                    fh.write(b",\n")
                fh.write(orjson.dumps(rec))
                count += 1
            fh.write(b"\n]\n")
    return count


def build_base_parser(description: str, *, allow_no_sort: bool = False, allow_user: bool = False, allow_index_out: bool = False) -> argparse.ArgumentParser:
    """Create a consistent CLI ArgumentParser for all conversion scripts."""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "-i",
        "--input",
        nargs="+",
        required=True,
        help="Input log file(s) or directory containing matching log files.",
    )
    parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="Output JSONL/NDJSON file path, or '-' for stdout.",
    )
    parser.add_argument(
        "--case-id",
        default="default",
        help="Case identifier used to generate deterministic raw_id/event_id (default: default).",
    )
    if allow_no_sort:
        parser.add_argument(
            "--no-sort",
            action="store_true",
            help="Disable chronological UTC sorting (sorting is enabled by default for RSigma correlations).",
        )
    if allow_user:
        parser.add_argument(
            "--user",
            default=None,
            help="Override username instead of inferring it from the bash_history filename.",
        )
    if allow_index_out:
        parser.add_argument(
            "--index-out",
            default=None,
            help="Optional JSONL path to write (Computer, Channel, EventRecordID) -> event_id reverse-lookup index.",
        )
    return parser
