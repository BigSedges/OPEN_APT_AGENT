"""Pure-stdlib E2E test helpers for OPEN_APT_AGENT.

Provides:
- ``load_indexed_records``: Exact ``Label_Index.json`` multi-format record extraction.
- ``assert_valid_prediction``: Strict ``Prediction`` export invariant checks.
- ``build_fake_engine_bins``: Executable cross-platform fake CLI binaries for
  ``zircolite``, ``hayabusa``, ``takajo``, ``rsigma``, and ``chainsaw``.

Kept pure stdlib so tests/e2e can be imported and validated independently of
``apt_agent`` or ``pytest``.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

_TS_MARKER_RE = re.compile(r"^#(\d+)\s*$")
_WINXML_EVENT_RE = re.compile(r"<Event\b[^>]*>.*?</Event>", re.DOTALL)
_TA_KEY_RE = re.compile(r"TA[0-9]{4}")
_JSONL_SUFFIXES = {".json", ".jsonl", ".ndjson"}


def _split_physical_lines(normalized_text: str) -> list[str]:
    if not normalized_text:
        return []
    if normalized_text.endswith("\n"):
        return normalized_text[:-1].split("\n")
    return normalized_text.split("\n")


def _resolve_log_path(data_root: Path, filepath: Any) -> Path:
    if not isinstance(filepath, str) or not filepath.strip():
        raise ValueError(f"Invalid filepath in Label_Index.json: {filepath!r}")
    if "\x00" in filepath:
        raise ValueError(f"Null byte in filepath: {filepath!r}")
    norm = filepath.replace("\\", "/")
    if norm.startswith("/") or Path(filepath).is_absolute() or Path(norm).is_absolute():
        raise ValueError(f"Absolute filepath not allowed in Label_Index.json: {filepath!r}")
    if len(norm) >= 2 and norm[1] == ":" and norm[0].isalpha():
        raise ValueError(f"Drive-prefixed filepath not allowed in Label_Index.json: {filepath!r}")

    rel = norm[5:] if norm.startswith("data/") else norm
    if not rel or rel.startswith("/") or Path(rel).is_absolute():
        raise ValueError(f"Invalid relative filepath in Label_Index.json: {filepath!r}")

    resolved = (data_root / rel).resolve()
    if not resolved.is_relative_to(data_root):
        raise ValueError(f"Path traversal outside data root rejected: {filepath!r}")
    if not resolved.is_file():
        raise FileNotFoundError(f"Indexed log file does not exist: {resolved}")
    return resolved


def _parse_bash_history_records(normalized_text: str) -> list[dict[str, Any]]:
    lines = _split_physical_lines(normalized_text)
    has_markers = any(_TS_MARKER_RE.match(ln) for ln in lines)
    if not has_markers:
        return [{"raw_text": ln, "timestamp": None} for ln in lines if ln != ""]

    groups: list[tuple[int, list[str]]] = []
    pre_marker: list[str] = []
    cur_ts: int | None = None
    cur_lines: list[str] = []
    first_group = True

    for ln in lines:
        match = _TS_MARKER_RE.match(ln)
        if match is not None:
            if cur_ts is not None:
                groups.append((cur_ts, cur_lines))
            cur_ts = int(match.group(1))
            if first_group:
                cur_lines = list(pre_marker)
                first_group = False
            else:
                cur_lines = []
        else:
            if cur_ts is None:
                if ln != "":
                    pre_marker.append(ln)
            else:
                cur_lines.append(ln)

    if cur_ts is not None:
        groups.append((cur_ts, cur_lines))

    records: list[dict[str, Any]] = []
    for ts, glines in groups:
        trimmed = list(glines)
        while trimmed and trimmed[-1] == "":
            trimmed.pop()
        records.append({"raw_text": "\n".join(trimmed), "timestamp": ts})
    return records


def _parse_file_records(resolved: Path) -> list[dict[str, Any]]:
    raw_text = resolved.read_text(encoding="utf-8-sig")
    normalized_text = raw_text.replace("\r\n", "\n").replace("\r", "\n")
    suffix = resolved.suffix.lower()

    if suffix in _JSONL_SUFFIXES:
        records: list[dict[str, Any]] = []
        for line_no, line in enumerate(_split_physical_lines(normalized_text), start=1):
            if line.strip() == "":
                records.append({"raw_text": line})
            else:
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"Invalid JSON in {resolved}:{line_no}: {exc}"
                    ) from exc
                if isinstance(obj, dict):
                    records.append(obj)
                else:
                    records.append({"raw_text": line, "value": obj})
        return records

    if suffix == ".xml":
        return [
            {"raw_text": match.group(0)}
            for match in _WINXML_EVENT_RE.finditer(normalized_text)
        ]

    if suffix == ".bash_history" or resolved.parent.name == "bash_history":
        return _parse_bash_history_records(normalized_text)

    return [{"raw_text": line} for line in _split_physical_lines(normalized_text)]


def load_indexed_records(
    scene_dir: Path,
) -> tuple[dict[str, dict[str, Any]], list[tuple[str, dict[str, Any]]]]:
    """Load ``Label_Index.json`` and extract ordered ``(physical_id, payload)`` pairs."""
    scene_root = Path(scene_dir).resolve()
    index_path = scene_root / "Label_Index.json"
    if not index_path.is_file():
        raise FileNotFoundError(f"Label_Index.json not found in {scene_root}")

    index = json.loads(index_path.read_text(encoding="utf-8-sig"))
    if not isinstance(index, dict):
        raise ValueError(f"Label_Index.json must be a JSON object, got {type(index).__name__}")

    data_candidate = (scene_root / "data").resolve()
    data_root = data_candidate if data_candidate.is_dir() else scene_root

    file_cache: dict[Path, list[dict[str, Any]]] = {}
    records: list[tuple[str, dict[str, Any]]] = []

    for pid, meta in index.items():
        if not isinstance(pid, str) or not pid.startswith("pr-"):
            raise ValueError(f"Invalid physical record id in Label_Index.json: {pid!r}")
        if not isinstance(meta, dict):
            raise ValueError(f"Index entry for {pid!r} must be a dict, got {type(meta).__name__}")
        if "filepath" not in meta or "linenumber" not in meta:
            raise ValueError(f"Index entry for {pid!r} missing 'filepath' or 'linenumber'")

        linenumber = meta["linenumber"]
        if type(linenumber) is not int or linenumber < 1:
            raise ValueError(
                f"Invalid linenumber for {pid!r}: {linenumber!r} (must be positive int, not bool)"
            )

        resolved = _resolve_log_path(data_root, meta["filepath"])
        if resolved not in file_cache:
            file_cache[resolved] = _parse_file_records(resolved)
        file_records = file_cache[resolved]

        if linenumber > len(file_records):
            raise ValueError(
                f"linenumber {linenumber} out of range (1..{len(file_records)}) "
                f"for {pid!r} in {meta['filepath']!r}"
            )
        records.append((pid, dict(file_records[linenumber - 1])))

    return index, records


def assert_valid_prediction(
    pred: dict[str, Any],
    valid_physical_ids: set[str] | None = None,
) -> None:
    """Assert all competition export invariants on a Prediction dictionary."""
    assert isinstance(pred, dict), f"Prediction must be a dict, got {type(pred).__name__}"
    assert set(pred.keys()) == {"physical_id_set", "ta_physical_ids"}, (
        "Prediction must have exactly {'physical_id_set', 'ta_physical_ids'}, "
        f"got {sorted(pred.keys())!r}"
    )

    pids = pred["physical_id_set"]
    assert isinstance(pids, list), f"physical_id_set must be a list, got {type(pids).__name__}"
    assert all(isinstance(x, str) and x.strip() != "" for x in pids), (
        f"physical_id_set must contain non-empty strings, got {pids!r}"
    )
    assert len(pids) == len(set(pids)), f"physical_id_set contains duplicates: {pids!r}"
    assert pids == sorted(pids), f"physical_id_set must be sorted: {pids!r}"

    ta_map = pred["ta_physical_ids"]
    assert isinstance(ta_map, dict), f"ta_physical_ids must be a dict, got {type(ta_map).__name__}"
    for ta, items in ta_map.items():
        assert isinstance(ta, str) and _TA_KEY_RE.fullmatch(ta), (
            f"Illegal tactic key {ta!r}; must match ^TA\\d{{4}}$"
        )
        assert isinstance(items, list), (
            f"ta_physical_ids[{ta!r}] must be a list, got {type(items).__name__}"
        )
        assert 1 <= len(items) <= 3, (
            f"ta_physical_ids[{ta!r}] must have 1..3 items, got {len(items)}: {items!r}"
        )
        assert all(isinstance(x, str) and x.strip() != "" for x in items), (
            f"ta_physical_ids[{ta!r}] must contain non-empty strings, got {items!r}"
        )
        assert len(items) == len(set(items)), (
            f"ta_physical_ids[{ta!r}] contains duplicates: {items!r}"
        )

    ta_union = {x for items in ta_map.values() for x in items}
    assert ta_union <= set(pids), (
        f"Subset invariant violated: {sorted(ta_union - set(pids))!r} not in physical_id_set"
    )

    if valid_physical_ids is not None:
        assert set(pids) <= valid_physical_ids, (
            f"physical_id_set contains unknown IDs: {sorted(set(pids) - valid_physical_ids)!r}"
        )
        assert ta_union <= valid_physical_ids, (
            f"ta_physical_ids contains unknown IDs: {sorted(ta_union - valid_physical_ids)!r}"
        )


_SHARED_FAKE_ENGINE_PRELUDE = r'''
import argparse
import csv
import datetime as _dt
import json
import os
import re
import sys
import time
from pathlib import Path

try:
    import yaml as _pyyaml
except Exception:
    _pyyaml = None


def _resolve_mode(engine: str, default_mode: str) -> str:
    fail_list = [
        x.strip().lower()
        for x in os.environ.get("APT_FAKE_ENGINE_FAIL", "").split(",")
        if x.strip()
    ]
    if engine.lower() in fail_list or "all" in fail_list:
        return "crash"
    return os.environ.get(f"FAKE_{engine.upper()}_MODE", default_mode).strip().lower()


def _handle_crash_or_timeout(engine: str, mode: str, default_sleep_s: float) -> None:
    if mode == "crash":
        sys.stderr.write(f"[fake-{engine}] simulated crash\n")
        exit_code = int(os.environ.get(f"FAKE_{engine.upper()}_EXIT_CODE", "2"))
        sys.exit(exit_code)
    if mode == "timeout":
        sleep_s = float(os.environ.get(f"FAKE_{engine.upper()}_SLEEP_S", str(default_sleep_s)))
        time.sleep(sleep_s)
        sys.exit(0)


def _strip_yaml_comment(line: str) -> str:
    in_sq = False
    in_dq = False
    for idx, ch in enumerate(line):
        if ch == "'" and not in_dq:
            in_sq = not in_sq
        elif ch == '"' and not in_sq and (idx == 0 or line[idx - 1] != "\\"):
            in_dq = not in_dq
        elif ch == "#" and not in_sq and not in_dq:
            if idx == 0 or line[idx - 1].isspace():
                return line[:idx].rstrip()
    return line.rstrip()


def _parse_yaml_scalar(raw: str):
    s = raw.strip()
    if s == "" or s in ("null", "Null", "NULL", "~"):
        return None
    if s in ("true", "True", "TRUE"):
        return True
    if s in ("false", "False", "FALSE"):
        return False
    if (s.startswith("'") and s.endswith("'") and len(s) >= 2):
        return s[1:-1].replace("''", "'")
    if (s.startswith('"') and s.endswith('"') and len(s) >= 2):
        inner = s[1:-1]
        _esc = {"\\": "\\", '"': '"', "n": "\n", "t": "\t", "r": "\r"}
        return re.sub(r"\\(.)", lambda m: _esc.get(m.group(1), m.group(0)), inner)
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        if not inner:
            return []
        return [_parse_yaml_scalar(p) for p in _split_inline(inner)]
    if s.startswith("{") and s.endswith("}"):
        inner = s[1:-1].strip()
        if not inner:
            return {}
        out = {}
        for part in _split_inline(inner):
            if ":" not in part:
                raise ValueError(f"Invalid inline mapping entry: {part!r}")
            k, v = part.split(":", 1)
            out[_parse_yaml_scalar(k)] = _parse_yaml_scalar(v)
        return out
    if s.startswith("[") or s.startswith("{"):
        raise ValueError(f"Unclosed YAML bracket in {s!r}")
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    if re.fullmatch(r"-?\d+\.\d+", s):
        return float(s)
    return s


def _split_inline(inner: str) -> list[str]:
    parts: list[str] = []
    cur: list[str] = []
    in_sq = False
    in_dq = False
    depth = 0
    for idx, ch in enumerate(inner):
        if ch == "'" and not in_dq:
            in_sq = not in_sq
        elif ch == '"' and not in_sq and (idx == 0 or inner[idx - 1] != "\\"):
            in_dq = not in_dq
        elif not in_sq and not in_dq:
            if ch in "[{":
                depth += 1
            elif ch in "]}":
                depth -= 1
            elif ch == "," and depth == 0:
                parts.append("".join(cur).strip())
                cur = []
                continue
        cur.append(ch)
    if cur or parts:
        parts.append("".join(cur).strip())
    return parts


def _split_kv(text: str) -> tuple[str, str | None]:
    in_sq = False
    in_dq = False
    for idx, ch in enumerate(text):
        if ch == "'" and not in_dq:
            in_sq = not in_sq
        elif ch == '"' and not in_sq and (idx == 0 or text[idx - 1] != "\\"):
            in_dq = not in_dq
        elif ch == ":" and not in_sq and not in_dq:
            if idx + 1 == len(text) or text[idx + 1].isspace():
                return text[:idx].strip(), text[idx + 1 :].strip()
    return text.strip(), None


def _fallback_yaml_load_doc(text: str):
    tokens: list[tuple[int, str]] = []
    for raw_ln in text.splitlines():
        cleaned = _strip_yaml_comment(raw_ln)
        if not cleaned.strip():
            continue
        indent = len(cleaned) - len(cleaned.lstrip(" "))
        tokens.append((indent, cleaned.lstrip(" ")))
    if not tokens:
        return None

    def parse_block(idx: int, min_indent: int):
        indent0, content0 = tokens[idx]
        if content0 == "-" or content0.startswith("- "):
            arr = []
            while idx < len(tokens):
                ind, cnt = tokens[idx]
                if ind < indent0 or not (cnt == "-" or cnt.startswith("- ")):
                    break
                if ind > indent0:
                    raise ValueError(f"Unexpected indentation in YAML list: {cnt!r}")
                rest = cnt[1:].strip() if cnt.startswith("- ") else ""
                idx += 1
                if not rest:
                    if idx < len(tokens) and tokens[idx][0] > indent0:
                        val, idx = parse_block(idx, indent0 + 1)
                        arr.append(val)
                    else:
                        arr.append(None)
                else:
                    k, v = _split_kv(rest)
                    if v is not None:
                        item = {}
                        key = str(_parse_yaml_scalar(k))
                        if v == "":
                            if idx < len(tokens) and tokens[idx][0] > indent0 + 2:
                                val, idx = parse_block(idx, indent0 + 3)
                                item[key] = val
                            elif idx < len(tokens) and tokens[idx][0] > indent0:
                                val, idx = parse_block(idx, indent0 + 1)
                                item[key] = val
                            else:
                                item[key] = None
                        else:
                            item[key] = _parse_yaml_scalar(v)
                        if idx < len(tokens) and tokens[idx][0] > indent0:
                            extra, idx = parse_block(idx, indent0 + 1)
                            if isinstance(extra, dict):
                                item.update(extra)
                        arr.append(item)
                    else:
                        arr.append(_parse_yaml_scalar(rest))
            return arr, idx

        k0, v0 = _split_kv(content0)
        if v0 is None:
            return _parse_yaml_scalar(content0), idx + 1

        obj = {}
        while idx < len(tokens):
            ind, cnt = tokens[idx]
            if ind < indent0:
                break
            if ind > indent0:
                raise ValueError(f"Unexpected indentation in YAML dict: {cnt!r}")
            if cnt == "-" or cnt.startswith("- "):
                break
            k, v = _split_kv(cnt)
            if v is None:
                raise ValueError(f"Expected key:value in YAML mapping: {cnt!r}")
            key = str(_parse_yaml_scalar(k))
            idx += 1
            if v == "":
                if idx < len(tokens) and tokens[idx][0] > indent0:
                    val, idx = parse_block(idx, indent0 + 1)
                    obj[key] = val
                elif idx < len(tokens) and tokens[idx][0] == indent0 and (
                    tokens[idx][1] == "-" or tokens[idx][1].startswith("- ")
                ):
                    val, idx = parse_block(idx, indent0)
                    obj[key] = val
                else:
                    obj[key] = None
            else:
                obj[key] = _parse_yaml_scalar(v)
        return obj, idx

    val, end_idx = parse_block(0, 0)
    if end_idx != len(tokens):
        raise ValueError(f"Unparsed YAML trailing content at token {tokens[end_idx]!r}")
    return val


def _load_yaml_docs(text: str) -> list:
    if _pyyaml is not None:
        return [d for d in _pyyaml.safe_load_all(text) if d is not None]
    chunks: list[list[str]] = [[]]
    for line in text.splitlines():
        if line.strip() == "---":
            chunks.append([])
        else:
            chunks[-1].append(line)
    docs = []
    for chunk in chunks:
        chunk_text = "\n".join(chunk)
        if not chunk_text.strip():
            continue
        doc = _fallback_yaml_load_doc(chunk_text)
        if doc is not None:
            docs.append(doc)
    return docs


def _load_sigma_rules(path_args: list[str | Path]) -> list[tuple[str, dict]]:
    loaded: list[tuple[str, dict]] = []
    files: list[Path] = []
    for p in path_args:
        if not p:
            continue
        path = Path(p)
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(sorted(path.rglob("*.yml")))
            files.extend(sorted(path.rglob("*.yaml")))
    seen: set[Path] = set()
    for f in files:
        rf = f.resolve()
        if rf in seen:
            continue
        seen.add(rf)
        text = f.read_text(encoding="utf-8-sig")
        for doc in _load_yaml_docs(text):
            if isinstance(doc, dict):
                loaded.append((str(f), doc))
    return loaded


def _lookup_field(ev: dict, field_name: str):
    if not isinstance(ev, dict):
        return []
    containers = [ev]
    for sub in ("EventData", "UserData", "System", "properties", "ExtraFieldInfo", "Details"):
        val = ev.get(sub)
        if isinstance(val, dict):
            containers.append(val)
            if sub == "UserData":
                for nested_k, nested_v in val.items():
                    if nested_k != "#attributes" and isinstance(nested_v, dict):
                        containers.append(nested_v)
    inner_ev = ev.get("Event")
    if isinstance(inner_ev, dict):
        containers.append(inner_ev)
        for sub in ("EventData", "UserData", "System"):
            val = inner_ev.get(sub)
            if isinstance(val, dict):
                containers.append(val)
                if sub == "UserData":
                    for nested_k, nested_v in val.items():
                        if nested_k != "#attributes" and isinstance(nested_v, dict):
                            containers.append(nested_v)

    results = []
    for c in containers:
        if field_name in c and c[field_name] is not None:
            results.append(c[field_name])
    if results:
        return results

    if "." in field_name:
        parts = field_name.split(".")
        for c in containers:
            cur = c
            ok = True
            for part in parts:
                if isinstance(cur, dict) and part in cur:
                    cur = cur[part]
                else:
                    ok = False
                    break
            if ok and cur is not None:
                results.append(cur)
        if results:
            return results

    lower_target = field_name.lower()
    for c in containers:
        for k, v in c.items():
            if isinstance(k, str) and k.lower() == lower_target and v is not None:
                results.append(v)
    return results


_FIELD_ALIASES = {
    "Image": ["image_path", "NewProcessName", "ProcessName"],
    "ParentImage": ["parent_image_path", "ParentProcessName"],
    "CommandLine": ["command_line"],
    "TargetFilename": ["file_path", "TargetObject"],
    "DestinationIp": ["dst_ip", "id.resp_h"],
    "SourceIp": ["src_ip", "id.orig_h"],
    "DestinationPort": ["dst_port", "id.resp_p"],
    "SourcePort": ["src_port", "id.orig_p"],
    "dst_ip": ["DestinationIp", "id.resp_h"],
    "src_ip": ["SourceIp", "id.orig_h"],
    "dst_port": ["DestinationPort", "id.resp_p"],
    "src_port": ["SourcePort", "id.orig_p"],
    "id.resp_h": ["dst_ip", "DestinationIp"],
    "id.orig_h": ["src_ip", "SourceIp"],
    "id.resp_p": ["dst_port", "DestinationPort"],
    "id.orig_p": ["src_port", "SourcePort"],
    "ProcessGuid": ["process_guid"],
    "Computer": ["hostname"],
    "User": ["principal", "TargetUserName", "SubjectUserName"],
    "cs-uri-query": ["uri", "cs-uri"],
    "message": ["Message", "raw_text"],
}


def _get_field_values(ev: dict, field_name: str) -> list:
    vals = _lookup_field(ev, field_name)
    if vals:
        return vals
    for alias in _FIELD_ALIASES.get(field_name, []):
        vals = _lookup_field(ev, alias)
        if vals:
            return vals
    return []


def _match_scalar(ev_val, expected, mods: set[str]) -> bool:
    if expected is None:
        return ev_val is None
    if ev_val is None:
        return False
    if isinstance(ev_val, list):
        return any(_match_scalar(item, expected, mods) for item in ev_val)

    cased = "cased" in mods
    s_ev = str(ev_val)
    s_exp = str(expected)
    cmp_ev = s_ev if cased else s_ev.lower()
    cmp_exp = s_exp if cased else s_exp.lower()

    if "re" in mods:
        flags = 0 if cased else re.IGNORECASE
        return re.search(s_exp, s_ev, flags) is not None
    if "contains" in mods:
        return cmp_exp in cmp_ev
    if "endswith" in mods:
        return cmp_ev.endswith(cmp_exp)
    if "startswith" in mods:
        return cmp_ev.startswith(cmp_exp)
    if isinstance(expected, bool) and isinstance(ev_val, bool):
        return ev_val == expected
    if isinstance(expected, (int, float)) and not isinstance(expected, bool):
        try:
            return float(ev_val) == float(expected)
        except Exception:
            pass
    return cmp_ev == cmp_exp


def _match_field_expr(ev: dict, key: str, expected, matched_fields: list[dict]) -> bool:
    parts = key.split("|")
    field_name = parts[0]
    mods = {m.lower() for m in parts[1:] if m}
    if not field_name:
        return False
    vals = _get_field_values(ev, field_name)
    if not vals:
        return False
    if isinstance(expected, list):
        if "all" in mods:
            ok = all(any(_match_scalar(v, exp, mods) for v in vals) for exp in expected)
        else:
            ok = any(_match_scalar(v, exp, mods) for exp in expected for v in vals)
    else:
        ok = any(_match_scalar(v, expected, mods) for v in vals)
    if ok:
        matched_fields.append({"field": field_name, "value": vals[0]})
    return ok


def _match_selection(ev: dict, sel, matched_fields: list[dict]) -> bool:
    if isinstance(sel, dict):
        local_fields: list[dict] = []
        for k, v in sel.items():
            if not _match_field_expr(ev, k, v, local_fields):
                return False
        matched_fields.extend(local_fields)
        return True
    if isinstance(sel, list):
        for item in sel:
            local_fields = []
            if isinstance(item, dict) and _match_selection(ev, item, local_fields):
                matched_fields.extend(local_fields)
                return True
            if not isinstance(item, dict):
                raw_text = str(ev.get("raw_text") or json.dumps(ev, ensure_ascii=False))
                if str(item).lower() in raw_text.lower():
                    return True
        return False
    return False


def _eval_condition_tokens(cond: str, sel_results: dict[str, bool]) -> bool:
    c = cond.strip()
    if c in sel_results:
        return sel_results[c]

    def _quantifier_match(expr: str) -> bool:
        m = re.fullmatch(r"(all|1)\s+of\s+([A-Za-z0-9_*]+)", expr.strip())
        if not m:
            raise ValueError(expr)
        quant, pattern = m.group(1), m.group(2)
        if pattern == "them":
            keys = [k for k in sel_results if not k.startswith("filter")]
            if not keys:
                keys = list(sel_results.keys())
        elif pattern.endswith("*"):
            prefix = pattern[:-1]
            keys = [k for k in sel_results if k.startswith(prefix)]
        else:
            keys = [k for k in sel_results if k == pattern]
        if not keys:
            return False
        vals = [sel_results[k] for k in keys]
        return all(vals) if quant == "all" else any(vals)

    # Tokenize boolean expression supporting parentheses, and, or, not, and quantifiers
    token_re = re.compile(
        r"\(|\)|\b(?:all|1)\s+of\s+[A-Za-z0-9_*]+\b|\b(?:and|or|not)\b|[A-Za-z0-9_.*-]+",
        re.IGNORECASE,
    )
    tokens = token_re.findall(c)
    pos = 0

    def parse_or() -> bool:
        nonlocal pos
        val = parse_and()
        while pos < len(tokens) and tokens[pos].lower() == "or":
            pos += 1
            rhs = parse_and()
            val = val or rhs
        return val

    def parse_and() -> bool:
        nonlocal pos
        val = parse_not()
        while pos < len(tokens) and tokens[pos].lower() == "and":
            pos += 1
            rhs = parse_not()
            val = val and rhs
        return val

    def parse_not() -> bool:
        nonlocal pos
        if pos < len(tokens) and tokens[pos].lower() == "not":
            pos += 1
            return not parse_not()
        return parse_atom()

    def parse_atom() -> bool:
        nonlocal pos
        if pos >= len(tokens):
            return False
        tok = tokens[pos]
        if tok == "(":
            pos += 1
            val = parse_or()
            if pos < len(tokens) and tokens[pos] == ")":
                pos += 1
            return val
        pos += 1
        if re.fullmatch(r"(?:all|1)\s+of\s+[A-Za-z0-9_*]+", tok, re.IGNORECASE):
            return _quantifier_match(tok.lower() if tok.lower().endswith("them") else tok)
        return bool(sel_results.get(tok, False))

    return parse_or()


def _match_sigma_rule(ev: dict, rule: dict) -> tuple[bool, list[str], list[dict]]:
    det = rule.get("detection")
    if not isinstance(det, dict):
        return False, [], []
    cond = det.get("condition")
    if not isinstance(cond, str) or not cond.strip():
        return False, [], []

    sel_results: dict[str, bool] = {}
    matched_sels: list[str] = []
    matched_fields: list[dict] = []
    for name, body in det.items():
        if name == "condition":
            continue
        fields_for_sel: list[dict] = []
        ok = _match_selection(ev, body, fields_for_sel)
        sel_results[name] = ok
        if ok:
            matched_sels.append(name)
            matched_fields.extend(fields_for_sel)

    try:
        hit = _eval_condition_tokens(cond, sel_results)
    except Exception:
        hit = False
    if not hit:
        return False, [], []
    return True, matched_sels, matched_fields


def _parse_timespan_secs(val) -> int:
    if isinstance(val, (int, float)):
        return int(val)
    s = str(val).strip().lower()
    m = re.fullmatch(r"(\d+)\s*([smhd])", s)
    if not m:
        return 300
    n = int(m.group(1))
    unit = m.group(2)
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    return n * mult


def _parse_event_ts(ev: dict, ts_field: str = "@timestamp") -> float:
    raw = ev.get(ts_field) or ev.get("@timestamp") or ev.get("timestamp") or ev.get("SystemTime") or ev.get("ts")
    if raw is None:
        return 0.0
    if isinstance(raw, (int, float)):
        v = float(raw)
        return v / 1000.0 if v > 1e12 else v
    s = str(raw).strip()
    if re.fullmatch(r"\d+(?:\.\d+)?", s):
        v = float(s)
        return v / 1000.0 if v > 1e12 else v
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    m = re.match(r"^(.*\.\d{6})\d+([+-]\d\d:\d\d)$", s)
    if m:
        s = m.group(1) + m.group(2)
    try:
        dt = _dt.datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_dt.timezone.utc)
        return dt.timestamp()
    except Exception:
        return 0.0


def _mitre_from_tags(tags: list) -> tuple[list[str], list[str], list[str]]:
    tactic_map = {
        "initial_access": "InitialAccess",
        "execution": "Execution",
        "persistence": "Persistence",
        "privilege_escalation": "PrivilegeEscalation",
        "defense_evasion": "DefenseEvasion",
        "credential_access": "CredentialAccess",
        "discovery": "Discovery",
        "lateral_movement": "LateralMovement",
        "collection": "Collection",
        "command_and_control": "CommandAndControl",
        "exfiltration": "Exfiltration",
        "impact": "Impact",
    }
    tactics: list[str] = []
    techniques: list[str] = []
    other: list[str] = []
    for tag in tags or []:
        t = str(tag)
        if t.startswith("attack."):
            suffix = t[7:]
            if re.fullmatch(r"t\d{4}(?:\.\d{3})?", suffix, re.IGNORECASE):
                techniques.append(suffix.upper())
            elif suffix.lower() in tactic_map:
                tactics.append(tactic_map[suffix.lower()])
            else:
                other.append(t)
        else:
            other.append(t)
    return tactics, techniques, other
'''


_FAKE_ZIRCOLITE_BODY = r'''
def _read_events(input_path: str, force_array: bool) -> list[dict]:
    p = Path(input_path)
    files = sorted(p.rglob("*.json")) + sorted(p.rglob("*.jsonl")) + sorted(p.rglob("*.ndjson")) if p.is_dir() else [p]
    events: list[dict] = []
    for f in files:
        if not f.is_file():
            continue
        text = f.read_text(encoding="utf-8-sig").strip()
        if not text:
            continue
        if force_array or text.startswith("["):
            data = json.loads(text)
            if isinstance(data, list):
                events.extend(x for x in data if isinstance(x, dict))
        else:
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                if isinstance(obj, dict):
                    events.append(obj)
    return events


def main() -> None:
    if any(a in ("--version", "-V") for a in sys.argv[1:]):
        print("Zircolite 4.8.0-fake")
        sys.exit(0)

    mode = _resolve_mode("zircolite", DEFAULT_MODE)
    _handle_crash_or_timeout("zircolite", mode, DEFAULT_SLEEP_S)

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-e", "--evtx", "--events", dest="evtx")
    parser.add_argument("-j", "--json-input", action="store_true")
    parser.add_argument("--json-array-input", action="store_true")
    parser.add_argument("-c", "--config", dest="config")
    parser.add_argument("-r", "--ruleset", dest="ruleset", action="append", default=[])
    parser.add_argument("-o", "--output", dest="output")
    parser.add_argument("-q", "--quiet", action="store_true")
    args, _ = parser.parse_known_args()

    def _emit_raw(content: str) -> None:
        if args.output:
            out_p = Path(args.output)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_text(content, encoding="utf-8")
        else:
            sys.stdout.write(content)

    if mode == "bad_json":
        _emit_raw("{corrupt-json\n")
        sys.exit(0)
    if mode == "zero_hit":
        _emit_raw("[]\n")
        sys.exit(0)

    if not args.evtx:
        sys.stderr.write("[fake-zircolite] missing -e/--evtx input\n")
        sys.exit(2)

    events = _read_events(args.evtx, args.json_array_input)

    rule_entries: list[tuple[str, dict]] = []
    for rp in args.ruleset:
        p = Path(rp)
        if p.is_file() and p.suffix.lower() == ".json":
            data = json.loads(p.read_text(encoding="utf-8-sig"))
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        rule_entries.append((str(p), item))
        else:
            rule_entries.extend(_load_sigma_rules([p]))

    results = []
    for rpath, rule in rule_entries:
        if "detection" not in rule:
            continue
        matches = []
        for idx, ev in enumerate(events, start=1):
            hit, _, _ = _match_sigma_rule(ev, rule)
            if hit:
                m = {"row_id": idx}
                m.update(ev)
                matches.append(m)
        if matches:
            results.append(
                {
                    "title": rule.get("title", "Untitled"),
                    "id": rule.get("id", ""),
                    "description": rule.get("description", ""),
                    "sigmafile": Path(rpath).name,
                    "sigma": [rule.get("title", "")],
                    "rule_level": rule.get("level", "medium"),
                    "tags": rule.get("tags", []),
                    "count": len(matches),
                    "matches": matches,
                }
            )

    _emit_raw(json.dumps(results, ensure_ascii=False, indent=2) + "\n")


if __name__ == "__main__":
    main()
'''


_FAKE_HAYABUSA_BODY = r'''
_BUILTIN_RULES = [
    {
        "title": "Synthetic Winword Spawns PowerShell",
        "id": "11111111-2222-3333-4444-555555555501",
        "status": "test",
        "level": "high",
        "tags": ["attack.execution", "attack.t1059.001"],
        "detection": {
            "selection": {
                "ParentImage|endswith": "\\WINWORD.EXE",
                "Image|endswith": "\\powershell.exe",
            },
            "condition": "selection",
        },
    },
    {
        "title": "Synthetic PowerShell Outbound C2 Flow",
        "id": "11111111-2222-3333-4444-555555555503",
        "status": "test",
        "level": "high",
        "tags": ["attack.command_and_control", "attack.t1071.001"],
        "detection": {
            "selection": {
                "Image|endswith": "\\powershell.exe",
                "DestinationIp": "203.0.113.8",
            },
            "condition": "selection",
        },
    },
]


def _read_hayabusa_events(file_arg: str | None, dir_arg: str | None) -> list[tuple[str, dict]]:
    paths: list[Path] = []
    if file_arg:
        paths.append(Path(file_arg))
    if dir_arg:
        d = Path(dir_arg)
        paths.extend(sorted(d.rglob("*.json")))
        paths.extend(sorted(d.rglob("*.jsonl")))
    out: list[tuple[str, dict]] = []
    for p in paths:
        if not p.is_file():
            continue
        text = p.read_text(encoding="utf-8-sig").strip()
        if not text:
            continue
        if text.startswith("["):
            arr = json.loads(text)
            if isinstance(arr, list):
                for item in arr:
                    if isinstance(item, dict):
                        out.append((str(p), item))
        else:
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                if isinstance(obj, dict):
                    out.append((str(p), obj))
    return out


def main() -> None:
    if any(a in ("--version", "-V") for a in sys.argv[1:]):
        print("hayabusa 4.5.0-fake")
        sys.exit(0)

    mode = _resolve_mode("hayabusa", DEFAULT_MODE)
    _handle_crash_or_timeout("hayabusa", mode, DEFAULT_SLEEP_S)

    if len(sys.argv) < 2 or sys.argv[1] != "dfir-timeline":
        sys.stderr.write("[fake-hayabusa] expected subcommand 'dfir-timeline'\n")
        sys.exit(2)

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-f", "--file", dest="file")
    parser.add_argument("-d", "--directory", dest="directory")
    parser.add_argument("-J", "--json-input", action="store_true")
    parser.add_argument("-t", "--output-type", default="jsonl")
    parser.add_argument("-p", "--profile", default="super-verbose")
    parser.add_argument("-o", "--output", dest="output")
    parser.add_argument("-r", "--rules", dest="rules", action="append", default=[])
    parser.add_argument("-c", "--rules-config", dest="rules_config")
    args, _ = parser.parse_known_args(sys.argv[2:])

    def _emit_raw(content: str) -> None:
        if args.output:
            out_p = Path(args.output)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_text(content, encoding="utf-8")
        else:
            sys.stdout.write(content)

    if not args.json_input:
        sys.stderr.write("[fake-hayabusa] -J/--json-input is required for JSONL input\n")
        sys.exit(2)

    if mode == "bad_json":
        _emit_raw("{corrupt-json\n")
        sys.exit(0)
    if mode == "zero_hit":
        _emit_raw("[]\n" if args.output_type == "json" else "")
        sys.exit(0)

    events = _read_hayabusa_events(args.file, args.directory)
    rules = _load_sigma_rules(args.rules) if args.rules else [("builtin.yml", r) for r in _BUILTIN_RULES]

    _HAYABUSA_HEADER_KEYS = frozenset(
        {
            "Timestamp",
            "SystemTime",
            "@timestamp",
            "timestamp",
            "Hostname",
            "hostname",
            "Computer",
            "Channel",
            "Provider",
            "Provider_Name",
            "Provider_Guid",
            "ProviderGuid",
            "SourceName",
            "EventID",
            "EventID_Qualifiers",
            "RecordNumber",
            "RecordID",
            "EventRecordID",
            "Level",
            "Task",
            "Opcode",
            "Keywords",
            "Version",
            "Execution_ProcessID",
            "Execution_ThreadID",
            "ExecutionProcessID",
            "ExecutionThreadID",
            "Security_UserID",
            "SecurityUserID",
            "log_source",
            "source_type",
            "source_file",
            "record_index",
            "event_id",
            "raw_id",
        }
    )

    def _merge_user_data(target: dict, ud: dict) -> None:
        for uk, uv in ud.items():
            if uk == "#attributes" or uv is None:
                continue
            if isinstance(uv, dict):
                for nk, nv in uv.items():
                    if nk != "#attributes" and nv is not None and nk not in target:
                        target[nk] = nv
            elif uk not in target:
                target[uk] = uv

    rows = []
    for src_file, ev in events:
        inner_ev = ev.get("Event") if isinstance(ev.get("Event"), dict) else {}
        sys_node = (
            ev.get("System")
            if isinstance(ev.get("System"), dict)
            else (inner_ev.get("System") if isinstance(inner_ev.get("System"), dict) else {})
        )

        if isinstance(ev.get("EventData"), dict):
            ev_data = dict(ev["EventData"])
            if isinstance(ev.get("UserData"), dict):
                _merge_user_data(ev_data, ev["UserData"])
        elif inner_ev:
            ev_data = {}
            if isinstance(inner_ev.get("EventData"), dict):
                ev_data.update(inner_ev["EventData"])
            if isinstance(inner_ev.get("UserData"), dict):
                _merge_user_data(ev_data, inner_ev["UserData"])
        else:
            ev_data = {
                k: v
                for k, v in ev.items()
                if k not in _HAYABUSA_HEADER_KEYS
                and k not in ("EventData", "UserData", "System", "Event")
                and v is not None
            }
            if isinstance(ev.get("UserData"), dict):
                _merge_user_data(ev_data, ev["UserData"])

        extra = dict(ev_data)
        for k in ("event_id", "raw_id", "source_file", "record_index"):
            if k in ev:
                extra[k] = ev[k]
        for rpath, rule in rules:
            if "detection" not in rule:
                continue
            hit, _, _ = _match_sigma_rule(ev, rule)
            if not hit:
                continue
            tactics, mitre_tags, other_tags = _mitre_from_tags(rule.get("tags", []))
            ts_node = sys_node.get("TimeCreated")
            sys_ts = ts_node.get("#attributes", {}).get("SystemTime") if isinstance(ts_node, dict) else ""
            ts = ev.get("@timestamp") or ev.get("Timestamp") or ev.get("SystemTime") or ev.get("timestamp") or sys_ts or ""
            computer = str(
                ev.get("Computer")
                or ev.get("Hostname")
                or ev.get("hostname")
                or sys_node.get("Computer")
                or ""
            )
            channel = ev.get("Channel") or sys_node.get("Channel") or ""
            raw_eid = ev.get("EventID") if ev.get("EventID") is not None else sys_node.get("EventID")
            if isinstance(raw_eid, dict):
                raw_eid = raw_eid.get("#text")
            event_id_num = raw_eid if raw_eid is not None else 0
            rec_id = (
                ev.get("RecordNumber")
                or ev.get("RecordID")
                or ev.get("EventRecordID")
                or sys_node.get("EventRecordID")
                or ev.get("record_index")
                or 0
            )
            prov_node = sys_node.get("Provider")
            sys_prov = (
                (prov_node.get("#attributes", {}).get("Name") or prov_node.get("Name"))
                if isinstance(prov_node, dict)
                else ""
            )
            provider = ev.get("SourceName") or ev.get("Provider_Name") or ev.get("Provider") or sys_prov or ""
            rows.append(
                {
                    "Timestamp": ts,
                    "RuleTitle": rule.get("title", "Untitled"),
                    "Level": rule.get("level", "medium"),
                    "Computer": computer,
                    "Channel": channel,
                    "EventID": event_id_num,
                    "Status": rule.get("status", "test"),
                    "RecordID": rec_id,
                    "Details": dict(ev_data) if ev_data else {"CommandLine": ev.get("CommandLine", "")},
                    "ExtraFieldInfo": extra,
                    "MitreTactics": tactics,
                    "MitreTags": mitre_tags,
                    "OtherTags": other_tags,
                    "Provider": provider,
                    "RuleFile": Path(rpath).name,
                    "RuleID": rule.get("id", ""),
                    "EvtxFile": src_file,
                }
            )

    if args.output_type == "json":
        _emit_raw(json.dumps(rows, ensure_ascii=False, indent=2) + "\n")
    else:
        _emit_raw("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows))


if __name__ == "__main__":
    main()
'''


_FAKE_TAKAJO_BODY = r'''
def main() -> None:
    if any(a in ("--version", "-V") for a in sys.argv[1:]):
        print("takajo 2.16.1-fake")
        sys.exit(0)

    mode = _resolve_mode("takajo", DEFAULT_MODE)
    _handle_crash_or_timeout("takajo", mode, DEFAULT_SLEEP_S)

    outputs = {
        "timeline-suspicious-processes": "TimelineSuspiciousProcesses.csv",
        "stack-processes": "StackProcesses.csv",
        "stack-cmdlines": "StackCmdlines.csv",
        "ttp-summary": "TTPSummary.csv",
    }
    if len(sys.argv) < 2 or sys.argv[1] not in {*outputs, "automagic"}:
        sys.stderr.write("[fake-takajo] unsupported subcommand\n")
        sys.exit(2)

    if os.path.realpath(os.getcwd()) != os.path.realpath(os.path.dirname(os.path.abspath(__file__))):
        sys.stderr.write(
            "The Takajo executable does not exist in the current directory. "
            "Please run it from the directory where you unzipped Takajo.\n"
        )
        sys.exit(2)

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-t", "--timeline", dest="timeline")
    parser.add_argument("-o", "--output", dest="output")
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("-s", "--skip-prompts", action="store_true")
    args, _ = parser.parse_known_args(sys.argv[2:])

    if not args.timeline or not args.output:
        sys.stderr.write("[fake-takajo] -t/--timeline and -o/--output are required\n")
        sys.exit(2)

    output = Path(args.output)
    subcommand = sys.argv[1]
    out_dir = output if subcommand == "automagic" else output.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    if mode == "bad_json":
        target = out_dir / "TTPSummary.csv" if subcommand == "automagic" else output
        target.write_text("{corrupt-csv\n", encoding="utf-8")
        sys.exit(0)

    alerts = []
    if mode != "zero_hit":
        tl_path = Path(args.timeline)
        if tl_path.is_file():
            for line in tl_path.read_text(encoding="utf-8-sig").splitlines():
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                if isinstance(obj, dict):
                    alerts.append(obj)

    proc_rows = []
    logon_rows = []
    ttp_counts = {}
    comp_counts = {}
    ips = set()
    domains = set()

    for a in alerts:
        comp = str(a.get("Computer") or "")
        if comp:
            comp_counts[comp] = comp_counts.get(comp, 0) + 1
        title = str(a.get("RuleTitle") or "")
        for tag in a.get("MitreTags") or []:
            ttp_counts[(tag, title)] = ttp_counts.get((tag, title), 0) + 1
        extra = a.get("ExtraFieldInfo") or {}
        details = a.get("Details") or {}
        merged = {}
        if isinstance(details, dict):
            merged.update(details)
        if isinstance(extra, dict):
            merged.update(extra)
        ev_id = str(merged.get("event_id") or "")
        raw_eid = a.get("EventID")
        eid_num = (
            int(raw_eid)
            if isinstance(raw_eid, int) and not isinstance(raw_eid, bool)
            else (
                int(raw_eid)
                if isinstance(raw_eid, str) and raw_eid.strip().isascii() and raw_eid.strip().isdigit()
                else None
            )
        )
        if eid_num in (1, 4688) or "Image" in merged or "CommandLine" in merged:
            proc_rows.append([
                a.get("Timestamp", ""),
                comp,
                title,
                str(eid_num or ""),
                str(merged.get("Image") or merged.get("NewProcessName") or ""),
                str(merged.get("ParentImage") or merged.get("ParentProcessName") or ""),
                str(merged.get("CommandLine", "")),
                str(merged.get("ProcessGuid", "")),
                ev_id,
            ])
        if eid_num in (4624, 4625):
            logon_rows.append([
                a.get("Timestamp", ""),
                comp,
                str(eid_num),
                str(merged.get("TargetUserName", "")),
                str(merged.get("IpAddress", "")),
                ev_id,
            ])
        for ip_k in ("DestinationIp", "SourceIp", "IpAddress", "dst_ip", "src_ip"):
            val = merged.get(ip_k)
            if isinstance(val, str) and val:
                ips.add(val)
        for dom_k in ("QueryName", "DestinationHostname", "query", "host"):
            val = merged.get(dom_k)
            if isinstance(val, str) and val:
                domains.add(val)

    def _write_csv(name: str, headers: list[str], rows: list[list[str]]) -> None:
        if subcommand != "automagic" and outputs[subcommand] != name:
            return
        target = out_dir / name if subcommand == "automagic" else output
        with target.open("w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(headers)
            w.writerows(rows)

    _write_csv(
        "TimelineSuspiciousProcesses.csv",
        ["Timestamp", "Computer", "RuleTitle", "EventID", "Image", "ParentImage", "CommandLine", "ProcessGuid", "event_id"],
        proc_rows,
    )
    _write_csv(
        "TimelineLogon.csv",
        ["Timestamp", "Computer", "EventID", "TargetUserName", "IpAddress", "event_id"],
        logon_rows,
    )
    _write_csv("StackProcesses.csv", ["Image"], [[row[4]] for row in proc_rows])
    _write_csv("StackCmdlines.csv", ["CommandLine"], [[row[6]] for row in proc_rows])
    _write_csv(
        "TTPSummary.csv",
        ["MitreTag", "RuleTitle", "Count"],
        [[tag, title, str(cnt)] for (tag, title), cnt in sorted(ttp_counts.items())],
    )
    _write_csv(
        "MetricsComputers.csv",
        ["Computer", "AlertCount"],
        [[c, str(n)] for c, n in sorted(comp_counts.items())],
    )
    _write_csv(
        "StackTargetComputers.csv",
        ["Computer", "AlertCount"],
        [[c, str(n)] for c, n in sorted(comp_counts.items())],
    )
    if subcommand != "automagic":
        return
    (out_dir / "ListIP-Addresses.txt").write_text(
        "\n".join(sorted(ips)) + ("\n" if ips else ""), encoding="utf-8"
    )
    (out_dir / "ListDomains.txt").write_text(
        "\n".join(sorted(domains)) + ("\n" if domains else ""), encoding="utf-8"
    )


if __name__ == "__main__":
    main()
'''


_FAKE_RSIGMA_BODY = r'''
def _load_rsigma_events(event_args: list[str]) -> list[dict]:
    if not event_args:
        raw = sys.stdin.read()
        chunks = [raw] if raw.strip() else []
    else:
        chunks = []
        for item in event_args:
            if item.startswith("@"):
                chunks.append(Path(item[1:]).read_text(encoding="utf-8-sig"))
            elif Path(item).is_file():
                chunks.append(Path(item).read_text(encoding="utf-8-sig"))
            else:
                chunks.append(item)

    events: list[dict] = []
    for chunk in chunks:
        text = chunk.strip()
        if not text:
            continue
        if text.startswith("["):
            arr = json.loads(text)
            if isinstance(arr, list):
                events.extend(x for x in arr if isinstance(x, dict))
        else:
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                if isinstance(obj, dict):
                    events.append(obj)
    return events


def _validate_rule_doc(doc: dict, known_rules: set[str]) -> list[str]:
    errs: list[str] = []
    if not isinstance(doc, dict):
        return ["Rule document must be a mapping"]
    if not isinstance(doc.get("title"), str) or not doc["title"].strip():
        errs.append("Missing required string 'title'")
    has_det = "detection" in doc
    has_corr = "correlation" in doc
    if not has_det and not has_corr:
        errs.append("Rule must define either 'detection' or 'correlation'")
    if has_det:
        if not isinstance(doc.get("logsource"), dict):
            errs.append("Single-event rule missing 'logsource' mapping")
        det = doc.get("detection")
        if not isinstance(det, dict) or not isinstance(det.get("condition"), str):
            errs.append("Single-event rule missing 'detection.condition'")
    if has_corr:
        corr = doc.get("correlation")
        if not isinstance(corr, dict):
            errs.append("'correlation' must be a mapping")
        else:
            if corr.get("type") not in ("event_count", "value_count", "temporal", "temporal_ordered"):
                errs.append(f"Invalid correlation.type: {corr.get('type')!r}")
            if not corr.get("timespan"):
                errs.append("Correlation rule missing 'timespan'")
            refs = corr.get("rules")
            if not isinstance(refs, list) or not refs:
                errs.append("Correlation rule missing 'rules' list")
            else:
                missing = [str(r) for r in refs if str(r) not in known_rules]
                if missing:
                    errs.append(f"Correlation references unknown rules: {missing!r}")
    return errs


def _handle_rule_cmd(argv: list[str]) -> None:
    if not argv:
        sys.stderr.write("[fake-rsigma] missing rule subcommand\n")
        sys.exit(2)
    sub = argv[0]
    rest = argv[1:]
    if sub not in ("validate", "lint", "stdin"):
        sys.stderr.write(f"[fake-rsigma] unsupported rule subcommand: {sub!r}\n")
        sys.exit(2)

    docs: list[tuple[str, dict]] = []
    if sub == "stdin":
        text = sys.stdin.read()
        try:
            for d in _load_yaml_docs(text):
                docs.append(("stdin", d))
        except Exception as exc:
            sys.stderr.write(f"YAML syntax error: {exc}\n")
            sys.exit(1)
    else:
        targets = [a for a in rest if not a.startswith("-")]
        files: list[Path] = []
        for t in targets:
            p = Path(t)
            if p.is_file():
                files.append(p)
            elif p.is_dir():
                files.extend(sorted(p.rglob("*.yml")))
                files.extend(sorted(p.rglob("*.yaml")))
            else:
                sys.stderr.write(f"Rule path not found: {t}\n")
                sys.exit(1)
        for f in files:
            try:
                loaded = _load_yaml_docs(f.read_text(encoding="utf-8-sig"))
                if not loaded:
                    sys.stderr.write(f"Empty YAML rule: {f}\n")
                    sys.exit(1)
                for d in loaded:
                    docs.append((str(f), d))
            except Exception as exc:
                sys.stderr.write(f"YAML syntax error in {f}: {exc}\n")
                sys.exit(1)

    known_rules: set[str] = set()
    for _, d in docs:
        if isinstance(d, dict) and "detection" in d:
            if d.get("id"):
                known_rules.add(str(d["id"]))
            if d.get("name"):
                known_rules.add(str(d["name"]))
            if d.get("title"):
                known_rules.add(str(d["title"]))

    errors: list[str] = []
    for src, d in docs:
        for err in _validate_rule_doc(d, known_rules):
            errors.append(f"{src}: {err}")

    if errors:
        sys.stderr.write("\n".join(errors) + "\n")
        sys.exit(2)
    sys.exit(0)


def _check_corr_condition(cond: dict, val: float) -> bool:
    if not isinstance(cond, dict) or not cond:
        return val >= 1
    if "gte" in cond and not (val >= float(cond["gte"])):
        return False
    if "gt" in cond and not (val > float(cond["gt"])):
        return False
    if "lte" in cond and not (val <= float(cond["lte"])):
        return False
    if "lt" in cond and not (val < float(cond["lt"])):
        return False
    if "eq" in cond and not (val == float(cond["eq"])):
        return False
    return True


def _handle_engine_eval(argv: list[str], mode: str) -> None:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-r", "--rules", action="append", default=[])
    parser.add_argument("-e", "--event", action="append", default=[])
    parser.add_argument("--output-format", default="ndjson")
    parser.add_argument("--correlation-event-mode", default="none")
    parser.add_argument("--max-correlation-events", type=int, default=10)
    parser.add_argument("--timestamp-field", default="@timestamp")
    parser.add_argument("-p", "--pipeline")
    parser.add_argument("-o", "--output")
    parser.add_argument("--no-stats", action="store_true")
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("--include-event", action="store_true")
    parser.add_argument("--emit-detections", action="store_true")
    args, _ = parser.parse_known_args(argv)

    def _emit_raw(content: str) -> None:
        if args.output:
            out_p = Path(args.output)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_text(content, encoding="utf-8")
        else:
            sys.stdout.write(content)

    if mode == "bad_json":
        _emit_raw("{corrupt-json\n")
        sys.exit(0)
    if mode == "zero_hit":
        _emit_raw("[]\n" if args.output_format == "json" else "")
        sys.exit(0)

    events = _load_rsigma_events(args.event)
    rule_entries = _load_sigma_rules(args.rules)

    single_rules: list[dict] = []
    corr_rules: list[dict] = []
    for _, doc in rule_entries:
        if "correlation" in doc:
            corr_rules.append(doc)
        elif "detection" in doc:
            single_rules.append(doc)

    detections: list[dict] = []
    hits_by_rule_key: dict[str, list[tuple[int, dict, str]]] = {}

    for rule in single_rules:
        r_title = rule.get("title", "Untitled")
        r_id = str(rule.get("id", ""))
        r_name = str(rule.get("name", ""))
        matched_list: list[tuple[int, dict, str]] = []
        for idx, ev in enumerate(events):
            hit, matched_sels, matched_fields = _match_sigma_rule(ev, rule)
            if hit:
                matched_list.append((idx, ev, r_title))
                det_obj = {
                    "rule_title": r_title,
                    "rule_id": r_id,
                    "level": rule.get("level", "medium"),
                    "tags": rule.get("tags", []),
                    "matched_selections": matched_sels,
                    "matched_fields": matched_fields,
                    "event": ev,
                }
                detections.append(det_obj)
        for key in (r_id, r_name, r_title):
            if key:
                hits_by_rule_key.setdefault(key, []).extend(matched_list)

    eff_corr_mode = "none" if mode == "count_only" else args.correlation_event_mode.strip().lower()

    for crule in corr_rules:
        corr = crule.get("correlation") or {}
        ctype = str(corr.get("type", "event_count"))
        refs = [str(r) for r in (corr.get("rules") or [])]
        group_by = [str(g) for g in (corr.get("group-by") or [])]
        timespan_secs = _parse_timespan_secs(corr.get("timespan", "5m"))
        cond = corr.get("condition") or {}

        pool: list[tuple[int, dict, str]] = []
        seen_idx_rule: set[tuple[int, str]] = set()
        for ref_key in refs:
            for idx, ev, src_title in hits_by_rule_key.get(ref_key, []):
                if (idx, ref_key) not in seen_idx_rule:
                    seen_idx_rule.add((idx, ref_key))
                    pool.append((idx, ev, src_title))

        grouped: dict[tuple, list[tuple[int, dict, str, float]]] = {}
        for idx, ev, src_title in pool:
            if group_by:
                key_vals = []
                missing = False
                for gf in group_by:
                    vals = _get_field_values(ev, gf)
                    if not vals:
                        missing = True
                        break
                    key_vals.append(vals[0])
                if missing:
                    continue
                gkey = tuple(key_vals)
            else:
                gkey = ()
            ts = _parse_event_ts(ev, args.timestamp_field)
            grouped.setdefault(gkey, []).append((idx, ev, src_title, ts))

        for gkey, items in grouped.items():
            items_sorted = sorted(items, key=lambda x: (x[3], x[0]))
            if not items_sorted:
                continue
            span = items_sorted[-1][3] - items_sorted[0][3]
            if span > timespan_secs:
                continue

            if ctype in ("temporal", "temporal_ordered"):
                distinct_rules = len({x[2] for x in items_sorted})
                agg_val = float(distinct_rules if len(refs) > 1 else len(items_sorted))
            elif ctype == "value_count":
                field_name = str(corr.get("condition", {}).get("field") or "")
                agg_val = float(len({str(_get_field_values(x[1], field_name)[0]) for x in items_sorted if _get_field_values(x[1], field_name)}))
            else:
                agg_val = float(len(items_sorted))

            if not _check_corr_condition(cond, agg_val):
                continue

            group_pairs = [[gf, gv] for gf, gv in zip(group_by, gkey)]
            matched_evs = [x[1] for x in items_sorted]
            capped_evs = matched_evs[: max(0, args.max_correlation_events)]
            corr_obj = {
                "rule_title": crule.get("title", "Untitled Correlation"),
                "rule_id": str(crule.get("id", "")),
                "level": crule.get("level", "high"),
                "tags": crule.get("tags", []),
                "correlation_type": ctype,
                "group_key": group_pairs,
                "aggregated_value": agg_val,
                "timespan_secs": timespan_secs,
                "event_sources": [{"rule": x[2]} for x in items_sorted],
            }
            if eff_corr_mode == "full":
                corr_obj["events"] = capped_evs
            elif eff_corr_mode == "refs":
                corr_obj["event_refs"] = [
                    {
                        "timestamp": int(_parse_event_ts(ev, args.timestamp_field)),
                        "id": str(ev.get("event_id") or ev.get("id") or ""),
                    }
                    for ev in capped_evs
                ]
            detections.append(corr_obj)

    if args.output_format == "json":
        _emit_raw(json.dumps(detections, ensure_ascii=False, indent=2) + "\n")
    else:
        _emit_raw("".join(json.dumps(d, ensure_ascii=False) + "\n" for d in detections))


def main() -> None:
    if any(a in ("--version", "-V") for a in sys.argv[1:]):
        print("rsigma 0.28.0-fake")
        sys.exit(0)

    mode = _resolve_mode("rsigma", DEFAULT_MODE)
    _handle_crash_or_timeout("rsigma", mode, DEFAULT_SLEEP_S)

    if len(sys.argv) >= 3 and sys.argv[1] == "engine" and sys.argv[2] == "eval":
        _handle_engine_eval(sys.argv[3:], mode)
    elif len(sys.argv) >= 2 and sys.argv[1] == "rule":
        _handle_rule_cmd(sys.argv[2:])
    else:
        sys.stderr.write("[fake-rsigma] expected 'engine eval' or 'rule validate|lint|stdin'\n")
        sys.exit(2)


if __name__ == "__main__":
    main()
'''


_FAKE_CHAINSAW_BODY = r'''
def _load_mapping_aliases(mapping_path: str | None) -> dict[str, list[str]]:
    aliases: dict[str, list[str]] = {}
    if not mapping_path:
        return aliases
    mp = Path(mapping_path)
    if not mp.is_file():
        return aliases
    for doc in _load_yaml_docs(mp.read_text(encoding="utf-8-sig")):
        if not isinstance(doc, dict):
            continue
        for grp in doc.get("groups") or []:
            if not isinstance(grp, dict):
                continue
            for f in grp.get("fields") or []:
                if isinstance(f, dict) and f.get("from") and f.get("to"):
                    aliases.setdefault(str(f["to"]), []).append(str(f["from"]))
                    aliases.setdefault(str(f["from"]), []).append(str(f["to"]))
    return aliases


def _apply_aliases(ev: dict, aliases: dict[str, list[str]]) -> dict:
    enriched = dict(ev)
    for target, srcs in aliases.items():
        if target not in enriched:
            for src in srcs:
                vals = _get_field_values(ev, src)
                if vals:
                    enriched[target] = vals[0]
                    break
    return enriched


def main() -> None:
    if any(a in ("--version", "-V") for a in sys.argv[1:]):
        print("chainsaw 2.18.0-fake")
        sys.exit(0)

    mode = _resolve_mode("chainsaw", DEFAULT_MODE)
    _handle_crash_or_timeout("chainsaw", mode, DEFAULT_SLEEP_S)

    if len(sys.argv) < 2 or sys.argv[1] != "hunt":
        sys.stderr.write("[fake-chainsaw] expected subcommand 'hunt'\n")
        sys.exit(2)

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-s", "--sigma", action="append", default=[])
    parser.add_argument("-m", "--mapping")
    parser.add_argument("-r", "--rule", action="append", default=[])
    parser.add_argument("-j", "--json", action="store_true")
    parser.add_argument("--jsonl", action="store_true")
    parser.add_argument("-o", "--output")
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("--skip-errors", action="store_true")
    parser.add_argument("--load-unknown", action="store_true")
    args, positionals = parser.parse_known_args(sys.argv[2:])

    def _emit_raw(content: str) -> None:
        if args.output:
            out_p = Path(args.output)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_text(content, encoding="utf-8")
        else:
            sys.stdout.write(content)

    if mode == "bad_json":
        _emit_raw("{corrupt-json\n")
        sys.exit(0)
    if mode == "zero_hit":
        _emit_raw("[]\n")
        sys.exit(0)

    rule_paths = list(args.sigma) + list(args.rule)
    event_paths: list[str] = []
    if not rule_paths and len(positionals) >= 2:
        rule_paths = [positionals[0]]
        event_paths = positionals[1:]
    else:
        event_paths = list(positionals)

    input_files: list[Path] = []
    for ep in event_paths:
        p = Path(ep)
        if p.is_file():
            input_files.append(p)
        elif p.is_dir():
            input_files.extend(sorted(p.rglob("*.json")))
            if args.jsonl:
                input_files.extend(sorted(p.rglob("*.jsonl")))

    loaded_events: list[tuple[Path, dict]] = []
    for f in input_files:
        text = f.read_text(encoding="utf-8-sig").strip()
        if not text:
            continue
        if args.jsonl and f.suffix.lower() in (".jsonl", ".ndjson"):
            for line in text.splitlines():
                line = line.strip()
                if line:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        loaded_events.append((f, obj))
        else:
            try:
                data = json.loads(text)
                if not isinstance(data, list):
                    raise ValueError("Chainsaw JSON input must be a JSON array")
                for item in data:
                    if isinstance(item, dict):
                        loaded_events.append((f, item))
            except Exception as exc:
                if args.skip_errors:
                    continue
                sys.stderr.write(f"[fake-chainsaw] invalid JSON array input {f}: {exc}\n")
                sys.exit(1)

    aliases = _load_mapping_aliases(args.mapping)
    rules = _load_sigma_rules(rule_paths)

    hits: list[dict] = []
    for src_path, orig_ev in loaded_events:
        enriched = _apply_aliases(orig_ev, aliases) if aliases else orig_ev
        for _, rule in rules:
            if "detection" not in rule:
                continue
            ok, _, _ = _match_sigma_rule(enriched, rule)
            if not ok:
                continue
            author_raw = rule.get("author")
            if isinstance(author_raw, str) and author_raw.strip():
                authors = [a.strip() for a in author_raw.split(",") if a.strip()]
            elif isinstance(rule.get("authors"), list):
                authors = list(rule["authors"])
            else:
                authors = []
            ts = orig_ev.get("timestamp") or orig_ev.get("@timestamp") or orig_ev.get("SystemTime") or ""
            hits.append(
                {
                    "group": "Sigma",
                    "kind": "individual",
                    "document": {
                        "kind": "json",
                        "path": str(src_path),
                        "data": orig_ev,
                    },
                    "name": rule.get("title", "Untitled"),
                    "timestamp": ts,
                    "authors": authors,
                    "level": rule.get("level", "medium"),
                    "source": "sigma",
                    "status": rule.get("status", "test"),
                    "id": str(rule.get("id", "")),
                    "logsource": rule.get("logsource", {}),
                    "tags": rule.get("tags", []),
                }
            )

    _emit_raw(json.dumps(hits, ensure_ascii=False, indent=2) + "\n")


if __name__ == "__main__":
    main()
'''


_ENGINE_BODIES: dict[str, str] = {
    "zircolite": _FAKE_ZIRCOLITE_BODY,
    "hayabusa": _FAKE_HAYABUSA_BODY,
    "takajo": _FAKE_TAKAJO_BODY,
    "rsigma": _FAKE_RSIGMA_BODY,
    "chainsaw": _FAKE_CHAINSAW_BODY,
}


def build_fake_engine_bins(
    tmp_path: Path,
    *,
    engine_modes: dict[str, str] | None = None,
    sleep_s: float = 30.0,
) -> dict[str, Path]:
    """Create executable fake engine scripts under ``tmp_path``."""
    out_dir = Path(tmp_path)
    out_dir.mkdir(parents=True, exist_ok=True)
    modes = {k.lower(): v for k, v in (engine_modes or {}).items()}
    py_exe = sys.executable or "/usr/bin/python3"
    shebang = f"#!{py_exe}\n"

    bins: dict[str, Path] = {}
    for engine, body in _ENGINE_BODIES.items():
        default_mode = modes.get(engine, "normal")
        script_path = out_dir / engine
        content = (
            f"{shebang}"
            f"DEFAULT_MODE = {default_mode!r}\n"
            f"DEFAULT_SLEEP_S = {float(sleep_s)!r}\n"
            f"{_SHARED_FAKE_ENGINE_PRELUDE}\n"
            f"{body.lstrip()}"
        )
        script_path.write_text(content, encoding="utf-8")
        os.chmod(script_path, 0o755)
        bins[engine] = script_path

    return bins


build_fake_engine_scripts = build_fake_engine_bins
