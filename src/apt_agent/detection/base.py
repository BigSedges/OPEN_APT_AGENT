"""Shared detection engine contracts, MITRE tag normalization, and safe CLI helpers."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Iterable, Mapping, Sequence
from collections.abc import Set as AbstractSet
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from apt_agent.config import EngineConfig
from apt_agent.exceptions import EngineError, OperationTimeoutError
from apt_agent.models import TACTIC_ID_PATTERN, Event, Hit, RuleRun, RunContext

TECHNIQUE_ID_PATTERN = re.compile(r"\AT[0-9]{4}(?:\.[0-9]{3})?\Z")
_VERSION_PATTERN = re.compile(r"\b(?:v)?(\d+\.\d+\.\d+(?:[-.\w]+)?)\b")

_SEVERITY_RANK: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
}

_SIGMA_TACTIC_MAP: dict[str, str] = {
    "reconnaissance": "TA0043",
    "resource_development": "TA0042",
    "resource-development": "TA0042",
    "initial_access": "TA0001",
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege_escalation": "TA0004",
    "privilege-escalation": "TA0004",
    "defense_evasion": "TA0005",
    "defense-evasion": "TA0005",
    "credential_access": "TA0006",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral_movement": "TA0008",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "exfiltration": "TA0010",
    "command_and_control": "TA0011",
    "command-and-control": "TA0011",
    "impact": "TA0040",
}

# All 15 Hayabusa mitre_tactics.txt abbreviations (case-insensitive key)
_HAYABUSA_TACTIC_MAP: dict[str, str] = {
    "recon": "TA0043",
    "resdev": "TA0042",
    "initaccess": "TA0001",
    "exec": "TA0002",
    "persis": "TA0003",
    "privesc": "TA0004",
    "stealth": "TA0005",
    "defimpair": "TA0005",
    "credaccess": "TA0006",
    "disc": "TA0007",
    "latmov": "TA0008",
    "collect": "TA0009",
    "c2": "TA0011",
    "exfil": "TA0010",
    "impact": "TA0040",
}

ALL_LOG_FORMATS: frozenset[str] = frozenset(
    {
        "winxml",
        "zeek_json",
        "ecar_json",
        "syslog",
        "web_access",
        "bash_history",
    }
)


def repo_root() -> Path:
    """Dynamically locate the repository root relative to this module."""
    return Path(__file__).resolve().parents[3]


def resolve_config_path(
    configured: Path | None,
    default_relative: str,
) -> tuple[Path | None, str | None]:
    """Resolve an engine config path without overriding an explicit missing path.

    Returns `(resolved_path, error_reason)`.
    If `configured` is explicitly set to a missing path, returns `(None, "config_not_found:...")`.
    If `configured` is `None`, falls back to `repo_root() / default_relative` if it exists.
    """
    if configured is not None:
        if configured.is_file():
            return configured, None
        return None, f"config_not_found:{configured}"
    candidate = repo_root() / default_relative
    if candidate.is_file():
        return candidate, None
    return None, None


class DetectionResult(BaseModel):
    """Structured multi-engine detection output supporting attribute and dict access."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hits: list[Hit] = Field(default_factory=list)
    coverage: list[RuleRun] = Field(default_factory=list)
    leads: list[dict[str, Any]] = Field(default_factory=list)
    event_to_physical: dict[str, str] = Field(default_factory=dict)

    hit_trace: list[dict[str, Any]] = Field(default_factory=list)

    _DICT_FIELDS = ("hits", "coverage", "leads", "event_to_physical")

    def __getitem__(self, key: str) -> Any:
        if key in self._DICT_FIELDS:
            return getattr(self, key)
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        if key in self._DICT_FIELDS:
            return getattr(self, key)
        return default

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and key in self._DICT_FIELDS

    def keys(self) -> tuple[str, ...]:
        return self._DICT_FIELDS

    def items(self) -> list[tuple[str, Any]]:
        return [(k, getattr(self, k)) for k in self._DICT_FIELDS]

    def to_dict(self) -> dict[str, Any]:
        return {
            "hits": list(self.hits),
            "coverage": list(self.coverage),
            "leads": list(self.leads),
            "event_to_physical": dict(self.event_to_physical),
        }


class AdapterOutput(BaseModel):
    """Raw unmerged output returned by a single detection engine adapter."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    engine: str
    engine_version: str = "unknown"
    hits: list[Hit] = Field(default_factory=list)
    coverage: list[RuleRun] = Field(default_factory=list)
    leads: list[dict[str, Any]] = Field(default_factory=list)


@runtime_checkable
class EngineAdapter(Protocol):
    """Protocol implemented by every M3 detection engine adapter."""

    engine_name: str
    supported_formats: frozenset[str]

    def run(
        self,
        ctx: RunContext,
        events: Sequence[Event],
        engine_cfg: EngineConfig,
        *,
        ruleset_version: str,
    ) -> AdapterOutput: ...


def classify_event_format(event: Event) -> str:
    """Classify an Event into one of the 6 normalized log format keys (or 'unknown')."""
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
    if ls == "ecar":
        return "ecar_json"
    if ls in ("syslog", "web_access", "bash_history"):
        return ls
    return "winxml" if "EventID" in event.fields and "Channel" in event.fields else "unknown"


def normalize_level(level: Any) -> str | None:
    """Normalize severity strings (including Hayabusa abbreviations) to canonical levels."""
    if not isinstance(level, str):
        return None
    cleaned = level.strip().lower()
    if not cleaned:
        return None
    mapping = {
        "crit": "critical",
        "critical": "critical",
        "high": "high",
        "med": "medium",
        "medium": "medium",
        "low": "low",
        "info": "informational",
        "informational": "informational",
    }
    return mapping.get(cleaned, cleaned)


def severity_rank(level: str | None) -> int:
    """Return numeric severity rank (higher = more severe)."""
    norm = normalize_level(level)
    return _SEVERITY_RANK.get(norm or "", 0)


def normalize_sigma_tags(
    tags: Iterable[Any],
    *,
    mitre_tactics: Iterable[Any] = (),
    mitre_tags: Iterable[Any] = (),
) -> tuple[list[str], list[str]]:
    """Normalize Sigma tags and Hayabusa MITRE fields into canonical (tactic_ids, technique_ids)."""
    tactics: set[str] = set()
    techniques: set[str] = set()

    def _process_token(raw_tok: Any) -> None:
        if not isinstance(raw_tok, str):
            return
        tok = raw_tok.strip()
        if not tok:
            return
        lowered = tok.lower()
        body = lowered[7:] if lowered.startswith("attack.") else lowered

        upper_body = body.upper()
        if TACTIC_ID_PATTERN.fullmatch(upper_body):
            tactics.add(upper_body)
            return
        if TECHNIQUE_ID_PATTERN.fullmatch(upper_body):
            techniques.add(upper_body)
            return
        if body in _SIGMA_TACTIC_MAP:
            tactics.add(_SIGMA_TACTIC_MAP[body])
            return
        if body in _HAYABUSA_TACTIC_MAP:
            tactics.add(_HAYABUSA_TACTIC_MAP[body])
            return

    for item in tags:
        _process_token(item)
    for item in mitre_tactics:
        _process_token(item)
    for item in mitre_tags:
        _process_token(item)

    return sorted(tactics), sorted(techniques)


def make_hit_id(engine: str, rule_id: str, event_ids: Sequence[str], extra: str = "") -> str:
    """Generate a deterministic Hit identifier."""
    payload = f"{engine}|{rule_id}|{','.join(event_ids)}|{extra}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"hit_{digest}"


def make_lead_id(engine: str, kind: str, detail: str) -> str:
    """Generate a deterministic lead identifier."""
    payload = f"{engine}|{kind}|{detail}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"lead_{digest}"


def validate_event_ids(
    raw_ids: Iterable[Any],
    valid_event_ids: AbstractSet[str],
) -> list[str]:
    """Filter candidate event_ids to those present in `valid_event_ids`, preserving order & uniqueness."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in raw_ids:
        if not isinstance(raw, str):
            continue
        eid = raw.strip()
        if not eid or eid in seen or eid not in valid_event_ids:
            continue
        seen.add(eid)
        out.append(eid)
    return out


def parse_utc_timestamp(value: Any) -> str | None:
    """Normalize a timestamp string to UTC ISO-8601 `Z` when parseable."""
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped:
        return None
    candidate = stripped[:-1] + "+00:00" if stripped.endswith("Z") else stripped
    try:
        dt = datetime.fromisoformat(candidate)
    except ValueError:
        return stripped
    if dt.tzinfo is None or dt.utcoffset() is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def resolve_rule_files(rules_dir: Path | None) -> list[Path]:
    """Discover Sigma `.yml`/`.yaml` or `.json` rule files safely."""
    if rules_dir is None or not rules_dir.exists():
        return []
    if rules_dir.is_file():
        return [rules_dir]
    if not rules_dir.is_dir():
        return []
    files = [
        p
        for p in sorted(rules_dir.rglob("*"))
        if p.is_file() and p.suffix.lower() in {".yml", ".yaml", ".json"}
    ]
    return files


def build_exec_argv(bin_path: Path, args: Sequence[str]) -> list[str]:
    """Build argv for an executable or Python script without shell invocation."""
    if bin_path.suffix.lower() == ".py" and not os.access(bin_path, os.X_OK):
        return [sys.executable, str(bin_path), *args]
    return [str(bin_path), *args]


def run_cli_readonly(
    argv: Sequence[str],
    *,
    timeout_s: float,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Execute an external detection CLI with `shell=False`, `stdin=DEVNULL`, and strict timeout."""
    if not argv:
        raise EngineError("Empty CLI argument list.", details={"argv": []})
    exe = argv[0]
    exe_path = Path(exe)
    if not (exe_path.is_file() or shutil.which(exe)):
        raise EngineError(
            f"Executable not found: {exe}",
            details={"executable": exe},
        )
    merged_env = dict(os.environ)
    if env:
        merged_env.update(env)
    try:
        return subprocess.run(
            list(argv),
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=timeout_s,
            cwd=str(cwd) if cwd is not None else None,
            env=merged_env,
        )
    except subprocess.TimeoutExpired as exc:
        raise OperationTimeoutError(
            f"Detection CLI timed out after {timeout_s}s: {exe_path.name}",
            details={"executable": exe, "timeout_s": timeout_s},
        ) from exc
    except OSError as exc:
        raise EngineError(
            f"Failed to execute detection CLI {exe_path.name}: {exc}",
            details={"executable": exe, "reason": str(exc)},
        ) from exc


def extract_version_text(text: str) -> str | None:
    """Extract a semver-like version string from CLI output."""
    if not text:
        return None
    match = _VERSION_PATTERN.search(text)
    return match.group(1) if match else None


def probe_engine_version(
    bin_path: Path,
    *,
    timeout_s: float = 5.0,
    cwd: Path | None = None,
) -> str:
    """Best-effort `--version` probe returning `'unknown'` on non-zero exit or failure."""
    try:
        argv = build_exec_argv(bin_path, ["--version"])
        proc = run_cli_readonly(argv, timeout_s=timeout_s, cwd=cwd)
    except (EngineError, OperationTimeoutError):
        return "unknown"
    if proc.returncode != 0:
        return "unknown"
    combined = "\n".join(part for part in (proc.stdout, proc.stderr) if part)
    return extract_version_text(combined) or "unknown"


__all__ = [
    "ALL_LOG_FORMATS",
    "AdapterOutput",
    "DetectionResult",
    "EngineAdapter",
    "TECHNIQUE_ID_PATTERN",
    "build_exec_argv",
    "classify_event_format",
    "extract_version_text",
    "make_hit_id",
    "make_lead_id",
    "normalize_level",
    "normalize_sigma_tags",
    "parse_utc_timestamp",
    "probe_engine_version",
    "repo_root",
    "resolve_config_path",
    "resolve_rule_files",
    "run_cli_readonly",
    "severity_rank",
    "validate_event_ids",
]
