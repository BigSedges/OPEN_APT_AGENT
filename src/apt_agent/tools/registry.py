"""Central role-scoped, case-scoped ToolRegistry with audit logging and LangGraph exports (F13)."""

from __future__ import annotations

import copy
import json
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from langchain_core.tools import StructuredTool, ToolException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from apt_agent.exceptions import (
    AptAgentError,
    ConfigError,
    InvalidArgumentError,
    OutOfScopeError,
    PermissionDeniedError,
)
from apt_agent.ingestion.store import RawEvidenceStore
from apt_agent.models import Event, RunContext
from apt_agent.tools.base_tools import (
    DEFAULT_BASH_ALLOWLIST,
    DEFAULT_BASH_MAX_OUTPUT_BYTES,
    DEFAULT_BASH_TIMEOUT_S,
    DEFAULT_READ_LIMIT,
    DEFAULT_WRITE_MAX_BYTES,
    tool_bash,
    tool_edit,
    tool_read,
    tool_write,
)
from apt_agent.tools.investigation import (
    _parse_time_bounds,
    _parse_utc_datetime,
    fetch_raw_evidence,
    query_events,
)
from apt_agent.tools.rag_service import RagService

REGISTERED_TOOLS: frozenset[str] = frozenset(
    {
        "read",
        "write",
        "edit",
        "bash",
        "fetch_raw_evidence",
        "query_events",
        "search_knowledge",
    }
)

INVESTIGATION_ROLES: frozenset[str] = frozenset(
    {"lead", "host", "network", "challenger", "verifier", "repair", "ranker"}
)
MAINTENANCE_ROLES: frozenset[str] = frozenset({"converter_agent", "rule_agent"})

_ROLE_ALIASES: dict[str, str] = {
    "lead": "lead",
    "lead_agent": "lead",
    "leadagent": "lead",
    "host": "host",
    "host_agent": "host",
    "hostagent": "host",
    "network": "network",
    "network_agent": "network",
    "networkagent": "network",
    "challenger": "challenger",
    "challenger_agent": "challenger",
    "challengeragent": "challenger",
    "verifier": "verifier",
    "verifier_agent": "verifier",
    "verifieragent": "verifier",
    "repair": "repair",
    "repair_agent": "repair",
    "repairagent": "repair",
    "ranker": "ranker",
    "ranker_agent": "ranker",
    "rankeragent": "ranker",
    "converter": "converter_agent",
    "converter_agent": "converter_agent",
    "converteragent": "converter_agent",
    "rule": "rule_agent",
    "rule_agent": "rule_agent",
    "ruleagent": "rule_agent",
}

_INVESTIGATION_ALLOWED_TOOLS: frozenset[str] = frozenset(
    {"fetch_raw_evidence", "query_events", "search_knowledge", "read"}
)
_MAINTENANCE_ALLOWED_TOOLS: frozenset[str] = frozenset(
    {"read", "write", "edit", "bash", "search_knowledge", "query_events"}
)

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    **{role: _INVESTIGATION_ALLOWED_TOOLS for role in INVESTIGATION_ROLES},
    **{role: _MAINTENANCE_ALLOWED_TOOLS for role in MAINTENANCE_ROLES},
}

_TOOL_ORDER: tuple[str, ...] = (
    "fetch_raw_evidence",
    "query_events",
    "search_knowledge",
    "read",
    "write",
    "edit",
    "bash",
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _format_utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_caller_role(role: str) -> str:
    """Normalize role identifiers (`HostAgent` / `host_agent` -> `host`)."""
    if not isinstance(role, str) or not role.strip():
        raise InvalidArgumentError("caller_role must be a non-blank string.")
    key = role.strip().lower().replace("-", "_").replace(" ", "_")
    if key in _ROLE_ALIASES:
        return _ROLE_ALIASES[key]
    raise PermissionDeniedError(
        f"Unknown or unauthorized caller role: {role!r}",
        details={"caller_role": role},
    )


class ToolCallResult(BaseModel):
    """Structured result returned by `ToolRegistry.invoke`."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    call_id: str
    tool_name: str
    caller_role: str
    case_id: str
    task_id: str | None = None
    query_id: str | None = None
    ok: bool
    data: dict[str, Any] = Field(default_factory=dict)
    error: dict[str, Any] | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    retrieval_id: str | None = None
    cached: bool = False

    @field_validator("call_id", "tool_name", "caller_role", "case_id")
    @classmethod
    def _validate_non_blank(cls, value: str, info: Any) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{info.field_name} must be a non-blank string.")
        return value

    @property
    def error_code(self) -> str | None:
        if self.error and isinstance(self.error, dict):
            code = self.error.get("code")
            return str(code) if code is not None else None
        return None

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class AuditLogEntry(BaseModel):
    """Immutable audit record emitted for every allowed, denied, or failed tool call."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    timestamp: str
    call_id: str
    caller_role: str
    tool_name: str
    case_id: str
    expected_case_id: str
    task_id: str | None = None
    allowed: bool
    outcome: Literal["ok", "denied", "error"]
    error_code: str | None = None
    reason: str | None = None
    arguments_summary: dict[str, Any] = Field(default_factory=dict)
    query_id: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# LangGraph StructuredTool Pydantic v2 argument schemas (role & case bound server-side)
# ---------------------------------------------------------------------------


class _ReadArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(description="Relative or sandbox-scoped file path to read.")
    offset: int = Field(default=0, ge=0, description="0-based line offset.")
    limit: int = Field(default=DEFAULT_READ_LIMIT, ge=1, le=2000, description="Max lines to read.")


class _WriteArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(description="File path inside the maintenance draft sandbox.")
    content: str = Field(description="UTF-8 file content to write.")
    overwrite: bool = Field(default=True, description="Whether to overwrite if file exists.")


class _EditArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(description="Existing file path inside the maintenance draft sandbox.")
    old_text: str = Field(min_length=1, description="Exact text snippet to replace.")
    new_text: str = Field(description="Replacement text.")
    replace_all: bool = Field(default=False, description="Replace all occurrences if True.")


class _BashArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command: str | list[str] = Field(
        description="Allowlisted command string or argument list executed with shell=False."
    )


class _FetchRawEvidenceArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    physical_ids: list[str] = Field(
        min_length=1,
        description="List of physical_record_id values to fetch from RawEvidenceStore.",
    )
    strict_scope: bool = Field(
        default=False,
        description="If true, reject missing IDs outside valid_physical_ids as OUT_OF_SCOPE.",
    )


class _QueryEventsArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filters: dict[str, Any] | None = Field(
        default=None,
        description="Structured event filters (host, entity, source_type, time_window, etc.).",
    )
    limit: int = Field(default=50, ge=1, le=500, description="Maximum events per page.")
    cursor: str | None = Field(default=None, description="Pagination cursor from prior response.")
    include_edges: bool = Field(
        default=False,
        description="Whether to return candidate lineage/flow edges for matched events.",
    )


class _SearchKnowledgeArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1, max_length=2000, description="Knowledge base search query.")
    top_k: int = Field(default=5, ge=1, le=20, description="Maximum knowledge references to return.")
    mode: Literal["bm25", "dense", "hybrid"] | None = Field(
        default=None,
        description="Retrieval mode (bm25, dense, or hybrid).",
    )
    filters: dict[str, Any] | None = Field(
        default=None,
        description="Optional metadata filters (product, version, logsource, field, rule_id).",
    )
    snapshot_id: str | None = Field(
        default=None,
        description="Optional knowledge snapshot identifier.",
    )


_TOOL_SPECS: dict[str, tuple[type[BaseModel], str]] = {
    "fetch_raw_evidence": (
        _FetchRawEvidenceArgs,
        "Fetch raw unmodified evidence records by physical_record_id within the active case.",
    ),
    "query_events": (
        _QueryEventsArgs,
        "Query normalized log events within the active case using structured filters and pagination.",
    ),
    "search_knowledge": (
        _SearchKnowledgeArgs,
        "Read-only search of the APT knowledge base (fields, Sigma rules, ATT&CK, playbooks). Never returns case evidence IDs.",
    ),
    "read": (
        _ReadArgs,
        "Read UTF-8 text from an allowed read-only workspace or sandbox file.",
    ),
    "write": (
        _WriteArgs,
        "Write UTF-8 text to a file strictly inside the maintenance draft sandbox.",
    ),
    "edit": (
        _EditArgs,
        "Replace exact text in an existing file inside the maintenance draft sandbox.",
    ),
    "bash": (
        _BashArgs,
        "Execute an allowlisted inspection command (shell=False) inside the maintenance draft sandbox.",
    ),
}


def _summarize_arguments(arguments: Mapping[str, Any] | None) -> dict[str, Any]:
    if not arguments:
        return {}
    summary: dict[str, Any] = {}
    for key, val in arguments.items():
        if isinstance(val, str) and len(val) > 120:
            summary[str(key)] = val[:117] + "..."
        elif isinstance(val, list) and len(val) > 10:
            summary[str(key)] = [*val[:5], f"...({len(val)} items)"]
        else:
            summary[str(key)] = copy.deepcopy(val)
    return summary


def _parse_window_pair(
    window: tuple[str, str] | Sequence[str], *, label: str
) -> tuple[datetime, datetime]:
    if (
        not isinstance(window, Sequence)
        or isinstance(window, (str, bytes, bytearray, Mapping))
        or len(window) != 2
    ):
        raise InvalidArgumentError(
            f"{label} must be a 2-tuple of UTC ISO-8601 strings (start, end).",
            details={"label": label, "value": window},
        )
    start_dt = _parse_utc_datetime(window[0], field_name=f"{label}[0]")
    end_dt = _parse_utc_datetime(window[1], field_name=f"{label}[1]")
    if start_dt > end_dt:
        raise InvalidArgumentError(
            f"{label} start must be <= end.",
            details={"label": label, "start": window[0], "end": window[1]},
        )
    return start_dt, end_dt


class ToolRegistry:
    """Central permission, case-scope, time-window, and audit registry for all M4 tools."""

    def __init__(
        self,
        ctx: RunContext,
        store: RawEvidenceStore,
        events: Sequence[Event],
        rag_service: RagService | None = None,
        workspace_root: Path | str | None = None,
        draft_sandbox_root: Path | str | None = None,
        *,
        read_roots: Sequence[Path | str] | None = None,
        protected_roots: Sequence[Path | str] | None = None,
        bash_allowlist: Iterable[str] | None = None,
        bash_timeout_s: float = DEFAULT_BASH_TIMEOUT_S,
        max_output_bytes: int = DEFAULT_BASH_MAX_OUTPUT_BYTES,
        case_time_window: tuple[str, str] | None = None,
    ) -> None:
        if not isinstance(ctx, RunContext):
            raise InvalidArgumentError("ctx must be a RunContext instance.")
        if not isinstance(store, RawEvidenceStore):
            raise InvalidArgumentError("store must be a RawEvidenceStore instance.")
        if store.case_id != ctx.case_id:
            raise OutOfScopeError(
                f"Store case_id {store.case_id!r} does not match ctx.case_id {ctx.case_id!r}."
            )

        self.ctx = ctx
        self.store = store
        self.events: list[Event] = list(events)
        self.rag_service = rag_service if rag_service is not None else RagService(ctx)
        self.workspace_root = Path(workspace_root) if workspace_root is not None else None
        self.draft_sandbox_root = (
            Path(draft_sandbox_root) if draft_sandbox_root is not None else None
        )
        self.read_roots: tuple[Path, ...] = tuple(Path(p) for p in (read_roots or ()))
        self.bash_allowlist: frozenset[str] = (
            frozenset(bash_allowlist) if bash_allowlist is not None else DEFAULT_BASH_ALLOWLIST
        )
        self.bash_timeout_s = float(bash_timeout_s)
        self.max_output_bytes = int(max_output_bytes)
        self.case_time_window = (
            _parse_window_pair(case_time_window, label="case_time_window")
            if case_time_window is not None
            else None
        )

        # Always protect active snapshots root and any explicit protected roots from mutation.
        prot_list: list[Path] = [Path(p) for p in (protected_roots or ())]
        if ctx.config is not None and ctx.config.snapshots is not None:
            prot_list.append(Path(ctx.config.snapshots.root_dir))
        self.protected_roots: tuple[Path, ...] = tuple(prot_list)

        self._events_by_id: dict[str, Event] = {ev.event_id: ev for ev in self.events}
        self._events_by_pid: dict[str, list[Event]] = defaultdict(list)
        for ev in self.events:
            self._events_by_pid[ev.physical_record_id].append(ev)

        self._audit_log: list[AuditLogEntry] = []
        self._task_queries: dict[str, dict[str, set[str]]] = defaultdict(dict)

    @property
    def audit_log(self) -> list[AuditLogEntry]:
        return list(self._audit_log)

    def get_task_queried_event_ids(self, task_id: str) -> set[str]:
        queries = self._task_queries.get(task_id)
        if not queries:
            return set()
        merged: set[str] = set()
        for eids in queries.values():
            merged.update(eids)
        return merged

    def get_task_query_map(self, task_id: str) -> dict[str, set[str]]:
        return {qid: set(eids) for qid, eids in self._task_queries.get(task_id, {}).items()}

    def _record_audit(
        self,
        *,
        call_id: str,
        caller_role: str,
        tool_name: str,
        case_id: str,
        task_id: str | None,
        allowed: bool,
        outcome: Literal["ok", "denied", "error"],
        error_code: str | None,
        reason: str | None,
        arguments: Mapping[str, Any] | None,
        query_id: str | None = None,
        evidence_ids: Sequence[str] = (),
        event_ids: Sequence[str] = (),
    ) -> None:
        self._audit_log.append(
            AuditLogEntry(
                timestamp=_utc_now_iso(),
                call_id=call_id,
                caller_role=caller_role,
                tool_name=tool_name,
                case_id=case_id,
                expected_case_id=self.ctx.case_id,
                task_id=task_id,
                allowed=allowed,
                outcome=outcome,
                error_code=error_code,
                reason=reason,
                arguments_summary=_summarize_arguments(arguments),
                query_id=query_id,
                evidence_ids=list(evidence_ids),
                event_ids=list(event_ids),
            )
        )

    def _error_result(
        self,
        *,
        call_id: str,
        tool_name: str,
        caller_role: str,
        case_id: str,
        task_id: str | None,
        exc: AptAgentError,
        allowed: bool,
        outcome: Literal["denied", "error"],
        arguments: Mapping[str, Any] | None,
        query_id: str | None = None,
    ) -> ToolCallResult:
        wire = exc.to_wire_error()
        self._record_audit(
            call_id=call_id,
            caller_role=caller_role,
            tool_name=tool_name,
            case_id=case_id,
            task_id=task_id,
            allowed=allowed,
            outcome=outcome,
            error_code=wire["code"],
            reason=wire["message"],
            arguments=arguments,
            query_id=query_id,
        )
        return ToolCallResult(
            call_id=call_id,
            tool_name=tool_name,
            caller_role=caller_role,
            case_id=case_id,
            task_id=task_id,
            query_id=query_id,
            ok=False,
            data={},
            error=wire,
            evidence_ids=[],
            event_ids=[],
        )

    def _resolve_effective_window(
        self, event_time_window: tuple[str, str] | None
    ) -> tuple[datetime, datetime] | None:
        if event_time_window is not None:
            ev_start, ev_end = _parse_window_pair(
                event_time_window, label="event_time_window"
            )
            if self.case_time_window is not None:
                c_start, c_end = self.case_time_window
                if ev_start < c_start or ev_end > c_end:
                    raise OutOfScopeError(
                        "Requested event_time_window exceeds case_time_window boundary.",
                        details={
                            "event_time_window": list(event_time_window),
                            "case_time_window": [
                                _format_utc_iso(c_start),
                                _format_utc_iso(c_end),
                            ],
                        },
                    )
            return ev_start, ev_end
        return self.case_time_window

    def _enforce_query_time_window(
        self,
        filters: Mapping[str, Any] | None,
        eff_window: tuple[datetime, datetime] | None,
    ) -> dict[str, Any] | None:
        if filters is not None and not isinstance(filters, Mapping):
            raise InvalidArgumentError(
                "filters must be a mapping or None.",
                details={"type": type(filters).__name__},
            )
        if eff_window is None:
            return dict(filters) if filters is not None else None

        eff_start, eff_end = eff_window
        eff_pair = [_format_utc_iso(eff_start), _format_utc_iso(eff_end)]
        if filters is None:
            return {"time_window": eff_pair}

        out_filters = dict(filters)
        req_start, req_end, _ = _parse_time_bounds(out_filters)
        if req_start is not None and (req_start < eff_start or req_start >= eff_end):
            raise OutOfScopeError(
                "Requested query start time is outside authorized event_time_window.",
                details={"requested_start": _format_utc_iso(req_start), "window": eff_pair},
            )
        if req_end is not None and (req_end > eff_end or req_end < eff_start):
            raise OutOfScopeError(
                "Requested query end time is outside authorized event_time_window.",
                details={"requested_end": _format_utc_iso(req_end), "window": eff_pair},
            )

        # Reject explicit event_id / physical_record_id lookups pointing outside eff_window.
        explicit_events: list[Event] = []
        for key in ("event_id", "event_ids"):
            val = out_filters.get(key)
            if isinstance(val, str):
                ev = self._events_by_id.get(val.strip())
                if ev is not None:
                    explicit_events.append(ev)
            elif isinstance(val, Iterable) and not isinstance(val, (bytes, bytearray, Mapping)):
                for item in val:
                    if isinstance(item, str):
                        ev = self._events_by_id.get(item.strip())
                        if ev is not None:
                            explicit_events.append(ev)
        for key in ("physical_record_id", "physical_record_ids"):
            val = out_filters.get(key)
            if isinstance(val, str):
                explicit_events.extend(self._events_by_pid.get(val.strip(), ()))
            elif isinstance(val, Iterable) and not isinstance(val, (bytes, bytearray, Mapping)):
                for item in val:
                    if isinstance(item, str):
                        explicit_events.extend(self._events_by_pid.get(item.strip(), ()))

        for ev in explicit_events:
            if ev.event_time is None:
                raise OutOfScopeError(
                    f"Event {ev.event_id!r} lacks timestamp for window-scoped access.",
                    details={"event_id": ev.event_id, "window": eff_pair},
                )
            ev_dt = _parse_utc_datetime(ev.event_time)
            if ev_dt < eff_start or ev_dt >= eff_end:
                raise OutOfScopeError(
                    f"Event {ev.event_id!r} at {ev.event_time} is outside authorized time window.",
                    details={
                        "event_id": ev.event_id,
                        "event_time": ev.event_time,
                        "window": eff_pair,
                    },
                )

        if req_start is None and req_end is None:
            out_filters["time_window"] = eff_pair
        else:
            clamped_start = max(req_start, eff_start) if req_start is not None else eff_start
            clamped_end = min(req_end, eff_end) if req_end is not None else eff_end
            out_filters.pop("start_time", None)
            out_filters.pop("end_time", None)
            out_filters["time_window"] = [
                _format_utc_iso(clamped_start),
                _format_utc_iso(clamped_end),
            ]
        return out_filters

    def _enforce_fetch_time_window(
        self,
        physical_ids: Any,
        eff_window: tuple[datetime, datetime] | None,
    ) -> None:
        if eff_window is None:
            return
        if not isinstance(physical_ids, Iterable) or isinstance(
            physical_ids, (str, bytes, bytearray, Mapping)
        ):
            return
        eff_start, eff_end = eff_window
        eff_pair = [_format_utc_iso(eff_start), _format_utc_iso(eff_end)]
        for pid in physical_ids:
            if not isinstance(pid, str):
                continue
            for ev in self._events_by_pid.get(pid, ()):
                if ev.event_time is None:
                    raise OutOfScopeError(
                        f"Record {pid!r} has un-timestamped event outside time window.",
                        details={"physical_record_id": pid, "window": eff_pair},
                    )
                ev_dt = _parse_utc_datetime(ev.event_time)
                if ev_dt < eff_start or ev_dt >= eff_end:
                    raise OutOfScopeError(
                        f"Record {pid!r} falls outside authorized event_time_window.",
                        details={
                            "physical_record_id": pid,
                            "event_time": ev.event_time,
                            "window": eff_pair,
                        },
                    )

    def _allowed_read_roots_for_role(self, canonical_role: str) -> list[Path]:
        roots: list[Path] = []
        if canonical_role in MAINTENANCE_ROLES and self.draft_sandbox_root is not None:
            roots.append(self.draft_sandbox_root)
        if self.workspace_root is not None:
            roots.append(self.workspace_root)
        roots.extend(self.read_roots)
        # Deduplicate while preserving order.
        deduped: list[Path] = []
        seen: set[Path] = set()
        for r in roots:
            if r not in seen:
                seen.add(r)
                deduped.append(r)
        return deduped

    def invoke(
        self,
        caller_role: str,
        tool_name: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        case_id: str,
        task_id: str | None = None,
        event_time_window: tuple[str, str] | None = None,
    ) -> ToolCallResult:
        """Validate permissions, case scope, and time window, execute tool, and audit."""
        call_id = f"call_{uuid4().hex[:16]}"
        if arguments is None:
            args: dict[str, Any] = {}
        elif isinstance(arguments, Mapping):
            args = dict(arguments)
        else:
            args = {"_raw_arguments": repr(arguments)[:120]}

        raw_role = caller_role if isinstance(caller_role, str) and caller_role.strip() else str(caller_role)
        raw_tool = tool_name if isinstance(tool_name, str) and tool_name.strip() else str(tool_name)
        raw_case = case_id if isinstance(case_id, str) and case_id.strip() else str(case_id)

        if not isinstance(caller_role, str) or not caller_role.strip():
            return self._error_result(
                call_id=call_id,
                tool_name=raw_tool,
                caller_role=raw_role,
                case_id=raw_case,
                task_id=task_id,
                exc=InvalidArgumentError("caller_role must be a non-blank string."),
                allowed=False,
                outcome="denied",
                arguments=args,
            )
        if not isinstance(tool_name, str) or not tool_name.strip():
            return self._error_result(
                call_id=call_id,
                tool_name=raw_tool,
                caller_role=raw_role,
                case_id=raw_case,
                task_id=task_id,
                exc=InvalidArgumentError("tool_name must be a non-blank string."),
                allowed=False,
                outcome="denied",
                arguments=args,
            )
        if not isinstance(case_id, str) or not case_id.strip():
            return self._error_result(
                call_id=call_id,
                tool_name=tool_name,
                caller_role=raw_role,
                case_id=raw_case,
                task_id=task_id,
                exc=InvalidArgumentError("case_id must be a non-blank string."),
                allowed=False,
                outcome="denied",
                arguments=args,
            )

        # 1. Case boundary enforcement (always checked first -> OUT_OF_SCOPE)
        if case_id != self.ctx.case_id:
            return self._error_result(
                call_id=call_id,
                tool_name=tool_name,
                caller_role=raw_role,
                case_id=case_id,
                task_id=task_id,
                exc=OutOfScopeError(
                    f"Cross-case tool call denied: {case_id!r} != {self.ctx.case_id!r}.",
                    details={"case_id": case_id, "expected_case_id": self.ctx.case_id},
                ),
                allowed=False,
                outcome="denied",
                arguments=args,
            )

        # 2. Tool registration check
        if tool_name not in REGISTERED_TOOLS:
            return self._error_result(
                call_id=call_id,
                tool_name=tool_name,
                caller_role=raw_role,
                case_id=case_id,
                task_id=task_id,
                exc=InvalidArgumentError(
                    f"Unregistered tool: {tool_name!r}",
                    details={"tool_name": tool_name},
                ),
                allowed=False,
                outcome="denied",
                arguments=args,
            )

        # 3. Role normalization & permission matrix enforcement
        try:
            canonical_role = normalize_caller_role(caller_role)
        except AptAgentError as exc:
            return self._error_result(
                call_id=call_id,
                tool_name=tool_name,
                caller_role=raw_role,
                case_id=case_id,
                task_id=task_id,
                exc=exc,
                allowed=False,
                outcome="denied",
                arguments=args,
            )

        allowed_tools = ROLE_PERMISSIONS.get(canonical_role, frozenset())
        if tool_name not in allowed_tools:
            return self._error_result(
                call_id=call_id,
                tool_name=tool_name,
                caller_role=canonical_role,
                case_id=case_id,
                task_id=task_id,
                exc=PermissionDeniedError(
                    f"Role {canonical_role!r} is not permitted to invoke tool {tool_name!r}.",
                    details={"caller_role": canonical_role, "tool_name": tool_name},
                ),
                allowed=False,
                outcome="denied",
                arguments=args,
            )

        # 4. Time window check
        try:
            eff_window = self._resolve_effective_window(event_time_window)
        except AptAgentError as exc:
            return self._error_result(
                call_id=call_id,
                tool_name=tool_name,
                caller_role=canonical_role,
                case_id=case_id,
                task_id=task_id,
                exc=exc,
                allowed=False,
                outcome="denied",
                arguments=args,
            )

        # 5. Execute tool safely
        try:
            if arguments is not None and not isinstance(arguments, Mapping):
                raise InvalidArgumentError(
                    "arguments must be a mapping or None.",
                    details={"type": type(arguments).__name__},
                )
            if tool_name == "fetch_raw_evidence":
                if "physical_ids" not in args:
                    raise InvalidArgumentError("fetch_raw_evidence requires 'physical_ids'.")
                self._enforce_fetch_time_window(args["physical_ids"], eff_window)
                res = fetch_raw_evidence(
                    self.ctx,
                    self.store,
                    args["physical_ids"],
                    task_id=task_id,
                    strict_scope=bool(args.get("strict_scope", False)),
                )
                serialized = {
                    **res,
                    "records": [rec.model_dump(mode="json") for rec in res["records"]],
                }
                query_id = res["query_id"]
                evidence_ids = list(res["evidence_ids"])
                self._record_audit(
                    call_id=call_id,
                    caller_role=canonical_role,
                    tool_name=tool_name,
                    case_id=case_id,
                    task_id=task_id,
                    allowed=True,
                    outcome="ok",
                    error_code=None,
                    reason=None,
                    arguments=args,
                    query_id=query_id,
                    evidence_ids=evidence_ids,
                )
                return ToolCallResult(
                    call_id=call_id,
                    tool_name=tool_name,
                    caller_role=canonical_role,
                    case_id=case_id,
                    task_id=task_id,
                    query_id=query_id,
                    ok=True,
                    data=serialized,
                    evidence_ids=evidence_ids,
                    event_ids=[],
                )

            if tool_name == "query_events":
                effective_task_id = task_id or args.get("task_id") or "default_task"
                scoped_filters = self._enforce_query_time_window(
                    args.get("filters"), eff_window
                )
                res = query_events(
                    self.ctx,
                    self.events,
                    effective_task_id,
                    filters=scoped_filters,
                    limit=args.get("limit", 50),
                    cursor=args.get("cursor"),
                    include_edges=bool(args.get("include_edges", False)),
                )
                serialized = {
                    **res,
                    "events": [ev.model_dump(mode="json") for ev in res["events"]],
                    "edges": [edge.model_dump(mode="json") for edge in res["edges"]],
                }
                query_id = res["query_id"]
                event_ids = list(res["event_ids"])
                evidence_ids = list(res["evidence_ids"])
                if effective_task_id:
                    self._task_queries[effective_task_id][query_id] = set(event_ids)
                self._record_audit(
                    call_id=call_id,
                    caller_role=canonical_role,
                    tool_name=tool_name,
                    case_id=case_id,
                    task_id=task_id,
                    allowed=True,
                    outcome="ok",
                    error_code=None,
                    reason=None,
                    arguments=args,
                    query_id=query_id,
                    evidence_ids=evidence_ids,
                    event_ids=event_ids,
                )
                return ToolCallResult(
                    call_id=call_id,
                    tool_name=tool_name,
                    caller_role=canonical_role,
                    case_id=case_id,
                    task_id=task_id,
                    query_id=query_id,
                    ok=True,
                    data=serialized,
                    evidence_ids=evidence_ids,
                    event_ids=event_ids,
                )

            if tool_name == "search_knowledge":
                if "query" not in args:
                    raise InvalidArgumentError("search_knowledge requires 'query'.")
                rag_res = self.rag_service.search_knowledge(
                    args["query"],
                    role=canonical_role,
                    filters=args.get("filters"),
                    top_k=args.get("top_k"),
                    mode=args.get("mode"),
                    snapshot_id=args.get("snapshot_id"),
                )
                # Defense-in-depth knowledge isolation check at registry boundary.
                rag_eids = rag_res.get("evidence_ids")
                if not isinstance(rag_eids, list) or len(rag_eids) > 0:
                    raise OutOfScopeError(
                        "Knowledge retrieval attempted to return non-empty evidence_ids.",
                        details={"evidence_ids": rag_eids},
                    )
                retrieval_id = rag_res.get("retrieval_id")
                cached = bool(rag_res.get("cached", False))
                if not rag_res.get("ok"):
                    err = rag_res.get("error") or {
                        "code": "RETRIEVAL_UNAVAILABLE",
                        "message": "RAG retrieval failed.",
                        "retryable": True,
                    }
                    err_code = str(err.get("code") or "RETRIEVAL_UNAVAILABLE")
                    outcome: Literal["denied", "error"] = (
                        "denied" if err_code in {"OUT_OF_SCOPE", "PERMISSION_DENIED"} else "error"
                    )
                    self._record_audit(
                        call_id=call_id,
                        caller_role=canonical_role,
                        tool_name=tool_name,
                        case_id=case_id,
                        task_id=task_id,
                        allowed=(outcome != "denied"),
                        outcome=outcome,
                        error_code=err_code,
                        reason=str(err.get("message") or ""),
                        arguments=args,
                    )
                    return ToolCallResult(
                        call_id=call_id,
                        tool_name=tool_name,
                        caller_role=canonical_role,
                        case_id=case_id,
                        task_id=task_id,
                        ok=False,
                        data=rag_res,
                        error=dict(err),
                        evidence_ids=[],
                        event_ids=[],
                        retrieval_id=retrieval_id,
                        cached=cached,
                    )

                self._record_audit(
                    call_id=call_id,
                    caller_role=canonical_role,
                    tool_name=tool_name,
                    case_id=case_id,
                    task_id=task_id,
                    allowed=True,
                    outcome="ok",
                    error_code=None,
                    reason=None,
                    arguments=args,
                    evidence_ids=[],
                    event_ids=[],
                )
                return ToolCallResult(
                    call_id=call_id,
                    tool_name=tool_name,
                    caller_role=canonical_role,
                    case_id=case_id,
                    task_id=task_id,
                    ok=True,
                    data=rag_res,
                    evidence_ids=[],
                    event_ids=[],
                    retrieval_id=retrieval_id,
                    cached=cached,
                )

            if tool_name == "read":
                if "path" not in args:
                    raise InvalidArgumentError("read requires 'path'.")
                allowed_roots = self._allowed_read_roots_for_role(canonical_role)
                if not allowed_roots:
                    raise ConfigError("No workspace_root or read_roots configured for read tool.")
                res = tool_read(
                    args["path"],
                    allowed_roots=allowed_roots,
                    offset=args.get("offset", 0),
                    limit=args.get("limit", DEFAULT_READ_LIMIT),
                    max_bytes=args.get("max_bytes", self.max_output_bytes),
                )
                self._record_audit(
                    call_id=call_id,
                    caller_role=canonical_role,
                    tool_name=tool_name,
                    case_id=case_id,
                    task_id=task_id,
                    allowed=True,
                    outcome="ok",
                    error_code=None,
                    reason=None,
                    arguments=args,
                )
                return ToolCallResult(
                    call_id=call_id,
                    tool_name=tool_name,
                    caller_role=canonical_role,
                    case_id=case_id,
                    task_id=task_id,
                    ok=True,
                    data=res,
                )

            if tool_name in {"write", "edit", "bash"}:
                if self.draft_sandbox_root is None:
                    raise PermissionDeniedError(
                        f"Tool {tool_name!r} requires a configured draft_sandbox_root for maintenance roles.",
                        details={"caller_role": canonical_role, "tool_name": tool_name},
                    )
                if tool_name == "write":
                    if "path" not in args or "content" not in args:
                        raise InvalidArgumentError("write requires 'path' and 'content'.")
                    res = tool_write(
                        args["path"],
                        args["content"],
                        sandbox_root=self.draft_sandbox_root,
                        overwrite=args.get("overwrite", True),
                        max_bytes=args.get("max_bytes", DEFAULT_WRITE_MAX_BYTES),
                        protected_roots=self.protected_roots,
                    )
                elif tool_name == "edit":
                    if "path" not in args or "old_text" not in args or "new_text" not in args:
                        raise InvalidArgumentError(
                            "edit requires 'path', 'old_text', and 'new_text'."
                        )
                    res = tool_edit(
                        args["path"],
                        args["old_text"],
                        args["new_text"],
                        sandbox_root=self.draft_sandbox_root,
                        replace_all=args.get("replace_all", False),
                        max_bytes=args.get("max_bytes", DEFAULT_WRITE_MAX_BYTES),
                        protected_roots=self.protected_roots,
                    )
                else:
                    if "command" not in args:
                        raise InvalidArgumentError("bash requires 'command'.")
                    res = tool_bash(
                        args["command"],
                        sandbox_root=self.draft_sandbox_root,
                        read_roots=self._allowed_read_roots_for_role(canonical_role),
                        allowed_commands=self.bash_allowlist,
                        timeout_s=args.get("timeout_s", self.bash_timeout_s),
                        max_output_bytes=args.get("max_output_bytes", self.max_output_bytes),
                        protected_roots=self.protected_roots,
                    )
                self._record_audit(
                    call_id=call_id,
                    caller_role=canonical_role,
                    tool_name=tool_name,
                    case_id=case_id,
                    task_id=task_id,
                    allowed=True,
                    outcome="ok",
                    error_code=None,
                    reason=None,
                    arguments=args,
                )
                return ToolCallResult(
                    call_id=call_id,
                    tool_name=tool_name,
                    caller_role=canonical_role,
                    case_id=case_id,
                    task_id=task_id,
                    ok=True,
                    data=res,
                )

            raise InvalidArgumentError(f"Unhandled tool: {tool_name!r}")
        except (OutOfScopeError, PermissionDeniedError) as exc:
            return self._error_result(
                call_id=call_id,
                tool_name=tool_name,
                caller_role=canonical_role,
                case_id=case_id,
                task_id=task_id,
                exc=exc,
                allowed=False,
                outcome="denied",
                arguments=args,
            )
        except AptAgentError as exc:
            return self._error_result(
                call_id=call_id,
                tool_name=tool_name,
                caller_role=canonical_role,
                case_id=case_id,
                task_id=task_id,
                exc=exc,
                allowed=True,
                outcome="error",
                arguments=args,
            )

    def to_langchain_tools(
        self,
        caller_role: str,
        *,
        case_id: str | None = None,
        task_id: str | None = None,
        event_time_window: tuple[str, str] | None = None,
        include_denied: bool = False,
    ) -> list[StructuredTool]:
        """Export role-scoped LangGraph `StructuredTool` bindings with host-bound role/case."""
        canonical_role = normalize_caller_role(caller_role)
        bound_case_id = case_id if case_id is not None else self.ctx.case_id
        allowed = ROLE_PERMISSIONS.get(canonical_role, frozenset())

        tools: list[StructuredTool] = []
        for tool_name in _TOOL_ORDER:
            if not include_denied and tool_name not in allowed:
                continue
            args_schema, description = _TOOL_SPECS[tool_name]

            def _make_func(t_name: str):
                def _invoke_tool(**kwargs: Any) -> str:
                    res = self.invoke(
                        canonical_role,
                        t_name,
                        kwargs,
                        case_id=bound_case_id,
                        task_id=task_id,
                        event_time_window=event_time_window,
                    )
                    if not res.ok:
                        raise ToolException(json.dumps(res.to_dict(), ensure_ascii=False))
                    return json.dumps(res.to_dict()["data"], ensure_ascii=False)

                return _invoke_tool

            tools.append(
                StructuredTool.from_function(
                    func=_make_func(tool_name),
                    name=tool_name,
                    description=description,
                    args_schema=args_schema,
                    handle_tool_error=True,
                )
            )
        return tools

    get_langchain_tools = to_langchain_tools


__all__ = [
    "AuditLogEntry",
    "INVESTIGATION_ROLES",
    "MAINTENANCE_ROLES",
    "REGISTERED_TOOLS",
    "ROLE_PERMISSIONS",
    "ToolCallResult",
    "ToolRegistry",
    "normalize_caller_role",
]
