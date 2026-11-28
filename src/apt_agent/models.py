"""Core domain, evidence, blackboard, and export models for OPEN_APT_AGENT."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from collections.abc import Set as AbstractSet
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from apt_agent.config import AppConfig, BudgetConfig

TACTIC_ID_PATTERN = re.compile(r"\ATA[0-9]{4}\Z")


def _require_non_blank(value: str, field_name: str = "value") -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-blank string.")
    return value


def _reject_bool_int(value: Any) -> Any:
    if isinstance(value, bool):
        raise ValueError("Boolean value is not valid for an integer field.")
    return value


class Locator(BaseModel):
    """Exact source file and 1-based line number locator for a raw record."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    filepath: str
    linenumber: int = Field(ge=1, strict=True)

    @field_validator("filepath")
    @classmethod
    def _validate_filepath(cls, value: str) -> str:
        return _require_non_blank(value, "filepath")

    @field_validator("linenumber", mode="before")
    @classmethod
    def _validate_linenumber(cls, value: Any) -> Any:
        return _reject_bool_int(value)


class RunContext(BaseModel):
    """Immutable snapshot, budget, and scope bindings for a single case run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    run_id: str
    data_snapshot_id: str = "default"
    mapping_version: str = "v1"
    ruleset_version: str = "v1"
    knowledge_snapshot_id: str = "public_kb"
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    engine_versions: dict[str, str] = Field(default_factory=dict)
    stop_reason: str | None = None
    config: AppConfig | None = None
    valid_physical_ids: frozenset[str] | None = None
    locator_map: dict[str, Locator] | None = None

    @field_validator(
        "case_id",
        "run_id",
        "data_snapshot_id",
        "mapping_version",
        "ruleset_version",
        "knowledge_snapshot_id",
    )
    @classmethod
    def _validate_non_blank_ids(cls, value: str, info: Any) -> str:
        return _require_non_blank(value, info.field_name)

    @field_validator("valid_physical_ids")
    @classmethod
    def _validate_valid_physical_ids(
        cls, value: frozenset[str] | None
    ) -> frozenset[str] | None:
        if value is None:
            return None
        for item in value:
            _require_non_blank(item, "valid_physical_ids item")
        return value


CaseRun = RunContext


class RawRecord(BaseModel):
    """Unmodified input record stored in RawEvidenceStore for provenance replay."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    physical_record_id: str
    payload: dict[str, Any]
    locator: Locator | None = None
    raw_id: str | None = None
    source_hint: str | None = None
    content_digest: str | None = None

    @field_validator("physical_record_id")
    @classmethod
    def _validate_physical_id(cls, value: str) -> str:
        return _require_non_blank(value, "physical_record_id")

    @field_validator("payload")
    @classmethod
    def _isolate_payload(cls, value: dict[str, Any]) -> dict[str, Any]:
        return copy.deepcopy(value)

    @field_validator("raw_id")
    @classmethod
    def _validate_raw_id(cls, value: str | None) -> str | None:
        if value is not None:
            return _require_non_blank(value, "raw_id")
        return None

    @model_validator(mode="after")
    def _default_raw_id(self) -> RawRecord:
        if self.raw_id is None:
            object.__setattr__(self, "raw_id", self.physical_record_id)
        return self


class Event(BaseModel):
    """Normalized log event derived 1->0..N from a RawRecord."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str
    physical_record_id: str
    raw_id: str | None = None
    source_type: str | None = None
    event_time: str | None = None
    fields: dict[str, Any] = Field(default_factory=dict)
    host: str | None = None
    parse_metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("event_id", "physical_record_id")
    @classmethod
    def _validate_ids(cls, value: str, info: Any) -> str:
        return _require_non_blank(value, info.field_name)

    @field_validator("raw_id")
    @classmethod
    def _validate_raw_id(cls, value: str | None) -> str | None:
        if value is not None:
            return _require_non_blank(value, "raw_id")
        return None

    @field_validator("event_time", mode="before")
    @classmethod
    def _validate_event_time(cls, value: Any) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("event_time must be an ISO-8601 string or None.")
        stripped = value.strip()
        if not stripped:
            return None
        parsed = datetime.fromisoformat(stripped)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("event_time must be timezone-aware UTC ISO-8601.")
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @model_validator(mode="after")
    def _default_raw_id(self) -> Event:
        if self.raw_id is None:
            object.__setattr__(self, "raw_id", self.physical_record_id)
        return self


class Hit(BaseModel):
    """Detection engine rule match referencing 0..N normalized events."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hit_id: str
    rule_id: str
    rule_version: str = "unknown"
    engine: str
    engine_version: str = "unknown"
    event_ids: list[str] = Field(default_factory=list)
    tactic_ids: list[str] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)
    matched_time: str | None = None
    level: str | None = None
    matched_fields: dict[str, Any] = Field(default_factory=dict)

    @field_validator("hit_id", "rule_id", "engine")
    @classmethod
    def _validate_required_ids(cls, value: str, info: Any) -> str:
        return _require_non_blank(value, info.field_name)

    @property
    def is_lead_only(self) -> bool:
        """Return True for count-only correlation hits lacking constituent event IDs."""
        return len(self.event_ids) == 0


class RuleRun(BaseModel):
    """Execution coverage record for a detection rule/engine run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str
    engine: str
    engine_version: str = "unknown"
    rule_version: str = "unknown"
    status: Literal["ran", "partial", "skipped", "failed"]
    reason: str | None = None
    hit_count: int = Field(default=0, ge=0)

    @field_validator("rule_id", "engine")
    @classmethod
    def _validate_required_ids(cls, value: str, info: Any) -> str:
        return _require_non_blank(value, info.field_name)

    @field_validator("hit_count", mode="before")
    @classmethod
    def _validate_hit_count(cls, value: Any) -> Any:
        return _reject_bool_int(value)


class KnowledgeRef(BaseModel):
    """Reproducible reference to external knowledge retrieved via RAG."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    retrieval_id: str
    doc_id: str
    chunk_id: str
    version: str
    locator: str
    excerpt: str
    match_reason: str
    source_url: str | None = None
    author: str | None = None

    @field_validator(
        "retrieval_id",
        "doc_id",
        "chunk_id",
        "version",
        "locator",
        "excerpt",
        "match_reason",
    )
    @classmethod
    def _validate_required_strings(cls, value: str, info: Any) -> str:
        return _require_non_blank(value, info.field_name)


class Finding(BaseModel):
    """Mutable investigator claim linking evidence events and optional knowledge."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    finding_id: str = Field(default_factory=lambda: uuid4().hex)
    claim: str
    status: Literal["observed", "hypothesis", "disputed"]
    evidence_event_ids: list[str] = Field(default_factory=list)
    opposing_event_ids: list[str] = Field(default_factory=list)
    knowledge_refs: list[KnowledgeRef] = Field(default_factory=list)
    tactic_ids: list[str] = Field(default_factory=list)
    task_id: str | None = None
    query_ids: list[str] = Field(default_factory=list)
    submitted_by: str | None = None
    sources: list[str] = Field(default_factory=list)
    verdict_malicious: bool | None = None

    @field_validator("finding_id", "claim")
    @classmethod
    def _validate_non_blank(cls, value: str, info: Any) -> str:
        return _require_non_blank(value, info.field_name)


class Edge(BaseModel):
    """Mutable directed causal/correlation edge between two events."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    from_event_id: str
    to_event_id: str
    relation: str
    join_keys: dict[str, Any] = Field(default_factory=dict)
    evidence_event_ids: list[str] = Field(default_factory=list)
    opposing_evidence_ids: list[str] = Field(default_factory=list)
    status: Literal["proposed", "verified", "disputed"] = "proposed"
    sources: list[str] = Field(default_factory=list)
    time_window: tuple[str, str] | None = None
    ambiguity_reason: str | None = None

    @field_validator("from_event_id", "to_event_id", "relation")
    @classmethod
    def _validate_non_blank(cls, value: str, info: Any) -> str:
        return _require_non_blank(value, info.field_name)

    @property
    def dedup_key(self) -> tuple[str, str, str]:
        """Endpoint + direction + relation identity used for edge deduplication."""
        return (self.from_event_id, self.to_event_id, self.relation)


class Task(BaseModel):
    """Investigation task dispatched by Lead to specialist agents."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    task_id: str
    role: str
    question: str
    target_entities: list[str] = Field(default_factory=list)
    time_window: tuple[str, str] | None = None
    stop_condition: str = "evidence_or_empty"
    seed_event_ids: list[str] = Field(default_factory=list)
    priority: int = 0

    @field_validator("task_id", "role", "question")
    @classmethod
    def _validate_non_blank(cls, value: str, info: Any) -> str:
        return _require_non_blank(value, info.field_name)

    @field_validator("priority", mode="before")
    @classmethod
    def _validate_priority(cls, value: Any) -> Any:
        return _reject_bool_int(value)


class Submission(BaseModel):
    """Agent blackboard submission payload checked for idempotency and provenance."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    run_id: str
    task_id: str
    submission_id: str
    submitted_by: str = "agent"
    query_ids: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    edges: list[Edge] = Field(default_factory=list)

    @field_validator("case_id", "run_id", "task_id", "submission_id", "submitted_by")
    @classmethod
    def _validate_non_blank(cls, value: str, info: Any) -> str:
        return _require_non_blank(value, info.field_name)

    def content_digest(self) -> str:
        """Compute deterministic SHA-256 digest of submission content for idempotency checks."""
        payload = {
            "case_id": self.case_id,
            "run_id": self.run_id,
            "task_id": self.task_id,
            "submitted_by": self.submitted_by,
            "query_ids": self.query_ids,
            "findings": [f.model_dump(mode="json") for f in self.findings],
            "edges": [e.model_dump(mode="json") for e in self.edges],
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class RejectedRef(BaseModel):
    """Structured rejection entry returned inside MergeReceipt."""

    model_config = ConfigDict(extra="allow", frozen=True)

    ref: str
    reason: str
    code: str = "OUT_OF_SCOPE"

    @field_validator("ref", "reason", "code")
    @classmethod
    def _validate_non_blank(cls, value: str, info: Any) -> str:
        return _require_non_blank(value, info.field_name)


class MergeReceipt(BaseModel):
    """Result returned by Blackboard.submit_findings."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    submission_id: str
    accepted_event_ids: list[str] = Field(default_factory=list)
    rejected_refs: list[RejectedRef] = Field(default_factory=list)
    state_version: int = Field(ge=0)
    replayed: bool = False

    @field_validator("submission_id")
    @classmethod
    def _validate_submission_id(cls, value: str) -> str:
        return _require_non_blank(value, "submission_id")

    @field_validator("state_version", mode="before")
    @classmethod
    def _validate_state_version(cls, value: Any) -> Any:
        return _reject_bool_int(value)


class GraphState(BaseModel):
    """Mutable shared blackboard state across investigation rounds."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    case_id: str
    run_id: str
    verified_event_refs: dict[str, dict[str, Any]] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    candidate_edges: list[Edge] = Field(default_factory=list)
    disputed_items: list[dict[str, Any]] = Field(default_factory=list)
    active_entities: list[str] = Field(default_factory=list)
    pending_tasks: list[Task] = Field(default_factory=list)
    query_signatures: dict[str, Any] = Field(default_factory=dict)
    investigation_ledger: list[dict[str, Any]] = Field(default_factory=list)
    round: int = Field(default=0, ge=0)
    budget_state: dict[str, Any] = Field(default_factory=dict)
    validation_errors: list[dict[str, Any]] = Field(default_factory=list)
    state_version: int = Field(default=0, ge=0)
    stop_reason: str | None = None

    @field_validator("case_id", "run_id")
    @classmethod
    def _validate_non_blank(cls, value: str, info: Any) -> str:
        return _require_non_blank(value, info.field_name)

    @field_validator("round", "state_version", mode="before")
    @classmethod
    def _validate_ints(cls, value: Any) -> Any:
        return _reject_bool_int(value)


class AttackChain(BaseModel):
    """Ranked candidate attack chain built from verified edges and events."""

    model_config = ConfigDict(extra="allow", frozen=True)

    chain_id: str
    event_ids: list[str] = Field(default_factory=list)
    edge_keys: list[tuple[str, str, str]] = Field(default_factory=list)
    critical_relations_clean: bool = False
    corroborated_critical_count: int = 0
    direct_evidence_stages: int = 0
    tactic_ids: list[str] = Field(default_factory=list)
    rule_ids: list[str] = Field(default_factory=list)
    locators: list[Locator | None] = Field(default_factory=list)
    unresolved_items: list[str] = Field(default_factory=list)

    @field_validator("chain_id")
    @classmethod
    def _validate_chain_id(cls, value: str) -> str:
        return _require_non_blank(value, "chain_id")

    @field_validator("corroborated_critical_count", "direct_evidence_stages", mode="before")
    @classmethod
    def _validate_counts(cls, value: Any) -> Any:
        return _reject_bool_int(value)

    def sort_key(self) -> tuple[int, int, int, str]:
        """Lexicographic rank key: desc(clean), desc(corroborated), desc(stages), asc(chain_id)."""
        return (
            -int(self.critical_relations_clean),
            -int(self.corroborated_critical_count),
            -int(self.direct_evidence_stages),
            self.chain_id,
        )


class CaseResult(BaseModel):
    """Internal investigation output produced by Ranker prior to competition export."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    case_id: str
    run_id: str
    chains: list[AttackChain] = Field(default_factory=list)
    tactic_top_k: dict[str, list[str]] = Field(default_factory=dict)
    attack_event_ids: list[str] = Field(default_factory=list)
    tactic_ranked_event_ids: dict[str, list[str]] = Field(default_factory=dict)
    unresolved: list[dict[str, Any]] = Field(default_factory=list)
    coverage: list[RuleRun] = Field(default_factory=list)
    stop_reason: str | None = None
    snapshot_refs: dict[str, str] = Field(default_factory=dict)
    event_to_physical: dict[str, str] = Field(default_factory=dict)
    knowledge_refs: list[KnowledgeRef] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    edges: list[Edge] = Field(default_factory=list)
    validation_errors: list[dict[str, Any]] = Field(default_factory=list)
    investigation_ledger: list[dict[str, Any]] = Field(default_factory=list)
    seed_event_ids: list[str] = Field(default_factory=list)
    attack_decisions: dict[str, dict[str, Any]] = Field(default_factory=dict)
    record_diagnostics: dict[str, dict[str, Any]] = Field(default_factory=dict)
    stage_timings_s: dict[str, float] = Field(default_factory=dict)
    llm_calls: list[dict[str, Any]] = Field(default_factory=list)
    input_record_count: int = Field(default=0, ge=0)

    @field_validator("case_id", "run_id")
    @classmethod
    def _validate_non_blank(cls, value: str, info: Any) -> str:
        return _require_non_blank(value, info.field_name)


class Prediction(BaseModel):
    """Strict external competition export schema (`physical_id_set`, `ta_physical_ids`)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    physical_id_set: list[str] = Field(default_factory=list)
    ta_physical_ids: dict[str, list[str]] = Field(default_factory=dict)

    @field_validator("physical_id_set")
    @classmethod
    def _validate_physical_id_set(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for item in value:
            _require_non_blank(item, "physical_id_set item")
            cleaned.append(item)
        return sorted(set(cleaned))

    @field_validator("ta_physical_ids")
    @classmethod
    def _validate_ta_physical_ids(cls, value: dict[str, list[str]]) -> dict[str, list[str]]:
        normalized: dict[str, list[str]] = {}
        for tactic_id, physical_ids in value.items():
            if not isinstance(tactic_id, str) or not TACTIC_ID_PATTERN.fullmatch(tactic_id):
                raise ValueError(
                    f"Invalid tactic key {tactic_id!r}; expected pattern ^TA\\d{{4}}$."
                )
            if not isinstance(physical_ids, list) or not (1 <= len(physical_ids) <= 3):
                raise ValueError(
                    f"Tactic {tactic_id!r} must map to 1..3 physical IDs."
                )
            for pid in physical_ids:
                _require_non_blank(pid, f"ta_physical_ids[{tactic_id}] item")
            if len(physical_ids) != len(set(physical_ids)):
                raise ValueError(
                    f"Tactic {tactic_id!r} contains duplicate physical IDs."
                )
            normalized[tactic_id] = list(physical_ids)
        return normalized

    @model_validator(mode="after")
    def _validate_subset_invariant(self) -> Prediction:
        allowed = set(self.physical_id_set)
        for tactic_id, physical_ids in self.ta_physical_ids.items():
            missing = [pid for pid in physical_ids if pid not in allowed]
            if missing:
                raise ValueError(
                    f"Tactic {tactic_id!r} references IDs missing from physical_id_set: {missing}"
                )
        return self

    def to_dict(self) -> dict[str, Any]:
        """Export exact 2-key dictionary expected by analyze_records contract."""
        return {
            "physical_id_set": list(self.physical_id_set),
            "ta_physical_ids": {
                tactic_id: list(ids)
                for tactic_id, ids in sorted(self.ta_physical_ids.items())
            },
        }

    @classmethod
    def empty(cls) -> Prediction:
        """Return valid empty prediction."""
        return cls(physical_id_set=[], ta_physical_ids={})

    @classmethod
    def from_candidates(
        cls,
        physical_ids: Sequence[str] | Iterable[str],
        ta_candidates: Mapping[str, Sequence[str]],
        *,
        valid_physical_ids: AbstractSet[str] | None = None,
        ta_limit: int = 3,
    ) -> Prediction:
        """Normalize candidate IDs: validate tactic keys, dedup before top-K truncation, and filter scope."""
        if isinstance(ta_limit, bool) or not isinstance(ta_limit, int) or ta_limit < 1:
            raise ValueError("ta_limit must be an integer >= 1.")

        for tactic_id in ta_candidates:
            if not isinstance(tactic_id, str) or not TACTIC_ID_PATTERN.fullmatch(tactic_id):
                raise ValueError(
                    f"Invalid tactic key {tactic_id!r}; expected pattern ^TA\\d{{4}}$."
                )

        filtered_physical: list[str] = []
        for pid in physical_ids:
            if not isinstance(pid, str) or not pid.strip():
                continue
            if valid_physical_ids is not None and pid not in valid_physical_ids:
                continue
            filtered_physical.append(pid)

        normalized_ta: dict[str, list[str]] = {}
        for tactic_id, candidates in ta_candidates.items():
            scoped_candidates = [
                pid
                for pid in candidates
                if isinstance(pid, str)
                and pid.strip()
                and (valid_physical_ids is None or pid in valid_physical_ids)
            ]
            deduped = list(dict.fromkeys(scoped_candidates))[:ta_limit]
            if deduped:
                normalized_ta[tactic_id] = deduped

        all_ids = sorted(
            set(filtered_physical)
            | {pid for ids in normalized_ta.values() for pid in ids}
        )
        return cls(physical_id_set=all_ids, ta_physical_ids=normalized_ta)


__all__ = [
    "AttackChain",
    "CaseResult",
    "CaseRun",
    "Edge",
    "Event",
    "Finding",
    "GraphState",
    "Hit",
    "KnowledgeRef",
    "Locator",
    "MergeReceipt",
    "Prediction",
    "RawRecord",
    "RejectedRef",
    "RuleRun",
    "RunContext",
    "Submission",
    "TACTIC_ID_PATTERN",
    "Task",
]
