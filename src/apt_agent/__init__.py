"""OPEN_APT_AGENT public package exports and standard external entrypoint."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from collections.abc import Set as AbstractSet
from pathlib import Path
from typing import Any

from apt_agent.config import (
    AppConfig,
    BudgetConfig,
    EngineConfig,
    EnginesConfig,
    LLMConfig,
    RagConfig,
    SnapshotsConfig,
    load_config,
)
from apt_agent.exceptions import (
    AptAgentError,
    BudgetExhaustedError,
    ConfigError,
    ConflictError,
    EngineError,
    ErrorCode,
    InvalidArgumentError,
    OperationTimeoutError,
    OutOfScopeError,
    PermissionDeniedError,
    RetrievalUnavailableError,
    exception_from_error_code,
)
from apt_agent.models import (
    TACTIC_ID_PATTERN,
    AttackChain,
    CaseResult,
    CaseRun,
    Edge,
    Event,
    Finding,
    GraphState,
    Hit,
    KnowledgeRef,
    Locator,
    MergeReceipt,
    Prediction,
    RawRecord,
    RejectedRef,
    RuleRun,
    RunContext,
    Submission,
    Task,
)

__version__ = "0.1.0"


def analyze_records(
    records: Iterator[tuple[str, dict[str, Any]]],
    *,
    config: AppConfig | Mapping[str, Any] | Path | str | None = None,
    valid_physical_ids: AbstractSet[str] | None = None,
    locator_map: Mapping[str, Locator] | None = None,
) -> dict[str, Any]:
    """Standard single-pass log investigation entrypoint (`analyze_records`)."""
    from apt_agent.pipeline import analyze_records as _analyze_records

    return _analyze_records(
        records,
        config=config,
        valid_physical_ids=valid_physical_ids,
        locator_map=locator_map,
    )


__all__ = [
    "AppConfig",
    "AptAgentError",
    "AttackChain",
    "BudgetConfig",
    "BudgetExhaustedError",
    "CaseResult",
    "CaseRun",
    "ConfigError",
    "ConflictError",
    "Edge",
    "EngineConfig",
    "EngineError",
    "EnginesConfig",
    "ErrorCode",
    "Event",
    "Finding",
    "GraphState",
    "Hit",
    "InvalidArgumentError",
    "KnowledgeRef",
    "LLMConfig",
    "Locator",
    "MergeReceipt",
    "OperationTimeoutError",
    "OutOfScopeError",
    "PermissionDeniedError",
    "Prediction",
    "RagConfig",
    "RawRecord",
    "RejectedRef",
    "RetrievalUnavailableError",
    "RuleRun",
    "RunContext",
    "SnapshotsConfig",
    "Submission",
    "TACTIC_ID_PATTERN",
    "Task",
    "__version__",
    "analyze_records",
    "exception_from_error_code",
    "load_config",
]
