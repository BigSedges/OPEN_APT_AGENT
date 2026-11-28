"""Run defensive log detection and export the competition prediction format."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Set
from pathlib import Path
from time import perf_counter
from typing import Any
from uuid import uuid4

from apt_agent.agents import BudgetManager, run_investigation
from apt_agent.config import AppConfig, load_config
from apt_agent.detection import DetectionCoordinator, DetectionResult
from apt_agent.exceptions import OutOfScopeError
from apt_agent.diagnostics import build_record_diagnostics
from apt_agent.ingestion import Normalizer, RawEvidenceStore, ingest_records
from apt_agent.maintenance import bind_snapshot_assets
from apt_agent.models import (
    TACTIC_ID_PATTERN,
    CaseResult,
    Locator,
    Prediction,
    RunContext,
)


def to_prediction(
    ctx: RunContext,
    case_result: CaseResult,
    *,
    valid_physical_ids: Set[str] | None = None,
) -> dict[str, Any]:
    """Map verified events to their physical records before deduplicating and truncating."""
    if (case_result.case_id, case_result.run_id) != (ctx.case_id, ctx.run_id):
        raise OutOfScopeError("Case result belongs to another case or run.")

    scope = ctx.valid_physical_ids
    if valid_physical_ids is not None:
        scope = frozenset(valid_physical_ids) if scope is None else scope & valid_physical_ids

    attack_events = {}
    for event_id in case_result.attack_event_ids:
        physical_id = case_result.event_to_physical.get(event_id)
        if physical_id and (scope is None or physical_id in scope):
            attack_events[event_id] = physical_id

    tactics = {}
    for tactic_id, event_ids in sorted(case_result.tactic_ranked_event_ids.items()):
        if not TACTIC_ID_PATTERN.fullmatch(tactic_id):
            raise ValueError(f"Invalid tactic ID: {tactic_id!r}.")
        physical_ids = list(dict.fromkeys(
            attack_events[event_id] for event_id in event_ids if event_id in attack_events
        ))
        if physical_ids:
            tactics[tactic_id] = physical_ids[:3]
    return Prediction(
        physical_id_set=list(attack_events.values()), ta_physical_ids=tactics
    ).model_dump(mode="json")


def analyze_records(
    records: Iterable[tuple[str, dict[str, Any]]],
    *,
    config: AppConfig | Mapping[str, Any] | Path | str | None = None,
    valid_physical_ids: Set[str] | None = None,
    locator_map: Mapping[str, Locator] | None = None,
    on_result: Callable[[CaseResult], None] | None = None,
) -> dict[str, Any]:
    """Consume a scene once and export a JSON-compatible prediction."""
    ctx, result = _investigate_records(records, config, valid_physical_ids, locator_map,
                                       collect_diagnostics=False)
    prediction = to_prediction(ctx, result)
    if on_result is not None:
        on_result(result)
    return prediction


def investigate_records(
    records: Iterable[tuple[str, dict[str, Any]]],
    *,
    config: AppConfig | Mapping[str, Any] | Path | str | None = None,
    valid_physical_ids: Set[str] | None = None,
    locator_map: Mapping[str, Locator] | None = None,
) -> CaseResult:
    """Analyze a scene and return chains, coverage, provenance and diagnostics."""
    _, result = _investigate_records(records, config, valid_physical_ids, locator_map)
    return result


def _investigate_records(
    records: Iterable[tuple[str, dict[str, Any]]],
    config: AppConfig | Mapping[str, Any] | Path | str | None,
    valid_physical_ids: Set[str] | None,
    locator_map: Mapping[str, Locator] | None,
    *,
    collect_diagnostics: bool = True,
) -> tuple[RunContext, CaseResult]:
    if isinstance(config, AppConfig):
        effective_config = config
    elif isinstance(config, Mapping):
        effective_config = load_config(overrides=config)
    else:
        effective_config = load_config(config)

    started = perf_counter()
    budget = BudgetManager(effective_config.budget)
    run_id = f"run-{uuid4().hex}"
    store = ingest_records(
        records,
        case_id=None,
        run_id=run_id,
        valid_physical_ids=valid_physical_ids,
        locator_map=locator_map,
    )
    ingested_at = perf_counter()
    with bind_snapshot_assets(effective_config) as bound_config:
        ctx, result = _run_case(store, bound_config, budget, collect_diagnostics=collect_diagnostics)
    result.stage_timings_s["ingestion"] = ingested_at - started
    result.stage_timings_s["total"] = perf_counter() - started
    return ctx, result


def _run_case(
    store: RawEvidenceStore, effective_config: AppConfig, budget: BudgetManager,
    *, collect_diagnostics: bool = True,
) -> tuple[RunContext, CaseResult]:
    snapshots = effective_config.snapshots
    ctx = RunContext(
        case_id=store.case_id,
        data_snapshot_id=store.case_id,
        run_id=store.run_id,
        mapping_version=snapshots.mapping_version,
        ruleset_version=snapshots.ruleset_version,
        knowledge_snapshot_id=snapshots.knowledge_snapshot_id,
        budget=effective_config.budget,
        config=effective_config,
        valid_physical_ids=store.physical_id_frozenset(),
    )
    started = perf_counter()
    normalized = Normalizer.normalize_batch(ctx, store)
    normalized_at = perf_counter()
    detection = (
        DetectionCoordinator(effective_config).detect(ctx, normalized.events)
        if normalized.events else DetectionResult()
    )
    detected_at = perf_counter()
    result = run_investigation(
        ctx, store, normalized.events, detection, budget_manager=budget
    )
    investigated_at = perf_counter()
    result.unresolved.extend(normalized.gaps)
    result.input_record_count = len(store)
    if collect_diagnostics:
        result.record_diagnostics = build_record_diagnostics(
            store, normalized.events, normalized.gaps, detection, result, to_prediction(ctx, result)
        )
    result.stage_timings_s = {
        "normalization": normalized_at - started,
        "detection": detected_at - normalized_at,
        "investigation_verification_ranking": investigated_at - detected_at,
        "diagnostics_export": perf_counter() - investigated_at,
    }
    return ctx, result
