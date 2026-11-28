"""Multi-engine detection coordinator with engine isolation, hit deduplication, and coverage tracking."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any

from apt_agent.config import AppConfig, EngineConfig
from apt_agent.detection.base import (
    AdapterOutput,
    DetectionResult,
    EngineAdapter,
    classify_event_format,
    make_hit_id,
    make_lead_id,
    normalize_level,
    parse_utc_timestamp,
    severity_rank,
    validate_event_ids,
)
from apt_agent.detection.chainsaw import ChainsawAdapter
from apt_agent.detection.hayabusa import HayabusaAdapter
from apt_agent.detection.rsigma import RSigmaAdapter, inspect_sigma_rules
from apt_agent.detection.zircolite import ZircoliteAdapter
from apt_agent.exceptions import InvalidArgumentError
from apt_agent.models import Event, Hit, RuleRun, RunContext


def _deduplicate_event_hits(hits: Sequence[Hit]) -> list[Hit]:
    """Deduplicate event-backed hits by sorted unique `event_ids`, preserving all sources."""
    grouped: dict[tuple[str, ...], list[Hit]] = defaultdict(list)
    for hit in hits:
        dedup_eids = tuple(sorted(dict.fromkeys(hit.event_ids)))
        if not dedup_eids:
            continue
        grouped[dedup_eids].append(hit)

    merged_hits: list[Hit] = []
    for eid_key in sorted(grouped):
        group = sorted(
            grouped[eid_key],
            key=lambda h: (-severity_rank(h.level), h.engine, h.rule_id, h.hit_id),
        )
        primary = group[0]

        tactic_ids = sorted({t for h in group for t in h.tactic_ids})
        technique_ids = sorted({t for h in group for t in h.technique_ids})

        best_level: str | None = None
        best_rank = 0
        for h in group:
            r = severity_rank(h.level)
            if r > best_rank:
                best_rank = r
                best_level = normalize_level(h.level)

        times = [
            ts
            for h in group
            if (ts := parse_utc_timestamp(h.matched_time)) is not None
        ]
        matched_time = min(times) if times else None

        contributing_sources = [
            {
                "hit_id": h.hit_id,
                "engine": h.engine,
                "engine_version": h.engine_version,
                "rule_id": h.rule_id,
                "rule_version": h.rule_version,
                "level": h.level,
                "tactic_ids": list(h.tactic_ids),
                "technique_ids": list(h.technique_ids),
            }
            for h in sorted(group, key=lambda item: (item.engine, item.rule_id, item.hit_id))
        ]
        engines = sorted({h.engine for h in group})
        rule_ids = sorted({h.rule_id for h in group})

        merged_fields: dict[str, Any] = {}
        for h in reversed(group):
            for k, v in h.matched_fields.items():
                if k not in {"contributing_sources", "engines", "rule_ids"}:
                    merged_fields[k] = v
        merged_fields["contributing_sources"] = contributing_sources
        merged_fields["engines"] = engines
        merged_fields["rule_ids"] = rule_ids

        hit_id = (
            primary.hit_id
            if len(group) == 1
            else make_hit_id("merged", ",".join(rule_ids), list(eid_key), ",".join(engines))
        )

        merged_hits.append(
            Hit(
                hit_id=hit_id,
                rule_id=primary.rule_id,
                rule_version=primary.rule_version,
                engine=primary.engine,
                engine_version=primary.engine_version,
                event_ids=list(eid_key),
                tactic_ids=tactic_ids,
                technique_ids=technique_ids,
                matched_time=matched_time,
                level=best_level,
                matched_fields=merged_fields,
            )
        )

    merged_hits.sort(key=lambda h: (tuple(h.event_ids), h.engine, h.rule_id, h.hit_id))
    return merged_hits


class DetectionCoordinator:
    """Routes normalized events across detection engines and merges coverage & hits."""

    def __init__(
        self,
        config: AppConfig | None = None,
        *,
        adapters: Sequence[EngineAdapter] | None = None,
    ) -> None:
        self.config: AppConfig = config if config is not None else AppConfig()
        if adapters is None:
            self._adapters: tuple[EngineAdapter, ...] = (
                ZircoliteAdapter(),
                HayabusaAdapter(),
                RSigmaAdapter(),
                ChainsawAdapter(),
            )
        else:
            self._adapters = tuple(adapters)

    def _resolve_engine_config(
        self,
        effective_config: AppConfig,
        engine_name: str,
    ) -> EngineConfig:
        if hasattr(effective_config.engines, engine_name):
            cfg = getattr(effective_config.engines, engine_name)
            if isinstance(cfg, EngineConfig):
                return cfg
        return EngineConfig(enabled=False)

    def detect(
        self,
        ctx: RunContext,
        events: Sequence[Event],
        ruleset_version: str | None = None,
    ) -> DetectionResult:
        if not isinstance(ctx, RunContext):
            raise InvalidArgumentError(
                "ctx must be a RunContext instance.",
                details={"type": type(ctx).__name__},
            )
        if isinstance(events, (str, bytes, bytearray, Mapping)) or not isinstance(
            events, Sequence
        ):
            raise InvalidArgumentError(
                "events must be a Sequence[Event].",
                details={"type": type(events).__name__},
            )
        for idx, ev in enumerate(events):
            if not isinstance(ev, Event):
                raise InvalidArgumentError(
                    f"events[{idx}] must be an Event instance.",
                    details={"index": idx, "type": type(ev).__name__},
                )

        if ruleset_version is not None:
            if not isinstance(ruleset_version, str) or not ruleset_version.strip():
                raise InvalidArgumentError(
                    "ruleset_version must be a non-blank string when provided.",
                    details={"ruleset_version": ruleset_version},
                )
            effective_ruleset = ruleset_version.strip()
        else:
            effective_ruleset = ctx.ruleset_version

        effective_config = ctx.config if ctx.config is not None else self.config
        event_to_physical = {ev.event_id: ev.physical_record_id for ev in events}
        valid_event_ids = set(event_to_physical)
        batch_formats = {
            fmt for ev in events if (fmt := classify_event_format(ev)) != "unknown"
        }

        raw_event_hits: list[Hit] = []
        lead_only_hits: list[Hit] = []
        all_coverage: list[RuleRun] = []
        leads_by_id: dict[str, dict[str, Any]] = {}

        for adapter in self._adapters:
            engine_name = adapter.engine_name
            engine_cfg = self._resolve_engine_config(effective_config, engine_name)

            try:
                if isinstance(adapter, HayabusaAdapter):
                    out: AdapterOutput = adapter.run(
                        ctx,
                        events,
                        engine_cfg,
                        ruleset_version=effective_ruleset,
                        takajo_cfg=effective_config.engines.takajo,
                    )
                else:
                    out = adapter.run(
                        ctx,
                        events,
                        engine_cfg,
                        ruleset_version=effective_ruleset,
                    )
            except Exception as exc:  # noqa: BLE001 - isolate engine failures
                all_coverage.append(
                    RuleRun(
                        rule_id=f"{engine_name}.batch",
                        engine=engine_name,
                        rule_version=effective_ruleset,
                        status="failed",
                        reason=f"adapter_exception:{type(exc).__name__}:{exc}",
                    )
                )
                continue

            all_coverage.extend(out.coverage)

            for lead in out.leads:
                if not isinstance(lead, dict):
                    continue
                lid = str(
                    lead.get("lead_id")
                    or make_lead_id(engine_name, str(lead.get("kind") or "lead"), str(len(leads_by_id)))
                )
                lead_copy = dict(lead)
                lead_copy.setdefault("lead_id", lid)
                leads_by_id[lid] = lead_copy

            for hit in out.hits:
                if hit.is_lead_only:
                    lead_only_hits.append(hit)
                    lid = make_lead_id(
                        hit.engine,
                        "correlation_count_only",
                        f"{hit.rule_id}:{hit.hit_id}",
                    )
                    # Only add synthetic lead if adapter did not already record one for this rule/hit.
                    already_has_corr_lead = any(
                        existing.get("engine") == hit.engine
                        and existing.get("rule_id") == hit.rule_id
                        and existing.get("kind") == "correlation_count_only"
                        for existing in leads_by_id.values()
                    )
                    if not already_has_corr_lead:
                        leads_by_id[lid] = {
                            "lead_id": lid,
                            "kind": "correlation_count_only",
                            "engine": hit.engine,
                            "rule_id": hit.rule_id,
                            "rule_version": hit.rule_version,
                            "tactic_ids": list(hit.tactic_ids),
                            "technique_ids": list(hit.technique_ids),
                            "reason": "count_only_correlation",
                        }
                else:
                    filtered_eids = validate_event_ids(hit.event_ids, valid_event_ids)
                    if not filtered_eids:
                        continue
                    if filtered_eids != hit.event_ids:
                        hit = hit.model_copy(update={"event_ids": filtered_eids})
                    raw_event_hits.append(hit)

        pysigma_cfg = effective_config.engines.pysigma
        try:
            pysigma_coverage = inspect_sigma_rules(
                pysigma_cfg.rules_dir,
                engine_cfg=pysigma_cfg,
                batch_formats=batch_formats,
                ruleset_version=effective_ruleset,
            )
            all_coverage.extend(pysigma_coverage)
        except Exception as exc:  # noqa: BLE001 - isolate pySigma failures
            all_coverage.append(
                RuleRun(
                    rule_id="pysigma.batch",
                    engine="pysigma",
                    rule_version=effective_ruleset,
                    status="failed",
                    reason=f"pysigma_exception:{type(exc).__name__}:{exc}",
                )
            )

        dedup_hits = _deduplicate_event_hits(raw_event_hits)
        lead_only_hits.sort(key=lambda h: (h.engine, h.rule_id, h.hit_id))
        final_hits = [*dedup_hits, *lead_only_hits]

        sorted_coverage = sorted(
            all_coverage,
            key=lambda r: (r.engine, r.rule_id, r.status, r.reason or ""),
        )
        sorted_leads = sorted(
            leads_by_id.values(),
            key=lambda item: (
                str(item.get("engine", "")),
                str(item.get("kind", "")),
                str(item.get("lead_id", "")),
            ),
        )

        return DetectionResult(
            hits=final_hits,
            coverage=sorted_coverage,
            leads=sorted_leads,
            event_to_physical=event_to_physical,
        )


__all__ = ["DetectionCoordinator"]
