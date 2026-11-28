"""Prediction-independent provenance and post-prediction physical-ID comparison.

No labels enter ingestion, detection or investigation. ``compare_records`` accepts
only a completed CaseResult and a caller-supplied set of expected physical IDs.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from typing import Any

from apt_agent.detection.base import DetectionResult
from apt_agent.ingestion.store import RawEvidenceStore
from apt_agent.models import CaseResult, Event


def build_record_diagnostics(
    store: RawEvidenceStore,
    events: Sequence[Event],
    gaps: list[dict[str, Any]],
    detection: DetectionResult,
    result: CaseResult,
    prediction: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Keep all input IDs, including records that produced no normalized event.

    ``ranked_attack`` records Ranker's decision; it does not claim that every
    direct Sigma seed was corroborated by a verified relationship.
    """
    records = {}
    for pid in sorted(store.physical_ids()):
        locator = store.get_locator(pid)
        records[pid] = {
            "locator": locator.model_dump() if locator else None,
            "event_ids": [], "source_types": [], "parse_warnings": [],
            "gaps": [], "hits": [], "seed_event_ids": [], "attack_decisions": [],
            "verified_relations": [], "unresolved_relations": [],
            "ranked_attack_event_ids": [], "exported": False,
            "exported_tactics": [], "last_stage": "ingested",
            "reason": "normalization_produced_no_events",
        }
    seeds = set(result.seed_event_ids)
    attacks = set(result.attack_event_ids)
    for event in events:
        item = records[event.physical_record_id]
        item["event_ids"].append(event.event_id)
        if event.source_type:
            item["source_types"].append(event.source_type)
        item["parse_warnings"].extend(event.parse_metadata.get("warnings", []))
        if event.event_id in result.attack_decisions:
            item["attack_decisions"].append({"event_id": event.event_id, **result.attack_decisions[event.event_id]})
        if event.event_id in seeds:
            item["seed_event_ids"].append(event.event_id)
        if event.event_id in attacks:
            item["ranked_attack_event_ids"].append(event.event_id)
    for gap in gaps:
        pid = gap.get("physical_record_id")
        if pid in records:
            records[pid]["gaps"].append(gap)
    for hit in detection.hit_trace:
        pid = hit.get("physical_record_id")
        if pid in records:
            records[pid]["hits"].append(dict(hit))
    for edge in result.edges:
        for pid in sorted({result.event_to_physical[eid] for eid in
                           (edge.from_event_id, edge.to_event_id)
                           if eid in result.event_to_physical}):
            records[pid]["verified_relations" if edge.status == "verified" else
                         "unresolved_relations"].append({
                "from_event_id": edge.from_event_id, "to_event_id": edge.to_event_id,
                "relation": edge.relation, "status": edge.status,
                "reason": edge.ambiguity_reason,
            })
    exported = set(prediction["physical_id_set"])
    for pid, item in records.items():
        item["exported"] = pid in exported
        item["exported_tactics"] = sorted(tactic for tactic, ids in
                                            prediction["ta_physical_ids"].items() if pid in ids)
        for key in ("event_ids", "source_types", "parse_warnings", "seed_event_ids",
                    "ranked_attack_event_ids"):
            item[key] = sorted(set(item[key]))
        if item["event_ids"]:
            item.update(last_stage="normalized", reason="no_event_backed_detector_hit;check_coverage")
        if item["hits"]:
            item.update(last_stage="detected", reason="all_hits_rejected_by_logsource")
        if any(hit["accepted"] for hit in item["hits"]):
            item.update(last_stage="source_accepted", reason="below_minimum_seed_level")
        if item["seed_event_ids"]:
            item.update(last_stage="seeded", reason="not_selected_by_ranker;check_validation")
        if not item["ranked_attack_event_ids"] and item["attack_decisions"]:
            item.update(last_stage=("assessed_context" if all(
                decision["reason"] == "context_only_rule" for decision in item["attack_decisions"]
            ) else "verified_context"), reason=";".join(sorted({
                decision["reason"] for decision in item["attack_decisions"]
            })))
        if item["ranked_attack_event_ids"]:
            item.update(last_stage="ranked_attack", reason="excluded_by_export_scope")
        if item["exported"]:
            reasons = {decision["reason"] for decision in item["attack_decisions"]
                       if decision["classification"] == "attack"}
            reason = ("direct_detection_seed" if "direct_detection_seed" in reasons else
                      "explicit_malicious_finding" if "explicit_malicious_finding" in reasons else
                      "investigation_expansion" if reasons else
                      "direct_detection_seed" if item["seed_event_ids"] else "investigation_expansion")
            item.update(last_stage="exported", reason=reason)
    return records


def compare_records(result: CaseResult, expected_physical_ids: Iterable[str]) -> dict[str, Any]:
    """Compare after prediction; count unique physical IDs rather than hit rows.

    The caller extracts IDs from their scorer's label schema. This report is a
    diagnostic comparison, not an implementation of the official scoring formula.
    """
    expected = set(expected_physical_ids)
    if any(not isinstance(pid, str) or not pid.strip() for pid in expected):
        raise ValueError("Expected physical IDs must be non-blank strings.")
    records = result.record_diagnostics
    predicted = {pid for pid, item in records.items() if item["exported"]}
    missed = sorted(expected - predicted)
    false_positives = predicted - expected
    groups: dict[tuple[str, str, str], dict[str, set[str]]] = defaultdict(
        lambda: {"raw": set(), "accepted": set(), "exported": set(), "false_positive": set()}
    )
    for pid, item in records.items():
        for hit in item["hits"]:
            group = groups[(hit["engine"], hit["rule_id"], hit["source_type"] or "unknown")]
            group["raw"].add(pid)
            if hit["accepted"]:
                group["accepted"].add(pid)
                if pid in predicted:
                    group["exported"].add(pid)
                if pid in false_positives:
                    group["false_positive"].add(pid)
    return {
        "case_id": result.case_id, "run_id": result.run_id,
        "stop_reason": result.stop_reason,
        "counts": {"expected": len(expected), "predicted": len(predicted),
                   "true_positive": len(expected & predicted),
                   "false_positive": len(false_positives), "false_negative": len(missed)},
        "missed_records": [{"physical_record_id": pid,
                            "last_stage": records[pid]["last_stage"] if pid in records else "input_missing",
                            "reason": records[pid]["reason"] if pid in records else "not_in_received_records",
                            "trace": records.get(pid)} for pid in missed],
        "false_positive_ids": sorted(false_positives),
        "rule_distribution": [
            {"engine": key[0], "rule_id": key[1], "source_type": key[2],
             **{name + "_physical_count": len(ids) for name, ids in group.items()},
             "false_positive_ids": sorted(group["false_positive"])}
            for key, group in sorted(groups.items())
        ],
        "coverage": [run.model_dump(mode="json") for run in result.coverage],
        "validation_errors": result.validation_errors,
    }
