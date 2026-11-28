"""Regression contracts for separating suspicious seeds and verified context."""
import pytest

from apt_agent.blackboard import Blackboard, rank, verify
from apt_agent.config import AppConfig
from apt_agent.ingestion import Normalizer, ingest_records
from apt_agent.models import Edge, Finding, Hit, RunContext, Submission


def case(level="high", extra=False):
    cfg = AppConfig(minimum_expansion_level=level)
    records = [("pr-create", {"id": "create", "hostname": "host", "timestamp_ms": 1700000000000,
        "object": "PROCESS", "action": "CREATE", "objectID": "instance",
        "properties": {"image_path": r"C:\tool.exe"}}),
        ("pr-module", {"id": "module", "hostname": "host", "timestamp_ms": 1700000001000,
        "object": "MODULE", "action": "LOAD", "objectID": "module-object", "actorID": "instance",
        "properties": {"image_path": r"C:\tool.exe", "file_path": r"C:\library.dll"}})]
    if extra:
        records.append(("pr-followup", {"id": "followup", "hostname": "host",
            "timestamp_ms": 1700000002000, "object": "FILE", "action": "READ",
            "objectID": "file-object", "actorID": "instance",
            "properties": {"image_path": r"C:\tool.exe", "file_path": r"C:\data.txt"}}))
    store = ingest_records(records, case_id="case", run_id="run")
    ctx = RunContext(case_id=store.case_id, run_id=store.run_id, config=cfg)
    events = Normalizer.normalize_batch(ctx, store).events
    board = Blackboard(ctx, {e.event_id for e in events}, store.physical_id_frozenset(), events=events)
    return ctx, store, events, board


def submit(ctx, events, board, verdicts=()):
    ids = [e.event_id for e in events]
    board.record_task_query("investigate", "query", ids)
    board.submit_findings(ctx, Submission(case_id=ctx.case_id, run_id=ctx.run_id,
        task_id="investigate", submission_id="submission", query_ids=["query"],
        findings=[Finding(claim="Observed case evidence", status="observed", evidence_event_ids=ids)] + [
            Finding(claim="Evidence verdict", status=status, verdict_malicious=value,
                    evidence_event_ids=[ids[index]]) for index, status, value in verdicts],
        edges=[Edge(from_event_id=ids[0], to_event_id=eid, relation="same_process_guid",
                    join_keys={"process_guid": "instance"}, evidence_event_ids=[ids[0], eid])
               for eid in ids[1:]]))


def seed(event, level):
    return Hit(hit_id=event.event_id + level, rule_id="fixture", engine="fixture",
               level=level, event_ids=[event.event_id], tactic_ids=["TA0002"])


@pytest.mark.parametrize("severity,expected", [("medium", {"pr-create"}),
                                               ("high", {"pr-create", "pr-module"})])
def test_expansion_threshold_preserves_direct_seed_but_requires_stronger_origin(severity, expected):
    ctx, store, events, board = case()
    submit(ctx, events, board)
    result = rank(ctx, verify(ctx, board).verified_state, store, [seed(events[0], severity)], [], events=events)
    assert {result.event_to_physical[eid] for eid in result.attack_event_ids} == expected
    if severity == "medium":
        assert result.attack_decisions[events[1].event_id]["reason"] == "no_qualifying_expansion_seed"


def test_high_anchor_can_pass_through_already_selected_medium_seed():
    ctx, store, events, board = case(extra=True)
    submit(ctx, events, board)
    result = rank(ctx, verify(ctx, board).verified_state, store,
                  [seed(events[0], "medium"), seed(events[1], "high")], [], events=events)
    assert set(result.attack_event_ids) == {event.event_id for event in events}


def test_benign_evidence_blocks_direct_hit_and_expansion():
    ctx, store, events, board = case()
    submit(ctx, events, board, [(0, "observed", False)])
    result = rank(ctx, verify(ctx, board).verified_state, store, [seed(events[0], "high")], [], events=events)
    assert result.attack_event_ids == []
    assert result.attack_decisions[events[0].event_id]["reason"] == "explicit_benign_finding"
    assert result.tactic_ranked_event_ids == {}


def test_conflicting_verified_verdicts_are_unresolved_not_attack_and_verify_is_idempotent():
    ctx, store, events, board = case()
    submit(ctx, events, board, [(0, "observed", False), (0, "observed", True)])
    first = verify(ctx, board)
    second = verify(ctx, first.verified_state)
    assert first.verified_state.disputed_items == second.verified_state.disputed_items
    result = rank(ctx, second.verified_state, store, [seed(events[0], "high")], [], events=events)
    assert not result.attack_event_ids
    assert result.attack_decisions[events[0].event_id]["reason"] == "conflicting_findings"


def test_hypothesis_does_not_override_case_evidence():
    ctx, store, events, board = case()
    submit(ctx, events, board, [(0, "hypothesis", False)])
    result = rank(ctx, verify(ctx, board).verified_state, store, [seed(events[0], "high")], [], events=events)
    assert len(result.attack_event_ids) == 2


def test_explicit_grounded_malicious_verdict_can_expand_without_high_rule():
    ctx, store, events, board = case()
    submit(ctx, events, board, [(1, "observed", True)])
    result = rank(ctx, verify(ctx, board).verified_state, store, [], [], events=events)
    assert len(result.attack_event_ids) == 2


def test_null_policy_preserves_legacy_expansion():
    ctx, store, events, board = case(None)
    submit(ctx, events, board)
    result = rank(ctx, verify(ctx, board).verified_state, store, [seed(events[0], "medium")], [], events=events)
    assert len(result.attack_event_ids) == 2


def test_unqueried_negative_verdict_cannot_veto_a_seed():
    ctx, store, events, board = case()
    submit(ctx, events, board)
    receipt = board.submit_findings(ctx, Submission(case_id=ctx.case_id, run_id=ctx.run_id,
        task_id="unqueried", submission_id="unqueried", query_ids=["absent-query"],
        findings=[Finding(claim="Unsupported verdict", status="observed", verdict_malicious=False,
                          evidence_event_ids=[events[0].event_id])]))
    assert receipt.rejected_refs
    result = rank(ctx, verify(ctx, board).verified_state, store, [seed(events[0], "high")], [], events=events)
    assert len(result.attack_event_ids) == 2


def test_context_only_rule_stays_available_but_does_not_declare_attack():
    ctx, store, events, board = case()
    ctx.config.context_only_rules = {"fixture": "Observation requiring independent confirmation"}
    submit(ctx, events, board)
    result = rank(ctx, verify(ctx, board).verified_state, store, [seed(events[0], "high")], [], events=events)
    assert result.attack_event_ids == []
    assert result.attack_decisions[events[0].event_id]["reason"] == "context_only_rule"
    assert result.findings and result.edges


def test_context_only_record_can_be_confirmed_by_independent_high_seed():
    ctx, store, events, board = case()
    ctx.config.context_only_rules = {"fixture": "Connection alone is not sufficient"}
    submit(ctx, events, board)
    independent = seed(events[1], "high").model_copy(update={"rule_id": "independent"})
    result = rank(ctx, verify(ctx, board).verified_state, store,
                  [seed(events[0], "medium"), independent], [], events=events)
    assert len(result.attack_event_ids) == 2
    assert result.attack_decisions[events[0].event_id]["reason"] == "verified_expansion"


def test_merged_context_high_cannot_lend_severity_or_tactics_to_medium_detection():
    ctx, store, events, board = case()
    ctx.config.context_only_rules = {"context-rule": "Collection observation"}
    submit(ctx, events, board)
    merged = seed(events[0], "high").model_copy(update={
        "matched_fields": {"contributing_sources": [
            {"rule_id": "context-rule", "level": "high", "tactic_ids": ["TA0008"]},
            {"rule_id": "independent", "level": "medium", "tactic_ids": ["TA0002"]},
        ]}})
    result = rank(ctx, verify(ctx, board).verified_state, store, [merged], [], events=events)
    assert result.attack_event_ids == [events[0].event_id]
    assert set(result.tactic_ranked_event_ids) == {"TA0002"}
    assert not result.attack_decisions[events[0].event_id]["can_expand"]


@pytest.mark.parametrize("policy", [{"": "reason"}, {"rule": " "}])
def test_policy_requires_reviewable_rule_ids_and_reasons(policy):
    with pytest.raises(ValueError):
        AppConfig(context_only_rules=policy)
