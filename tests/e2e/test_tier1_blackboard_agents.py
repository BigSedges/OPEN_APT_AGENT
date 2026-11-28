"""Tier 1 opaque-box E2E tests for Blackboard, Multi-Agent Graph, Ranker, and Budget (F07, F09, F10, F12).

All ``apt_agent.*`` imports are intentionally kept lazy inside test functions
and local helpers so pytest collection succeeds cleanly prior to M6 implementation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from _helpers import assert_valid_prediction


def _unwrap_verification(res: Any) -> tuple[Any, list[Any], list[Any]]:
    """Extract (verified_state, errors, unresolved) from attribute or dict result."""
    if isinstance(res, dict):
        state = res["verified_state"]
        errors = list(res.get("errors") or [])
        unresolved = list(res.get("unresolved") or [])
    else:
        state = res.verified_state
        errors = list(getattr(res, "errors", None) or [])
        unresolved = list(getattr(res, "unresolved", None) or [])
    return state, errors, unresolved


def _build_locator_map(index: dict[str, dict[str, Any]]) -> dict[str, Any]:
    from apt_agent.models import Locator

    return {
        pid: Locator(filepath=meta["filepath"], linenumber=meta["linenumber"])
        for pid, meta in index.items()
    }


def _prepare_normalized_scene(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_run_context: Any,
    make_app_config: Any,
    scene_name: str,
    *,
    case_id: str = "case-e2e-t1",
    run_id: str = "run-e2e-t1",
    stop_reason: str | None = None,
) -> tuple[Any, Any, Any, dict[str, dict[str, Any]], list[tuple[str, dict[str, Any]]], dict[str, Any]]:
    from apt_agent.ingestion import Normalizer, ingest_records

    scene_dir = e2e_fixtures_dir / "scenarios" / scene_name
    index, records = load_scene_records(scene_dir)
    loc_map = _build_locator_map(index)
    cfg = make_app_config(llm_enabled=False)
    ctx = make_run_context(
        case_id=case_id,
        run_id=run_id,
        config=cfg,
        valid_physical_ids=frozenset(index),
        locator_map=loc_map,
        stop_reason=stop_reason,
    )
    store = ingest_records(
        records,
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        locator_map=loc_map,
        valid_physical_ids=set(index),
    )
    norm = Normalizer().normalize_batch(ctx, store)
    pid_to_event = {ev.physical_record_id: ev for ev in norm.events}
    return ctx, store, norm, index, records, pid_to_event


def _ingest_synthetic_records(
    make_run_context: Any,
    make_app_config: Any,
    raw_items: list[tuple[str, dict[str, Any]]],
    *,
    case_id: str = "case-synth-t1",
    run_id: str = "run-synth-t1",
) -> tuple[Any, Any, Any, dict[str, Any]]:
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.models import Locator

    loc_map = {
        pid: Locator(filepath="data/synthetic/events.json", linenumber=idx)
        for idx, (pid, _) in enumerate(raw_items, start=1)
    }
    valid_pids = {pid for pid, _ in raw_items}
    cfg = make_app_config(llm_enabled=False)
    ctx = make_run_context(
        case_id=case_id,
        run_id=run_id,
        config=cfg,
        valid_physical_ids=frozenset(valid_pids),
        locator_map=loc_map,
    )
    store = ingest_records(
        raw_items,
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        locator_map=loc_map,
        valid_physical_ids=valid_pids,
    )
    norm = Normalizer().normalize_batch(ctx, store)
    assert norm.gaps == []
    assert len(norm.events) == len(raw_items)
    pid_to_event = {ev.physical_record_id: ev for ev in norm.events}
    return ctx, store, norm, pid_to_event


# ---------------------------------------------------------------------------
# F07: Multi-Agent Investigation Graph (5 tests)
# ---------------------------------------------------------------------------


@pytest.mark.tier1
def test_f07_multi_agent_phishing_c2_full_chain(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.pipeline import analyze_records

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    index, records = load_scene_records(scene_dir)
    loc_map = _build_locator_map(index)
    cfg = make_app_config(llm_enabled=False)

    pred = analyze_records(
        iter(records),
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=loc_map,
    )

    assert_valid_prediction(pred, set(index))
    assert {"pr-s01-0001", "pr-s01-0002", "pr-s01-0003"} <= set(pred["physical_id_set"])
    assert {"TA0002", "TA0011"} <= set(pred["ta_physical_ids"])


@pytest.mark.tier1
def test_f07_host_and_network_specialists_on_web_to_shell(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.pipeline import analyze_records

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_03_web_to_shell"
    index, records = load_scene_records(scene_dir)
    loc_map = _build_locator_map(index)
    cfg = make_app_config(llm_enabled=False)

    pred = analyze_records(
        iter(records),
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=loc_map,
    )

    assert_valid_prediction(pred, set(index))
    assert {"pr-s03-0001", "pr-s03-0003", "pr-s03-0004"} <= set(pred["physical_id_set"])
    assert {"TA0001", "TA0002", "TA0003"} <= set(pred["ta_physical_ids"])


@pytest.mark.tier1
def test_f07_challenger_and_verifier_separate_verified_from_disputed_nat(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.pipeline import analyze_records

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_06_nat_ambiguous"
    index, records = load_scene_records(scene_dir)
    loc_map = _build_locator_map(index)
    cfg = make_app_config(llm_enabled=False)

    pred = analyze_records(
        iter(records),
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=loc_map,
    )

    assert_valid_prediction(pred, set(index))
    assert {"pr-s06-0001", "pr-s06-0002"} <= set(pred["physical_id_set"])
    assert "pr-s06-0003" not in pred["physical_id_set"]


@pytest.mark.tier1
def test_f07_verifier_and_repair_resubmit_through_blackboard(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_run_context: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.blackboard import Blackboard, verify
    from apt_agent.models import Edge, Finding, Submission

    ctx, _store, norm, index, _records, pid_to_ev = _prepare_normalized_scene(
        e2e_fixtures_dir,
        load_scene_records,
        make_run_context,
        make_app_config,
        "scene_01_phishing_c2",
    )
    ev1 = pid_to_ev["pr-s01-0001"].event_id
    ev2 = pid_to_ev["pr-s01-0002"].event_id
    valid_event_ids = {ev.event_id for ev in norm.events}

    bb = Blackboard(ctx, valid_event_ids, set(index))
    bb.record_task_query("t-host", "q-host-1", {ev1})

    host_sub = Submission(
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        task_id="t-host",
        submission_id="sub-host-1",
        submitted_by="host",
        query_ids=["q-host-1"],
        findings=[
            Finding(
                claim="WINWORD spawned powershell with ProcessGuid G7",
                status="observed",
                evidence_event_ids=[ev1],
                tactic_ids=["TA0002"],
                submitted_by="host",
                verdict_malicious=True,
            )
        ],
        edges=[
            Edge(
                from_event_id=ev1,
                to_event_id=ev2,
                relation="same_process_guid",
                join_keys={"ProcessGuid": "G7"},
                evidence_event_ids=[ev1, ev2],
                status="proposed",
                sources=["host"],
            )
        ],
    )
    r1 = bb.submit_findings(ctx, host_sub)
    state1, errors1, unresolved1 = _unwrap_verification(verify(ctx, bb))

    assert ev1 in r1.accepted_event_ids
    assert ev2 not in state1.verified_event_refs
    assert errors1 or unresolved1 or r1.rejected_refs or state1.validation_errors

    # Repair must query ev2 and resubmit through the same Blackboard submission gate.
    bb.record_task_query("t-rep", "q-rep", {ev2})
    repair_sub = Submission(
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        task_id="t-rep",
        submission_id="sub-repair-1",
        submitted_by="repair",
        query_ids=["q-rep"],
        findings=[
            Finding(
                claim="Queried outbound network event for ProcessGuid G7",
                status="observed",
                evidence_event_ids=[ev2],
                tactic_ids=["TA0011"],
                submitted_by="repair",
                verdict_malicious=True,
            )
        ],
        edges=[
            Edge(
                from_event_id=ev1,
                to_event_id=ev2,
                relation="same_process_guid",
                join_keys={"ProcessGuid": "G7"},
                evidence_event_ids=[ev2],
                status="verified",
                sources=["repair"],
            )
        ],
    )
    r2 = bb.submit_findings(ctx, repair_sub)
    state2, _errors2, _unresolved2 = _unwrap_verification(verify(ctx, bb))

    assert ev2 in r2.accepted_event_ids
    assert ev1 in state2.verified_event_refs
    assert ev2 in state2.verified_event_refs
    verified_e41_e42 = [
        edge
        for edge in state2.candidate_edges
        if edge.from_event_id == ev1
        and edge.to_event_id == ev2
        and edge.status == "verified"
    ]
    assert verified_e41_e42


@pytest.mark.tier1
def test_f07_benign_workload_converges_to_empty_prediction(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.pipeline import analyze_records

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_09_benign"
    index, records = load_scene_records(scene_dir)
    loc_map = _build_locator_map(index)
    cfg = make_app_config(llm_enabled=False)

    pred = analyze_records(
        iter(records),
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=loc_map,
    )

    assert_valid_prediction(pred, set(index))
    assert pred == {"physical_id_set": [], "ta_physical_ids": {}}


# ---------------------------------------------------------------------------
# F09: Deterministic Blackboard Merger & Idempotency (5 tests)
# ---------------------------------------------------------------------------


@pytest.mark.tier1
def test_f09_submit_findings_valid_provenance_updates_state_version_and_receipt(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_run_context: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.blackboard import Blackboard
    from apt_agent.models import Finding, MergeReceipt, Submission

    ctx, _store, norm, index, _records, pid_to_ev = _prepare_normalized_scene(
        e2e_fixtures_dir,
        load_scene_records,
        make_run_context,
        make_app_config,
        "scene_01_phishing_c2",
    )
    ev1 = pid_to_ev["pr-s01-0001"].event_id
    bb = Blackboard(ctx, {ev.event_id for ev in norm.events}, set(index))
    bb.record_task_query("t-1", "q-1", {ev1})

    sub = Submission(
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        task_id="t-1",
        submission_id="sub-1",
        submitted_by="host",
        query_ids=["q-1"],
        findings=[
            Finding(
                claim="winword->ps",
                status="observed",
                evidence_event_ids=[ev1],
                tactic_ids=["TA0002"],
                verdict_malicious=True,
            )
        ],
    )
    receipt = bb.submit_findings(ctx, sub)

    assert isinstance(receipt, MergeReceipt)
    assert receipt.submission_id == "sub-1"
    assert ev1 in receipt.accepted_event_ids
    assert receipt.rejected_refs == []
    assert receipt.state_version >= 1
    assert receipt.replayed is False


@pytest.mark.tier1
def test_f09_idempotent_submission_replay_returns_cached_receipt(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_run_context: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.blackboard import Blackboard, verify
    from apt_agent.models import Finding, Submission

    ctx, _store, norm, index, _records, pid_to_ev = _prepare_normalized_scene(
        e2e_fixtures_dir,
        load_scene_records,
        make_run_context,
        make_app_config,
        "scene_01_phishing_c2",
    )
    ev1 = pid_to_ev["pr-s01-0001"].event_id
    bb = Blackboard(ctx, {ev.event_id for ev in norm.events}, set(index))
    bb.record_task_query("t-1", "q-1", {ev1})

    sub = Submission(
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        task_id="t-1",
        submission_id="sub-1",
        submitted_by="host",
        query_ids=["q-1"],
        findings=[
            Finding(
                claim="winword->ps",
                status="observed",
                evidence_event_ids=[ev1],
                tactic_ids=["TA0002"],
                verdict_malicious=True,
            )
        ],
    )
    r1 = bb.submit_findings(ctx, sub)
    r2 = bb.submit_findings(ctx, sub.model_copy(deep=True))
    state, _errors, _unresolved = _unwrap_verification(verify(ctx, bb))

    assert r2.submission_id == r1.submission_id
    assert r2.accepted_event_ids == r1.accepted_event_ids
    assert r2.state_version == r1.state_version
    assert r2.replayed is True
    assert len(state.findings) == 1


@pytest.mark.tier1
def test_f09_event_and_edge_dedup_merges_multiple_agent_sources(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_run_context: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.blackboard import Blackboard, verify
    from apt_agent.models import Edge, Finding, Submission

    ctx, _store, norm, index, _records, pid_to_ev = _prepare_normalized_scene(
        e2e_fixtures_dir,
        load_scene_records,
        make_run_context,
        make_app_config,
        "scene_01_phishing_c2",
    )
    ev1 = pid_to_ev["pr-s01-0001"].event_id
    ev2 = pid_to_ev["pr-s01-0002"].event_id
    bb = Blackboard(ctx, {ev.event_id for ev in norm.events}, set(index))
    bb.record_task_query("t-host", "q-h1", {ev1, ev2})
    bb.record_task_query("t-net", "q-n1", {ev1, ev2})

    sub_host = Submission(
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        task_id="t-host",
        submission_id="sub-host",
        submitted_by="host",
        query_ids=["q-h1"],
        findings=[
            Finding(
                claim="Host verified G7 process and socket",
                status="observed",
                evidence_event_ids=[ev1, ev2],
                tactic_ids=["TA0002"],
                submitted_by="host",
                verdict_malicious=True,
            )
        ],
        edges=[
            Edge(
                from_event_id=ev1,
                to_event_id=ev2,
                relation="same_process_guid",
                join_keys={"ProcessGuid": "G7"},
                evidence_event_ids=[ev1, ev2],
                status="verified",
                sources=["host"],
            )
        ],
    )
    sub_net = Submission(
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        task_id="t-net",
        submission_id="sub-net",
        submitted_by="network",
        query_ids=["q-n1"],
        findings=[
            Finding(
                claim="Network corroborated C2 flow from G7",
                status="observed",
                evidence_event_ids=[ev2],
                tactic_ids=["TA0011"],
                submitted_by="network",
                verdict_malicious=True,
            )
        ],
        edges=[
            Edge(
                from_event_id=ev1,
                to_event_id=ev2,
                relation="same_process_guid",
                join_keys={"ProcessGuid": "G7"},
                evidence_event_ids=[ev1, ev2],
                status="verified",
                sources=["network"],
            )
        ],
    )

    bb.submit_findings(ctx, sub_host)
    bb.submit_findings(ctx, sub_net)
    state, _errors, _unresolved = _unwrap_verification(verify(ctx, bb))

    assert ev2 in state.verified_event_refs
    assert list(state.verified_event_refs).count(ev2) == 1
    matching_edges = [
        edge
        for edge in state.candidate_edges
        if (edge.from_event_id, edge.to_event_id, edge.relation)
        == (ev1, ev2, "same_process_guid")
    ]
    assert len(matching_edges) == 1
    assert {"host", "network"} <= set(matching_edges[0].sources)


@pytest.mark.tier1
def test_f09_submission_arrival_order_independence_host_vs_network(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_run_context: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.models import Edge, Finding, Hit, RuleRun, Submission
    from apt_agent.pipeline import to_prediction

    ctx, store, norm, index, _records, pid_to_ev = _prepare_normalized_scene(
        e2e_fixtures_dir,
        load_scene_records,
        make_run_context,
        make_app_config,
        "scene_01_phishing_c2",
    )
    ev1 = pid_to_ev["pr-s01-0001"].event_id
    ev2 = pid_to_ev["pr-s01-0002"].event_id
    ev3 = pid_to_ev["pr-s01-0003"].event_id
    valid_events = {ev.event_id for ev in norm.events}

    sub_host = Submission(
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        task_id="t-host",
        submission_id="sub-host-order",
        submitted_by="host",
        query_ids=["q-host"],
        findings=[
            Finding(
                claim="Winword spawned powershell",
                status="observed",
                evidence_event_ids=[ev1, ev2],
                tactic_ids=["TA0002"],
                submitted_by="host",
                verdict_malicious=True,
            )
        ],
        edges=[
            Edge(
                from_event_id=ev1,
                to_event_id=ev2,
                relation="same_process_guid",
                join_keys={"ProcessGuid": "G7"},
                evidence_event_ids=[ev1, ev2],
                status="verified",
                sources=["host"],
            )
        ],
    )
    sub_net = Submission(
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        task_id="t-net",
        submission_id="sub-net-order",
        submitted_by="network",
        query_ids=["q-net"],
        findings=[
            Finding(
                claim="Zeek conn corroborated outbound 5-tuple",
                status="observed",
                evidence_event_ids=[ev2, ev3],
                tactic_ids=["TA0011"],
                submitted_by="network",
                verdict_malicious=True,
            )
        ],
        edges=[
            Edge(
                from_event_id=ev2,
                to_event_id=ev3,
                relation="network_5tuple_flow",
                join_keys={"proto": "tcp", "dst_ip": "203.0.113.8", "dst_port": 443},
                evidence_event_ids=[ev2, ev3],
                status="verified",
                sources=["network"],
            )
        ],
    )
    hits = [
        Hit(
            hit_id="hit-1",
            rule_id="win_winword_powershell",
            engine="pysigma",
            event_ids=[ev1],
            tactic_ids=["TA0002"],
        ),
        Hit(
            hit_id="hit-2",
            rule_id="win_powershell_c2_flow",
            engine="pysigma",
            event_ids=[ev2],
            tactic_ids=["TA0011"],
        ),
    ]
    coverage = [RuleRun(rule_id="win_winword_powershell", engine="pysigma", status="ran", hit_count=1)]

    def _run_with_order(first: Submission, second: Submission) -> tuple[Any, dict[str, Any]]:
        bb = Blackboard(ctx, valid_events, set(index))
        bb.record_task_query("t-host", "q-host", {ev1, ev2})
        bb.record_task_query("t-net", "q-net", {ev2, ev3})
        bb.submit_findings(ctx, first.model_copy(deep=True))
        bb.submit_findings(ctx, second.model_copy(deep=True))
        state, _err, _unres = _unwrap_verification(verify(ctx, bb))
        cr = rank(ctx, state, store, hits, coverage)
        pred = to_prediction(ctx, cr, valid_physical_ids=set(index))
        return cr, pred

    cr_ab, pred_ab = _run_with_order(sub_host, sub_net)
    cr_ba, pred_ba = _run_with_order(sub_net, sub_host)

    assert len(cr_ab.chains) >= 1
    assert cr_ab.attack_event_ids
    assert cr_ab.tactic_ranked_event_ids
    assert {"pr-s01-0001", "pr-s01-0002", "pr-s01-0003"} <= set(pred_ab["physical_id_set"])
    assert cr_ab.attack_event_ids == cr_ba.attack_event_ids
    assert [c.chain_id for c in cr_ab.chains] == [c.chain_id for c in cr_ba.chains]
    assert cr_ab.tactic_ranked_event_ids == cr_ba.tactic_ranked_event_ids
    assert pred_ab == pred_ba


@pytest.mark.tier1
def test_f09_contradictory_claims_coexist_as_disputed_without_overwrite(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_run_context: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.blackboard import Blackboard, verify
    from apt_agent.models import Finding, Submission

    ctx, _store, norm, index, _records, pid_to_ev = _prepare_normalized_scene(
        e2e_fixtures_dir,
        load_scene_records,
        make_run_context,
        make_app_config,
        "scene_01_phishing_c2",
    )
    ev1 = pid_to_ev["pr-s01-0001"].event_id
    bb = Blackboard(ctx, {ev.event_id for ev in norm.events}, set(index))
    bb.record_task_query("t-host", "q-host", {ev1})
    bb.record_task_query("t-chal", "q-chal", {ev1})

    bb.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="t-host",
            submission_id="sub-host-claim",
            submitted_by="host",
            query_ids=["q-host"],
            findings=[
                Finding(
                    claim="Malicious PowerShell",
                    status="observed",
                    evidence_event_ids=[ev1],
                    tactic_ids=["TA0002"],
                    submitted_by="host",
                    verdict_malicious=True,
                )
            ],
        ),
    )
    bb.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="t-chal",
            submission_id="sub-chal-claim",
            submitted_by="challenger",
            query_ids=["q-chal"],
            findings=[
                Finding(
                    claim="Benign add-in maintenance",
                    status="disputed",
                    evidence_event_ids=[ev1],
                    opposing_event_ids=[ev1],
                    tactic_ids=["TA0002"],
                    submitted_by="challenger",
                    verdict_malicious=False,
                )
            ],
        ),
    )

    state, _errors, _unresolved = _unwrap_verification(verify(ctx, bb))
    claims = [f.claim for f in state.findings]
    assert "Malicious PowerShell" in claims
    assert "Benign add-in maintenance" in claims
    assert any(f.status == "disputed" for f in state.findings) or len(state.disputed_items) >= 1
    assert any(ev1 in f.evidence_event_ids for f in state.findings)
    assert any(ev1 in f.opposing_event_ids for f in state.findings)


# ---------------------------------------------------------------------------
# F10: Correlation Priority Join Keys & Deterministic Ranker (5 tests)
# ---------------------------------------------------------------------------


@pytest.mark.tier1
def test_f10_priority1_and_priority2_join_keys_correlate_e41_e42_e43(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_run_context: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.models import Edge, Finding, Hit, RuleRun, Submission
    from apt_agent.pipeline import to_prediction

    ctx, store, norm, index, _records, pid_to_ev = _prepare_normalized_scene(
        e2e_fixtures_dir,
        load_scene_records,
        make_run_context,
        make_app_config,
        "scene_01_phishing_c2",
    )
    ev_e41 = pid_to_ev["pr-s01-0001"].event_id
    ev_e42 = pid_to_ev["pr-s01-0002"].event_id
    ev_e43 = pid_to_ev["pr-s01-0003"].event_id

    bb = Blackboard(ctx, {ev.event_id for ev in norm.events}, set(index))
    bb.record_task_query("t-corr", "q-corr", {ev_e41, ev_e42, ev_e43})
    bb.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="t-corr",
            submission_id="sub-corr-1",
            submitted_by="host",
            query_ids=["q-corr"],
            findings=[
                Finding(
                    claim="E41->E42->E43 correlated chain",
                    status="observed",
                    evidence_event_ids=[ev_e41, ev_e42, ev_e43],
                    tactic_ids=["TA0002", "TA0011"],
                    verdict_malicious=True,
                )
            ],
            edges=[
                Edge(
                    from_event_id=ev_e41,
                    to_event_id=ev_e42,
                    relation="same_process_guid",
                    join_keys={"ProcessGuid": "G7", "host": "H1.example.local"},
                    evidence_event_ids=[ev_e41, ev_e42],
                    status="verified",
                    sources=["host"],
                ),
                Edge(
                    from_event_id=ev_e42,
                    to_event_id=ev_e43,
                    relation="network_5tuple_flow",
                    join_keys={
                        "proto": "tcp",
                        "src_ip": "10.0.1.8",
                        "src_port": 51030,
                        "dst_ip": "203.0.113.8",
                        "dst_port": 443,
                    },
                    evidence_event_ids=[ev_e42, ev_e43],
                    status="verified",
                    sources=["network"],
                ),
            ],
        ),
    )

    state, _err, _unres = _unwrap_verification(verify(ctx, bb))
    hits = [
        Hit(
            hit_id="h-e41",
            rule_id="win_winword_powershell",
            engine="pysigma",
            event_ids=[ev_e41],
            tactic_ids=["TA0002"],
        ),
        Hit(
            hit_id="h-e42",
            rule_id="win_powershell_c2_flow",
            engine="pysigma",
            event_ids=[ev_e42],
            tactic_ids=["TA0011"],
        ),
    ]
    coverage = [RuleRun(rule_id="win_winword_powershell", engine="pysigma", status="ran", hit_count=1)]
    cr = rank(ctx, state, store, hits, coverage)
    pred = to_prediction(ctx, cr, valid_physical_ids=set(index))

    matching_chains = [
        chain for chain in cr.chains if {ev_e41, ev_e42, ev_e43} <= set(chain.event_ids)
    ]
    assert matching_chains
    chain = matching_chains[0]
    assert chain.chain_id
    assert chain.locators
    assert {cr.event_to_physical[e] for e in (ev_e41, ev_e42, ev_e43)} == {
        "pr-s01-0001",
        "pr-s01-0002",
        "pr-s01-0003",
    }
    assert_valid_prediction(pred, set(index))
    assert pred["physical_id_set"] == ["pr-s01-0001", "pr-s01-0002", "pr-s01-0003"]


@pytest.mark.tier1
def test_f10_chain_lexicographic_sort_orders_clean_corroborated_multistage_first(
    make_run_context: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.models import Edge, Finding, Hit, RuleRun, Submission

    def _rec(pid: str, ts: str, host: str, guid: str, cmd: str) -> tuple[str, dict[str, Any]]:
        return (
            pid,
            {
                "id": f"ecar-{pid}",
                "object": "PROCESS",
                "action": "CREATE",
                "hostname": host,
                "timestamp": ts,
                "properties": {
                    "process_guid": guid,
                    "command_line": cmd,
                },
            },
        )

    raw_items = [
        # Chain A (clean=True, corroborated=2, direct_stages=2)
        _rec("pr-a-1", "2024-05-30T10:00:01Z", "HOST-A", "GA-1", "a1"),
        _rec("pr-a-2", "2024-05-30T10:00:02Z", "HOST-A", "GA-1", "a2"),
        _rec("pr-a-3", "2024-05-30T10:00:03Z", "HOST-A", "GA-1", "a3"),
        # Chain B (clean=True, corroborated=0/1, direct_stages=3)
        _rec("pr-b-1", "2024-05-30T10:01:01Z", "HOST-B", "GB-1", "b1"),
        _rec("pr-b-2", "2024-05-30T10:01:02Z", "HOST-B", "GB-1", "b2"),
        _rec("pr-b-3", "2024-05-30T10:01:03Z", "HOST-B", "GB-1", "b3"),
        _rec("pr-b-4", "2024-05-30T10:01:04Z", "HOST-B", "GB-1", "b4"),
        # Chain C (clean=True, corroborated=0/1, direct_stages=1)
        _rec("pr-c-1", "2024-05-30T10:02:01Z", "HOST-C", "GC-1", "c1"),
        _rec("pr-c-2", "2024-05-30T10:02:02Z", "HOST-C", "GC-1", "c2"),
        # Chain D (clean=False / disputed, corroborated=3, direct_stages=3)
        _rec("pr-d-1", "2024-05-30T10:03:01Z", "HOST-D", "GD-1", "d1"),
        _rec("pr-d-2", "2024-05-30T10:03:02Z", "HOST-D", "GD-1", "d2"),
        _rec("pr-d-3", "2024-05-30T10:03:03Z", "HOST-D", "GD-1", "d3"),
        _rec("pr-d-4", "2024-05-30T10:03:04Z", "HOST-D", "GD-1", "d4"),
    ]
    ctx, store, norm, p2e = _ingest_synthetic_records(make_run_context, make_app_config, raw_items)
    ev = {pid: event.event_id for pid, event in p2e.items()}
    valid_events = set(ev.values())
    valid_pids = set(p2e.keys())

    bb = Blackboard(ctx, valid_events, valid_pids)
    bb.record_task_query("t-all", "q-all", valid_events)

    edges = [
        # A: 2 verified edges, each corroborated by 2 distinct sources
        Edge(from_event_id=ev["pr-a-1"], to_event_id=ev["pr-a-2"], relation="same_process_guid", join_keys={"ProcessGuid": "GA-1"}, evidence_event_ids=[ev["pr-a-1"], ev["pr-a-2"]], status="verified", sources=["host", "network"]),
        Edge(from_event_id=ev["pr-a-2"], to_event_id=ev["pr-a-3"], relation="same_process_guid", join_keys={"ProcessGuid": "GA-1"}, evidence_event_ids=[ev["pr-a-2"], ev["pr-a-3"]], status="verified", sources=["host", "network"]),
        # B: 3 verified edges, single source each
        Edge(from_event_id=ev["pr-b-1"], to_event_id=ev["pr-b-2"], relation="same_process_guid", join_keys={"ProcessGuid": "GB-1"}, evidence_event_ids=[ev["pr-b-1"], ev["pr-b-2"]], status="verified", sources=["host"]),
        Edge(from_event_id=ev["pr-b-2"], to_event_id=ev["pr-b-3"], relation="same_process_guid", join_keys={"ProcessGuid": "GB-1"}, evidence_event_ids=[ev["pr-b-2"], ev["pr-b-3"]], status="verified", sources=["host"]),
        Edge(from_event_id=ev["pr-b-3"], to_event_id=ev["pr-b-4"], relation="same_process_guid", join_keys={"ProcessGuid": "GB-1"}, evidence_event_ids=[ev["pr-b-3"], ev["pr-b-4"]], status="verified", sources=["host"]),
        # C: 1 verified edge, single source
        Edge(from_event_id=ev["pr-c-1"], to_event_id=ev["pr-c-2"], relation="same_process_guid", join_keys={"ProcessGuid": "GC-1"}, evidence_event_ids=[ev["pr-c-1"], ev["pr-c-2"]], status="verified", sources=["host"]),
        # D: 3 edges with 3 sources, but contains disputed relation
        Edge(from_event_id=ev["pr-d-1"], to_event_id=ev["pr-d-2"], relation="same_process_guid", join_keys={"ProcessGuid": "GD-1"}, evidence_event_ids=[ev["pr-d-1"], ev["pr-d-2"]], status="verified", sources=["host", "network", "verifier"]),
        Edge(from_event_id=ev["pr-d-2"], to_event_id=ev["pr-d-3"], relation="same_process_guid", join_keys={"ProcessGuid": "GD-1"}, evidence_event_ids=[ev["pr-d-2"], ev["pr-d-3"]], status="verified", sources=["host", "network", "verifier"]),
        Edge(from_event_id=ev["pr-d-3"], to_event_id=ev["pr-d-4"], relation="network_5tuple_flow", join_keys={"dst_ip": "203.0.113.8"}, evidence_event_ids=[ev["pr-d-3"], ev["pr-d-4"]], opposing_evidence_ids=[ev["pr-d-4"]], status="disputed", ambiguity_reason="nat_egress_without_translation_log", sources=["host", "network", "challenger"]),
    ]
    findings = [
        Finding(claim="Chain A", status="observed", evidence_event_ids=[ev["pr-a-1"], ev["pr-a-2"], ev["pr-a-3"]], tactic_ids=["TA0002"], verdict_malicious=True),
        Finding(claim="Chain B", status="observed", evidence_event_ids=[ev["pr-b-1"], ev["pr-b-2"], ev["pr-b-3"], ev["pr-b-4"]], tactic_ids=["TA0002"], verdict_malicious=True),
        Finding(claim="Chain C", status="observed", evidence_event_ids=[ev["pr-c-1"], ev["pr-c-2"]], tactic_ids=["TA0002"], verdict_malicious=True),
        Finding(claim="Chain D disputed", status="disputed", evidence_event_ids=[ev["pr-d-1"], ev["pr-d-2"], ev["pr-d-3"]], opposing_event_ids=[ev["pr-d-4"]], tactic_ids=["TA0002"], verdict_malicious=True),
    ]
    bb.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="t-all",
            submission_id="sub-lex",
            submitted_by="host",
            query_ids=["q-all"],
            findings=findings,
            edges=edges,
        ),
    )

    state, _err, _unres = _unwrap_verification(verify(ctx, bb))
    hits = [
        Hit(hit_id="ha1", rule_id="r1", engine="pysigma", event_ids=[ev["pr-a-1"]], tactic_ids=["TA0002"]),
        Hit(hit_id="ha2", rule_id="r2", engine="pysigma", event_ids=[ev["pr-a-2"]], tactic_ids=["TA0002"]),
        Hit(hit_id="hb1", rule_id="r1", engine="pysigma", event_ids=[ev["pr-b-1"]], tactic_ids=["TA0002"]),
        Hit(hit_id="hb2", rule_id="r2", engine="pysigma", event_ids=[ev["pr-b-2"]], tactic_ids=["TA0002"]),
        Hit(hit_id="hb3", rule_id="r3", engine="pysigma", event_ids=[ev["pr-b-3"]], tactic_ids=["TA0002"]),
        Hit(hit_id="hc1", rule_id="r1", engine="pysigma", event_ids=[ev["pr-c-1"]], tactic_ids=["TA0002"]),
        Hit(hit_id="hd1", rule_id="r1", engine="pysigma", event_ids=[ev["pr-d-1"]], tactic_ids=["TA0002"]),
        Hit(hit_id="hd2", rule_id="r2", engine="pysigma", event_ids=[ev["pr-d-2"]], tactic_ids=["TA0002"]),
        Hit(hit_id="hd3", rule_id="r3", engine="pysigma", event_ids=[ev["pr-d-3"]], tactic_ids=["TA0002"]),
    ]
    coverage = [RuleRun(rule_id="r1", engine="pysigma", status="ran", hit_count=4)]

    cr = rank(ctx, state, store, hits, coverage)

    def _idx_of(seed_ev: str) -> int:
        for i, chain in enumerate(cr.chains):
            if seed_ev in chain.event_ids:
                return i
        raise AssertionError(f"Chain containing {seed_ev!r} not found in {cr.chains!r}")

    idx_a = _idx_of(ev["pr-a-1"])
    idx_b = _idx_of(ev["pr-b-1"])
    idx_c = _idx_of(ev["pr-c-1"])
    idx_d = _idx_of(ev["pr-d-1"])
    assert idx_a < idx_b < idx_c < idx_d


@pytest.mark.tier1
def test_f10_per_tactic_top_k_sort_prioritizes_direct_evidence_then_corroboration_then_id(
    make_run_context: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.models import Finding, Hit, RuleRun, Submission
    from apt_agent.pipeline import to_prediction

    def _ecar_proc(pid: str, ts: str, cmd: str) -> tuple[str, dict[str, Any]]:
        return (
            pid,
            {
                "id": f"ecar-{pid}",
                "object": "PROCESS",
                "action": "CREATE",
                "hostname": "H1",
                "timestamp": ts,
                "properties": {"command_line": cmd},
            },
        )

    raw_items = [
        _ecar_proc("pr-t-d2", "2024-05-30T10:00:01Z", "d2"),
        _ecar_proc("pr-t-x", "2024-05-30T10:00:02Z", "dx"),
        _ecar_proc("pr-t-y", "2024-05-30T10:00:03Z", "dy"),
        _ecar_proc("pr-t-ind2", "2024-05-30T10:00:04Z", "ind2"),
    ]
    ctx, store, _norm, p2e = _ingest_synthetic_records(make_run_context, make_app_config, raw_items)
    ev_d2 = p2e["pr-t-d2"].event_id
    ev_d1_a, ev_d1_b = sorted([p2e["pr-t-x"].event_id, p2e["pr-t-y"].event_id])
    ev_ind2 = p2e["pr-t-ind2"].event_id
    all_evs = {ev_d2, ev_d1_a, ev_d1_b, ev_ind2}
    ev_to_pid = {event.event_id: pid for pid, event in p2e.items()}

    bb = Blackboard(ctx, all_evs, set(p2e.keys()))
    bb.record_task_query("t-host", "q-h", all_evs)
    bb.record_task_query("t-net", "q-n", {ev_d2, ev_ind2})

    bb.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="t-host",
            submission_id="sub-host-rank",
            submitted_by="host",
            query_ids=["q-h"],
            findings=[
                Finding(
                    claim="Host TA0002 candidates",
                    status="observed",
                    evidence_event_ids=[ev_d2, ev_d1_a, ev_d1_b, ev_ind2],
                    tactic_ids=["TA0002"],
                    submitted_by="host",
                    sources=["host"],
                    verdict_malicious=True,
                )
            ],
        ),
    )
    bb.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="t-net",
            submission_id="sub-net-rank",
            submitted_by="network",
            query_ids=["q-n"],
            findings=[
                Finding(
                    claim="Network corroborates d2 and ind2",
                    status="observed",
                    evidence_event_ids=[ev_d2, ev_ind2],
                    tactic_ids=["TA0002"],
                    submitted_by="network",
                    sources=["network"],
                    verdict_malicious=True,
                )
            ],
        ),
    )

    state, _err, _unres = _unwrap_verification(verify(ctx, bb))
    hits = [
        Hit(hit_id="h1", rule_id="r-ta2", engine="pysigma", event_ids=[ev_d2], tactic_ids=["TA0002"]),
        Hit(hit_id="h2", rule_id="r-ta2", engine="pysigma", event_ids=[ev_d1_a], tactic_ids=["TA0002"]),
        Hit(hit_id="h3", rule_id="r-ta2", engine="pysigma", event_ids=[ev_d1_b], tactic_ids=["TA0002"]),
    ]
    coverage = [RuleRun(rule_id="r-ta2", engine="pysigma", status="ran", hit_count=3)]

    cr = rank(ctx, state, store, hits, coverage)
    pred = to_prediction(ctx, cr, valid_physical_ids=set(p2e.keys()))

    assert cr.tactic_ranked_event_ids["TA0002"] == [ev_d2, ev_d1_a, ev_d1_b, ev_ind2]
    assert_valid_prediction(pred, set(p2e.keys()))
    assert pred["ta_physical_ids"]["TA0002"] == [
        ev_to_pid[ev_d2],
        ev_to_pid[ev_d1_a],
        ev_to_pid[ev_d1_b],
    ]


@pytest.mark.tier1
def test_f10_duplicate_connection_observations_count_as_one_behavior_with_all_raw_refs(
    make_run_context: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.models import Edge, Finding, Hit, RuleRun, Submission

    proc_item = (
        "pr-dup-proc",
        {
            "id": "ecar-pr-dup-proc",
            "object": "PROCESS",
            "action": "CREATE",
            "hostname": "H1",
            "timestamp": "2024-05-30T10:00:00Z",
            "properties": {
                "process_guid": "G7",
                "command_line": "powershell.exe",
            },
        },
    )
    conn_1 = (
        "pr-dup-c1",
        {
            "ts": 1717063203.0,
            "uid": "Cg7Dup001",
            "id.orig_h": "10.0.1.8",
            "id.orig_p": 51030,
            "id.resp_h": "203.0.113.8",
            "id.resp_p": 443,
            "proto": "tcp",
            "zeek_log_type": "conn",
        },
    )
    conn_2 = (
        "pr-dup-c2",
        {
            "ts": 1717063203.0,
            "uid": "Cg7Dup001-dup",
            "id.orig_h": "10.0.1.8",
            "id.orig_p": 51030,
            "id.resp_h": "203.0.113.8",
            "id.resp_p": 443,
            "proto": "tcp",
            "zeek_log_type": "conn",
        },
    )

    # Single-observation baseline
    ctx_s, store_s, _ns, p2e_s = _ingest_synthetic_records(
        make_run_context, make_app_config, [proc_item, conn_1], case_id="case-s", run_id="run-s"
    )
    ev_ps = p2e_s["pr-dup-proc"].event_id
    ev_c1s = p2e_s["pr-dup-c1"].event_id
    bb_s = Blackboard(ctx_s, {ev_ps, ev_c1s}, {"pr-dup-proc", "pr-dup-c1"})
    bb_s.record_task_query("t-1", "q-1", {ev_ps, ev_c1s})
    bb_s.submit_findings(
        ctx_s,
        Submission(
            case_id=ctx_s.case_id,
            run_id=ctx_s.run_id,
            task_id="t-1",
            submission_id="sub-s",
            submitted_by="network",
            query_ids=["q-1"],
            findings=[
                Finding(
                    claim="Single 5-tuple observation",
                    status="observed",
                    evidence_event_ids=[ev_ps, ev_c1s],
                    tactic_ids=["TA0011"],
                    verdict_malicious=True,
                )
            ],
            edges=[
                Edge(
                    from_event_id=ev_ps,
                    to_event_id=ev_c1s,
                    relation="network_5tuple_flow",
                    join_keys={"proto": "tcp", "src_ip": "10.0.1.8", "src_port": 51030, "dst_ip": "203.0.113.8", "dst_port": 443},
                    evidence_event_ids=[ev_ps, ev_c1s],
                    status="verified",
                    sources=["network"],
                )
            ],
        ),
    )
    st_s, _, _ = _unwrap_verification(verify(ctx_s, bb_s))
    cr_single = rank(
        ctx_s,
        st_s,
        store_s,
        [Hit(hit_id="hs", rule_id="r-c2", engine="pysigma", event_ids=[ev_ps, ev_c1s], tactic_ids=["TA0011"])],
        [RuleRun(rule_id="r-c2", engine="pysigma", status="ran", hit_count=1)],
    )

    # Duplicate-observation run (two raw records of identical 5-tuple connection)
    ctx_d, store_d, _nd, p2e_d = _ingest_synthetic_records(
        make_run_context, make_app_config, [proc_item, conn_1, conn_2], case_id="case-d", run_id="run-d"
    )
    ev_pd = p2e_d["pr-dup-proc"].event_id
    ev_c1d = p2e_d["pr-dup-c1"].event_id
    ev_c2d = p2e_d["pr-dup-c2"].event_id
    bb_d = Blackboard(ctx_d, {ev_pd, ev_c1d, ev_c2d}, {"pr-dup-proc", "pr-dup-c1", "pr-dup-c2"})
    bb_d.record_task_query("t-1", "q-1", {ev_pd, ev_c1d, ev_c2d})
    bb_d.submit_findings(
        ctx_d,
        Submission(
            case_id=ctx_d.case_id,
            run_id=ctx_d.run_id,
            task_id="t-1",
            submission_id="sub-d",
            submitted_by="network",
            query_ids=["q-1"],
            findings=[
                Finding(
                    claim="Duplicate 5-tuple observations",
                    status="observed",
                    evidence_event_ids=[ev_pd, ev_c1d, ev_c2d],
                    tactic_ids=["TA0011"],
                    verdict_malicious=True,
                )
            ],
            edges=[
                Edge(
                    from_event_id=ev_pd,
                    to_event_id=ev_c1d,
                    relation="network_5tuple_flow",
                    join_keys={"proto": "tcp", "src_ip": "10.0.1.8", "src_port": 51030, "dst_ip": "203.0.113.8", "dst_port": 443},
                    evidence_event_ids=[ev_pd, ev_c1d],
                    status="verified",
                    sources=["network"],
                ),
                Edge(
                    from_event_id=ev_pd,
                    to_event_id=ev_c2d,
                    relation="network_5tuple_flow",
                    join_keys={"proto": "tcp", "src_ip": "10.0.1.8", "src_port": 51030, "dst_ip": "203.0.113.8", "dst_port": 443},
                    evidence_event_ids=[ev_pd, ev_c2d],
                    status="verified",
                    sources=["network"],
                ),
            ],
        ),
    )
    st_d, _, _ = _unwrap_verification(verify(ctx_d, bb_d))
    cr_dup = rank(
        ctx_d,
        st_d,
        store_d,
        [
            Hit(hit_id="hd1", rule_id="r-c2", engine="pysigma", event_ids=[ev_pd, ev_c1d], tactic_ids=["TA0011"]),
            Hit(hit_id="hd2", rule_id="r-c2", engine="pysigma", event_ids=[ev_c2d], tactic_ids=["TA0011"]),
        ],
        [RuleRun(rule_id="r-c2", engine="pysigma", status="ran", hit_count=2)],
    )

    assert {"pr-dup-proc", "pr-dup-c1", "pr-dup-c2"} <= set(cr_dup.event_to_physical.values())
    assert {ev_pd, ev_c1d, ev_c2d} <= set(st_d.verified_event_refs.keys())
    assert cr_dup.chains and cr_single.chains
    assert cr_dup.chains[0].corroborated_critical_count == cr_single.chains[0].corroborated_critical_count
    assert cr_dup.chains[0].direct_evidence_stages == cr_single.chains[0].direct_evidence_stages


@pytest.mark.tier1
def test_f10_snapshot_replay_reverify_and_rerank_is_identical(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_run_context: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.models import Edge, Finding, GraphState, Hit, RuleRun, Submission
    from apt_agent.pipeline import to_prediction

    ctx, store, norm, index, _records, pid_to_ev = _prepare_normalized_scene(
        e2e_fixtures_dir,
        load_scene_records,
        make_run_context,
        make_app_config,
        "scene_01_phishing_c2",
    )
    ev1 = pid_to_ev["pr-s01-0001"].event_id
    ev2 = pid_to_ev["pr-s01-0002"].event_id
    ev3 = pid_to_ev["pr-s01-0003"].event_id

    bb = Blackboard(ctx, {ev.event_id for ev in norm.events}, set(index))
    bb.record_task_query("t-1", "q-1", {ev1, ev2, ev3})
    bb.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="t-1",
            submission_id="sub-snap-1",
            submitted_by="host",
            query_ids=["q-1"],
            findings=[
                Finding(
                    claim="Full chain E41->E42->E43",
                    status="observed",
                    evidence_event_ids=[ev1, ev2, ev3],
                    tactic_ids=["TA0002", "TA0011"],
                    verdict_malicious=True,
                )
            ],
            edges=[
                Edge(from_event_id=ev1, to_event_id=ev2, relation="same_process_guid", join_keys={"ProcessGuid": "G7"}, evidence_event_ids=[ev1, ev2], status="verified", sources=["host"]),
                Edge(from_event_id=ev2, to_event_id=ev3, relation="network_5tuple_flow", join_keys={"proto": "tcp", "dst_ip": "203.0.113.8", "dst_port": 443}, evidence_event_ids=[ev2, ev3], status="verified", sources=["network"]),
            ],
        ),
    )

    v_state, _err, _unres = _unwrap_verification(verify(ctx, bb))
    snap_payload = v_state.model_dump()
    v_rehydrated = GraphState.model_validate(snap_payload)

    hits = [
        Hit(hit_id="h1", rule_id="win_winword_powershell", engine="pysigma", event_ids=[ev1], tactic_ids=["TA0002"]),
        Hit(hit_id="h2", rule_id="win_powershell_c2_flow", engine="pysigma", event_ids=[ev2], tactic_ids=["TA0011"]),
    ]
    coverage = [RuleRun(rule_id="win_winword_powershell", engine="pysigma", status="ran", hit_count=1)]

    cr1 = rank(ctx, v_state, store, hits, coverage)
    cr2 = rank(ctx, v_rehydrated, store, hits, coverage)
    p1 = to_prediction(ctx, cr1, valid_physical_ids=set(index))
    p2 = to_prediction(ctx, cr2, valid_physical_ids=set(index))

    assert len(cr1.chains) >= 1
    assert cr1.attack_event_ids
    assert cr1.tactic_ranked_event_ids
    assert {"pr-s01-0001", "pr-s01-0002", "pr-s01-0003"} <= set(p1["physical_id_set"])
    assert cr1.model_dump() == cr2.model_dump()
    assert p1 == p2


# ---------------------------------------------------------------------------
# F12: Budget, Caching & Graceful Degradation (5 tests)
# ---------------------------------------------------------------------------


@pytest.mark.tier1
def test_f12_default_budget_config_matches_spec_defaults(
    make_app_config: Any,
) -> None:
    from apt_agent.config import load_config

    for cfg in (make_app_config(), load_config()):
        assert cfg.budget.max_tasks_per_round == 3
        assert cfg.budget.max_rounds == 5
        assert cfg.budget.max_steps_per_task == 8
        assert cfg.budget.max_challenger_rounds == 1
        assert cfg.budget.max_repair_rounds == 1
        assert cfg.budget.wall_clock_s == 300.0
        assert cfg.budget.max_tokens == 120000
        assert cfg.budget.reserve_ratio == 0.8


@pytest.mark.tier1
def test_f12_llm_disabled_uses_deterministic_seed_fallback(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.pipeline import analyze_records

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    index, records = load_scene_records(scene_dir)
    loc_map = _build_locator_map(index)
    cfg = make_app_config(llm_enabled=False)

    pred = analyze_records(
        iter(records),
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=loc_map,
    )

    assert_valid_prediction(pred, set(index))
    assert {"pr-s01-0001", "pr-s01-0002", "pr-s01-0003"} <= set(pred["physical_id_set"])


@pytest.mark.tier1
def test_f12_degraded_engine_crash_and_rag_timeout_export_partial_results(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_app_config: Any,
) -> None:
    import json

    from apt_agent.pipeline import analyze_records

    slow_dir = tmp_path / "slow_rag"
    slow_dir.mkdir(parents=True, exist_ok=True)
    langgraph_rag_dir = (
        Path(__file__).resolve().parents[2] / "packages" / "apt-rag" / "tools" / "langgraph_rag"
    )
    orig_manifest = json.loads((langgraph_rag_dir / "tool.json").read_text(encoding="utf-8"))
    slow_worker = slow_dir / "slow_worker.py"
    slow_worker.write_text("import time\ntime.sleep(5)\n", encoding="utf-8")
    slow_manifest = slow_dir / "tool.json"
    slow_manifest.write_text(
        json.dumps({**orig_manifest, "argv": ["{python}", "-B", slow_worker.name], "timeout_ms": 100}),
        encoding="utf-8",
    )

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_07_degraded"
    index, records = load_scene_records(scene_dir)
    loc_map = _build_locator_map(index)
    cfg = make_app_config(
        base_dir=tmp_path / "degraded_env",
        engine_modes={"hayabusa": "crash"},
        rag_timeout_ms=100,
        rag_offline=False,
        overrides={"rag": {"config_path": str(slow_manifest), "offline": False}},
        budget_overrides={"max_rounds": 1, "reserve_ratio": 0.8},
        llm_enabled=False,
    )

    pred = analyze_records(
        iter(records),
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=loc_map,
    )

    assert_valid_prediction(pred, set(index))
    assert pred["physical_id_set"]
    assert set(pred["physical_id_set"]) & {"pr-s07-0001", "pr-s07-0002", "pr-s07-0003"}


@pytest.mark.tier1
def test_f12_stop_reason_and_coverage_propagated_into_case_result_only(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_run_context: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.models import Finding, Hit, RuleRun, Submission
    from apt_agent.pipeline import to_prediction

    ctx, store, norm, index, _records, pid_to_ev = _prepare_normalized_scene(
        e2e_fixtures_dir,
        load_scene_records,
        make_run_context,
        make_app_config,
        "scene_01_phishing_c2",
        stop_reason="BUDGET_EXHAUSTED",
    )
    ev1 = pid_to_ev["pr-s01-0001"].event_id
    bb = Blackboard(ctx, {ev.event_id for ev in norm.events}, set(index))
    bb.record_task_query("t-1", "q-1", {ev1})
    bb.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="t-1",
            submission_id="sub-stop-1",
            submitted_by="host",
            query_ids=["q-1"],
            findings=[
                Finding(
                    claim="Verified before budget exhaustion",
                    status="observed",
                    evidence_event_ids=[ev1],
                    tactic_ids=["TA0002"],
                    verdict_malicious=True,
                )
            ],
        ),
    )

    v_state, _err, _unres = _unwrap_verification(verify(ctx, bb))
    hits = [Hit(hit_id="h1", rule_id="win_winword_powershell", engine="pysigma", event_ids=[ev1], tactic_ids=["TA0002"])]
    coverage = [
        RuleRun(rule_id="win_winword_powershell", engine="pysigma", status="ran", hit_count=1),
        RuleRun(rule_id="win_powershell_c2_flow", engine="takajo", status="skipped", reason="binary not configured", hit_count=0),
        RuleRun(rule_id="zeek_http_c2_beacon", engine="hayabusa", status="failed", reason="simulated crash", hit_count=0),
    ]

    cr = rank(ctx, v_state, store, hits, coverage)
    pred = to_prediction(ctx, cr, valid_physical_ids=set(index))

    assert cr.stop_reason == "BUDGET_EXHAUSTED"
    assert len(cr.coverage) == 3
    assert [r.status for r in cr.coverage] == ["ran", "skipped", "failed"]
    assert_valid_prediction(pred, set(index))
    assert set(pred.keys()) == {"physical_id_set", "ta_physical_ids"}


@pytest.mark.tier1
def test_f12_repeated_offline_runs_produce_identical_cached_predictions(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.pipeline import analyze_records

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    index, records = load_scene_records(scene_dir)
    loc_map = _build_locator_map(index)
    cfg = make_app_config(llm_enabled=False, rag_mode="bm25")

    pred1 = analyze_records(
        iter(records),
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=loc_map,
    )
    pred2 = analyze_records(
        iter(records),
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=loc_map,
    )

    assert_valid_prediction(pred1, set(index))
    assert pred1 == pred2
