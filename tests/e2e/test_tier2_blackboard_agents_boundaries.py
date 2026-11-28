"""Tier 2 boundary-value and negative opaque-box E2E tests (F07, F09, F10, F12).

All ``apt_agent.*`` imports are kept lazy inside test functions and local
helpers so pytest collection runs cleanly prior to M6 implementation.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import shutil
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
    case_id: str = "case-e2e-t2",
    run_id: str = "run-e2e-t2",
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
    )
    store = ingest_records(
        records,
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        locator_map=loc_map,
        valid_physical_ids=set(index),
    )
    norm = Normalizer().normalize_batch(ctx, store)
    pid_to_ev = {ev.physical_record_id: ev for ev in norm.events}
    return ctx, store, norm, index, records, pid_to_ev


def _ingest_synthetic_records(
    make_run_context: Any,
    make_app_config: Any,
    raw_items: list[tuple[str, dict[str, Any]]],
    *,
    case_id: str = "case-synth-t2",
    run_id: str = "run-synth-t2",
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
    pid_to_ev = {ev.physical_record_id: ev for ev in norm.events}
    return ctx, store, norm, pid_to_ev


# ---------------------------------------------------------------------------
# F07 Boundaries (5 tests)
# ---------------------------------------------------------------------------


@pytest.mark.tier2
def test_f07_boundary_zero_sigma_hits_uses_seed_fallback_and_returns_empty(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.pipeline import analyze_records

    rules_only_dir = tmp_path / "rules_only_benign"
    rules_only_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(
        e2e_fixtures_dir / "rules" / "valid" / "benign_no_match.yml",
        rules_only_dir / "benign_no_match.yml",
    )

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    index, records = load_scene_records(scene_dir)
    loc_map = _build_locator_map(index)
    cfg = make_app_config(rules_dir=rules_only_dir, llm_enabled=False)

    pred = analyze_records(
        iter(records),
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=loc_map,
    )

    assert_valid_prediction(pred, set(index))
    assert pred == {"physical_id_set": [], "ta_physical_ids": {}}


@pytest.mark.tier2
def test_f07_boundary_kb_only_hypothesis_never_promoted_to_physical_id_set(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_run_context: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.models import Finding, KnowledgeRef, Submission
    from apt_agent.pipeline import to_prediction

    ctx, store, norm, index, _records, _p2e = _prepare_normalized_scene(
        e2e_fixtures_dir,
        load_scene_records,
        make_run_context,
        make_app_config,
        "scene_09_benign",
    )
    bb = Blackboard(ctx, {ev.event_id for ev in norm.events}, set(index))
    kb_ref = KnowledgeRef(
        retrieval_id="ret-kb-hist-1",
        doc_id="doc-hist-wks99",
        chunk_id="kb-hist-unrelated-certutil",
        version="kb-1.0",
        locator="kb/synthetic_kb.jsonl:5",
        excerpt=(
            "Sanitized historical incident on WKS-99: certutil.exe -urlcache "
            "staged payload from 192.0.2.55 (unrelated to current case assets)."
        ),
        match_reason="historical_case",
        source_url="https://kb.synthetic.local/history/wks-99-certutil",
        author="IR Archive",
    )

    bb.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="t-kb-only",
            submission_id="sub-kb-hyp-1",
            submitted_by="network",
            query_ids=[],
            findings=[
                Finding(
                    claim="Historical certutil staging hypothesis",
                    status="hypothesis",
                    evidence_event_ids=[],
                    knowledge_refs=[kb_ref],
                    tactic_ids=["TA0011"],
                    verdict_malicious=True,
                )
            ],
        ),
    )

    state, _err, _unres = _unwrap_verification(verify(ctx, bb))
    cr = rank(ctx, state, store, [], [])
    pred = to_prediction(ctx, cr, valid_physical_ids=set(index))

    assert cr.attack_event_ids == []
    assert_valid_prediction(pred, set(index))
    assert pred == {"physical_id_set": [], "ta_physical_ids": {}}


@pytest.mark.tier2
def test_f07_boundary_kb_id_spoofed_as_evidence_rejected_by_blackboard_and_verifier(
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
    spoofed_ids = ["kb-playbook-e41-pivot", "doc-playbook-proc-net", "rag:req-1"]

    bb = Blackboard(ctx, {ev.event_id for ev in norm.events}, set(index))
    bb.record_task_query("t-spoof", "q-spoof", {ev1})

    receipt = bb.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="t-spoof",
            submission_id="sub-spoof-1",
            submitted_by="host",
            query_ids=["q-spoof"],
            findings=[
                Finding(
                    claim="Attempted spoofed KB IDs as event evidence",
                    status="observed",
                    evidence_event_ids=spoofed_ids,
                    tactic_ids=["TA0002"],
                    verdict_malicious=True,
                )
            ],
        ),
    )
    state, _err, _unres = _unwrap_verification(verify(ctx, bb))

    assert receipt.accepted_event_ids == []
    assert len(receipt.rejected_refs) == 3
    assert {r.ref for r in receipt.rejected_refs} == set(spoofed_ids)
    for bad_id in spoofed_ids:
        assert bad_id not in state.verified_event_refs


@pytest.mark.tier2
def test_f07_boundary_single_engine_timeout_preserves_surviving_branches(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_fake_engine_bins: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.pipeline import analyze_records

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    index, records = load_scene_records(scene_dir)
    loc_map = _build_locator_map(index)
    bins = make_fake_engine_bins(engine_modes={"hayabusa": "timeout"}, sleep_s=5.0)
    cfg = make_app_config(fake_bins=bins, timeout_s=0.3, llm_enabled=False)

    pred = analyze_records(
        iter(records),
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=loc_map,
    )

    assert_valid_prediction(pred, set(index))
    assert pred["physical_id_set"]
    assert {"pr-s01-0001", "pr-s01-0003"} <= set(pred["physical_id_set"])


@pytest.mark.tier2
def test_f07_boundary_repair_cannot_bypass_task_query_provenance(
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
    ev2 = pid_to_ev["pr-s01-0002"].event_id

    bb = Blackboard(ctx, {ev.event_id for ev in norm.events}, set(index))
    bb.record_task_query("t-host", "q-1", {ev1})

    repair_sub = Submission(
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        task_id="t-rep",
        submission_id="sub-repair-bypass",
        submitted_by="repair",
        query_ids=[],
        findings=[
            Finding(
                claim="Repair claiming unqueried ev2",
                status="observed",
                evidence_event_ids=[ev2],
                tactic_ids=["TA0011"],
                submitted_by="repair",
                verdict_malicious=True,
            )
        ],
    )
    receipt = bb.submit_findings(ctx, repair_sub)
    state, _err, _unres = _unwrap_verification(verify(ctx, bb))

    assert ev2 not in receipt.accepted_event_ids
    assert ev2 in [x.ref for x in receipt.rejected_refs]
    assert ev2 not in state.verified_event_refs


# ---------------------------------------------------------------------------
# F09 Boundaries (6 tests)
# ---------------------------------------------------------------------------


@pytest.mark.tier2
def test_f09_boundary_same_submission_id_different_payload_raises_conflict(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_run_context: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.blackboard import Blackboard, verify
    from apt_agent.exceptions import ConflictError
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

    sub_a = Submission(
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        task_id="t-1",
        submission_id="sub-dup",
        submitted_by="host",
        query_ids=["q-1"],
        findings=[
            Finding(
                claim="A",
                status="observed",
                evidence_event_ids=[ev1],
                tactic_ids=["TA0002"],
                verdict_malicious=True,
            )
        ],
    )
    r_a = bb.submit_findings(ctx, sub_a)

    sub_b = Submission(
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        task_id="t-1",
        submission_id="sub-dup",
        submitted_by="host",
        query_ids=["q-1"],
        findings=[
            Finding(
                claim="B",
                status="observed",
                evidence_event_ids=[ev1],
                tactic_ids=["TA0002"],
                verdict_malicious=True,
            )
        ],
    )
    with pytest.raises(ConflictError):
        bb.submit_findings(ctx, sub_b)

    state, _err, _unres = _unwrap_verification(verify(ctx, bb))
    assert [f.claim for f in state.findings] == ["A"]
    assert state.state_version == r_a.state_version


@pytest.mark.tier2
def test_f09_boundary_same_submission_id_distinct_run_ids_do_not_collide(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_run_context: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.blackboard import Blackboard
    from apt_agent.models import Finding, Submission

    ctx1, _s1, norm1, idx1, _r1, p2e1 = _prepare_normalized_scene(
        e2e_fixtures_dir,
        load_scene_records,
        make_run_context,
        make_app_config,
        "scene_01_phishing_c2",
        case_id="case-run-iso",
        run_id="run-1",
    )
    ctx2, _s2, norm2, idx2, _r2, p2e2 = _prepare_normalized_scene(
        e2e_fixtures_dir,
        load_scene_records,
        make_run_context,
        make_app_config,
        "scene_01_phishing_c2",
        case_id="case-run-iso",
        run_id="run-2",
    )
    ev1_r1 = p2e1["pr-s01-0001"].event_id
    ev1_r2 = p2e2["pr-s01-0001"].event_id

    bb1 = Blackboard(ctx1, {ev.event_id for ev in norm1.events}, set(idx1))
    bb1.record_task_query("t-1", "q-1", {ev1_r1})
    bb2 = Blackboard(ctx2, {ev.event_id for ev in norm2.events}, set(idx2))
    bb2.record_task_query("t-1", "q-1", {ev1_r2})

    r1 = bb1.submit_findings(
        ctx1,
        Submission(
            case_id=ctx1.case_id,
            run_id="run-1",
            task_id="t-1",
            submission_id="sub-001",
            submitted_by="host",
            query_ids=["q-1"],
            findings=[
                Finding(
                    claim="Run1",
                    status="observed",
                    evidence_event_ids=[ev1_r1],
                    tactic_ids=["TA0002"],
                    verdict_malicious=True,
                )
            ],
        ),
    )
    r2 = bb2.submit_findings(
        ctx2,
        Submission(
            case_id=ctx2.case_id,
            run_id="run-2",
            task_id="t-1",
            submission_id="sub-001",
            submitted_by="host",
            query_ids=["q-1"],
            findings=[
                Finding(
                    claim="Run2",
                    status="observed",
                    evidence_event_ids=[ev1_r2],
                    tactic_ids=["TA0002"],
                    verdict_malicious=True,
                )
            ],
        ),
    )

    assert r1.submission_id == "sub-001"
    assert r2.submission_id == "sub-001"
    assert r1.replayed is False
    assert r2.replayed is False


@pytest.mark.tier2
def test_f09_boundary_cross_case_event_id_rejected_as_out_of_scope(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_run_context: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.blackboard import Blackboard, verify
    from apt_agent.exceptions import OutOfScopeError
    from apt_agent.models import Finding, Submission

    ctx, _store, _norm, _idx, _recs, pid_to_ev = _prepare_normalized_scene(
        e2e_fixtures_dir,
        load_scene_records,
        make_run_context,
        make_app_config,
        "scene_01_phishing_c2",
    )
    ev1 = pid_to_ev["pr-s01-0001"].event_id
    ev_foreign = "ev-other-case-999"

    bb = Blackboard(ctx, {ev1}, {"pr-s01-0001"})
    bb.record_task_query("t-1", "q-1", {ev1})

    r_foreign = bb.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="t-1",
            submission_id="sub-foreign-ev",
            submitted_by="host",
            query_ids=["q-1"],
            findings=[
                Finding(
                    claim="Foreign case event",
                    status="observed",
                    evidence_event_ids=[ev_foreign],
                    tactic_ids=["TA0002"],
                    verdict_malicious=True,
                )
            ],
        ),
    )
    assert ev_foreign not in r_foreign.accepted_event_ids
    assert any(
        ref.ref == ev_foreign and str(ref.code) == "OUT_OF_SCOPE"
        for ref in r_foreign.rejected_refs
    )

    cross_case_sub = Submission(
        case_id="other-case",
        run_id=ctx.run_id,
        task_id="t-1",
        submission_id="sub-wrong-case-id",
        submitted_by="host",
        query_ids=["q-1"],
        findings=[
            Finding(
                claim="Cross-case submission",
                status="observed",
                evidence_event_ids=[ev1],
                tactic_ids=["TA0002"],
                verdict_malicious=True,
            )
        ],
    )
    try:
        r_cross = bb.submit_findings(ctx, cross_case_sub)
    except OutOfScopeError:
        pass
    else:
        assert r_cross.accepted_event_ids == []
        assert any(str(ref.code) == "OUT_OF_SCOPE" for ref in r_cross.rejected_refs)

    state, _err, _unres = _unwrap_verification(verify(ctx, bb))
    assert ev_foreign not in state.verified_event_refs


@pytest.mark.tier2
def test_f09_boundary_in_case_unqueried_event_id_rejected_for_observed_claim(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_run_context: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.blackboard import Blackboard, verify
    from apt_agent.models import Finding, Submission

    ctx, _store, _norm, index, _recs, pid_to_ev = _prepare_normalized_scene(
        e2e_fixtures_dir,
        load_scene_records,
        make_run_context,
        make_app_config,
        "scene_01_phishing_c2",
    )
    ev1 = pid_to_ev["pr-s01-0001"].event_id
    ev2 = pid_to_ev["pr-s01-0002"].event_id

    bb = Blackboard(ctx, {ev1, ev2}, set(index))
    bb.record_task_query("t-1", "q-1", {ev1})

    receipt = bb.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="t-1",
            submission_id="sub-partial-query",
            submitted_by="host",
            query_ids=["q-1"],
            findings=[
                Finding(
                    claim="Observed claim mixing queried ev1 and unqueried ev2",
                    status="observed",
                    evidence_event_ids=[ev1, ev2],
                    tactic_ids=["TA0002"],
                    verdict_malicious=True,
                )
            ],
        ),
    )
    state, _err, _unres = _unwrap_verification(verify(ctx, bb))

    assert ev1 in receipt.accepted_event_ids
    assert ev2 not in receipt.accepted_event_ids
    assert ev2 in [x.ref for x in receipt.rejected_refs]
    assert ev2 not in state.verified_event_refs


@pytest.mark.tier2
def test_f09_boundary_edge_direction_distinguishes_a_to_b_vs_b_to_a(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_run_context: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.blackboard import Blackboard, verify
    from apt_agent.models import Edge, Finding, Submission

    ctx, _store, norm, index, _recs, pid_to_ev = _prepare_normalized_scene(
        e2e_fixtures_dir,
        load_scene_records,
        make_run_context,
        make_app_config,
        "scene_01_phishing_c2",
    )
    ev1 = pid_to_ev["pr-s01-0001"].event_id
    ev2 = pid_to_ev["pr-s01-0002"].event_id

    bb = Blackboard(ctx, {ev.event_id for ev in norm.events}, set(index))
    bb.record_task_query("t-dir", "q-dir", {ev1, ev2})

    bb.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="t-dir",
            submission_id="sub-dir-1",
            submitted_by="host",
            query_ids=["q-dir"],
            findings=[
                Finding(
                    claim="Directional edges test",
                    status="observed",
                    evidence_event_ids=[ev1, ev2],
                    tactic_ids=["TA0002"],
                    verdict_malicious=True,
                )
            ],
            edges=[
                Edge(
                    from_event_id=ev1,
                    to_event_id=ev2,
                    relation="related",
                    evidence_event_ids=[ev1, ev2],
                    status="verified",
                    sources=["host"],
                ),
                Edge(
                    from_event_id=ev2,
                    to_event_id=ev1,
                    relation="related",
                    evidence_event_ids=[ev1, ev2],
                    status="verified",
                    sources=["network"],
                ),
            ],
        ),
    )

    state, _err, _unres = _unwrap_verification(verify(ctx, bb))
    edge_tuples = {(e.from_event_id, e.to_event_id, e.relation) for e in state.candidate_edges}
    assert (ev1, ev2, "related") in edge_tuples
    assert (ev2, ev1, "related") in edge_tuples


@pytest.mark.tier2
def test_f09_boundary_concurrent_threads_submit_safely_without_lost_updates(
    make_run_context: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.blackboard import Blackboard, verify
    from apt_agent.models import Finding, Submission

    raw_items = [
        (
            f"pr-conc-{i}",
            {
                "id": f"ecar-conc-{i}",
                "object": "PROCESS",
                "action": "CREATE",
                "hostname": "HOST-CONC",
                "timestamp": f"2024-05-30T10:00:{i:02d}Z",
                "properties": {
                    "process_guid": f"GC-{i}",
                    "command_line": f"cmd-{i}.exe",
                },
            },
        )
        for i in range(10)
    ]
    ctx, _store, _norm, p2e = _ingest_synthetic_records(make_run_context, make_app_config, raw_items)
    valid_pids = set(p2e.keys())
    evs = [p2e[f"pr-conc-{i}"].event_id for i in range(10)]

    bb = Blackboard(ctx, set(evs), valid_pids)
    for i, ev_id in enumerate(evs):
        bb.record_task_query(f"t-{i}", f"q-{i}", {ev_id})

    submissions = [
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id=f"t-{i}",
            submission_id=f"sub-{i}",
            submitted_by="host",
            query_ids=[f"q-{i}"],
            findings=[
                Finding(
                    claim=f"Concurrent claim {i}",
                    status="observed",
                    evidence_event_ids=[evs[i]],
                    tactic_ids=["TA0002"],
                    verdict_malicious=True,
                )
            ],
        )
        for i in range(10)
    ]
    submissions.append(submissions[0].model_copy(deep=True))

    with ThreadPoolExecutor(max_workers=5) as pool:
        receipts = list(pool.map(lambda s: bb.submit_findings(ctx, s), submissions))

    assert len(receipts) == 11
    state, _err, _unres = _unwrap_verification(verify(ctx, bb))
    assert len(state.verified_event_refs) == 10
    assert set(state.verified_event_refs.keys()) == set(evs)


# ---------------------------------------------------------------------------
# F10 Boundaries (5 tests)
# ---------------------------------------------------------------------------


@pytest.mark.tier2
def test_f10_boundary_missing_g7_and_duplicate_flows_degrade_edges_to_unresolved(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_run_context: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.models import Edge, Finding, Hit, RuleRun, Submission
    from apt_agent.pipeline import analyze_records

    # E2E pipeline check on both ambiguous scenes
    for scene_name in ("scene_01b_missing_g7", "scene_01c_ambiguous_flows"):
        scene_dir = e2e_fixtures_dir / "scenarios" / scene_name
        index, records = load_scene_records(scene_dir)
        cfg = make_app_config(llm_enabled=False)
        pred = analyze_records(
            iter(records),
            config=cfg,
            valid_physical_ids=set(index),
            locator_map=_build_locator_map(index),
        )
        assert_valid_prediction(pred, set(index))

    # Component check: scene_01b missing ProcessGuid G7
    ctx_b, store_b, norm_b, idx_b, _rb, p2e_b = _prepare_normalized_scene(
        e2e_fixtures_dir,
        load_scene_records,
        make_run_context,
        make_app_config,
        "scene_01b_missing_g7",
        case_id="case-01b",
        run_id="run-01b",
    )
    ev_b1 = p2e_b["pr-s01b-0001"].event_id
    ev_b2 = p2e_b["pr-s01b-0002"].event_id
    bb_b = Blackboard(ctx_b, {ev.event_id for ev in norm_b.events}, set(idx_b))
    bb_b.record_task_query("t-b", "q-b", {ev_b1, ev_b2})
    bb_b.submit_findings(
        ctx_b,
        Submission(
            case_id=ctx_b.case_id,
            run_id=ctx_b.run_id,
            task_id="t-b",
            submission_id="sub-b",
            submitted_by="host",
            query_ids=["q-b"],
            findings=[
                Finding(
                    claim="Missing G7 on E42",
                    status="observed",
                    evidence_event_ids=[ev_b1, ev_b2],
                    tactic_ids=["TA0002"],
                    verdict_malicious=True,
                )
            ],
            edges=[
                Edge(
                    from_event_id=ev_b1,
                    to_event_id=ev_b2,
                    relation="same_process_guid",
                    join_keys={},
                    evidence_event_ids=[ev_b1, ev_b2],
                    status="proposed",
                    ambiguity_reason="missing_process_guid_g7",
                    sources=["host"],
                )
            ],
        ),
    )
    st_b, _eb, _ub = _unwrap_verification(verify(ctx_b, bb_b))
    cr_b = rank(
        ctx_b,
        st_b,
        store_b,
        [Hit(hit_id="hb1", rule_id="win_winword_powershell", engine="pysigma", event_ids=[ev_b1], tactic_ids=["TA0002"])],
        [RuleRun(rule_id="win_winword_powershell", engine="pysigma", status="ran", hit_count=1)],
    )
    assert cr_b.unresolved
    assert not any(
        c.critical_relations_clean and {ev_b1, ev_b2} <= set(c.event_ids)
        for c in cr_b.chains
    )

    # Component check: scene_01c duplicate Zeek 5-tuple flows
    ctx_c, store_c, norm_c, idx_c, _rc, p2e_c = _prepare_normalized_scene(
        e2e_fixtures_dir,
        load_scene_records,
        make_run_context,
        make_app_config,
        "scene_01c_ambiguous_flows",
        case_id="case-01c",
        run_id="run-01c",
    )
    ev_c2 = p2e_c["pr-s01c-0002"].event_id
    ev_c3 = p2e_c["pr-s01c-0003"].event_id
    ev_c4 = p2e_c["pr-s01c-0004"].event_id
    bb_c = Blackboard(ctx_c, {ev.event_id for ev in norm_c.events}, set(idx_c))
    bb_c.record_task_query("t-c", "q-c", {ev_c2, ev_c3, ev_c4})
    bb_c.submit_findings(
        ctx_c,
        Submission(
            case_id=ctx_c.case_id,
            run_id=ctx_c.run_id,
            task_id="t-c",
            submission_id="sub-c",
            submitted_by="network",
            query_ids=["q-c"],
            findings=[
                Finding(
                    claim="Duplicate 5-tuple Zeek flows",
                    status="observed",
                    evidence_event_ids=[ev_c2, ev_c3, ev_c4],
                    tactic_ids=["TA0011"],
                    verdict_malicious=True,
                )
            ],
            edges=[
                Edge(
                    from_event_id=ev_c2,
                    to_event_id=ev_c3,
                    relation="network_5tuple_flow",
                    join_keys={"dst_ip": "203.0.113.8", "dst_port": 443},
                    evidence_event_ids=[ev_c2, ev_c3],
                    status="proposed",
                    ambiguity_reason="duplicate_zeek_5tuple_flows",
                    sources=["network"],
                ),
                Edge(
                    from_event_id=ev_c2,
                    to_event_id=ev_c4,
                    relation="network_5tuple_flow",
                    join_keys={"dst_ip": "203.0.113.8", "dst_port": 443},
                    evidence_event_ids=[ev_c2, ev_c4],
                    status="proposed",
                    ambiguity_reason="duplicate_zeek_5tuple_flows",
                    sources=["network"],
                ),
            ],
        ),
    )
    st_c, _ec, _uc = _unwrap_verification(verify(ctx_c, bb_c))
    cr_c = rank(
        ctx_c,
        st_c,
        store_c,
        [Hit(hit_id="hc1", rule_id="win_powershell_c2_flow", engine="pysigma", event_ids=[ev_c2], tactic_ids=["TA0011"])],
        [RuleRun(rule_id="win_powershell_c2_flow", engine="pysigma", status="ran", hit_count=1)],
    )
    assert cr_c.unresolved
    assert not any(
        c.critical_relations_clean and ({ev_c2, ev_c3} <= set(c.event_ids) or {ev_c2, ev_c4} <= set(c.event_ids))
        for c in cr_c.chains
    )


@pytest.mark.tier2
def test_f10_boundary_shared_ip_or_time_proximity_alone_cannot_form_verified_chain(
    make_run_context: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.models import Edge, Finding, Hit, RuleRun, Submission

    raw_items = [
        (
            "pr-ip-1",
            {
                "id": "ecar-ip-1",
                "object": "PROCESS",
                "action": "CREATE",
                "hostname": "HOST-ALPHA",
                "timestamp": "2024-05-30T10:00:00Z",
                "properties": {
                    "dst_ip": "203.0.113.8",
                    "command_line": "alpha.exe",
                },
            },
        ),
        (
            "pr-ip-2",
            {
                "id": "ecar-ip-2",
                "object": "PROCESS",
                "action": "CREATE",
                "hostname": "HOST-BETA",
                "timestamp": "2024-05-30T10:00:01Z",
                "properties": {
                    "dst_ip": "203.0.113.8",
                    "command_line": "beta.exe",
                },
            },
        ),
    ]
    ctx, store, _norm, p2e = _ingest_synthetic_records(make_run_context, make_app_config, raw_items)
    ev1 = p2e["pr-ip-1"].event_id
    ev2 = p2e["pr-ip-2"].event_id

    bb = Blackboard(ctx, {ev1, ev2}, {"pr-ip-1", "pr-ip-2"})
    bb.record_task_query("t-ip", "q-ip", {ev1, ev2})
    bb.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="t-ip",
            submission_id="sub-ip-only",
            submitted_by="network",
            query_ids=["q-ip"],
            findings=[
                Finding(
                    claim="Two hosts share dst_ip within 1s",
                    status="observed",
                    evidence_event_ids=[ev1, ev2],
                    tactic_ids=["TA0011"],
                    verdict_malicious=True,
                )
            ],
            edges=[
                Edge(
                    from_event_id=ev1,
                    to_event_id=ev2,
                    relation="shared_dst_ip",
                    join_keys={"dst_ip": "203.0.113.8"},
                    evidence_event_ids=[ev1, ev2],
                    status="proposed",
                    sources=["network"],
                )
            ],
        ),
    )

    state, _err, _unres = _unwrap_verification(verify(ctx, bb))
    assert not any(
        edge.from_event_id == ev1 and edge.to_event_id == ev2 and edge.status == "verified"
        for edge in state.candidate_edges
    )

    cr = rank(
        ctx,
        state,
        store,
        [Hit(hit_id="hip", rule_id="r-ip", engine="pysigma", event_ids=[ev1, ev2], tactic_ids=["TA0011"])],
        [RuleRun(rule_id="r-ip", engine="pysigma", status="ran", hit_count=1)],
    )
    assert cr.unresolved
    assert not any(
        c.critical_relations_clean and {ev1, ev2} <= set(c.event_ids)
        for c in cr.chains
    )


@pytest.mark.tier2
def test_f10_boundary_rag_similarity_and_agent_votes_do_not_affect_ranking(
    make_run_context: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.models import Finding, Hit, KnowledgeRef, RuleRun, Submission

    raw_items = [
        (
            "pr-tie-1",
            {
                "id": "ecar-tie-1",
                "object": "PROCESS",
                "action": "CREATE",
                "hostname": "H1",
                "timestamp": "2024-05-30T10:00:01Z",
                "properties": {"command_line": "one.exe"},
            },
        ),
        (
            "pr-tie-2",
            {
                "id": "ecar-tie-2",
                "object": "PROCESS",
                "action": "CREATE",
                "hostname": "H1",
                "timestamp": "2024-05-30T10:00:02Z",
                "properties": {"command_line": "two.exe"},
            },
        ),
    ]
    ctx, store, _norm, p2e = _ingest_synthetic_records(make_run_context, make_app_config, raw_items)
    ev_low_id, ev_high_id = sorted([p2e["pr-tie-1"].event_id, p2e["pr-tie-2"].event_id])

    kb_refs = [
        KnowledgeRef(
            retrieval_id=f"ret-{i}",
            doc_id="doc-playbook-proc-net",
            chunk_id="kb-playbook-e41-pivot",
            version="kb-1.0",
            locator=f"kb/synthetic_kb.jsonl:{i}",
            excerpt="Playbook pivot guidance.",
            match_reason="high_bm25_score_0.99",
        )
        for i in range(1, 4)
    ]

    bb = Blackboard(ctx, {ev_low_id, ev_high_id}, {"pr-tie-1", "pr-tie-2"})
    bb.record_task_query("t-tie", "q-tie", {ev_low_id, ev_high_id})

    # Higher-ID event gets 3 KnowledgeRefs and 3 findings from the same agent source,
    # whereas lower-ID event gets 0 KnowledgeRefs and 1 finding from that source.
    bb.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="t-tie",
            submission_id="sub-tie-votes",
            submitted_by="host",
            query_ids=["q-tie"],
            findings=[
                Finding(
                    claim="Vote 1 on high-rag event",
                    status="observed",
                    evidence_event_ids=[ev_high_id],
                    knowledge_refs=kb_refs,
                    tactic_ids=["TA0002"],
                    submitted_by="host",
                    sources=["host"],
                    verdict_malicious=True,
                ),
                Finding(
                    claim="Vote 2 on high-rag event",
                    status="observed",
                    evidence_event_ids=[ev_high_id],
                    knowledge_refs=kb_refs,
                    tactic_ids=["TA0002"],
                    submitted_by="host",
                    sources=["host"],
                    verdict_malicious=True,
                ),
                Finding(
                    claim="Vote 3 on high-rag event",
                    status="observed",
                    evidence_event_ids=[ev_high_id],
                    knowledge_refs=kb_refs,
                    tactic_ids=["TA0002"],
                    submitted_by="host",
                    sources=["host"],
                    verdict_malicious=True,
                ),
                Finding(
                    claim="Single finding with zero RAG refs",
                    status="observed",
                    evidence_event_ids=[ev_low_id],
                    knowledge_refs=[],
                    tactic_ids=["TA0002"],
                    submitted_by="host",
                    sources=["host"],
                    verdict_malicious=True,
                ),
            ],
        ),
    )

    state, _err, _unres = _unwrap_verification(verify(ctx, bb))
    hits = [
        Hit(hit_id="h-low", rule_id="r-tie", engine="pysigma", event_ids=[ev_low_id], tactic_ids=["TA0002"]),
        Hit(hit_id="h-high", rule_id="r-tie", engine="pysigma", event_ids=[ev_high_id], tactic_ids=["TA0002"]),
    ]
    coverage = [RuleRun(rule_id="r-tie", engine="pysigma", status="ran", hit_count=2)]

    cr = rank(ctx, state, store, hits, coverage)
    assert cr.tactic_ranked_event_ids["TA0002"] == [ev_low_id, ev_high_id]


@pytest.mark.tier2
def test_f10_boundary_tie_breaker_deterministic_under_shuffled_input_order(
    make_run_context: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.models import Edge, Finding, Hit, RuleRun, Submission

    raw_items = [
        (
            f"pr-shuf-{i}",
            {
                "id": f"ecar-shuf-{i}",
                "object": "PROCESS",
                "action": "CREATE",
                "hostname": f"HOST-{i}",
                "timestamp": f"2024-05-30T10:0{i}:00Z",
                "properties": {
                    "process_guid": f"GS-{i}",
                    "command_line": f"tool-{i}.exe",
                },
            },
        )
        for i in (1, 2, 3)
    ]

    def _run_ordered(items: list[tuple[str, dict[str, Any]]], reverse_hits: bool) -> Any:
        ctx, store, _norm, p2e = _ingest_synthetic_records(
            make_run_context,
            make_app_config,
            items,
            case_id="case-shuf",
            run_id="run-shuf",
        )
        evs = [p2e[pid].event_id for pid, _ in items]
        bb = Blackboard(ctx, set(evs), {pid for pid, _ in items})
        bb.record_task_query("t-shuf", "q-shuf", set(evs))
        findings = [
            Finding(
                claim=f"Claim for {ev}",
                status="observed",
                evidence_event_ids=[ev],
                tactic_ids=["TA0002"],
                submitted_by="host",
                verdict_malicious=True,
            )
            for ev in evs
        ]
        bb.submit_findings(
            ctx,
            Submission(
                case_id=ctx.case_id,
                run_id=ctx.run_id,
                task_id="t-shuf",
                submission_id="sub-shuf",
                submitted_by="host",
                query_ids=["q-shuf"],
                findings=findings,
                edges=[
                    Edge(
                        from_event_id=ev,
                        to_event_id=ev,
                        relation="self_anchor",
                        evidence_event_ids=[ev],
                        status="verified",
                        sources=["host"],
                    )
                    for ev in evs
                ],
            ),
        )
        state, _err, _unres = _unwrap_verification(verify(ctx, bb))
        hits = [
            Hit(hit_id=f"h-{i}", rule_id="r-shuf", engine="pysigma", event_ids=[ev], tactic_ids=["TA0002"])
            for i, ev in enumerate(evs)
        ]
        if reverse_hits:
            hits.reverse()
        coverage = [RuleRun(rule_id="r-shuf", engine="pysigma", status="ran", hit_count=3)]
        return rank(ctx, state, store, hits, coverage)

    cr_fwd = _run_ordered(raw_items, reverse_hits=False)
    cr_rev = _run_ordered(list(reversed(raw_items)), reverse_hits=True)

    assert len(cr_fwd.chains) >= 1
    assert cr_fwd.tactic_ranked_event_ids
    assert cr_fwd.attack_event_ids
    assert [c.chain_id for c in cr_fwd.chains] == [c.chain_id for c in cr_rev.chains]
    assert cr_fwd.tactic_ranked_event_ids == cr_rev.tactic_ranked_event_ids
    assert cr_fwd.attack_event_ids == cr_rev.attack_event_ids


@pytest.mark.tier2
def test_f10_boundary_time_reversed_edge_flagged_and_excluded_from_clean_chains(
    make_run_context: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.models import Edge, Finding, Hit, RuleRun, Submission

    raw_items = [
        (
            "pr-trev-early",
            {
                "id": "ecar-trev-early",
                "object": "PROCESS",
                "action": "CREATE",
                "hostname": "HOST-TIME",
                "timestamp": "2024-05-30T10:00:00Z",
                "properties": {
                    "process_guid": "GT-1",
                    "command_line": "child.exe",
                },
            },
        ),
        (
            "pr-trev-late",
            {
                "id": "ecar-trev-late",
                "object": "PROCESS",
                "action": "CREATE",
                "hostname": "HOST-TIME",
                "timestamp": "2024-05-30T10:05:00Z",
                "properties": {
                    "process_guid": "GT-1",
                    "command_line": "parent.exe",
                },
            },
        ),
    ]
    ctx, store, _norm, p2e = _ingest_synthetic_records(make_run_context, make_app_config, raw_items)
    ev_earlier = p2e["pr-trev-early"].event_id
    ev_later = p2e["pr-trev-late"].event_id

    bb = Blackboard(ctx, {ev_earlier, ev_later}, {"pr-trev-early", "pr-trev-late"})
    bb.record_task_query("t-time", "q-time", {ev_earlier, ev_later})
    bb.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="t-time",
            submission_id="sub-trev",
            submitted_by="host",
            query_ids=["q-time"],
            findings=[
                Finding(
                    claim="Time-reversed edge candidate",
                    status="observed",
                    evidence_event_ids=[ev_later, ev_earlier],
                    tactic_ids=["TA0002"],
                    verdict_malicious=True,
                )
            ],
            edges=[
                Edge(
                    from_event_id=ev_later,
                    to_event_id=ev_earlier,
                    relation="spawned",
                    join_keys={"ProcessGuid": "GT-1"},
                    time_window=("2024-05-30T10:05:00Z", "2024-05-30T10:00:00Z"),
                    evidence_event_ids=[ev_later, ev_earlier],
                    status="proposed",
                    sources=["host"],
                )
            ],
        ),
    )

    state, errors, unresolved = _unwrap_verification(verify(ctx, bb))
    assert errors or unresolved or state.validation_errors or state.disputed_items

    cr = rank(
        ctx,
        state,
        store,
        [Hit(hit_id="ht", rule_id="r-time", engine="pysigma", event_ids=[ev_earlier, ev_later], tactic_ids=["TA0002"])],
        [RuleRun(rule_id="r-time", engine="pysigma", status="ran", hit_count=1)],
    )
    assert not any(
        c.critical_relations_clean and {ev_later, ev_earlier} <= set(c.event_ids)
        for c in cr.chains
    )


# ---------------------------------------------------------------------------
# F12 Boundaries (5 tests)
# ---------------------------------------------------------------------------


@pytest.mark.tier2
def test_f12_boundary_80_percent_reserve_ratio_and_min_token_cap_export_cleanly(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.pipeline import analyze_records

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    index, records = load_scene_records(scene_dir)
    cfg = make_app_config(
        llm_enabled=False,
        budget_overrides={"max_rounds": 5, "max_tokens": 1, "reserve_ratio": 0.8},
    )

    pred = analyze_records(
        iter(records),
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=_build_locator_map(index),
    )
    assert_valid_prediction(pred, set(index))


@pytest.mark.tier2
def test_f12_boundary_unreachable_llm_endpoint_falls_back_gracefully(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.pipeline import analyze_records

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    index, records = load_scene_records(scene_dir)
    cfg = make_app_config(
        llm_enabled=True,
        overrides={
            "llm": {
                "base_url": "http://127.0.0.1:1/v1",
                "api_key": "offline-dummy",
                "timeout_s": 0.2,
            }
        },
    )

    pred = analyze_records(
        iter(records),
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=_build_locator_map(index),
    )
    assert_valid_prediction(pred, set(index))
    assert pred["physical_id_set"]


@pytest.mark.tier2
def test_f12_boundary_tight_wall_clock_and_step_caps_do_not_crash_entry(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.pipeline import analyze_records

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    index, records = load_scene_records(scene_dir)
    cfg = make_app_config(
        llm_enabled=False,
        budget_overrides={
            "max_rounds": 1,
            "max_tasks_per_round": 1,
            "max_steps_per_task": 1,
            "wall_clock_s": 0.001,
            "reserve_ratio": 0.8,
        },
    )

    pred = analyze_records(
        iter(records),
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=_build_locator_map(index),
    )
    assert_valid_prediction(pred, set(index))


@pytest.mark.tier2
def test_f12_boundary_all_engines_crash_degrades_gracefully_to_empty_prediction(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_app_config: Any,
) -> None:
    from apt_agent.pipeline import analyze_records

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    index, records = load_scene_records(scene_dir)
    cfg = make_app_config(
        engine_modes={
            "zircolite": "crash",
            "hayabusa": "crash",
            "takajo": "crash",
            "rsigma": "crash",
            "chainsaw": "crash",
        },
        enabled_engines={"zircolite", "hayabusa", "takajo", "rsigma", "chainsaw"},
        llm_enabled=False,
    )

    pred = analyze_records(
        iter(records),
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=_build_locator_map(index),
    )
    assert_valid_prediction(pred, set(index))
    assert pred == {"physical_id_set": [], "ta_physical_ids": {}}


@pytest.mark.tier2
def test_f12_boundary_invalid_budget_values_rejected_by_config_validation() -> None:
    from pydantic import ValidationError

    from apt_agent.config import BudgetConfig, load_config
    from apt_agent.exceptions import ConfigError

    bad_cases: list[dict[str, Any]] = [
        {"max_rounds": 0},
        {"max_tokens": 0},
        {"reserve_ratio": 0.0},
        {"reserve_ratio": 1.5},
        {"wall_clock_s": -1.0},
    ]
    for bad_budget in bad_cases:
        with pytest.raises((ValidationError, ConfigError)):
            BudgetConfig(**bad_budget)

        with pytest.raises((ValidationError, ConfigError)):
            load_config(overrides={"budget": bad_budget})
