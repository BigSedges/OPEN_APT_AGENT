"""Tier 1 opaque-box E2E tests for F01-F05 (Ingestion, Normalization, Detection).

All ``apt_agent`` imports are kept inside test functions and local helpers so
``pytest --collect-only`` works independently of M3-M6 implementation progress.
"""

from __future__ import annotations

import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.tier1

_RULE_WINWORD_PS = "11111111-2222-3333-4444-555555555501"
_RULE_CORR_WINWORD_C2 = "11111111-2222-3333-4444-555555555502"
_RULE_PS_C2_FLOW = "11111111-2222-3333-4444-555555555503"
_RULE_ZEEK_HTTP = "11111111-2222-3333-4444-555555555504"
_RULE_ECAR_WEBSHELL = "11111111-2222-3333-4444-555555555505"
_RULE_SYSLOG_SSH = "11111111-2222-3333-4444-555555555506"
_RULE_WEB_SQLI = "11111111-2222-3333-4444-555555555507"
_RULE_BASH_CURL = "11111111-2222-3333-4444-555555555508"
_RULE_BENIGN = "11111111-2222-3333-4444-555555555599"

_ALL_VALID_RULE_IDS = {
    _RULE_WINWORD_PS,
    _RULE_PS_C2_FLOW,
    _RULE_ZEEK_HTTP,
    _RULE_ECAR_WEBSHELL,
    _RULE_SYSLOG_SSH,
    _RULE_WEB_SQLI,
    _RULE_BASH_CURL,
    _RULE_BENIGN,
}


def _field(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _build_locator_map(index_dict: dict[str, dict[str, Any]]) -> dict[str, Any]:
    from apt_agent.models import Locator

    return {
        pid: Locator(filepath=meta["filepath"], linenumber=meta["linenumber"])
        for pid, meta in index_dict.items()
    }


def _combined_rules_dir(
    tmp_path: Path, e2e_fixtures_dir: Path, *, include_invalid: bool = False
) -> Path:
    dest = tmp_path / "rules"
    dest.mkdir(parents=True, exist_ok=True)
    for src_sub in ("valid", "correlation"):
        for yml in (e2e_fixtures_dir / "rules" / src_sub).glob("*.yml"):
            shutil.copy2(yml, dest / yml.name)
    if include_invalid:
        for yml in (e2e_fixtures_dir / "rules" / "invalid").glob("*.yml"):
            shutil.copy2(yml, dest / yml.name)
    return dest


def _build_defensive_model(model_cls: Any, preferred: dict[str, Any]) -> Any:
    fields = getattr(model_cls, "model_fields", {})
    kwargs: dict[str, Any] = {}
    for fname, finfo in fields.items():
        if fname in preferred:
            kwargs[fname] = preferred[fname]
        elif finfo.is_required():
            ann = str(finfo.annotation)
            if "list" in ann or "List" in ann:
                kwargs[fname] = []
            elif "dict" in ann or "Dict" in ann:
                kwargs[fname] = {}
            elif "set" in ann or "Set" in ann:
                kwargs[fname] = set()
            elif "bool" in ann:
                kwargs[fname] = False
            elif "int" in ann:
                kwargs[fname] = 0
            elif "float" in ann:
                kwargs[fname] = 0.0
            else:
                kwargs[fname] = f"{fname}-default"
    return model_cls(**kwargs)


def _assert_utc_timestamp(ts_str: str | None) -> datetime:
    assert isinstance(ts_str, str) and ts_str.strip(), f"Expected UTC timestamp string, got {ts_str!r}"
    assert ts_str.endswith("Z") or ts_str.endswith("+00:00"), f"Timestamp not UTC: {ts_str!r}"
    parsed = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    assert parsed.tzinfo == timezone.utc
    return parsed


def _ingest_and_normalize(
    records: list[tuple[str, dict[str, Any]]],
    index: dict[str, dict[str, Any]] | None,
    make_run_context: Any,
    *,
    config: Any | None = None,
    case_id: str = "case-e2e-det",
    run_id: str = "run-e2e-det",
) -> tuple[Any, Any, list[Any]]:
    from apt_agent.ingestion import Normalizer, ingest_records

    loc_map = _build_locator_map(index) if index is not None else None
    valid_pids = set(index.keys()) if index is not None else {pid for pid, _ in records}
    ctx = make_run_context(
        case_id=case_id,
        run_id=run_id,
        config=config,
        valid_physical_ids=valid_pids,
        locator_map=loc_map,
    )
    store = ingest_records(
        iter(records),
        case_id=case_id,
        run_id=run_id,
        locator_map=loc_map,
    )
    norm_res = Normalizer().normalize_batch(ctx, store)
    events = _field(norm_res, "events")
    return ctx, store, events


# ===========================================================================
# F01 — Case & Snapshot Lifecycle (5 tests)
# ===========================================================================


def test_f01_run_context_immutable_version_bindings(make_run_context) -> None:
    from pydantic import ValidationError

    ctx = make_run_context(
        case_id="case-f01-01",
        run_id="run-f01-01",
        data_snapshot_id="ds-v1",
        mapping_version="map-v1",
        ruleset_version="rules-v1",
        knowledge_snapshot_id="kb-v1",
    )
    assert ctx.case_id == "case-f01-01"
    assert ctx.run_id == "run-f01-01"
    assert ctx.data_snapshot_id == "ds-v1"
    assert ctx.mapping_version == "map-v1"
    assert ctx.ruleset_version == "rules-v1"
    assert ctx.knowledge_snapshot_id == "kb-v1"

    with pytest.raises((ValidationError, TypeError, AttributeError)):
        ctx.case_id = "mutated"  # type: ignore[misc]
    with pytest.raises((ValidationError, TypeError, AttributeError)):
        ctx.ruleset_version = "rules-v2"  # type: ignore[misc]


def test_f01_app_config_budget_defaults_and_overrides(monkeypatch, make_app_config) -> None:
    from apt_agent.config import load_config

    for key in list(os.environ):
        if key.startswith(("APT_AGENT_", "OPENAI_")):
            monkeypatch.delenv(key, raising=False)

    default_cfg = load_config()
    assert default_cfg.budget.max_tasks_per_round == 3
    assert default_cfg.budget.max_rounds == 5
    assert default_cfg.budget.max_steps_per_task == 8
    assert default_cfg.budget.max_challenger_rounds == 1
    assert default_cfg.budget.max_repair_rounds == 1
    assert default_cfg.budget.wall_clock_s == 300
    assert default_cfg.budget.max_tokens == 120000
    assert default_cfg.budget.reserve_ratio == 0.8

    overridden = make_app_config(
        budget_overrides={"max_rounds": 2, "reserve_ratio": 0.75, "wall_clock_s": 60.0}
    )
    assert overridden.budget.max_rounds == 2
    assert overridden.budget.reserve_ratio == 0.75
    assert overridden.budget.wall_clock_s == 60.0


def test_f01_case_result_and_graph_state_stop_reason_roundtrip(make_run_context) -> None:
    from apt_agent import models

    ctx = make_run_context(
        case_id="case-f01-rt",
        run_id="run-f01-rt",
        data_snapshot_id="ds-rt",
        mapping_version="map-rt",
        ruleset_version="rules-rt",
        knowledge_snapshot_id="kb-rt",
    )
    common = {
        "case_id": ctx.case_id,
        "run_id": ctx.run_id,
        "data_snapshot_id": ctx.data_snapshot_id,
        "mapping_version": ctx.mapping_version,
        "ruleset_version": ctx.ruleset_version,
        "knowledge_snapshot_id": ctx.knowledge_snapshot_id,
        "context": ctx,
        "run_context": ctx,
        "ctx": ctx,
        "stop_reason": "completed",
        "attack_event_ids": [],
        "tactic_ranked_event_ids": {},
        "chains": [],
        "candidate_chains": [],
        "findings": [],
        "verified_findings": [],
        "edges": [],
        "verified_edges": [],
        "tasks": [],
        "unresolved": [],
        "gaps": [],
        "hits": [],
        "coverage": [],
    }

    case_res = _build_defensive_model(models.CaseResult, common)
    restored_res = models.CaseResult.model_validate_json(case_res.model_dump_json())
    if hasattr(restored_res, "stop_reason"):
        assert restored_res.stop_reason == "completed"
    for attr in ("case_id", "run_id", "ruleset_version"):
        if hasattr(restored_res, attr):
            assert getattr(restored_res, attr) == getattr(ctx, attr)

    graph_state = _build_defensive_model(models.GraphState, common)
    restored_state = models.GraphState.model_validate_json(graph_state.model_dump_json())
    if hasattr(restored_state, "stop_reason"):
        assert restored_state.stop_reason == "completed"

    case_run_cls = getattr(models, "CaseRun", None)
    if case_run_cls is not None:
        case_run = _build_defensive_model(case_run_cls, common)
        restored_run = case_run_cls.model_validate_json(case_run.model_dump_json())
        if hasattr(restored_run, "stop_reason"):
            assert restored_run.stop_reason == "completed"


def test_f01_isolated_case_runs_independent_snapshots(
    tmp_path: Path, make_app_config, make_run_context
) -> None:
    cfg_a = make_app_config(base_dir=tmp_path / "case_a", snapshots_dir=tmp_path / "snaps_a")
    cfg_b = make_app_config(base_dir=tmp_path / "case_b", snapshots_dir=tmp_path / "snaps_b")

    ctx_a = make_run_context(
        case_id="case-a",
        run_id="run-a",
        ruleset_version="r-v1",
        config=cfg_a,
        valid_physical_ids={"pr-a1"},
    )
    ctx_b = make_run_context(
        case_id="case-b",
        run_id="run-b",
        ruleset_version="r-v2",
        config=cfg_b,
        valid_physical_ids={"pr-b1"},
    )

    assert Path(cfg_a.snapshots.root_dir) != Path(cfg_b.snapshots.root_dir)
    assert ctx_a.case_id == "case-a"
    assert ctx_b.case_id == "case-b"
    assert ctx_a.ruleset_version == "r-v1"
    assert ctx_b.ruleset_version == "r-v2"
    if hasattr(ctx_a, "valid_physical_ids") and hasattr(ctx_b, "valid_physical_ids"):
        assert ctx_a.valid_physical_ids == {"pr-a1"}
        assert ctx_b.valid_physical_ids == {"pr-b1"}


def test_f01_run_context_locator_map_and_valid_physical_ids(make_run_context) -> None:
    from apt_agent.models import Locator

    loc = Locator(filepath="data/H1/ecar.json", linenumber=1)
    ctx = make_run_context(
        locator_map={"pr-1": loc},
        valid_physical_ids={"pr-1"},
    )
    assert ctx.valid_physical_ids == {"pr-1"}
    assert ctx.locator_map is not None
    assert ctx.locator_map["pr-1"].filepath == "data/H1/ecar.json"
    assert ctx.locator_map["pr-1"].linenumber == 1


# ===========================================================================
# F02 — Raw Evidence Store & Label_Index Localization (5 tests)
# ===========================================================================


def test_f02_load_indexed_records_all_36_fixture_records(
    e2e_fixtures_dir: Path, load_scene_records
) -> None:
    index, records = load_scene_records(e2e_fixtures_dir / "logs")
    assert len(index) == 36
    assert len(records) == 36
    assert [pid for pid, _ in records] == list(index.keys())
    assert all(pid.startswith("pr-") for pid in index)

    rec_by_id = dict(records)
    assert records[0][0] == "pr-000000000000000000000001"
    assert records[0][1]["id"] == "ecar-0001"
    assert "<Event" in rec_by_id["pr-000000000000000000000006"]["raw_text"]
    assert rec_by_id["pr-000000000000000000000016"]["timestamp"] == 1717063330
    assert "\n" in rec_by_id["pr-000000000000000000000016"]["raw_text"]
    assert "Failed password" in rec_by_id["pr-000000000000000000000013"]["raw_text"]


def test_f02_ingest_records_single_pass_iterator_and_raw_id_binding(
    e2e_fixtures_dir: Path, load_scene_records
) -> None:
    from apt_agent.ingestion import ingest_records

    index, records = load_scene_records(e2e_fixtures_dir / "logs")
    gen = (item for item in records)
    store = ingest_records(
        gen,
        case_id="case-f02",
        run_id="run-f02",
        locator_map=_build_locator_map(index),
    )
    assert next(gen, None) is None

    found, missing = store.fetch_raw_evidence(list(index.keys()))
    assert missing == []
    assert len(found) == 36
    for rec in found:
        raw_id = getattr(rec, "raw_id", rec.physical_record_id)
        assert raw_id == rec.physical_record_id


def test_f02_fetch_raw_evidence_preserves_locator_and_payload(
    e2e_fixtures_dir: Path, load_scene_records
) -> None:
    from apt_agent.ingestion import ingest_records

    index, records = load_scene_records(e2e_fixtures_dir / "logs")
    rec_by_id = dict(records)
    store = ingest_records(
        iter(records),
        case_id="case-f02-loc",
        run_id="run-f02-loc",
        locator_map=_build_locator_map(index),
    )

    target_ids = [
        "pr-000000000000000000000006",
        "pr-000000000000000000000029",
        "pr-000000000000000000000016",
    ]
    found, missing = store.fetch_raw_evidence(target_ids)
    assert missing == []
    assert len(found) == 3
    for rec in found:
        pid = rec.physical_record_id
        assert rec.locator is not None
        assert rec.locator.filepath == index[pid]["filepath"]
        assert rec.locator.linenumber == index[pid]["linenumber"]
        assert rec.payload == rec_by_id[pid]


def test_f02_ingest_records_without_locator_map_sets_locator_none(
    e2e_fixtures_dir: Path, load_scene_records
) -> None:
    from apt_agent.ingestion import ingest_records

    _, records = load_scene_records(e2e_fixtures_dir / "logs")
    subset = records[:5]
    store = ingest_records(iter(subset), case_id="case-noloc", run_id="run-noloc", locator_map=None)

    found, missing = store.fetch_raw_evidence([pid for pid, _ in subset])
    assert missing == []
    assert len(found) == 5
    assert all(rec.locator is None for rec in found)


def test_f02_fetch_raw_evidence_is_replayable_across_calls(
    e2e_fixtures_dir: Path, load_scene_records
) -> None:
    from apt_agent.ingestion import ingest_records

    index, records = load_scene_records(e2e_fixtures_dir / "logs")
    store = ingest_records(
        iter(records),
        case_id="case-replay",
        run_id="run-replay",
        locator_map=_build_locator_map(index),
    )
    pids = ["pr-000000000000000000000001", "pr-000000000000000000000022"]
    first_found, first_missing = store.fetch_raw_evidence(pids)
    second_found, second_missing = store.fetch_raw_evidence(pids)

    assert first_missing == []
    assert second_missing == []
    assert first_found == second_found


# ===========================================================================
# F03 — Deterministic Log Normalization (6 tests)
# ===========================================================================


def test_f03_normalize_ecar_preserves_sigma_fields_utc_and_unknown_fields(
    e2e_fixtures_dir: Path, load_scene_records, make_run_context
) -> None:
    from apt_agent.ingestion import Normalizer, ingest_records

    full_index, full_records = load_scene_records(e2e_fixtures_dir / "logs")
    ecar_ids = {f"pr-00000000000000000000000{i}" for i in range(1, 6)}
    ecar_index = {k: v for k, v in full_index.items() if k in ecar_ids}
    ecar_records = [(k, v) for k, v in full_records if k in ecar_ids]

    ctx = make_run_context(
        case_id="case-ecar",
        run_id="run-ecar",
        valid_physical_ids=ecar_ids,
        locator_map=_build_locator_map(ecar_index),
    )
    store = ingest_records(
        iter(ecar_records),
        case_id="case-ecar",
        run_id="run-ecar",
        locator_map=_build_locator_map(ecar_index),
    )
    norm_res = Normalizer().normalize_batch(ctx, store)
    events = _field(norm_res, "events")
    assert len(events) == 5

    by_pid = {ev.physical_record_id: ev for ev in events}
    for ev in events:
        _assert_utc_timestamp(ev.event_time)

    ev1 = by_pid["pr-000000000000000000000001"]
    assert "Image" in ev1.fields and ev1.fields["Image"].endswith("powershell.exe")
    assert "ParentImage" in ev1.fields and ev1.fields["ParentImage"].endswith("WINWORD.EXE")
    assert "CommandLine" in ev1.fields and "powershell.exe" in ev1.fields["CommandLine"]
    proc_guid = (
        ev1.fields.get("ProcessGuid")
        or ev1.fields.get("properties_process_guid")
        or (ev1.fields.get("properties") or {}).get("process_guid")
    )
    assert proc_guid == "G7"

    found_03, _ = store.fetch_raw_evidence(["pr-000000000000000000000003"])
    single_res = Normalizer().normalize(ctx, found_03[0])
    single_events = _field(single_res, "events")
    assert len(single_events) == 1
    f3 = single_events[0].fields
    assert f3.get("TargetFilename") == "/var/www/html/shell.php"
    unknown_val = (
        f3.get("custom_sensor_flag")
        or f3.get("properties_custom_sensor_flag")
        or (f3.get("properties") or {}).get("custom_sensor_flag")
    )
    assert unknown_val == "unmapped_v2"


def test_f03_normalize_winxml_sysmon_and_security(
    e2e_fixtures_dir: Path, load_scene_records, make_run_context
) -> None:
    full_index, full_records = load_scene_records(e2e_fixtures_dir / "logs")
    win_ids = {f"pr-{i:024d}" for i in range(6, 12)}
    win_index = {k: v for k, v in full_index.items() if k in win_ids}
    win_records = [(k, v) for k, v in full_records if k in win_ids]

    _, _, events = _ingest_and_normalize(win_records, win_index, make_run_context, case_id="case-winxml")
    assert len(events) == 6
    assert {ev.physical_record_id for ev in events} == win_ids

    event_ids_seen = set()
    computers_seen = set()
    channels_seen = set()
    for ev in events:
        _assert_utc_timestamp(ev.event_time)
        event_ids_seen.add(ev.fields.get("EventID"))
        computers_seen.add(ev.fields.get("Computer"))
        channels_seen.add(ev.fields.get("Channel"))

    assert event_ids_seen == {1, 3, 4624, 4625, 4688, 1102}
    assert computers_seen == {"H1.example.local", "DC-01.example.local"}
    assert channels_seen == {"Microsoft-Windows-Sysmon/Operational", "Security"}


def test_f03_normalize_all_10_zeek_log_types(
    e2e_fixtures_dir: Path, load_scene_records, make_run_context
) -> None:
    full_index, full_records = load_scene_records(e2e_fixtures_dir / "logs")
    zeek_ids = {f"pr-{i:024d}" for i in range(25, 37)}
    zeek_index = {k: v for k, v in full_index.items() if k in zeek_ids}
    zeek_records = [(k, v) for k, v in full_records if k in zeek_ids]

    _, _, events = _ingest_and_normalize(zeek_records, zeek_index, make_run_context, case_id="case-zeek")
    assert len(events) == 12

    seen_zeek_types: set[str] = set()
    by_pid = {ev.physical_record_id: ev for ev in events}
    for ev in events:
        _assert_utc_timestamp(ev.event_time)
        zt = ev.fields.get("zeek_log_type") or ev.source_type
        assert isinstance(zt, str) and zt
        for candidate in ("conn", "dns", "http", "ssl", "x509", "ocsp", "dhcp", "files", "pe", "smtp"):
            if candidate in zt:
                seen_zeek_types.add(candidate)

    assert seen_zeek_types == {"conn", "dns", "http", "ssl", "x509", "ocsp", "dhcp", "files", "pe", "smtp"}

    for net_pid in (
        "pr-000000000000000000000025",
        "pr-000000000000000000000027",
        "pr-000000000000000000000029",
        "pr-000000000000000000000030",
        "pr-000000000000000000000036",
    ):
        f = by_pid[net_pid].fields
        assert f.get("src_ip") or f.get("id.orig_h") or f.get("id_orig_h")
        assert f.get("dst_ip") or f.get("id.resp_h") or f.get("id_resp_h")

    assert by_pid["pr-000000000000000000000027"].fields.get("answers")
    assert by_pid["pr-000000000000000000000035"].fields.get("section_names")
    assert by_pid["pr-000000000000000000000036"].fields.get("msg_types") or by_pid["pr-000000000000000000000036"].fields.get("rcptto")


def test_f03_normalize_syslog_web_access_and_bash_history(
    e2e_fixtures_dir: Path, load_scene_records, make_run_context
) -> None:
    full_index, full_records = load_scene_records(e2e_fixtures_dir / "logs")
    target_ids = {
        "pr-000000000000000000000012",
        "pr-000000000000000000000022",
        "pr-000000000000000000000015",
        "pr-000000000000000000000017",
    }
    sub_index = {k: v for k, v in full_index.items() if k in target_ids}
    sub_records = [(k, v) for k, v in full_records if k in target_ids]

    _, _, events = _ingest_and_normalize(sub_records, sub_index, make_run_context, case_id="case-text")
    assert len(events) == 4
    by_pid = {ev.physical_record_id: ev for ev in events}

    for ev in events:
        _assert_utc_timestamp(ev.event_time)

    sys_f = by_pid["pr-000000000000000000000012"].fields
    assert sys_f.get("hostname") == "APP-LNX-02"
    assert sys_f.get("app_name") == "sshd"
    assert sys_f.get("pid") == 2345

    web_f = by_pid["pr-000000000000000000000022"].fields
    assert web_f.get("c-ip") == "198.51.100.45"
    assert web_f.get("cs-method") == "GET"
    assert web_f.get("cs-uri-stem") == "/login.php"
    assert web_f.get("sc-status") == 200
    assert web_f.get("cs-User-Agent") == "sqlmap/1.7.8"

    bash_f = by_pid["pr-000000000000000000000017"].fields
    assert bash_f.get("User") == "sarah.oconnell"
    assert bash_f.get("Image") == "curl"
    assert "stage2.sh" in (bash_f.get("CommandLine") or "")


def test_f03_normalize_one_to_zero_and_one_to_many_deterministic_ids(
    e2e_fixtures_dir: Path, make_run_context
) -> None:
    from apt_agent.ingestion import Normalizer
    from apt_agent.models import Locator, RawRecord

    ctx = make_run_context(case_id="case-1n", run_id="run-1n")
    norm = Normalizer()

    xml_text = (e2e_fixtures_dir / "logs/data/H1/windows_event_sysmon.xml").read_text(encoding="utf-8")
    raw_multi = RawRecord(
        physical_record_id="pr-multi-xml",
        payload={"raw_text": xml_text},
        locator=Locator(filepath="data/H1/windows_event_sysmon.xml", linenumber=1),
    )

    res1 = norm.normalize(ctx, raw_multi)
    res2 = norm.normalize(ctx, raw_multi)
    events1 = _field(res1, "events")
    events2 = _field(res2, "events")

    assert len(events1) == 2
    assert all(ev.physical_record_id == "pr-multi-xml" for ev in events1)
    assert events1[0].event_id != events1[1].event_id
    assert [ev.event_id for ev in events1] == [ev.event_id for ev in events2]

    raw_blank = RawRecord(
        physical_record_id="pr-blank",
        payload={"raw_text": ""},
        locator=Locator(filepath="data/H1/ecar.json", linenumber=2),
    )
    blank_res = norm.normalize(ctx, raw_blank)
    assert _field(blank_res, "events") == []
    assert len(_field(blank_res, "gaps")) >= 1


def test_f03_normalize_batch_without_locators_and_source_type_counts(
    e2e_fixtures_dir: Path, load_scene_records, make_run_context
) -> None:
    from apt_agent.ingestion import Normalizer, ingest_records

    index, records = load_scene_records(e2e_fixtures_dir / "logs")
    ctx = make_run_context(
        case_id="case-batch-noloc",
        run_id="run-batch-noloc",
        valid_physical_ids=set(index.keys()),
        locator_map=None,
    )
    store = ingest_records(iter(records), case_id="case-batch-noloc", run_id="run-batch-noloc", locator_map=None)
    norm_res = Normalizer().normalize_batch(ctx, store)

    events = _field(norm_res, "events")
    source_type_counts = _field(norm_res, "source_type_counts")
    assert len(events) >= 34
    assert isinstance(source_type_counts, dict) and len(source_type_counts) > 0
    assert sum(source_type_counts.values()) == len(events)
    assert all(ev.physical_record_id in index for ev in events)


# ===========================================================================
# F04 — Multi-Engine Sigma Detection (5 tests)
# ===========================================================================


def test_f04_zircolite_detects_multiformat_rules(
    e2e_fixtures_dir: Path, load_scene_records, make_app_config, make_run_context
) -> None:
    from apt_agent.detection import DetectionCoordinator

    index, records = load_scene_records(e2e_fixtures_dir / "logs")
    cfg = make_app_config(enabled_engines=("zircolite",))
    ctx, _, events = _ingest_and_normalize(records, index, make_run_context, config=cfg)

    result = DetectionCoordinator(cfg).detect(ctx, events)
    hits = _field(result, "hits")
    hit_rule_ids = {_field(h, "rule_id") for h in hits}

    expected_rules = {
        _RULE_WINWORD_PS,
        _RULE_PS_C2_FLOW,
        _RULE_ZEEK_HTTP,
        _RULE_ECAR_WEBSHELL,
        _RULE_SYSLOG_SSH,
        _RULE_WEB_SQLI,
        _RULE_BASH_CURL,
    }
    assert expected_rules <= hit_rule_ids
    assert _RULE_BENIGN not in hit_rule_ids


def test_f04_hayabusa_and_takajo_windows_detection(
    e2e_fixtures_dir: Path, load_scene_records, make_app_config, make_run_context
) -> None:
    from apt_agent.detection import DetectionCoordinator

    full_index, full_records = load_scene_records(e2e_fixtures_dir / "logs")
    win_ids = {f"pr-{i:024d}" for i in range(6, 12)}
    win_index = {k: v for k, v in full_index.items() if k in win_ids}
    win_records = [(k, v) for k, v in full_records if k in win_ids]

    cfg = make_app_config(enabled_engines=("hayabusa", "takajo"))
    ctx, _, events = _ingest_and_normalize(win_records, win_index, make_run_context, config=cfg)

    result = DetectionCoordinator(cfg).detect(ctx, events)
    hits = _field(result, "hits")
    coverage = _field(result, "coverage")

    ev_to_pid = {ev.event_id: ev.physical_record_id for ev in events}
    rule_to_pids: dict[str, set[str]] = {}
    for h in hits:
        rid = _field(h, "rule_id")
        for eid in _field(h, "event_ids", []):
            if eid in ev_to_pid:
                rule_to_pids.setdefault(rid, set()).add(ev_to_pid[eid])

    assert "pr-000000000000000000000006" in rule_to_pids.get(_RULE_WINWORD_PS, set())
    assert "pr-000000000000000000000007" in rule_to_pids.get(_RULE_PS_C2_FLOW, set())

    haya_cov = [c for c in coverage if _field(c, "engine") == "hayabusa"]
    assert haya_cov and any(_field(c, "status") == "ran" for c in haya_cov)
    taka_cov = [c for c in coverage if _field(c, "engine") == "takajo"]
    assert all(_field(c, "status") != "failed" for c in taka_cov)


def test_f04_chainsaw_detects_with_custom_mapping(
    e2e_fixtures_dir: Path, load_scene_records, make_app_config, make_run_context
) -> None:
    from apt_agent.detection import DetectionCoordinator

    index, records = load_scene_records(e2e_fixtures_dir / "logs")
    cfg = make_app_config(enabled_engines=("chainsaw",))
    ctx, _, events = _ingest_and_normalize(records, index, make_run_context, config=cfg)

    result = DetectionCoordinator(cfg).detect(ctx, events)
    hits = _field(result, "hits")
    hit_rule_ids = {_field(h, "rule_id") for h in hits}

    expected = {
        _RULE_WINWORD_PS,
        _RULE_PS_C2_FLOW,
        _RULE_ZEEK_HTTP,
        _RULE_ECAR_WEBSHELL,
        _RULE_SYSLOG_SSH,
        _RULE_WEB_SQLI,
        _RULE_BASH_CURL,
    }
    assert expected <= hit_rule_ids
    assert all(len(_field(h, "event_ids", [])) > 0 for h in hits)


def test_f04_rsigma_single_and_correlation_rules_full_events(
    tmp_path: Path, e2e_fixtures_dir: Path, load_scene_records, make_app_config, make_run_context
) -> None:
    from apt_agent.detection import DetectionCoordinator

    combined_dir = _combined_rules_dir(tmp_path, e2e_fixtures_dir)
    index, records = load_scene_records(e2e_fixtures_dir / "logs")
    cfg = make_app_config(enabled_engines=("rsigma", "pysigma"), rules_dir=combined_dir)
    ctx, _, events = _ingest_and_normalize(records, index, make_run_context, config=cfg)

    result = DetectionCoordinator(cfg).detect(ctx, events)
    hits = _field(result, "hits")
    ev_to_pid = {ev.event_id: ev.physical_record_id for ev in events}

    single_hits = [h for h in hits if _field(h, "rule_id") == _RULE_WINWORD_PS]
    assert single_hits

    corr_hits = [h for h in hits if _field(h, "rule_id") == _RULE_CORR_WINWORD_C2]
    assert corr_hits, "Expected full-mode correlation hit from rsigma"
    corr_pids = {
        ev_to_pid[eid]
        for h in corr_hits
        for eid in _field(h, "event_ids", [])
        if eid in ev_to_pid
    }
    assert {"pr-000000000000000000000006", "pr-000000000000000000000007"} <= corr_pids


def test_f04_coordinator_all_engines_combined_run(
    tmp_path: Path, e2e_fixtures_dir: Path, load_scene_records, make_app_config, make_run_context
) -> None:
    from apt_agent.detection import DetectionCoordinator

    combined_dir = _combined_rules_dir(tmp_path, e2e_fixtures_dir)
    index, records = load_scene_records(e2e_fixtures_dir / "logs")
    cfg = make_app_config(rules_dir=combined_dir)
    ctx, _, events = _ingest_and_normalize(records, index, make_run_context, config=cfg)

    result = DetectionCoordinator(cfg).detect(ctx, events)
    hits = _field(result, "hits")
    coverage = _field(result, "coverage")

    assert len(hits) > 0
    assert len(coverage) > 0
    known_rules = _ALL_VALID_RULE_IDS | {_RULE_CORR_WINWORD_C2}
    assert all(_field(h, "rule_id") in known_rules for h in hits)


# ===========================================================================
# F05 — Traceability & RuleRun Coverage (5 tests)
# ===========================================================================


def test_f05_hit_event_id_to_physical_record_id_roundtrip(
    e2e_fixtures_dir: Path, load_scene_records, make_app_config, make_run_context
) -> None:
    from apt_agent.detection import DetectionCoordinator

    index, records = load_scene_records(e2e_fixtures_dir / "logs")
    cfg = make_app_config(enabled_engines=("zircolite", "hayabusa", "rsigma", "chainsaw"))
    ctx, store, events = _ingest_and_normalize(records, index, make_run_context, config=cfg)

    result = DetectionCoordinator(cfg).detect(ctx, events)
    hits = _field(result, "hits")
    assert len(hits) > 0

    event_by_id = {ev.event_id: ev for ev in events}
    for hit in hits:
        for eid in _field(hit, "event_ids", []):
            assert eid in event_by_id
            pid = event_by_id[eid].physical_record_id
            assert pid in index
            found, missing = store.fetch_raw_evidence([pid])
            assert missing == []
            assert len(found) == 1 and found[0].physical_record_id == pid


def test_f05_multi_engine_hit_dedup_and_provenance(
    e2e_fixtures_dir: Path, load_scene_records, make_app_config, make_run_context
) -> None:
    from apt_agent.detection import DetectionCoordinator

    full_index, full_records = load_scene_records(e2e_fixtures_dir / "logs")
    sub_ids = {"pr-000000000000000000000006", "pr-000000000000000000000007"}
    sub_index = {k: v for k, v in full_index.items() if k in sub_ids}
    sub_records = [(k, v) for k, v in full_records if k in sub_ids]

    cfg = make_app_config(enabled_engines=("zircolite", "hayabusa", "rsigma", "chainsaw"))
    ctx, _, events = _ingest_and_normalize(sub_records, sub_index, make_run_context, config=cfg)

    result = DetectionCoordinator(cfg).detect(ctx, events)
    hits = _field(result, "hits")

    winword_hits = [h for h in hits if _field(h, "rule_id") == _RULE_WINWORD_PS]
    assert len(winword_hits) >= 2
    dedup_keys = [
        (_field(h, "engine"), _field(h, "rule_id"), tuple(sorted(_field(h, "event_ids", []))))
        for h in winword_hits
    ]
    assert len(dedup_keys) == len(set(dedup_keys))
    assert len({_field(h, "engine") for h in winword_hits}) >= 2


def test_f05_rule_run_coverage_distinguishes_ran_skipped_failed(
    e2e_fixtures_dir: Path, load_scene_records, make_app_config, make_run_context
) -> None:
    from apt_agent.detection import DetectionCoordinator

    full_index, full_records = load_scene_records(e2e_fixtures_dir / "logs")
    sub_ids = {f"pr-{i:024d}" for i in range(6, 12)} | {"pr-000000000000000000000029"}
    sub_index = {k: v for k, v in full_index.items() if k in sub_ids}
    sub_records = [(k, v) for k, v in full_records if k in sub_ids]

    cfg = make_app_config(
        engine_modes={"hayabusa": "crash"},
        overrides={"engines": {"chainsaw": {"bin_path": None}}},
    )
    ctx, _, events = _ingest_and_normalize(sub_records, sub_index, make_run_context, config=cfg)

    result = DetectionCoordinator(cfg).detect(ctx, events)
    coverage = _field(result, "coverage")

    zirc_ran = [
        c for c in coverage if _field(c, "engine") == "zircolite" and _field(c, "status") == "ran"
    ]
    assert zirc_ran
    assert any(_field(c, "reason") is None for c in zirc_ran)

    chain_skipped = [
        c for c in coverage if _field(c, "engine") == "chainsaw" and _field(c, "status") == "skipped"
    ]
    assert chain_skipped and all(_field(c, "reason") for c in chain_skipped)

    haya_failed = [
        c for c in coverage if _field(c, "engine") == "hayabusa" and _field(c, "status") == "failed"
    ]
    assert haya_failed and all(_field(c, "reason") for c in haya_failed)


def test_f05_rule_run_supports_partial_status_and_version_metadata(
    tmp_path: Path, e2e_fixtures_dir: Path, load_scene_records, make_app_config, make_run_context
) -> None:
    from apt_agent.detection import DetectionCoordinator
    from apt_agent.models import RuleRun

    for status in ("ran", "partial", "skipped", "failed"):
        rr = _build_defensive_model(
            RuleRun,
            {
                "rule_id": _RULE_WINWORD_PS,
                "engine": "rsigma",
                "status": status,
                "reason": None if status == "ran" else f"status-{status}",
            },
        )
        assert _field(rr, "status") == status
        assert _field(rr, "rule_id") == _RULE_WINWORD_PS
        assert _field(rr, "engine") == "rsigma"

    combined_dir = _combined_rules_dir(tmp_path, e2e_fixtures_dir)
    full_index, full_records = load_scene_records(e2e_fixtures_dir / "logs")
    sub_ids = {"pr-000000000000000000000006", "pr-000000000000000000000007"}
    sub_index = {k: v for k, v in full_index.items() if k in sub_ids}
    sub_records = [(k, v) for k, v in full_records if k in sub_ids]

    cfg = make_app_config(
        rules_dir=combined_dir,
        engine_modes={"rsigma": "normal", "hayabusa": "crash"},
    )
    ctx, _, events = _ingest_and_normalize(sub_records, sub_index, make_run_context, config=cfg)

    result = DetectionCoordinator(cfg).detect(ctx, events)
    coverage = _field(result, "coverage")
    hits = _field(result, "hits")

    assert coverage
    for rr in coverage:
        assert _field(rr, "rule_id")
        assert _field(rr, "engine")
        assert _field(rr, "status") in {"ran", "partial", "skipped", "failed"}

    assert hits
    for hit in hits:
        assert _field(hit, "rule_id")
        assert _field(hit, "engine_version")
        assert _field(hit, "rule_version")


def test_f05_count_only_correlation_emits_lead_not_grounded_hit(
    tmp_path: Path, e2e_fixtures_dir: Path, load_scene_records, make_app_config, make_run_context
) -> None:
    from apt_agent.detection import DetectionCoordinator

    combined_dir = _combined_rules_dir(tmp_path, e2e_fixtures_dir)
    full_index, full_records = load_scene_records(e2e_fixtures_dir / "logs")
    sub_ids = {"pr-000000000000000000000006", "pr-000000000000000000000007"}
    sub_index = {k: v for k, v in full_index.items() if k in sub_ids}
    sub_records = [(k, v) for k, v in full_records if k in sub_ids]

    cfg = make_app_config(
        engine_modes={"rsigma": "count_only"},
        enabled_engines=("rsigma",),
        rules_dir=combined_dir,
    )
    ctx, _, events = _ingest_and_normalize(sub_records, sub_index, make_run_context, config=cfg)

    result = DetectionCoordinator(cfg).detect(ctx, events)
    hits = _field(result, "hits", [])
    leads = _field(result, "leads", [])

    corr_hits_with_events = [
        h for h in hits if _field(h, "rule_id") == _RULE_CORR_WINWORD_C2 and len(_field(h, "event_ids", [])) > 0
    ]
    assert corr_hits_with_events == []

    count_only_hits = [
        h for h in hits if _field(h, "rule_id") == _RULE_CORR_WINWORD_C2 and _field(h, "event_ids", []) == []
    ]
    corr_leads = [ld for ld in leads if _field(ld, "rule_id") == _RULE_CORR_WINWORD_C2]
    assert corr_leads or count_only_hits
