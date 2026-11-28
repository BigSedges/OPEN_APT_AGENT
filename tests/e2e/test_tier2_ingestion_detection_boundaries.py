"""Tier 2 opaque-box boundary and negative E2E tests for F01-F05.

All ``apt_agent`` imports are kept inside test functions and local helpers so
``pytest --collect-only`` works independently of M3-M6 implementation progress.
"""

from __future__ import annotations

import json
import shutil
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.tier2

_RULE_WINWORD_PS = "11111111-2222-3333-4444-555555555501"
_RULE_CORR_WINWORD_C2 = "11111111-2222-3333-4444-555555555502"
_RULE_PS_C2_FLOW = "11111111-2222-3333-4444-555555555503"
_RULE_ZEEK_HTTP = "11111111-2222-3333-4444-555555555504"
_RULE_SYSLOG_SSH = "11111111-2222-3333-4444-555555555506"
_RULE_BENIGN = "11111111-2222-3333-4444-555555555599"


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


def _ingest_and_normalize(
    records: list[tuple[str, dict[str, Any]]],
    index: dict[str, dict[str, Any]] | None,
    make_run_context: Any,
    *,
    config: Any | None = None,
    case_id: str = "case-t2-det",
    run_id: str = "run-t2-det",
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
    return ctx, store, _field(norm_res, "events")


# ===========================================================================
# F01 — Boundary & Negative Cases (5 tests)
# ===========================================================================


def test_f01_strict_models_reject_extra_fields_and_wrong_types() -> None:
    from pydantic import ValidationError

    from apt_agent.models import Event, Locator, RawRecord

    with pytest.raises(ValidationError):
        Locator(filepath="a.json", linenumber=1, extra_field=123)  # type: ignore[call-arg]

    with pytest.raises(ValidationError):
        Locator(filepath="a.json", linenumber="1")  # type: ignore[arg-type]

    with pytest.raises(ValidationError):
        Locator(filepath="a.json", linenumber=True)  # type: ignore[arg-type]

    with pytest.raises(ValidationError):
        RawRecord(physical_record_id="pr-1", payload={}, extra_x=1)  # type: ignore[call-arg]

    with pytest.raises(ValidationError):
        Event(
            event_id="e1",
            physical_record_id="pr-1",
            source_type="ecar",
            event_time=None,
            fields={},
            extra_y=2,  # type: ignore[call-arg]
        )


def test_f01_invalid_budget_and_reserve_ratio_rejected(make_app_config) -> None:
    from pydantic import ValidationError

    from apt_agent.exceptions import ConfigError

    invalid_cases = [
        {"reserve_ratio": 1.5},
        {"reserve_ratio": -0.1},
        {"max_rounds": 0},
        {"wall_clock_s": -1.0},
        {"max_tokens": -10},
    ]
    for budget_ov in invalid_cases:
        with pytest.raises((ValidationError, ValueError, ConfigError)):
            make_app_config(budget_overrides=budget_ov)


def test_f01_locator_rejects_zero_negative_linenumber_and_empty_filepath() -> None:
    from pydantic import ValidationError

    from apt_agent.models import Locator

    with pytest.raises((ValidationError, ValueError)):
        Locator(filepath="data/H1/ecar.json", linenumber=0)

    with pytest.raises((ValidationError, ValueError)):
        Locator(filepath="data/H1/ecar.json", linenumber=-5)

    with pytest.raises((ValidationError, ValueError)):
        Locator(filepath="", linenumber=1)


def test_f01_concurrent_run_contexts_thread_isolated(
    tmp_path: Path, make_app_config, make_run_context
) -> None:
    def _worker(idx: int) -> tuple[str, str, set[str] | None, Path]:
        cfg = make_app_config(
            base_dir=tmp_path / f"w{idx}",
            snapshots_dir=tmp_path / f"s{idx}",
        )
        ctx = make_run_context(
            case_id=f"case-t-{idx}",
            run_id=f"run-t-{idx}",
            config=cfg,
            valid_physical_ids={f"pr-{idx}"},
        )
        return ctx.case_id, ctx.run_id, getattr(ctx, "valid_physical_ids", None), Path(cfg.snapshots.root_dir)

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(_worker, range(4)))

    for idx, (cid, rid, vpids, snap_dir) in enumerate(results):
        assert cid == f"case-t-{idx}"
        assert rid == f"run-t-{idx}"
        if vpids is not None:
            assert vpids == {f"pr-{idx}"}
        assert snap_dir == (tmp_path / f"s{idx}")


def test_f01_partial_and_corrupt_locator_map_handling(make_run_context) -> None:
    from pydantic import ValidationError

    from apt_agent.ingestion import ingest_records
    from apt_agent.models import Locator

    with pytest.raises(ValidationError):
        make_run_context(locator_map={"pr-1": {"filepath": "a", "linenumber": "bad"}})

    partial_map = {"pr-1": Locator(filepath="data/H1/ecar.json", linenumber=1)}
    store = ingest_records(
        iter([("pr-1", {"a": 1}), ("pr-2", {"b": 2})]),
        case_id="c",
        run_id="r",
        locator_map=partial_map,
    )
    found, missing = store.fetch_raw_evidence(["pr-1", "pr-2"])
    assert missing == []
    by_id = {rec.physical_record_id: rec for rec in found}
    assert by_id["pr-1"].locator == Locator(filepath="data/H1/ecar.json", linenumber=1)
    assert by_id["pr-2"].locator is None


# ===========================================================================
# F02 — Boundary & Negative Cases (5 tests)
# ===========================================================================


def test_f02_load_indexed_records_blank_lines_preserved(
    tmp_path: Path, e2e_fixtures_dir: Path, load_scene_records
) -> None:
    blank_scene = tmp_path / "blank_scene"
    blank_scene.mkdir()
    shutil.copy2(e2e_fixtures_dir / "logs" / "Label_Index_blank_line.json", blank_scene / "Label_Index.json")
    (blank_scene / "data").symlink_to(e2e_fixtures_dir / "logs" / "data")

    index, records = load_scene_records(blank_scene)
    assert len(index) == 2
    assert records == [
        ("pr-900000000000000000000001", {"raw_text": ""}),
        ("pr-900000000000000000000002", {"raw_text": ""}),
    ]


def test_f02_fetch_raw_evidence_missing_empty_and_mixed_ids(
    e2e_fixtures_dir: Path, load_scene_records
) -> None:
    from apt_agent.ingestion import ingest_records

    _, records = load_scene_records(e2e_fixtures_dir / "logs")
    store = ingest_records(iter(records[:3]), case_id="c-mix", run_id="r-mix")

    assert store.fetch_raw_evidence([]) == ([], [])

    found, missing = store.fetch_raw_evidence(
        ["pr-000000000000000000000001", "pr-does-not-exist", "pr-000000000000000000000002"]
    )
    assert len(found) == 2
    assert [r.physical_record_id for r in found] == [
        "pr-000000000000000000000001",
        "pr-000000000000000000000002",
    ]
    assert missing == ["pr-does-not-exist"]


def test_f02_ingest_records_exhausted_iterator_and_duplicate_id() -> None:
    from apt_agent.exceptions import AptAgentError
    from apt_agent.ingestion import ingest_records

    it = iter([("pr-1", {"k": 1})])
    next(it)
    empty_store = ingest_records(it, case_id="c-empty", run_id="r-empty")
    assert empty_store.fetch_raw_evidence(["pr-1"]) == ([], ["pr-1"])

    dup_iter = iter([("pr-dup", {"v": 1}), ("pr-dup", {"v": 2})])
    try:
        dup_store = ingest_records(dup_iter, case_id="c-dup", run_id="r-dup")
    except (ValueError, AptAgentError):
        return
    found, missing = dup_store.fetch_raw_evidence(["pr-dup"])
    assert missing == []
    assert len(found) == 1


def test_f02_load_indexed_records_rejects_malformed_index_and_traversal(
    tmp_path: Path, e2e_fixtures_dir: Path, load_scene_records
) -> None:
    malformed_cases: list[Any] = [
        [],
        {"bad-prefix": {"filepath": "data/H1/ecar.json", "linenumber": 1}},
        {"pr-1": {"filepath": "data/H1/ecar.json", "linenumber": True}},
        {"pr-1": {"filepath": "../etc/passwd", "linenumber": 1}},
        {"pr-1": {"filepath": "/etc/passwd", "linenumber": 1}},
    ]
    for idx, payload in enumerate(malformed_cases):
        scene = tmp_path / f"malformed_{idx}"
        scene.mkdir()
        (scene / "data").symlink_to(e2e_fixtures_dir / "logs" / "data")
        (scene / "Label_Index.json").write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises((ValueError, FileNotFoundError)):
            load_scene_records(scene)


def test_f02_load_indexed_records_rejects_out_of_range_linenumber(
    tmp_path: Path, e2e_fixtures_dir: Path, load_scene_records
) -> None:
    oor_scene = tmp_path / "oor_scene"
    oor_scene.mkdir()
    (oor_scene / "data").symlink_to(e2e_fixtures_dir / "logs" / "data")
    (oor_scene / "Label_Index.json").write_text(
        json.dumps({"pr-1": {"filepath": "data/H1/ecar.json", "linenumber": 999}}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        load_scene_records(oor_scene)


# ===========================================================================
# F03 — Boundary & Negative Cases (6 tests)
# ===========================================================================


def test_f03_winxml_seven_digit_systemtime_utc_precision(
    e2e_fixtures_dir: Path, load_scene_records, make_run_context
) -> None:
    full_index, full_records = load_scene_records(e2e_fixtures_dir / "logs")
    pid = "pr-000000000000000000000006"
    sub_index = {pid: full_index[pid]}
    sub_records = [(k, v) for k, v in full_records if k == pid]

    _, _, events = _ingest_and_normalize(sub_records, sub_index, make_run_context, case_id="case-7d")
    assert len(events) == 1
    ev = events[0]
    assert isinstance(ev.event_time, str)
    parsed = datetime.fromisoformat(ev.event_time.replace("Z", "+00:00"))
    assert parsed.tzinfo == timezone.utc
    assert parsed.microsecond == 123456
    assert "2024-05-30T10:00:00.123456" in ev.event_time
    assert ev.fields.get("SystemTime") == "2024-05-30T10:00:00.1234567Z" or ev.fields.get("UtcTime")


def test_f03_winxml_qualifiers_userdata_and_processid_collision(
    e2e_fixtures_dir: Path, load_scene_records, make_run_context
) -> None:
    full_index, full_records = load_scene_records(e2e_fixtures_dir / "logs")
    target_ids = {"pr-000000000000000000000006", "pr-000000000000000000000011"}
    sub_index = {k: v for k, v in full_index.items() if k in target_ids}
    sub_records = [(k, v) for k, v in full_records if k in target_ids]

    _, _, events = _ingest_and_normalize(sub_records, sub_index, make_run_context, case_id="case-col")
    assert len(events) == 2
    by_pid = {ev.physical_record_id: ev for ev in events}

    f6 = by_pid["pr-000000000000000000000006"].fields
    assert f6.get("EventID") == 1
    assert f6.get("Execution_ProcessID") == 2048
    proc_id_val = f6.get("ProcessId") or f6.get("EventData_ProcessId")
    assert str(proc_id_val) == "7740"
    assert "unnamed_extra" in [str(v) for v in f6.values()]

    f11 = by_pid["pr-000000000000000000000011"].fields
    assert f11.get("EventID") == 1102
    subj = f11.get("SubjectUserName") or f11.get("UserData_SubjectUserName")
    assert subj == "svc_backup"


def test_f03_bash_history_markerless_premarker_multiline_wrapper_unclosed(
    e2e_fixtures_dir: Path, load_scene_records, make_run_context
) -> None:
    full_index, full_records = load_scene_records(e2e_fixtures_dir / "logs")
    target_ids = {f"pr-{i:024d}" for i in range(16, 22)}
    sub_index = {k: v for k, v in full_index.items() if k in target_ids}
    sub_records = [(k, v) for k, v in full_records if k in target_ids]

    _, _, events = _ingest_and_normalize(sub_records, sub_index, make_run_context, case_id="case-bash")
    assert len(events) == 6
    by_pid = {ev.physical_record_id: ev for ev in events}

    ev16 = by_pid["pr-000000000000000000000016"]
    assert "import socket" in (ev16.fields.get("CommandLine") or ev16.fields.get("command") or "")

    ev17 = by_pid["pr-000000000000000000000017"]
    assert ev17.fields.get("Image") == "curl"

    ev18 = by_pid["pr-000000000000000000000018"]
    assert ev18.fields.get("Image") == "echo"

    assert by_pid["pr-000000000000000000000019"].event_time is None
    assert by_pid["pr-000000000000000000000020"].event_time is None

    ev21 = by_pid["pr-000000000000000000000021"]
    assert isinstance(ev21.event_time, str) and ev21.event_time.startswith("2024-05-30T10:03:20")
    cmd21 = ev21.fields.get("CommandLine") or ev21.fields.get("command") or ""
    assert "export PATH" in cmd21
    assert "ls -la" in cmd21


def test_f03_syslog_rfc3164_and_unknown_line(
    e2e_fixtures_dir: Path, load_scene_records, make_run_context
) -> None:
    full_index, full_records = load_scene_records(e2e_fixtures_dir / "logs")
    target_ids = {"pr-000000000000000000000013", "pr-000000000000000000000014"}
    sub_index = {k: v for k, v in full_index.items() if k in target_ids}
    sub_records = [(k, v) for k, v in full_records if k in target_ids]

    _, _, events = _ingest_and_normalize(sub_records, sub_index, make_run_context, case_id="case-sys")
    assert len(events) == 2
    by_pid = {ev.physical_record_id: ev for ev in events}

    f13 = by_pid["pr-000000000000000000000013"].fields
    assert f13.get("hostname") == "DB-01"
    assert f13.get("app_name") == "sshd"
    assert f13.get("pid") == 4567
    assert "Failed password" in (f13.get("message") or "")

    ev14 = by_pid["pr-000000000000000000000014"]
    assert ev14.event_time in (None, "")
    msg14 = ev14.fields.get("message") or ev14.fields.get("raw_line") or ""
    assert "ring buffer overflow" in msg14


def test_f03_web_access_common_dash_bytes_and_unmatched_line(
    e2e_fixtures_dir: Path, load_scene_records, make_run_context
) -> None:
    from apt_agent.ingestion import Normalizer, ingest_records

    full_index, full_records = load_scene_records(e2e_fixtures_dir / "logs")
    target_ids = {"pr-000000000000000000000023", "pr-000000000000000000000024"}
    sub_index = {k: v for k, v in full_index.items() if k in target_ids}
    sub_records = [(k, v) for k, v in full_records if k in target_ids]

    ctx = make_run_context(
        case_id="case-web",
        run_id="run-web",
        valid_physical_ids=target_ids,
        locator_map=_build_locator_map(sub_index),
    )
    store = ingest_records(
        iter(sub_records),
        case_id="case-web",
        run_id="run-web",
        locator_map=_build_locator_map(sub_index),
    )
    norm_res = Normalizer().normalize_batch(ctx, store)
    events = _field(norm_res, "events")
    gaps = _field(norm_res, "gaps", [])
    by_pid = {ev.physical_record_id: ev for ev in events}

    assert "pr-000000000000000000000023" in by_pid
    f23 = by_pid["pr-000000000000000000000023"].fields
    assert f23.get("cs-username") == "sarah"
    assert f23.get("sc-status") == 201
    assert f23.get("sc-bytes") is None

    ev24 = by_pid.get("pr-000000000000000000000024")
    if ev24 is not None:
        assert ev24.fields.get("parse_error") == "unmatched_line"
    else:
        assert len(gaps) >= 1


def test_f03_blank_and_corrupt_jsonl_produce_empty_events_and_gaps(make_run_context) -> None:
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.models import Locator

    ecar_line4 = {
        "id": "ecar-0003",
        "object": "FILE",
        "action": "WRITE",
        "objectID": "file-ws-1",
        "actorID": "proc-web-1",
        "hostname": "WEB-01.example.local",
        "principal": "www-data",
        "pid": 3102,
        "ppid": 1200,
        "tid": 3102,
        "timestamp": "2024-05-30T10:02:15.500Z",
        "properties": {
            "image_path": "/usr/sbin/apache2",
            "file_path": "/var/www/html/shell.php",
            "custom_sensor_flag": "unmapped_v2",
        },
    }
    loc_map = {
        "pr-blank": Locator(filepath="data/H1/ecar.json", linenumber=2),
        "pr-corrupt": Locator(filepath="data/H1/ecar.json", linenumber=7),
        "pr-ecar-unk": Locator(filepath="data/H1/ecar.json", linenumber=4),
    }
    ctx = make_run_context(
        case_id="case-corrupt",
        run_id="run-corrupt",
        valid_physical_ids=set(loc_map.keys()),
        locator_map=loc_map,
    )
    store = ingest_records(
        iter([
            ("pr-blank", {"raw_text": ""}),
            ("pr-corrupt", {"raw_text": "{not-valid-json"}),
            ("pr-ecar-unk", ecar_line4),
        ]),
        case_id="case-corrupt",
        run_id="run-corrupt",
        locator_map=loc_map,
    )
    norm = Normalizer()
    batch_res = norm.normalize_batch(ctx, store)
    events = _field(batch_res, "events")
    gaps = _field(batch_res, "gaps")

    assert len(events) == 1
    assert events[0].physical_record_id == "pr-ecar-unk"
    f_unk = events[0].fields
    unk_val = (
        f_unk.get("custom_sensor_flag")
        or f_unk.get("properties_custom_sensor_flag")
        or (f_unk.get("properties") or {}).get("custom_sensor_flag")
    )
    assert unk_val == "unmapped_v2"
    assert len(gaps) >= 2

    found_corrupt, missing_corrupt = store.fetch_raw_evidence(["pr-blank", "pr-corrupt"])
    assert missing_corrupt == []
    assert len(found_corrupt) == 2

    single_corrupt = norm.normalize(ctx, found_corrupt[1])
    assert _field(single_corrupt, "events") == []
    assert len(_field(single_corrupt, "gaps")) >= 1


# ===========================================================================
# F04 — Boundary & Negative Cases (5 tests)
# ===========================================================================


def test_f04_engine_crash_and_timeout_recorded_as_failed(
    e2e_fixtures_dir: Path,
    load_scene_records,
    make_fake_engine_bins,
    make_app_config,
    make_run_context,
) -> None:
    from apt_agent.detection import DetectionCoordinator

    full_index, full_records = load_scene_records(e2e_fixtures_dir / "logs")
    sub_ids = {"pr-000000000000000000000006", "pr-000000000000000000000007"}
    sub_index = {k: v for k, v in full_index.items() if k in sub_ids}
    sub_records = [(k, v) for k, v in full_records if k in sub_ids]

    bins = make_fake_engine_bins(engine_modes={"zircolite": "crash", "chainsaw": "timeout"}, sleep_s=5.0)
    cfg = make_app_config(fake_bins=bins, enabled_engines=("zircolite", "chainsaw"), timeout_s=0.3)
    ctx, _, events = _ingest_and_normalize(sub_records, sub_index, make_run_context, config=cfg)

    result = DetectionCoordinator(cfg).detect(ctx, events)
    coverage = _field(result, "coverage")

    for eng in ("zircolite", "chainsaw"):
        eng_cov = [c for c in coverage if _field(c, "engine") == eng]
        assert eng_cov, f"Expected coverage entries for {eng}"
        assert any(_field(c, "status") == "failed" and _field(c, "reason") for c in eng_cov)


def test_f04_engine_bad_json_output_handled_gracefully(
    e2e_fixtures_dir: Path, load_scene_records, make_app_config, make_run_context
) -> None:
    from apt_agent.detection import DetectionCoordinator

    full_index, full_records = load_scene_records(e2e_fixtures_dir / "logs")
    sub_ids = {"pr-000000000000000000000006", "pr-000000000000000000000007"}
    sub_index = {k: v for k, v in full_index.items() if k in sub_ids}
    sub_records = [(k, v) for k, v in full_records if k in sub_ids]

    cfg = make_app_config(
        engine_modes={"zircolite": "bad_json", "rsigma": "bad_json"},
        enabled_engines=("zircolite", "rsigma"),
    )
    ctx, _, events = _ingest_and_normalize(sub_records, sub_index, make_run_context, config=cfg)

    result = DetectionCoordinator(cfg).detect(ctx, events)
    assert _field(result, "hits") == []
    coverage = _field(result, "coverage")
    for eng in ("zircolite", "rsigma"):
        eng_cov = [c for c in coverage if _field(c, "engine") == eng]
        assert eng_cov
        assert any(_field(c, "status") == "failed" and _field(c, "reason") for c in eng_cov)


def test_f04_engine_zero_hit_mode_emits_ran_coverage(
    e2e_fixtures_dir: Path, load_scene_records, make_app_config, make_run_context
) -> None:
    from apt_agent.detection import DetectionCoordinator

    full_index, full_records = load_scene_records(e2e_fixtures_dir / "logs")
    sub_ids = {"pr-000000000000000000000006", "pr-000000000000000000000007"}
    sub_index = {k: v for k, v in full_index.items() if k in sub_ids}
    sub_records = [(k, v) for k, v in full_records if k in sub_ids]

    cfg = make_app_config(
        engine_modes={"zircolite": "zero_hit", "chainsaw": "zero_hit", "rsigma": "zero_hit"},
        enabled_engines=("zircolite", "chainsaw", "rsigma"),
    )
    ctx, _, events = _ingest_and_normalize(sub_records, sub_index, make_run_context, config=cfg)

    result = DetectionCoordinator(cfg).detect(ctx, events)
    assert _field(result, "hits") == []
    coverage = _field(result, "coverage")
    for eng in ("zircolite", "chainsaw", "rsigma"):
        eng_cov = [c for c in coverage if _field(c, "engine") == eng]
        assert eng_cov
        assert all(_field(c, "status") == "ran" and _field(c, "reason") is None for c in eng_cov)


def test_f04_takajo_wrong_cwd_and_missing_binary(
    tmp_path: Path, e2e_fixtures_dir: Path, load_scene_records, make_app_config, make_run_context
) -> None:
    from apt_agent.detection import DetectionCoordinator

    full_index, full_records = load_scene_records(e2e_fixtures_dir / "logs")
    sub_ids = {"pr-000000000000000000000006", "pr-000000000000000000000007"}
    sub_index = {k: v for k, v in full_index.items() if k in sub_ids}
    sub_records = [(k, v) for k, v in full_records if k in sub_ids]

    wrong_dir = tmp_path / "wrong_cwd"
    wrong_dir.mkdir()
    cfg1 = make_app_config(
        base_dir=tmp_path / "run1",
        enabled_engines=("hayabusa", "takajo"),
        overrides={"engines": {"takajo": {"working_dir": str(wrong_dir)}}},
    )
    ctx1, _, events1 = _ingest_and_normalize(sub_records, sub_index, make_run_context, config=cfg1)
    res1 = DetectionCoordinator(cfg1).detect(ctx1, events1)
    assert any(_field(h, "engine") == "hayabusa" for h in _field(res1, "hits"))
    taka_cov1 = [c for c in _field(res1, "coverage") if _field(c, "engine") == "takajo"]
    assert taka_cov1 and any(_field(c, "status") == "failed" for c in taka_cov1)

    cfg2 = make_app_config(
        base_dir=tmp_path / "run2",
        enabled_engines=("hayabusa", "takajo"),
        overrides={"engines": {"takajo": {"bin_path": None}}},
    )
    ctx2, _, events2 = _ingest_and_normalize(sub_records, sub_index, make_run_context, config=cfg2)
    res2 = DetectionCoordinator(cfg2).detect(ctx2, events2)
    assert any(_field(h, "engine") == "hayabusa" for h in _field(res2, "hits"))
    taka_cov2 = [c for c in _field(res2, "coverage") if _field(c, "engine") == "takajo"]
    assert taka_cov2 and any(_field(c, "status") == "skipped" for c in taka_cov2)


def test_f04_invalid_rules_handled_without_aborting_valid_rules(
    tmp_path: Path, e2e_fixtures_dir: Path, load_scene_records, make_app_config, make_run_context
) -> None:
    from apt_agent.detection import DetectionCoordinator

    mixed_dir = tmp_path / "mixed_rules"
    mixed_dir.mkdir()
    shutil.copy2(e2e_fixtures_dir / "rules/valid/win_winword_powershell.yml", mixed_dir / "win_winword_powershell.yml")
    for inv in (e2e_fixtures_dir / "rules/invalid").glob("*.yml"):
        shutil.copy2(inv, mixed_dir / inv.name)

    full_index, full_records = load_scene_records(e2e_fixtures_dir / "logs")
    sub_ids = {"pr-000000000000000000000006"}
    sub_index = {k: v for k, v in full_index.items() if k in sub_ids}
    sub_records = [(k, v) for k, v in full_records if k in sub_ids]

    cfg = make_app_config(rules_dir=mixed_dir, enabled_engines=("rsigma", "pysigma"))
    ctx, _, events = _ingest_and_normalize(sub_records, sub_index, make_run_context, config=cfg)

    result = DetectionCoordinator(cfg).detect(ctx, events)
    coverage = _field(result, "coverage")
    assert coverage
    assert any(
        _field(c, "status") in ("failed", "skipped") and _field(c, "reason")
        for c in coverage
    )
    assert any(_field(h, "rule_id") == _RULE_WINWORD_PS for h in _field(result, "hits", []))


# ===========================================================================
# F05 — Boundary & Negative Cases (5 tests)
# ===========================================================================


def test_f05_count_only_correlation_never_promoted_to_physical_id_set(
    tmp_path: Path, e2e_fixtures_dir: Path, load_scene_records, make_app_config, make_run_context
) -> None:
    from _helpers import assert_valid_prediction
    from apt_agent import models
    from apt_agent.detection import DetectionCoordinator
    from apt_agent.pipeline import to_prediction

    corr_dir = tmp_path / "corr_rules"
    corr_dir.mkdir()
    shutil.copy2(e2e_fixtures_dir / "rules/valid/win_winword_powershell.yml", corr_dir / "win_winword_powershell.yml")
    shutil.copy2(e2e_fixtures_dir / "rules/valid/win_powershell_c2_flow.yml", corr_dir / "win_powershell_c2_flow.yml")
    shutil.copy2(e2e_fixtures_dir / "rules/correlation/winword_ps_c2_temporal.yml", corr_dir / "winword_ps_c2_temporal.yml")

    full_index, full_records = load_scene_records(e2e_fixtures_dir / "logs")
    sub_ids = {"pr-000000000000000000000006", "pr-000000000000000000000007"}
    sub_index = {k: v for k, v in full_index.items() if k in sub_ids}
    sub_records = [(k, v) for k, v in full_records if k in sub_ids]

    cfg = make_app_config(
        engine_modes={"rsigma": "count_only"},
        enabled_engines=("rsigma",),
        rules_dir=corr_dir,
    )
    ctx, _, events = _ingest_and_normalize(sub_records, sub_index, make_run_context, config=cfg)

    result = DetectionCoordinator(cfg).detect(ctx, events)
    hits = _field(result, "hits", [])
    leads = _field(result, "leads", [])

    assert [
        h for h in hits if _field(h, "rule_id") == _RULE_CORR_WINWORD_C2 and len(_field(h, "event_ids", [])) > 0
    ] == []
    assert any(_field(ld, "rule_id") == _RULE_CORR_WINWORD_C2 for ld in leads) or any(
        _field(h, "rule_id") == _RULE_CORR_WINWORD_C2 and _field(h, "event_ids", []) == [] for h in hits
    )

    empty_case_result = _build_defensive_model(
        models.CaseResult,
        {
            "case_id": ctx.case_id,
            "run_id": ctx.run_id,
            "data_snapshot_id": ctx.data_snapshot_id,
            "mapping_version": ctx.mapping_version,
            "ruleset_version": ctx.ruleset_version,
            "knowledge_snapshot_id": ctx.knowledge_snapshot_id,
            "context": ctx,
            "run_context": ctx,
            "ctx": ctx,
            "attack_event_ids": [],
            "tactic_ranked_event_ids": {},
            "chains": [],
            "candidate_chains": [],
            "verified_findings": [],
            "verified_edges": [],
            "findings": [],
            "edges": [],
            "stop_reason": "completed",
        },
    )
    pred = to_prediction(ctx, empty_case_result, valid_physical_ids=sub_ids)
    assert pred == {"physical_id_set": [], "ta_physical_ids": {}}
    assert_valid_prediction(pred, valid_physical_ids=sub_ids)


def test_f05_coverage_differentiates_zero_hit_ran_vs_missing_logsource_skipped_vs_crash_failed(
    e2e_fixtures_dir: Path, load_scene_records, make_app_config, make_run_context
) -> None:
    from apt_agent.detection import DetectionCoordinator

    full_index, full_records = load_scene_records(e2e_fixtures_dir / "logs")
    sub_ids = {"pr-000000000000000000000029"}
    sub_index = {k: v for k, v in full_index.items() if k in sub_ids}
    sub_records = [(k, v) for k, v in full_records if k in sub_ids]

    cfg = make_app_config(
        engine_modes={"hayabusa": "crash"},
        overrides={"engines": {"chainsaw": {"bin_path": None}}},
    )
    ctx, _, events = _ingest_and_normalize(sub_records, sub_index, make_run_context, config=cfg)

    result = DetectionCoordinator(cfg).detect(ctx, events)
    coverage = _field(result, "coverage")

    assert any(_field(c, "engine") == "zircolite" and _field(c, "status") == "ran" for c in coverage)
    assert any(_field(c, "status") == "skipped" and _field(c, "reason") for c in coverage)
    assert any(_field(c, "engine") == "hayabusa" and _field(c, "status") == "failed" and _field(c, "reason") for c in coverage)


def test_f05_multi_engine_hit_dedup_preserves_all_rules_and_engines(
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
    hit_rules = {_field(h, "rule_id") for h in hits}
    assert {_RULE_WINWORD_PS, _RULE_PS_C2_FLOW} <= hit_rules

    dedup_keys = [
        (_field(h, "engine"), _field(h, "rule_id"), tuple(sorted(_field(h, "event_ids", []))))
        for h in hits
    ]
    assert len(dedup_keys) == len(set(dedup_keys))
    assert len({_field(h, "engine") for h in hits}) >= 2


def test_f05_trace_roundtrip_on_multi_event_physical_record(
    e2e_fixtures_dir: Path, make_app_config, make_run_context
) -> None:
    from apt_agent.detection import DetectionCoordinator
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.models import Locator

    xml_text = (e2e_fixtures_dir / "logs/data/H1/windows_event_sysmon.xml").read_text(encoding="utf-8")
    loc_map = {"pr-multi-winxml": Locator(filepath="data/H1/windows_event_sysmon.xml", linenumber=1)}

    cfg = make_app_config(enabled_engines=("zircolite",))
    ctx = make_run_context(
        case_id="case-multi-trace",
        run_id="run-multi-trace",
        config=cfg,
        valid_physical_ids={"pr-multi-winxml"},
        locator_map=loc_map,
    )
    store = ingest_records(
        iter([("pr-multi-winxml", {"raw_text": xml_text})]),
        case_id="case-multi-trace",
        run_id="run-multi-trace",
        locator_map=loc_map,
    )
    norm_res = Normalizer().normalize_batch(ctx, store)
    events = _field(norm_res, "events")
    assert len(events) == 2
    assert all(ev.physical_record_id == "pr-multi-winxml" for ev in events)

    result = DetectionCoordinator(cfg).detect(ctx, events)
    hits = _field(result, "hits")
    ev_by_id = {ev.event_id: ev for ev in events}

    eids_5501 = {eid for h in hits if _field(h, "rule_id") == _RULE_WINWORD_PS for eid in _field(h, "event_ids", [])}
    eids_5503 = {eid for h in hits if _field(h, "rule_id") == _RULE_PS_C2_FLOW for eid in _field(h, "event_ids", [])}
    assert eids_5501 and eids_5503
    assert eids_5501 != eids_5503
    for eid in eids_5501 | eids_5503:
        assert ev_by_id[eid].physical_record_id == "pr-multi-winxml"


def test_f05_empty_events_batch_returns_empty_hits_and_safe_coverage(
    make_app_config, make_run_context
) -> None:
    from apt_agent.detection import DetectionCoordinator

    cfg = make_app_config()
    ctx = make_run_context(case_id="case-empty-det", run_id="run-empty-det", config=cfg)
    result = DetectionCoordinator(cfg).detect(ctx, [])

    assert _field(result, "hits") == []
    assert _field(result, "leads", []) == []
    coverage = _field(result, "coverage")
    assert isinstance(coverage, list)
    for rr in coverage:
        assert _field(rr, "status") in {"ran", "skipped", "partial", "failed"}
