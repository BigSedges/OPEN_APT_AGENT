"""Tier 2 opaque-box E2E boundary & negative tests for F11 & F15.

All ``apt_agent`` imports are kept lazy inside test functions or local helpers so
test collection succeeds independently of milestone completion.
"""

from __future__ import annotations

import importlib.metadata as importlib_metadata
import inspect
import os
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from _helpers import assert_valid_prediction

pytestmark = pytest.mark.tier2

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _clear_apt_and_openai_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove ambient APT_AGENT_* and OPENAI_* env vars for isolated tests."""
    for key in list(os.environ):
        if key.startswith(("APT_AGENT_", "OPENAI_")):
            monkeypatch.delenv(key, raising=False)


def _normalize_pred(raw: Any) -> dict[str, Any]:
    """Normalize a Prediction model or dict to a plain dictionary."""
    if hasattr(raw, "model_dump"):
        return raw.model_dump()
    return dict(raw)


def _build_case_result(
    ctx: Any,
    *,
    attack_event_ids: list[str],
    tactic_ranked_event_ids: dict[str, list[str]],
    event_to_physical: dict[str, str],
) -> Any:
    """Defensively construct a CaseResult inspecting Pydantic model_fields."""
    from apt_agent.models import CaseResult, Event

    ev_fields = set(getattr(Event, "model_fields", {}).keys())
    event_objs: list[Any] = []
    for ev_id, pid in event_to_physical.items():
        ev_kwargs: dict[str, Any] = {
            "event_id": ev_id,
            "physical_record_id": pid,
        }
        if "raw_id" in ev_fields:
            ev_kwargs["raw_id"] = pid
        if "source_type" in ev_fields:
            ev_kwargs["source_type"] = "sysmon"
        if "event_time" in ev_fields:
            ev_kwargs["event_time"] = "2026-01-01T00:00:00Z"
        if "fields" in ev_fields:
            ev_kwargs["fields"] = {}
        event_objs.append(Event(**ev_kwargs))

    cr_fields = getattr(CaseResult, "model_fields", {})
    accepted = set(cr_fields.keys())
    kwargs: dict[str, Any] = {}

    if "case_id" in accepted:
        kwargs["case_id"] = getattr(ctx, "case_id", "case-e2e-001")
    if "run_id" in accepted:
        kwargs["run_id"] = getattr(ctx, "run_id", "run-e2e-001")
    if "attack_event_ids" in accepted:
        kwargs["attack_event_ids"] = list(attack_event_ids)
    if "tactic_ranked_event_ids" in accepted:
        kwargs["tactic_ranked_event_ids"] = {
            k: list(v) for k, v in tactic_ranked_event_ids.items()
        }

    for map_field in ("event_to_physical", "event_physical_map", "physical_id_map"):
        if map_field in accepted:
            kwargs[map_field] = dict(event_to_physical)
    if "events" in accepted:
        kwargs["events"] = event_objs

    return CaseResult(**kwargs)


# ---------------------------------------------------------------------------
# F11: Competition Export Boundaries & Negative Cases (6 tests)
# ---------------------------------------------------------------------------


def test_f11_clean_zero_hit_benign_scene_and_empty_stream(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    fake_engine_bins: dict[str, Path],
    make_app_config: Any,
    load_scene_records: Any,
) -> None:
    """Clean benign scene and empty record stream both return legal empty Prediction."""
    from apt_agent import analyze_records

    cfg = make_app_config(
        tmp_path,
        fake_bins=fake_engine_bins,
        llm_enabled=False,
        rag_offline=True,
    )
    index, records = load_scene_records(
        e2e_fixtures_dir / "scenarios" / "scene_09_benign"
    )

    pred_benign = _normalize_pred(
        analyze_records(iter(records), config=cfg, valid_physical_ids=set(index.keys()))
    )
    assert pred_benign == {"physical_id_set": [], "ta_physical_ids": {}}
    assert_valid_prediction(pred_benign, valid_physical_ids=set(index.keys()))

    pred_empty = _normalize_pred(analyze_records(iter([]), config=cfg))
    assert pred_empty == {"physical_id_set": [], "ta_physical_ids": {}}
    assert_valid_prediction(pred_empty)


def test_f11_empty_tactic_omitted_and_empty_list_rejected_by_prediction(
    make_run_context: Any,
) -> None:
    """to_prediction omits empty tactic lists; Prediction rejects empty list values."""
    from apt_agent.models import Prediction
    from apt_agent.pipeline import to_prediction

    ctx = make_run_context(valid_physical_ids={"pr-1"})
    case_result = _build_case_result(
        ctx,
        attack_event_ids=["ev-1"],
        tactic_ranked_event_ids={"TA0002": [], "TA0011": ["ev-1"]},
        event_to_physical={"ev-1": "pr-1"},
    )

    pred = _normalize_pred(to_prediction(ctx, case_result))
    assert_valid_prediction(pred, valid_physical_ids={"pr-1"})
    assert "TA0002" not in pred["ta_physical_ids"]
    assert pred["ta_physical_ids"] == {"TA0011": ["pr-1"]}

    with pytest.raises(ValidationError):
        Prediction(physical_id_set=["pr-1"], ta_physical_ids={"TA0002": []})


def test_f11_illegal_tactic_keys_rejected_including_technique_and_non_ascii(
    make_run_context: Any,
) -> None:
    """Illegal tactic keys (technique IDs, wrong length/case, Arabic digits) are rejected."""
    from apt_agent.exceptions import AptAgentError
    from apt_agent.models import Prediction
    from apt_agent.pipeline import to_prediction

    illegal_keys = [
        "T1059",
        "ta0002",
        "TA002",
        "TA00002",
        "TA\u0660\u0661\u0662\u0663",
        "EXECUTION",
        "",
    ]
    ctx = make_run_context(valid_physical_ids={"pr-1"})

    for bad_key in illegal_keys:
        with pytest.raises(ValidationError):
            Prediction(physical_id_set=["pr-1"], ta_physical_ids={bad_key: ["pr-1"]})

        with pytest.raises((ValidationError, ValueError, AptAgentError)):
            case_result = _build_case_result(
                ctx,
                attack_event_ids=["ev-1"],
                tactic_ranked_event_ids={bad_key: ["ev-1"]},
                event_to_physical={"ev-1": "pr-1"},
            )
            to_prediction(ctx, case_result)


def test_f11_four_candidates_plus_two_sibling_events_dedup_before_top3(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    fake_engine_bins: dict[str, Path],
    make_app_config: Any,
    make_run_context: Any,
    load_scene_records: Any,
) -> None:
    """S7.3: Sibling events from same physical record deduplicate before top-3 truncation."""
    from apt_agent import analyze_records
    from apt_agent.pipeline import to_prediction

    # Part A: Deterministic unit boundary on to_prediction
    valid_ids = {"pr-ta2-1", "pr-ta2-2", "pr-ta2-3", "pr-ta2-4"}
    ctx = make_run_context(valid_physical_ids=valid_ids)
    case_result = _build_case_result(
        ctx,
        attack_event_ids=["ev-1a", "ev-1b", "ev-2", "ev-3", "ev-4"],
        tactic_ranked_event_ids={
            "TA0002": ["ev-1a", "ev-1b", "ev-2", "ev-3", "ev-4"]
        },
        event_to_physical={
            "ev-1a": "pr-ta2-1",
            "ev-1b": "pr-ta2-1",
            "ev-2": "pr-ta2-2",
            "ev-3": "pr-ta2-3",
            "ev-4": "pr-ta2-4",
        },
    )
    pred = _normalize_pred(to_prediction(ctx, case_result))
    assert_valid_prediction(pred, valid_physical_ids=valid_ids)
    assert pred["ta_physical_ids"]["TA0002"] == ["pr-ta2-1", "pr-ta2-2", "pr-ta2-3"]
    assert pred["physical_id_set"] == ["pr-ta2-1", "pr-ta2-2", "pr-ta2-3", "pr-ta2-4"]

    # Part B: Live pipeline execution on scene_05_full_16_types
    index, records = load_scene_records(
        e2e_fixtures_dir / "scenarios" / "scene_05_full_16_types"
    )
    cfg = make_app_config(
        tmp_path,
        fake_bins=fake_engine_bins,
        llm_enabled=False,
        rag_offline=True,
    )
    pred_s5 = _normalize_pred(
        analyze_records(iter(records), config=cfg, valid_physical_ids=set(index.keys()))
    )
    assert_valid_prediction(pred_s5, valid_physical_ids=set(index.keys()))
    assert len(pred_s5["ta_physical_ids"].get("TA0002", [])) <= 3
    assert len(pred_s5["physical_id_set"]) >= 4


def test_f11_non_index_and_cross_case_physical_ids_never_exported(
    make_run_context: Any,
) -> None:
    """Foreign or non-index physical IDs are either rejected or stripped from exports."""
    from apt_agent.exceptions import AptAgentError
    from apt_agent.pipeline import to_prediction

    valid_ids = {"pr-valid-1"}
    ctx = make_run_context(valid_physical_ids=valid_ids)
    case_result = _build_case_result(
        ctx,
        attack_event_ids=["ev-valid", "ev-foreign"],
        tactic_ranked_event_ids={"TA0002": ["ev-foreign", "ev-valid"]},
        event_to_physical={
            "ev-valid": "pr-valid-1",
            "ev-foreign": "pr-foreign-999",
        },
    )

    try:
        raw = to_prediction(ctx, case_result, valid_physical_ids=valid_ids)
    except (AptAgentError, ValidationError, ValueError):
        return

    pred = _normalize_pred(raw)
    assert_valid_prediction(pred, valid_physical_ids=valid_ids)
    assert "pr-foreign-999" not in pred["physical_id_set"]
    for items in pred["ta_physical_ids"].values():
        assert "pr-foreign-999" not in items


def test_f11_prediction_rejects_extra_keys_subset_violation_overlimit_and_empty_ids() -> None:
    """Prediction strictly rejects extra keys, subset violations, >3 items, empty IDs, and dups."""
    from apt_agent.models import Prediction

    # (a) extra key
    with pytest.raises(ValidationError):
        Prediction(physical_id_set=["pr-1"], ta_physical_ids={}, extra="bad")

    # (b) subset violation
    with pytest.raises(ValidationError):
        Prediction(physical_id_set=["pr-1"], ta_physical_ids={"TA0002": ["pr-2"]})

    # (c) > 3 items for a tactic
    with pytest.raises(ValidationError):
        Prediction(
            physical_id_set=["pr-1", "pr-2", "pr-3", "pr-4"],
            ta_physical_ids={"TA0002": ["pr-1", "pr-2", "pr-3", "pr-4"]},
        )

    # (d) empty string in physical_id_set / ta_physical_ids
    with pytest.raises(ValidationError):
        Prediction(physical_id_set=[""], ta_physical_ids={})
    with pytest.raises(ValidationError):
        Prediction(physical_id_set=["pr-1"], ta_physical_ids={"TA0002": [""]})

    # (e) duplicate physical ID in ta_physical_ids
    with pytest.raises(ValidationError):
        Prediction(
            physical_id_set=["pr-1"],
            ta_physical_ids={"TA0002": ["pr-1", "pr-1"]},
        )


# ---------------------------------------------------------------------------
# F15: Packaging & Config Boundaries / Negative Cases (5 tests)
# ---------------------------------------------------------------------------


def test_f15_missing_config_file_and_invalid_yaml_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing YAML paths (direct or via env) and malformed/non-mapping YAML fail cleanly."""
    from apt_agent.config import load_config
    from apt_agent.exceptions import AptAgentError

    _clear_apt_and_openai_env(monkeypatch)
    accepted_errors = (FileNotFoundError, yaml.YAMLError, ValueError, AptAgentError)

    with pytest.raises(accepted_errors):
        load_config(tmp_path / "missing.yaml")

    monkeypatch.setenv("APT_AGENT_CONFIG", str(tmp_path / "missing2.yaml"))
    with pytest.raises(accepted_errors):
        load_config()
    monkeypatch.delenv("APT_AGENT_CONFIG", raising=False)

    bad_syntax = tmp_path / "bad_syntax.yaml"
    bad_syntax.write_text("engines: [unclosed\n", encoding="utf-8")
    with pytest.raises(accepted_errors):
        load_config(bad_syntax)

    list_yaml = tmp_path / "list_root.yaml"
    list_yaml.write_text("- item1\n- item2\n", encoding="utf-8")
    with pytest.raises(accepted_errors):
        load_config(list_yaml)


def test_f15_invalid_overrides_and_invalid_field_types_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invalid overrides type and non-coercible config field types raise validation errors."""
    from apt_agent.config import load_config
    from apt_agent.exceptions import AptAgentError

    _clear_apt_and_openai_env(monkeypatch)
    accepted_errors = (ValidationError, TypeError, ValueError, AptAgentError)

    invalid_inputs: list[Any] = [
        "not-a-dict",
        {"rag": {"top_k": "not-an-int"}},
        {"budget": {"reserve_ratio": "not-a-float"}},
        {"llm": {"max_tokens": "bad"}},
        {"engines": {"zircolite": {"timeout_s": "bad"}}},
    ]
    for bad in invalid_inputs:
        with pytest.raises(accepted_errors):
            load_config(overrides=bad)


def test_f15_config_precedence_overrides_gt_apt_env_gt_openai_env_gt_yaml_gt_defaults(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify strict precedence: overrides > APT_AGENT_* > OPENAI_* > YAML > defaults."""
    from apt_agent.config import load_config

    _clear_apt_and_openai_env(monkeypatch)
    cfg_file = tmp_path / "precedence.yaml"
    cfg_file.write_text(
        yaml.safe_dump(
            {
                "llm": {"model": "yaml-m", "api_key": "yaml-k"},
                "rag": {"top_k": 11},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    # Layer 1: YAML > defaults
    c1 = load_config(cfg_file)
    assert c1.llm.model == "yaml-m"
    assert c1.llm.api_key == "yaml-k"
    assert c1.rag.top_k == 11

    # Layer 2: OPENAI_* > YAML
    monkeypatch.setenv("OPENAI_MODEL", "openai-m")
    monkeypatch.setenv("OPENAI_API_KEY", "openai-k")
    c2 = load_config(cfg_file)
    assert c2.llm.model == "openai-m"
    assert c2.llm.api_key == "openai-k"
    assert c2.rag.top_k == 11

    # Layer 3: APT_AGENT_* > OPENAI_*
    monkeypatch.setenv("APT_AGENT_LLM__MODEL", "apt-m")
    monkeypatch.setenv("APT_AGENT_RAG__TOP_K", "13")
    c3 = load_config(cfg_file)
    assert c3.llm.model == "apt-m"
    assert c3.llm.api_key == "openai-k"
    assert c3.rag.top_k == 13

    # Layer 4: overrides > APT_AGENT_*
    c4 = load_config(
        cfg_file,
        overrides={"llm": {"model": "ovr-m"}, "rag": {"top_k": 17}},
    )
    assert c4.llm.model == "ovr-m"
    assert c4.llm.api_key == "openai-k"
    assert c4.rag.top_k == 17


def test_f15_llm_disabled_offline_deterministic_mode(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    fake_engine_bins: dict[str, Path],
    make_app_config: Any,
    load_scene_records: Any,
) -> None:
    """With llm.enabled=False and bogus unreachable base_url, analyze_records is deterministic."""
    from apt_agent import analyze_records

    cfg = make_app_config(
        tmp_path,
        fake_bins=fake_engine_bins,
        llm_enabled=False,
        rag_offline=True,
        overrides={
            "llm": {
                "enabled": False,
                "base_url": "http://127.0.0.1:1/v1",
                "api_key": "sk-unused",
                "timeout_s": 1.0,
            }
        },
    )
    index, records = load_scene_records(
        e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    )
    valid_ids = set(index.keys())

    pred1 = _normalize_pred(
        analyze_records(iter(records), config=cfg, valid_physical_ids=valid_ids)
    )
    pred2 = _normalize_pred(
        analyze_records(iter(records), config=cfg, valid_physical_ids=valid_ids)
    )

    assert_valid_prediction(pred1, valid_physical_ids=valid_ids)
    assert_valid_prediction(pred2, valid_physical_ids=valid_ids)
    assert pred1 == pred2


def test_f15_public_package_metadata_and_analyze_records_signature_contract() -> None:
    """Installed distribution metadata and analyze_records signature satisfy R3/R4."""
    import apt_agent

    dist = importlib_metadata.distribution("open-apt-agent")
    assert dist.metadata["Requires-Python"] == ">=3.12"
    requires = dist.requires or []
    assert any(r.split(";")[0].strip().startswith("apt-rag") for r in requires)
    joined_reqs = "\n".join(requires)
    assert "submission_agent" not in joined_reqs
    assert "apt_tracer" not in joined_reqs

    for rel in (
        "uv.lock",
        ".env.example",
        "config/default.example.yaml",
        "config/local.example.yaml",
    ):
        content = (_REPO_ROOT / rel).read_text("utf-8")
        assert "/home/yue/experience" not in content
        assert "submission_agent" not in content
        assert "apt_tracer" not in content

    sig = inspect.signature(apt_agent.analyze_records)
    params = list(sig.parameters.values())
    assert len(params) >= 1
    first = params[0]
    assert first.kind in (
        inspect.Parameter.POSITIONAL_ONLY,
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
    )
    for remaining in params[1:]:
        assert remaining.default is not inspect.Parameter.empty or remaining.kind in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
