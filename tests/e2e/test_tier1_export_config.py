"""Tier 1 opaque-box E2E tests for F11 (Competition Export) & F15 (Packaging/Config).

All ``apt_agent`` imports are kept lazy inside test functions or local helpers so
test collection succeeds independently of milestone completion.
"""

from __future__ import annotations

import importlib.metadata as importlib_metadata
import json
import os
import re
import tomllib
from pathlib import Path
from typing import Any

import pytest
import yaml

from _helpers import assert_valid_prediction

pytestmark = pytest.mark.tier1

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TA_ASCII_RE = re.compile(r"TA[0-9]{4}")


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
# F11: Competition Export Contract (5 tests)
# ---------------------------------------------------------------------------


def test_f11_analyze_records_single_positional_arg_and_json_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    e2e_fixtures_dir: Path,
    fake_engine_bins: dict[str, Path],
    make_app_config: Any,
    load_scene_records: Any,
) -> None:
    """analyze_records(records) accepts 1 positional iterator, consumes once, and returns JSON."""
    from apt_agent import analyze_records

    _clear_apt_and_openai_env(monkeypatch)
    cfg_dict = make_app_config(
        tmp_path,
        fake_bins=fake_engine_bins,
        llm_enabled=False,
        rag_offline=True,
        as_dict=True,
    )
    cfg_path = tmp_path / "cfg.yaml"
    cfg_path.write_text(yaml.safe_dump(cfg_dict, sort_keys=False), encoding="utf-8")
    monkeypatch.setenv("APT_AGENT_CONFIG", str(cfg_path))

    index, records = load_scene_records(
        e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    )
    gen = (item for item in records)

    raw = analyze_records(gen)
    pred = _normalize_pred(raw)

    assert next(gen, None) is None, "analyze_records must consume iterator in single pass"
    dumped = json.dumps(pred, ensure_ascii=False)
    assert isinstance(dumped, str) and len(dumped) > 0
    assert_valid_prediction(pred, valid_physical_ids=set(index.keys()))
    assert len(pred["physical_id_set"]) >= 1
    assert {"TA0002", "TA0011"} & set(pred["ta_physical_ids"])


def test_f11_to_prediction_exact_keys_sorted_unique_physical_id_set(
    make_run_context: Any,
) -> None:
    """to_prediction returns exact keys with deduplicated, sorted physical_id_set."""
    from apt_agent.pipeline import to_prediction

    valid_ids = {"pr-001", "pr-002", "pr-003"}
    ctx = make_run_context(valid_physical_ids=valid_ids)
    case_result = _build_case_result(
        ctx,
        attack_event_ids=["ev-3", "ev-1", "ev-3b", "ev-2"],
        tactic_ranked_event_ids={"TA0002": ["ev-2", "ev-1"]},
        event_to_physical={
            "ev-1": "pr-001",
            "ev-2": "pr-002",
            "ev-3": "pr-003",
            "ev-3b": "pr-003",
        },
    )

    pred = _normalize_pred(to_prediction(ctx, case_result))

    assert set(pred.keys()) == {"physical_id_set", "ta_physical_ids"}
    assert pred["physical_id_set"] == ["pr-001", "pr-002", "pr-003"]
    assert_valid_prediction(pred, valid_physical_ids=valid_ids)


def test_f11_to_prediction_tactic_keys_regex_and_per_tactic_priority(
    make_run_context: Any,
) -> None:
    """to_prediction preserves per-tactic priority order and omits empty tactics."""
    from apt_agent.pipeline import to_prediction

    valid_ids = {"pr-a", "pr-b", "pr-c"}
    ctx = make_run_context(valid_physical_ids=valid_ids)
    case_result = _build_case_result(
        ctx,
        attack_event_ids=["ev-a", "ev-b", "ev-c"],
        tactic_ranked_event_ids={
            "TA0002": ["ev-c", "ev-a", "ev-b"],
            "TA0011": ["ev-a"],
            "TA0001": [],
        },
        event_to_physical={
            "ev-a": "pr-a",
            "ev-b": "pr-b",
            "ev-c": "pr-c",
        },
    )

    pred = _normalize_pred(to_prediction(ctx, case_result))

    assert_valid_prediction(pred, valid_physical_ids=valid_ids)
    assert "TA0001" not in pred["ta_physical_ids"]
    assert pred["ta_physical_ids"]["TA0002"] == ["pr-c", "pr-a", "pr-b"]
    assert pred["ta_physical_ids"]["TA0011"] == ["pr-a"]
    assert all(_TA_ASCII_RE.fullmatch(k) for k in pred["ta_physical_ids"])


def test_f11_to_prediction_subset_invariant_and_excess_ids_retained(
    make_run_context: Any,
) -> None:
    """physical_id_set retains attack IDs beyond per-tactic top-3 and tacticless IDs."""
    from apt_agent.pipeline import to_prediction

    valid_ids = {"pr-1", "pr-2", "pr-3", "pr-4", "pr-5"}
    ctx = make_run_context(valid_physical_ids=valid_ids)
    case_result = _build_case_result(
        ctx,
        attack_event_ids=["ev-1", "ev-2", "ev-3", "ev-4", "ev-5"],
        tactic_ranked_event_ids={"TA0002": ["ev-1", "ev-2", "ev-3", "ev-4"]},
        event_to_physical={
            "ev-1": "pr-1",
            "ev-2": "pr-2",
            "ev-3": "pr-3",
            "ev-4": "pr-4",
            "ev-5": "pr-5",
        },
    )

    pred = _normalize_pred(to_prediction(ctx, case_result))

    assert_valid_prediction(pred, valid_physical_ids=valid_ids)
    ta_union = {pid for items in pred["ta_physical_ids"].values() for pid in items}
    assert ta_union <= set(pred["physical_id_set"])
    assert pred["ta_physical_ids"]["TA0002"] == ["pr-1", "pr-2", "pr-3"]
    assert "pr-4" in pred["physical_id_set"]
    assert "pr-5" in pred["physical_id_set"]


def test_f11_label_index_membership_enforced_by_pipeline_and_exporter(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    fake_engine_bins: dict[str, Path],
    make_app_config: Any,
    load_scene_records: Any,
) -> None:
    """All IDs exported by analyze_records belong to the scene's Label_Index keys."""
    from apt_agent import analyze_records

    index, records = load_scene_records(
        e2e_fixtures_dir / "scenarios" / "scene_01_phishing_c2"
    )
    cfg = make_app_config(
        tmp_path,
        fake_bins=fake_engine_bins,
        llm_enabled=False,
        rag_offline=True,
    )
    valid_ids = set(index.keys())

    pred = _normalize_pred(
        analyze_records(iter(records), config=cfg, valid_physical_ids=valid_ids)
    )

    assert_valid_prediction(pred, valid_physical_ids=valid_ids)
    assert set(pred["physical_id_set"]) <= valid_ids


# ---------------------------------------------------------------------------
# F15: uv Packaging & Externalized Config (5 tests)
# ---------------------------------------------------------------------------


def test_f15_pyproject_and_uv_lock_python_312_and_workspace_sources() -> None:
    """pyproject.toml, uv.lock, and package metadata declare >=3.12 and apt-rag."""
    pyproject_data = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text("utf-8"))
    project = pyproject_data["project"]
    assert project["name"] == "open-apt-agent"
    assert ">=3.12" in project["requires-python"]

    deps = project["dependencies"]
    assert any(d == "apt-rag" or d.startswith("apt-rag") for d in deps)
    assert pyproject_data["tool"]["uv"]["sources"]["apt-rag"]["path"] == "packages/apt-rag"
    assert pyproject_data["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == [
        "src/apt_agent"
    ]

    uv_lock_path = _REPO_ROOT / "uv.lock"
    assert uv_lock_path.is_file()
    uv_lock_head = "\n".join(uv_lock_path.read_text("utf-8").splitlines()[:10])
    assert 'requires-python = ">=3.12"' in uv_lock_head

    dist = importlib_metadata.distribution("open-apt-agent")
    assert dist.metadata["Name"] == "open-apt-agent"
    assert ">=3.12" in (dist.metadata["Requires-Python"] or "")
    assert dist.requires is not None
    assert any(req.split(";")[0].strip().startswith("apt-rag") for req in dist.requires)


def test_f15_load_config_from_yaml_path_and_apt_agent_config_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """load_config loads YAML both via explicit path argument and APT_AGENT_CONFIG."""
    from apt_agent.config import load_config

    _clear_apt_and_openai_env(monkeypatch)
    fake_zircolite = str(tmp_path / "bin" / "zircolite")
    snap_dir = str(tmp_path / "custom_snapshots")
    yaml_payload = {
        "engines": {
            "zircolite": {"bin_path": fake_zircolite, "enabled": True},
            "hayabusa": {"timeout_s": 42.0},
        },
        "rag": {"top_k": 9},
        "llm": {"model": "custom-model-v1", "enabled": False},
        "budget": {"max_rounds": 3},
        "snapshots": {"root_dir": snap_dir},
    }
    cfg_file = tmp_path / "custom.yaml"
    cfg_file.write_text(yaml.safe_dump(yaml_payload, sort_keys=False), encoding="utf-8")

    cfg_direct = load_config(cfg_file)
    monkeypatch.setenv("APT_AGENT_CONFIG", str(cfg_file))
    cfg_env = load_config()

    for cfg in (cfg_direct, cfg_env):
        assert str(cfg.engines.zircolite.bin_path) == fake_zircolite
        assert cfg.engines.hayabusa.timeout_s == pytest.approx(42.0)
        assert cfg.rag.top_k == 9
        assert cfg.llm.model == "custom-model-v1"
        assert cfg.llm.enabled is False
        assert cfg.budget.max_rounds == 3
        assert str(cfg.snapshots.root_dir) == snap_dir


def test_f15_load_config_env_vars_nested_flat_and_openai_fallbacks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """load_config honors OPENAI_* fallbacks, nested APT_AGENT_*__*, and flat aliases."""
    from apt_agent.config import load_config

    # Sub-case A: OPENAI_* fallback env vars
    _clear_apt_and_openai_env(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-openai-fallback")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://fallback.example.invalid/v1")
    monkeypatch.setenv("OPENAI_MODEL", "fallback-model-a")
    cfg_a = load_config()
    assert cfg_a.llm.api_key == "sk-test-openai-fallback"
    assert cfg_a.llm.base_url == "https://fallback.example.invalid/v1"
    assert cfg_a.llm.model == "fallback-model-a"

    # Sub-case B: canonical nested APT_AGENT_<SECTION>__<FIELD>
    _clear_apt_and_openai_env(monkeypatch)
    rsigma_bin = str(tmp_path / "tools" / "rsigma")
    monkeypatch.setenv("APT_AGENT_LLM__API_KEY", "sk-test-nested")
    monkeypatch.setenv("APT_AGENT_LLM__MODEL", "nested-model-b")
    monkeypatch.setenv("APT_AGENT_ENGINES__RSIGMA__BIN_PATH", rsigma_bin)
    cfg_b = load_config()
    assert cfg_b.llm.api_key == "sk-test-nested"
    assert cfg_b.llm.model == "nested-model-b"
    assert str(cfg_b.engines.rsigma.bin_path) == rsigma_bin

    # Sub-case C: supported flat aliases
    _clear_apt_and_openai_env(monkeypatch)
    monkeypatch.setenv("APT_AGENT_LLM_MODEL", "flat-model-c")
    monkeypatch.setenv("APT_AGENT_RAG_MODE", "hybrid")
    monkeypatch.setenv("APT_AGENT_SNAPSHOTS_ROOT_DIR", str(tmp_path / "flat_snaps"))
    cfg_c = load_config()
    assert cfg_c.llm.model == "flat-model-c"
    assert cfg_c.rag.mode == "hybrid"
    assert str(cfg_c.snapshots.root_dir) == str(tmp_path / "flat_snaps")


def test_f15_zero_hardcoded_local_or_starter_paths_in_templates_and_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Templates and default AppConfig contain zero hardcoded machine or starter paths."""
    from apt_agent.config import load_config

    _clear_apt_and_openai_env(monkeypatch)
    forbidden = ("/home/yue/experience", "submission_agent", "apt_tracer")

    template_paths = [
        _REPO_ROOT / "pyproject.toml",
        _REPO_ROOT / ".env.example",
        _REPO_ROOT / "config" / "default.example.yaml",
        _REPO_ROOT / "config" / "local.example.yaml",
    ]
    for path in template_paths:
        text = path.read_text("utf-8")
        for needle in forbidden:
            assert needle not in text, f"Forbidden token {needle!r} found in {path}"

    cfg = load_config()
    dumped_json = cfg.model_dump_json()
    for needle in forbidden:
        assert needle not in dumped_json, f"Forbidden token {needle!r} in default AppConfig"

    for engine_name in ("zircolite", "hayabusa", "takajo", "chainsaw", "rsigma", "pysigma"):
        engine_cfg = getattr(cfg.engines, engine_name)
        assert engine_cfg.bin_path is None, (
            f"Default engines.{engine_name}.bin_path must be None, got {engine_cfg.bin_path!r}"
        )


def test_f15_llm_config_entry_fields_and_templates_alignment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Config templates expose complete LLM entry fields with enabled=False by default."""
    from apt_agent.config import load_config

    _clear_apt_and_openai_env(monkeypatch)
    expected_llm_fields = {
        "provider",
        "base_url",
        "api_key",
        "model",
        "temperature",
        "max_tokens",
        "timeout_s",
        "enabled",
    }

    for rel in ("config/default.example.yaml", "config/local.example.yaml"):
        cfg = load_config(_REPO_ROOT / rel)
        llm_dict = cfg.llm.model_dump()
        assert expected_llm_fields <= set(llm_dict.keys())
        assert cfg.llm.enabled is False

    env_example = (_REPO_ROOT / ".env.example").read_text("utf-8")
    for env_key in (
        "APT_AGENT_LLM__ENABLED",
        "APT_AGENT_LLM__PROVIDER",
        "APT_AGENT_LLM__BASE_URL",
        "APT_AGENT_LLM__API_KEY",
        "APT_AGENT_LLM__MODEL",
        "OPENAI_BASE_URL",
        "OPENAI_API_KEY",
        "OPENAI_MODEL",
    ):
        assert env_key in env_example
