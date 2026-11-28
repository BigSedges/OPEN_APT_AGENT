"""Shared pytest fixtures and marker registration for opaque-box E2E tests.

All ``apt_agent`` imports are kept lazy inside factory callables so E2E test
modules and helpers can be collected/validated independently of ``src/apt_agent``.
"""

from __future__ import annotations

import inspect
import sys
from pathlib import Path
from typing import Any

import pytest

_E2E_DIR = str(Path(__file__).resolve().parent)
if _E2E_DIR not in sys.path:
    sys.path.insert(0, _E2E_DIR)

import _helpers  # noqa: E402


def pytest_configure(config: pytest.Config) -> None:
    """Register E2E tier, acceptance, and slow markers."""
    config.addinivalue_line(
        "markers", "tier1: Tier 1 core functional E2E tests (F01-F15)"
    )
    config.addinivalue_line(
        "markers", "tier2: Tier 2 boundary value and negative E2E tests (F01-F15)"
    )
    config.addinivalue_line(
        "markers", "tier3: Tier 3 pairwise cross-feature integration E2E tests"
    )
    config.addinivalue_line(
        "markers", "tier4: Tier 4 realistic multi-format APT and benign workload scenarios"
    )
    config.addinivalue_line(
        "markers", "acceptance: Interface Section 7 (S7.1-S7.6) and Prototype (P1-P9) acceptance tests"
    )
    config.addinivalue_line(
        "markers", "slow: Long-running or optional external local engine binary tests"
    )


def _deep_merge(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, val in extra.items():
        if isinstance(val, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], val)
        else:
            merged[key] = val
    return merged


@pytest.fixture(scope="session")
def e2e_fixtures_dir() -> Path:
    """Return the root directory of E2E synthetic fixtures."""
    return (Path(__file__).resolve().parents[1] / "fixtures" / "e2e").resolve()


@pytest.fixture(scope="function")
def make_fake_engine_bins(tmp_path: Path):
    """Factory creating executable fake CLI binaries for all 5 detection engines."""

    def _factory(
        target_dir: Path | None = None,
        *,
        engine_modes: dict[str, str] | None = None,
        sleep_s: float = 30.0,
    ) -> dict[str, Path]:
        out_dir = Path(target_dir) if target_dir is not None else (tmp_path / "fake_bins")
        return _helpers.build_fake_engine_bins(
            out_dir,
            engine_modes=engine_modes,
            sleep_s=sleep_s,
        )

    return _factory


@pytest.fixture(scope="function")
def fake_engine_bins(make_fake_engine_bins) -> dict[str, Path]:
    """Convenience fixture providing default normal-mode fake engine binaries."""
    return make_fake_engine_bins()


@pytest.fixture(scope="function")
def make_fake_engine_bin(make_fake_engine_bins):
    """Factory alias returning a single requested fake engine binary Path."""

    def _factory(
        engine: str,
        target_dir: Path | None = None,
        *,
        mode: str = "normal",
        sleep_s: float = 30.0,
    ) -> Path:
        bins = make_fake_engine_bins(
            target_dir,
            engine_modes={engine: mode},
            sleep_s=sleep_s,
        )
        key = engine.lower()
        if key not in bins:
            raise ValueError(
                f"Unknown fake engine {engine!r}; expected one of {sorted(bins)}"
            )
        return bins[key]

    return _factory


@pytest.fixture(scope="function")
def make_app_config(tmp_path: Path, e2e_fixtures_dir: Path, make_fake_engine_bins):
    """Factory building an isolated, config-injected AppConfig (or dict)."""

    def _factory(
        base_dir: Path | None = None,
        *,
        fake_bins: dict[str, Path] | None = None,
        engine_modes: dict[str, str] | None = None,
        rules_dir: Path | None = None,
        knowledge_path: Path | None = None,
        snapshots_dir: Path | None = None,
        llm_enabled: bool = False,
        enabled_engines: tuple[str, ...] | set[str] | None = None,
        timeout_s: float = 15.0,
        rag_mode: str = "bm25",
        rag_top_k: int = 5,
        rag_timeout_ms: int = 5000,
        rag_offline: bool = True,
        budget_overrides: dict[str, Any] | None = None,
        overrides: dict[str, Any] | None = None,
        as_dict: bool = False,
    ) -> Any:
        work_root = Path(base_dir) if base_dir is not None else tmp_path
        bins = (
            fake_bins
            if fake_bins is not None
            else make_fake_engine_bins(work_root / "fake_bins", engine_modes=engine_modes)
        )
        repo_root = Path(__file__).resolve().parents[2]
        default_rules = Path(rules_dir) if rules_dir is not None else (e2e_fixtures_dir / "rules" / "valid")
        default_kb = (
            Path(knowledge_path)
            if knowledge_path is not None
            else (e2e_fixtures_dir / "kb" / "synthetic_kb.jsonl")
        )
        default_snaps = Path(snapshots_dir) if snapshots_dir is not None else (work_root / "snapshots")
        default_snaps.mkdir(parents=True, exist_ok=True)

        enabled_set = (
            {e.lower() for e in enabled_engines}
            if enabled_engines is not None
            else {"zircolite", "hayabusa", "takajo", "rsigma", "chainsaw", "pysigma"}
        )

        budget_cfg: dict[str, Any] = {
            "max_tasks_per_round": 3,
            "max_rounds": 5,
            "max_steps_per_task": 8,
            "max_challenger_rounds": 1,
            "max_repair_rounds": 1,
            "wall_clock_s": 300.0,
            "max_tokens": 120000,
            "reserve_ratio": 0.8,
        }
        if budget_overrides:
            budget_cfg = _deep_merge(budget_cfg, budget_overrides)

        cfg_dict: dict[str, Any] = {
            "engines": {
                "zircolite": {
                    "bin_path": str(bins["zircolite"]),
                    "rules_dir": str(default_rules),
                    "config_path": str(repo_root / "script/log_convert/configs/zircolite_config.yaml"),
                    "mapping_path": None,
                    "working_dir": str(bins["zircolite"].parent),
                    "enabled": "zircolite" in enabled_set,
                    "timeout_s": timeout_s,
                },
                "hayabusa": {
                    "bin_path": str(bins["hayabusa"]),
                    "rules_dir": str(default_rules),
                    "config_path": None,
                    "mapping_path": None,
                    "working_dir": str(bins["hayabusa"].parent),
                    "enabled": "hayabusa" in enabled_set,
                    "timeout_s": timeout_s,
                },
                "takajo": {
                    "bin_path": str(bins["takajo"]),
                    "rules_dir": None,
                    "config_path": None,
                    "mapping_path": None,
                    "working_dir": str(bins["takajo"].parent),
                    "enabled": "takajo" in enabled_set,
                    "timeout_s": timeout_s,
                },
                "rsigma": {
                    "bin_path": str(bins["rsigma"]),
                    "rules_dir": str(default_rules),
                    "config_path": str(repo_root / "script/log_convert/configs/rsigma_pipeline.yml"),
                    "mapping_path": None,
                    "working_dir": str(bins["rsigma"].parent),
                    "enabled": "rsigma" in enabled_set,
                    "timeout_s": timeout_s,
                },
                "chainsaw": {
                    "bin_path": str(bins["chainsaw"]),
                    "rules_dir": str(default_rules),
                    "config_path": None,
                    "mapping_path": str(repo_root / "script/log_convert/configs/chainsaw_custom_mapping.yml"),
                    "working_dir": str(bins["chainsaw"].parent),
                    "enabled": "chainsaw" in enabled_set,
                    "timeout_s": timeout_s,
                },
                "pysigma": {
                    "bin_path": None,
                    "rules_dir": str(default_rules),
                    "config_path": None,
                    "mapping_path": None,
                    "working_dir": None,
                    "enabled": "pysigma" in enabled_set,
                    "timeout_s": timeout_s,
                },
            },
            "rag": {
                "knowledge_path": str(default_kb),
                "config_path": None,
                "mode": rag_mode,
                "top_k": rag_top_k,
                "timeout_ms": rag_timeout_ms,
                "offline": rag_offline,
            },
            "llm": {
                "provider": "openai_compatible",
                "base_url": None,
                "api_key": None,
                "model": "gpt-4o-mini",
                "temperature": 0.0,
                "max_tokens": 4096,
                "timeout_s": timeout_s,
                "enabled": llm_enabled,
            },
            "budget": budget_cfg,
            "snapshots": {
                "root_dir": str(default_snaps),
            },
        }

        if overrides:
            cfg_dict = _deep_merge(cfg_dict, overrides)

        if as_dict:
            return cfg_dict

        from apt_agent.config import load_config

        return load_config(overrides=cfg_dict)

    return _factory


@pytest.fixture(scope="function")
def make_run_context(make_app_config):
    """Factory building an immutable RunContext via defensive field inspection."""

    def _factory(
        *,
        case_id: str = "case-e2e-001",
        run_id: str = "run-e2e-001",
        data_snapshot_id: str = "data-snap-v1",
        mapping_version: str = "map-v1",
        ruleset_version: str = "rules-v1",
        knowledge_snapshot_id: str = "kb-v1",
        config: Any | None = None,
        valid_physical_ids: set[str] | None = None,
        locator_map: dict[str, Any] | None = None,
        **extra: Any,
    ) -> Any:
        from apt_agent.models import RunContext

        try:
            from apt_agent.models import Locator
        except ImportError:
            Locator = None

        cfg = config if config is not None else make_app_config()

        coerced_locators = locator_map
        if locator_map is not None and Locator is not None:
            coerced_locators = {
                k: (Locator(**v) if isinstance(v, dict) else v)
                for k, v in locator_map.items()
            }

        model_fields = getattr(RunContext, "model_fields", None)
        if isinstance(model_fields, dict):
            accepted_fields = set(model_fields.keys())
        else:
            sig = inspect.signature(RunContext)
            accepted_fields = set(sig.parameters.keys())

        candidate_kwargs: dict[str, Any] = {
            "case_id": case_id,
            "run_id": run_id,
            "data_snapshot_id": data_snapshot_id,
            "mapping_version": mapping_version,
            "ruleset_version": ruleset_version,
            "knowledge_snapshot_id": knowledge_snapshot_id,
        }
        if "config" in accepted_fields:
            candidate_kwargs["config"] = cfg
        elif "app_config" in accepted_fields:
            candidate_kwargs["app_config"] = cfg

        if valid_physical_ids is not None and "valid_physical_ids" in accepted_fields:
            candidate_kwargs["valid_physical_ids"] = valid_physical_ids
        if coerced_locators is not None and "locator_map" in accepted_fields:
            candidate_kwargs["locator_map"] = coerced_locators

        for key, val in extra.items():
            if key in accepted_fields:
                candidate_kwargs[key] = val

        return RunContext(**candidate_kwargs)

    return _factory


@pytest.fixture(scope="session")
def load_scene_records():
    """Return the helper callable loading Label_Index.json and ordered records."""
    return _helpers.load_indexed_records
