"""Planner audit must record real attempts and validation without leaking credentials."""
from types import SimpleNamespace
import json

import pytest

from apt_agent.agents import BudgetManager, _plan_tasks
from apt_agent.config import AppConfig
from apt_agent.models import RunContext


@pytest.mark.parametrize("content,outcome", [("[1,0]", "applied"), ("[1,1]", "fallback")])
def test_actual_request_and_plan_validation_are_audited(monkeypatch, content, outcome):
    import openai
    cfg = AppConfig(llm={"enabled": True, "base_url": "https://example.invalid", "model": "fixture", "api_key": "private-fixture-key"})
    budget = BudgetManager(cfg.budget)
    completion = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))], usage=SimpleNamespace(total_tokens=42))
    class Client:
        def __init__(self, **kwargs):
            self.chat = SimpleNamespace(completions=SimpleNamespace(create=lambda **kwargs: completion))
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
    monkeypatch.setattr(openai, "OpenAI", Client)
    ctx = RunContext(case_id="case", run_id="run", config=cfg)
    tasks = [("host", []), ("network", [])]
    issues = []
    result = _plan_tasks(ctx, budget, tasks, [], issues)
    assert result == (list(reversed(tasks)) if outcome == "applied" else tasks)
    assert budget.llm_calls[0]["requested"]
    assert budget.llm_calls[0]["request_succeeded"]
    assert budget.llm_calls[0]["tokens"] == 42
    assert budget.llm_calls[0]["outcome"] == outcome
    assert "private-fixture-key" not in json.dumps(budget.llm_calls)
    assert bool(issues) == (outcome == "fallback")


def test_disabled_planner_records_no_request():
    cfg = AppConfig(llm={"enabled": False})
    ctx = RunContext(case_id="case", run_id="run", config=cfg)
    budget = BudgetManager(cfg.budget)
    tasks = [("host", []), ("network", [])]
    assert _plan_tasks(ctx, budget, tasks, [], []) == tasks
    assert not any(call["requested"] for call in budget.llm_calls)


def test_observer_does_not_add_fields_or_change_prediction():
    from apt_agent.pipeline import analyze_records
    observed = []
    cfg = AppConfig(llm={"enabled": False})
    for name in type(cfg.engines).model_fields:
        getattr(cfg.engines, name).enabled = False
    result = analyze_records(iter([]), config=cfg, on_result=observed.append)
    assert result == {"physical_id_set": [], "ta_physical_ids": {}}
    assert len(observed) == 1
    assert observed[0].stop_reason == "NO_DETECTION_SEEDS"


def test_public_callback_keeps_counts_without_building_full_diagnostics():
    from apt_agent.pipeline import analyze_records, investigate_records
    cfg = AppConfig(llm={"enabled": False})
    for name in type(cfg.engines).model_fields:
        getattr(cfg.engines, name).enabled = False
    records = [("pr-one", {"unknown": "raw evidence retained"})]
    observed = []
    prediction = analyze_records(iter(records), config=cfg, on_result=observed.append)
    diagnostic = investigate_records(iter(records), config=cfg)
    assert prediction == {"physical_id_set": [], "ta_physical_ids": {}}
    assert observed[0].input_record_count == diagnostic.input_record_count == 1
    assert observed[0].record_diagnostics == {}
    assert "pr-one" in diagnostic.record_diagnostics
    assert observed[0].unresolved == diagnostic.unresolved


def test_package_entrypoint_forwards_runtime_observer():
    from apt_agent import analyze_records
    cfg = AppConfig(llm={"enabled": False})
    for name in type(cfg.engines).model_fields:
        getattr(cfg.engines, name).enabled = False
    observed = []
    result = analyze_records(iter([]), config=cfg, on_result=observed.append)
    assert result == {"physical_id_set": [], "ta_physical_ids": {}}
    assert len(observed) == 1
    assert observed[0].input_record_count == 0
