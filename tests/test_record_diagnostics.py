"""P0 provenance tests derived from the handoff and physical-ID contract."""
from apt_agent.config import AppConfig
from apt_agent.detection.base import AdapterOutput
from apt_agent.detection.coordinator import DetectionCoordinator
from apt_agent.diagnostics import compare_records
from apt_agent.models import Hit
from apt_agent.pipeline import investigate_records


class FixtureAdapter:
    engine_name = "rsigma"
    supported_formats = frozenset({"bash_history"})

    def run(self, ctx, events, engine_cfg, **kwargs):
        hits = []
        for event in events:
            pid = event.physical_record_id
            rule = "wrong-source" if pid == "pr-filtered" else "bash-rule"
            hits.append(Hit(hit_id=pid, rule_id=rule, engine="rsigma",
                            event_ids=[event.event_id],
                            level="low" if pid == "pr-low" else "high"))
        return AdapterOutput(engine="rsigma", hits=hits)


def test_physical_trace_and_post_prediction_comparison(tmp_path, monkeypatch):
    (tmp_path / "rules.yml").write_text("""id: bash-rule
logsource:
  product: linux
  service: bash
---
id: wrong-source
logsource:
  product: windows
  service: sysmon
""")
    config = AppConfig.model_validate({
        "engines": {"rsigma": {"rules_dir": str(tmp_path)}, "pysigma": {"enabled": False}},
        "rag": {"offline": True}, "llm": {"enabled": False},
    })
    coordinator = DetectionCoordinator(config, adapters=[FixtureAdapter()])
    monkeypatch.setattr("apt_agent.pipeline.DetectionCoordinator", lambda cfg: coordinator)
    consumed = []

    def records():
        for pid in ("pr-attack", "pr-low", "pr-filtered", "pr-bad"):
            consumed.append(pid)
            yield pid, ({"raw_text": "echo benign", "timestamp": 1700000000}
                        if pid != "pr-bad" else {"unrecognized": "value"})

    case = investigate_records(records(), config=config)
    trace = case.record_diagnostics
    assert len(consumed) == 4
    assert trace["pr-bad"]["last_stage"] == "ingested"
    assert trace["pr-bad"]["gaps"]
    assert trace["pr-filtered"]["last_stage"] == "detected"
    assert trace["pr-filtered"]["hits"][0]["reason"] == "outside_rule_logsource"
    assert trace["pr-low"]["last_stage"] == "source_accepted"
    assert trace["pr-attack"]["exported"]
    before = case.model_dump_json()
    report = compare_records(case, {"pr-filtered", "pr-missing"})
    assert report["counts"] == {"expected": 2, "predicted": 1, "true_positive": 0,
                                 "false_positive": 1, "false_negative": 2}
    assert report["missed_records"][1]["last_stage"] == "input_missing"
    assert case.model_dump_json() == before
    assert report["rule_distribution"][0]["raw_physical_count"] == 2
