"""The delivery audit checks the two-field prediction contract without labels."""
import importlib.util
import json
from pathlib import Path

import pytest


def auditor():
    path = Path(__file__).resolve().parents[1] / "script/evaluate/run_pair.py"
    spec = importlib.util.spec_from_file_location("audit_official", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.audit_run


def files(tmp_path, prediction):
    run, train, runtime = (tmp_path / name for name in ("run", "train", "runtime"))
    (run / "predictions/scene").mkdir(parents=True)
    (run / "scores/scene").mkdir(parents=True)
    (train / "scene").mkdir(parents=True)
    runtime.mkdir()
    (run / "predictions/done.txt").write_text("")
    (run / "predictions/scene/predict.json").write_text(json.dumps(prediction))
    (run / "scores/scene/evaluation.json").write_text('{"overall_score_100": 0}')
    (train / "scene/Label_Index.json").write_text('{"pr-one": {"filepath":"data/log.json","linenumber":1}}')
    (runtime / "runtime.json").write_text(json.dumps({"scene": "scene", "input_record_count": 1,
        "physical_prediction_count": len(prediction["physical_id_set"]), "llm_calls": []}))
    return run, train, runtime


def test_official_run_audit_requires_no_gold_file(tmp_path):
    run, train, runtime = files(tmp_path, {"physical_id_set": ["pr-one"], "ta_physical_ids": {"TA0002": ["pr-one"]}})
    report = auditor()(run, train, runtime)
    assert report["done_txt"] and report["scene_count"] == 1
    assert not (train / "scene/Label.json").exists()


@pytest.mark.parametrize("prediction", [
    {"physical_id_set": ["pr-outside"], "ta_physical_ids": {}},
    {"physical_id_set": ["pr-one", "pr-one"], "ta_physical_ids": {}},
])
def test_invalid_scope_and_duplicate_evidence_fail_delivery_audit(tmp_path, prediction):
    run, train, runtime = files(tmp_path, prediction)
    with pytest.raises(ValueError):
        auditor()(run, train, runtime)
