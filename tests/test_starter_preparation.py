"""Public callback integration must preserve the original starter and its IO flow."""
import importlib.util
from pathlib import Path
import ast

import pytest


def module():
    path = Path(__file__).resolve().parents[1] / "script/evaluate/prepare_starter.py"
    spec = importlib.util.spec_from_file_location("prepare_starter", path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def test_prepared_copy_forwards_records_and_read_only_index_context(tmp_path, monkeypatch):
    import apt_agent
    import apt_agent.ingestion
    source = tmp_path / "source"
    for name in ("submission_agent", "scripts", "scoring", "data"):
        (source / name).mkdir(parents=True)
    text = '''from __future__ import annotations
from pathlib import Path
from typing import Any, Iterator

def _run_multi_scenario(index_path, records):
    return analyze_records(records)

def analyze_records(records):
    """Original starter example."""
    return {"physical_id_set": [], "ta_physical_ids": {}}
'''
    original = text.encode()
    (source / "submission_agent/runner.py").write_bytes(original)
    output = tmp_path / "prepared"
    manifest = module().prepare(source, output)
    assert (source / "submission_agent/runner.py").read_bytes() == original
    assert (output / "data").is_symlink()
    assert manifest["callback"] == "apt_agent.analyze_records"
    assert not manifest["container_ready"]
    observed = {}
    def investigate(records, **kwargs):
        observed["records"] = list(records)
        observed.update(kwargs)
        return {"physical_id_set": ["pr-one"], "ta_physical_ids": {}}
    monkeypatch.setattr(apt_agent, "analyze_records", investigate)
    monkeypatch.setattr(apt_agent.ingestion, "load_label_index", lambda index_path, data_dir: {"pr-one": "locator"})
    namespace = {}
    adapted = (output / "submission_agent/runner.py").read_text()
    ast.parse(adapted)
    exec(compile(adapted, "prepared-runner", "exec"), namespace)
    records = iter([("pr-one", {"raw_text": "evidence"})])
    prediction = namespace["_run_multi_scenario"](tmp_path / "Label_Index.json", records)
    assert prediction["physical_id_set"] == ["pr-one"]
    assert observed["records"] == [("pr-one", {"raw_text": "evidence"})]
    assert observed["valid_physical_ids"] == frozenset({"pr-one"})
    assert observed["locator_map"] == {"pr-one": "locator"}
    with pytest.raises(FileExistsError):
        module().prepare(source, output)


def test_unsupported_starter_is_rejected():
    with pytest.raises(ValueError):
        module().adapt_runner("def other_callback(records):\n    pass\n")
