"""Prepare a separate official starter copy using the public investigation API."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import shutil


CALLBACK = '''def analyze_records(records: Iterator[tuple[str, dict[str, Any]]], *, index_path: Path | None = None) -> dict[str, Any]:
    """Forward the record stream, index context and optional local telemetry."""
    from collections import Counter
    from time import perf_counter
    from apt_agent import analyze_records as investigate
    started = perf_counter()
    def observe(result):
        directory = os.environ.get("APT_AGENT_RUN_REPORT_DIR")
        if not directory:
            return
        destination = Path(directory)
        destination.mkdir(parents=True, exist_ok=True)
        data = {"case_id": result.case_id, "run_id": result.run_id,
                "scene": index_path.parent.name if index_path else None,
                "stop_reason": result.stop_reason, "elapsed_s": perf_counter() - started,
                "stage_timings_s": result.stage_timings_s, "llm_calls": result.llm_calls,
                "input_record_count": result.input_record_count,
                "physical_prediction_count": len({result.event_to_physical[eid] for eid in result.attack_event_ids}),
                "coverage": [{"engine": engine, "status": status, "count": count}
                             for (engine, status), count in sorted(Counter((row.engine, row.status) for row in result.coverage).items())]}
        target = destination / (result.run_id + ".json")
        temporary = target.with_suffix(".tmp")
        temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(target)
    if index_path is None:
        return investigate(records, on_result=observe)
    from apt_agent.ingestion import load_label_index
    locators = load_label_index(index_path, data_dir=index_path.parent / "data")
    return investigate(records, valid_physical_ids=frozenset(locators), locator_map=locators, on_result=observe)
'''


def adapt_runner(text: str) -> str:
    tree = ast.parse(text)
    callbacks = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "analyze_records"]
    loops = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_run_multi_scenario"]
    if len(callbacks) != 1 or len(loops) != 1 or callbacks[0].decorator_list:
        raise ValueError("Unsupported starter: expected one plain callback and scenario runner.")
    calls = [node for node in ast.walk(loops[0]) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Name) and node.func.id == "analyze_records"]
    if len(calls) != 1 or len(calls[0].args) != 1 or calls[0].keywords:
        raise ValueError("Unsupported starter callback call site.")
    lines = text.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    def span(node):
        # Starter identifiers/call sites are ASCII; callback body may contain UTF-8 prose.
        start = offsets[node.lineno - 1] + len(lines[node.lineno - 1].encode()[:node.col_offset].decode())
        end = offsets[node.end_lineno - 1] + len(lines[node.end_lineno - 1].encode()[:node.end_col_offset].decode())
        return start, end
    call = ast.get_source_segment(text, calls[0])
    edits = [(*span(callbacks[0]), CALLBACK.rstrip()),
             (*span(calls[0]), call[:-1] + ", index_path=index_path)")]
    for start, end, replacement in sorted(edits, reverse=True):
        text = text[:start] + replacement + text[end:]
    ast.parse(text)
    return text


def prepare(source: Path, output: Path) -> dict:
    source = source.resolve()
    output = output.absolute()
    if output.exists():
        raise FileExistsError("Output already exists; use a new starter directory.")
    if output.resolve().is_relative_to(source):
        raise ValueError("Output must be outside the source starter.")
    runner = source / "submission_agent/runner.py"
    original = runner.read_bytes()
    adapted = adapt_runner(original.decode("utf-8")).encode("utf-8")
    for name in ("submission_agent", "scripts", "scoring", "data"):
        if not (source / name).is_dir():
            raise ValueError(f"Incomplete starter: missing {name}.")
    output.mkdir(parents=True)
    for name in ("submission_agent", "scripts", "scoring", "docs"):
        if (source / name).is_dir():
            shutil.copytree(source / name, output / name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for name in ("README.md", "Dockerfile", "Makefile", "requirements.txt", ".dockerignore", ".gitignore"):
        if (source / name).is_file():
            shutil.copy2(source / name, output / name)
    (output / "data").symlink_to(source / "data", target_is_directory=True)
    (output / "submission_agent/runner.py").write_bytes(adapted)
    manifest = {"source": str(source), "original_runner_sha256": hashlib.sha256(original).hexdigest(),
                "adapted_runner_sha256": hashlib.sha256(adapted).hexdigest(),
                "callback": "apt_agent.analyze_records", "read_only_index_context": True,
                "data_mode": "symlink", "container_ready": False}
    (output / "apt-adapter.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.source, args.output)))


if __name__ == "__main__":
    main()
