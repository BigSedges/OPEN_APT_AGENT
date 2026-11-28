"""Run official offline/LLM controls with one frozen, credential-free configuration."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from time import perf_counter
from urllib.parse import urlsplit, urlunsplit

import yaml

from apt_agent.config import load_config
from apt_agent.models import Prediction


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()



def fingerprint(path: Path) -> dict:
    path = path.resolve()
    if not path.exists():
        return {"path": str(path), "exists": False}
    if path.is_file():
        return {"path": str(path), "sha256": sha256(path)}
    values = [(str(item.relative_to(path)), sha256(item)) for item in sorted(path.rglob("*")) if item.is_file()]
    return {"path": str(path), "files": len(values),
            "sha256": hashlib.sha256(json.dumps(values).encode()).hexdigest()}


def resources(cfg) -> dict:
    from apt_agent.detection.hayabusa import _resolve_hayabusa_config_args
    values = {}
    for name in type(cfg.engines).model_fields:
        engine = getattr(cfg.engines, name)
        if not engine.enabled:
            continue
        for field in ("bin_path", "rules_dir", "config_path", "mapping_path"):
            path = getattr(engine, field)
            if path is not None:
                values[name + "/" + field] = fingerprint(path)
        if name == "hayabusa" and engine.bin_path and engine.rules_dir:
            args, error = _resolve_hayabusa_config_args(engine.bin_path, engine.rules_dir, engine.config_path)
            if args:
                values[name + "/resolved_config"] = fingerprint(Path(args[1]))
    if cfg.rag.knowledge_path:
        values["knowledge"] = fingerprint(cfg.rag.knowledge_path)
    project = Path(__file__).resolve().parents[2]
    files = [*sorted((project / "src/apt_agent").rglob("*.py")),
             *sorted((project / "script/log_convert/lib").rglob("*.py")),
             *sorted((project / "script/evaluate").glob("*.py")),
             *sorted((project / "packages/apt-rag/apt_rag").rglob("*.py")),
             *sorted((project / "packages/apt-rag/tools/langgraph_rag").rglob("*.py")), project / "uv.lock"]
    values["source"] = {str(path.relative_to(project)): sha256(path) for path in files}
    return values


def audit_run(run: Path, train: Path, telemetry: Path) -> dict:
    if not (run / "predictions/done.txt").is_file():
        raise ValueError("Official runner did not create done.txt.")
    expected = sorted(path.name for path in train.iterdir() if (path / "Label_Index.json").is_file())
    found = sorted(path.name for path in (run / "predictions").iterdir() if path.is_dir())
    if found != expected:
        raise ValueError("Predictions do not cover exactly the supplied scenes.")
    reports = {}
    for path in telemetry.glob("*.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        if data["scene"] in reports:
            raise ValueError("Duplicate telemetry for a scene.")
        reports[data["scene"]] = data
    if sorted(reports) != expected:
        raise ValueError("Missing scene runtime telemetry.")
    scenes = []
    for name in expected:
        path = run / "predictions" / name / "predict.json"
        raw = json.loads(path.read_text(encoding="utf-8"))
        canonical = Prediction.model_validate(raw).model_dump(mode="json")
        if raw != canonical:
            raise ValueError("Prediction is not canonical or contains duplicates.")
        ids = set(json.loads((train / name / "Label_Index.json").read_text(encoding="utf-8")))
        physical = set(raw["physical_id_set"])
        if not physical <= ids or any(not set(values) <= physical for values in raw["ta_physical_ids"].values()):
            raise ValueError("Prediction contains out-of-scope evidence.")
        if reports[name]["physical_prediction_count"] != len(physical) or reports[name]["input_record_count"] != len(ids):
            raise ValueError("Runtime scope/count does not match the official prediction.")
        score_path = run / "scores" / name / "evaluation.json"
        score = json.loads(score_path.read_text(encoding="utf-8"))
        scenes.append({"scene": name, "runtime": reports[name], "evaluation": score,
                       "prediction_path": str(path), "prediction_sha256": sha256(path),
                       "score_path": str(score_path), "score_sha256": sha256(score_path),
                       "index_sha256": sha256(train / name / "Label_Index.json")})
    return {"done_txt": True, "scene_count": len(scenes), "scenes": scenes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--starter", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--modes", nargs="+", choices=("offline", "online"), default=["offline", "online"])
    args = parser.parse_args()
    if len(set(args.modes)) != len(args.modes):
        parser.error("Each mode may run only once.")
    if args.output.exists():
        parser.error("Output must be a new directory.")
    overrides = yaml.safe_load(args.policy.read_text(encoding="utf-8")) if args.policy else {}
    cfg = load_config(args.config, overrides=overrides)
    if "online" in args.modes and (not cfg.llm.model or not cfg.llm.base_url):
        parser.error("Online mode requires a configured endpoint and model.")
    args.output.mkdir(parents=True)
    # Credentials are supplied only through each child process environment.
    frozen = cfg.model_dump(mode="json")
    api_key = frozen["llm"].pop("api_key", None)
    frozen["llm"]["enabled"] = True
    frozen_path = args.output / "frozen-config.yaml"
    frozen_path.write_text(yaml.safe_dump(frozen, sort_keys=False), encoding="utf-8")
    frozen_path.chmod(0o600)
    redacted = cfg.redacted_dump()
    if redacted["llm"]["base_url"]:
        parts = urlsplit(redacted["llm"]["base_url"])
        host = parts.hostname or ""
        if parts.port:
            host += ":" + str(parts.port)
        redacted["llm"]["base_url"] = urlunsplit((parts.scheme, host, parts.path, "", ""))
    report = {"configuration": redacted, "frozen_config_sha256": sha256(frozen_path),
              "python": sys.version, "resources": resources(cfg), "runs": {}}
    starter = args.starter.resolve()
    if not (starter / "apt-adapter.json").is_file():
        raise ValueError("Prepare an instrumented starter first.")
    report["adapter"] = json.loads((starter / "apt-adapter.json").read_text())
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("APT_AGENT_", "OPENAI_"))}
    env.update(APT_AGENT_CONFIG=str(frozen_path.resolve()), PYTHONUNBUFFERED="1")
    if api_key:
        env["APT_AGENT_LLM__API_KEY"] = api_key
    for mode in args.modes:
        destination = args.output / mode
        telemetry = destination / "runtime"
        telemetry.mkdir(parents=True)
        output_root = starter / ".local-output"
        previous = set(output_root.glob("run-*")) if output_root.exists() else set()
        child_env = {**env, "APT_AGENT_LLM__ENABLED": "true" if mode == "online" else "false",
                     "APT_AGENT_RUN_REPORT_DIR": str(telemetry.resolve())}
        started = perf_counter()
        print(f"[{mode}] starting official three-scene evaluation", flush=True)
        with (destination / "runner.log").open("w", encoding="utf-8") as log:
            result = subprocess.run([sys.executable, "scripts/test_local.py"], cwd=starter,
                                    env=child_env, stdout=log, stderr=subprocess.STDOUT)
        new_runs = set(output_root.glob("run-*")) - previous
        row = {"exit_code": result.returncode, "elapsed_s": perf_counter() - started}
        if result.returncode != 0 or len(new_runs) != 1:
            report["runs"][mode] = row
            (args.output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
            raise RuntimeError(f"Official {mode} run failed; inspect its runner.log.")
        run = new_runs.pop()
        row.update(audit_run(run, starter / "data/train", telemetry))
        if resources(cfg) != report["resources"]:
            raise RuntimeError("A source, rule, mapping or knowledge asset changed during the control run.")
        calls = [call for scene in row["scenes"] for call in scene["runtime"]["llm_calls"] if call.get("requested")]
        row["llm_requests"] = len(calls)
        row["llm_applied"] = sum(call["outcome"] == "applied" for call in calls)
        row["llm_tokens"] = sum(call.get("tokens") or 0 for call in calls)
        row["llm_control_valid"] = not calls if mode == "offline" else bool(calls) and row["llm_applied"] == len(calls)
        report["runs"][mode] = row
        (args.output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[{mode}] exit=0 done.txt verified, model requests={len(calls)} applied={row['llm_applied']}", flush=True)
    if set(args.modes) == {"offline", "online"}:
        before = {row["scene"]: row for row in report["runs"]["offline"]["scenes"]}
        report["comparison"] = [{"scene": row["scene"],
            "offline_score_100": before[row["scene"]]["evaluation"]["overall_score_100"],
            "online_score_100": row["evaluation"]["overall_score_100"],
            "predictions_equal": before[row["scene"]]["prediction_sha256"] == row["prediction_sha256"]}
            for row in report["runs"]["online"]["scenes"]]
        (args.output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
