"""Persist prediction and record diagnostics; deliberately never reads Label.json."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from time import perf_counter

from pydantic_core import to_jsonable_python

from apt_agent.config import load_config
from apt_agent.ingestion import load_indexed_records
from apt_agent.models import Locator, RunContext
from apt_agent.pipeline import investigate_records, to_prediction


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scene", type=Path)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True,
                        help="New output directory; existing directories are rejected")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    config = load_config(args.config)
    index_path = args.scene / "Label_Index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    locators = {pid: Locator.model_validate(value) for pid, value in index.items()}
    started = perf_counter()
    case = investigate_records(load_indexed_records(index_path, args.scene / "data"),
                               config=config, valid_physical_ids=set(index), locator_map=locators)
    ctx = RunContext(case_id=case.case_id, run_id=case.run_id, valid_physical_ids=frozenset(index))
    prediction = to_prediction(ctx, case)
    # Prediction is saved first; labels must be compared only in a separate step.
    (args.output / "predict.json").write_text(json.dumps(prediction, ensure_ascii=False), encoding="utf-8")
    # Serialize references to fields, avoiding a second complete case dictionary
    # and a full-size JSON string in memory at the same time.
    with (args.output / "case.json").open("w", encoding="utf-8") as output:
        json.dump({name: getattr(case, name) for name in type(case).model_fields},
                  output, default=to_jsonable_python, ensure_ascii=False, indent=2)
    summary = {"case_id": case.case_id, "run_id": case.run_id,
               "elapsed_s": perf_counter() - started, "stop_reason": case.stop_reason,
               "input_records": len(index), "predicted_records": len(prediction["physical_id_set"]),
               "snapshots": case.snapshot_refs, "stage_timings_s": case.stage_timings_s,
               "llm_enabled": config.llm.enabled}
    (args.output / "runtime.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
