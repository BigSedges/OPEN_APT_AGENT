"""Compare a completed diagnostic case with labels, after prediction is saved."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from apt_agent.diagnostics import compare_records
from apt_agent.models import CaseResult


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", type=Path, required=True)
    parser.add_argument("--gold", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Output already exists; choose a new file.")
    case = CaseResult.model_validate_json(args.case.read_bytes())
    gold = json.loads(args.gold.read_text(encoding="utf-8"))
    ids = gold["physical_id_set"]
    if not isinstance(ids, list):
        parser.error("Label.json physical_id_set must be a list.")
    report = compare_records(case, ids)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report["counts"]))


if __name__ == "__main__":
    main()
