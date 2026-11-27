"""Frozen-reference COPOD and equal RRF60. Scores are not probabilities."""
import json
import math
from collections import Counter
from pathlib import Path

import numpy as np
from .statistics import FeatureReference, FrozenTails


class DataError(ValueError):
    pass


def rows(path):
    """The only readable data format: neutral, host-bound feature JSONL."""
    try:
        with Path(path).open(encoding="utf-8") as handle:
            for line in handle:
                row = json.loads(line)
                rid = row["physical_record_id"]
                cat, num = row["categories"], row["numbers"]
                if not isinstance(rid, str) or not rid or len(rid) > 256:
                    raise ValueError()
                if not isinstance(cat, list) or len(cat) != 7 or any(type(x) is not int or not 0 <= x < 2**64 for x in cat):
                    raise ValueError()
                if not isinstance(num, list) or len(num) != 16 or any(type(x) not in (int, float) or not math.isfinite(x) or abs(x) > 1e30 for x in num):
                    raise ValueError()
                if not isinstance(row.get("entity", ""), str):
                    raise ValueError()
                if not isinstance(row.get("host"), str) or not isinstance(row.get("source_type"), str):
                    raise ValueError()
                if row.get("locator") is not None:
                    loc = row["locator"]
                    if not isinstance(loc, dict) or set(loc) != {"filepath", "linenumber"} or not isinstance(loc["filepath"], str) or type(loc["linenumber"]) is not int or loc["linenumber"] < 1:
                        raise ValueError()
                yield row
    except (OSError, ValueError, KeyError, TypeError, OverflowError):
        raise DataError("Invalid or unreadable feature JSONL resource.") from None


def rank(records, references, fusion):
    records, references = Path(records).resolve(), Path(references).resolve()
    if not records.is_file() or not references.is_dir():
        raise DataError("records must be a file and references a directory.")
    files = sorted(references.glob("*.jsonl"))
    if not files or any(p.resolve() == records for p in files):
        raise DataError("Bind independent reference JSONL files, excluding records.")
    ids, cats, nums, entities, locators = [], [], [], [], []
    for row in rows(records):
        ids.append(row["physical_record_id"])
        cats.append(row["categories"])
        nums.append(row["numbers"])
        entities.append(row.get("entity", ""))
        locators.append(row.get("locator"))
    if len(ids) != len(set(ids)):
        raise DataError("Duplicate physical_record_id in records.")
    if not ids:
        return [], {"records": 0, "copod_scored": 0, "entity_scored": 0, "candidate_pool": 0, "reference_records": 0}
    sampled_cat, sampled_num, counts = [], [], Counter()
    reference_count = 0
    for i, path in enumerate(files):
        n = sum(1 for _ in rows(path))
        reference_count += n
        selection = set(np.sort(np.random.default_rng(43+i).choice(n, 60000, replace=False)).tolist()) if n > 60000 else None
        for j, row in enumerate(rows(path)):
            if selection is None or j in selection:
                sampled_cat.append(row["categories"])
                sampled_num.append(row["numbers"])
            if fusion and row.get("entity"):
                counts[row["entity"]] += 1
    if not sampled_cat:
        raise DataError("Reference resources contain no records.")
    cat = np.asarray(sampled_cat, dtype="uint64")
    num = np.asarray(sampled_num, dtype="float32")
    ref = FeatureReference(cat, num)
    model = FrozenTails("copod-frozen")
    model.fit(ref.transform(cat, num))
    a = model.decision_function(ref.transform(np.asarray(cats, dtype="uint64"), np.asarray(nums, dtype="float32")))
    if not np.isfinite(a).all():
        raise DataError("Nonfinite COPOD score.")
    tie = np.random.default_rng(11).permutation(len(ids))
    order = np.lexsort((tie, -a))
    b = np.array([-np.log1p(counts[e]) if e else -np.inf for e in entities])
    rrf = {}
    if fusion:
        other = np.lexsort((tie, -b))
        other = other[np.isfinite(b[other])]
        for branch in (order[:10000], other[:10000]):
            for position, index in enumerate(branch, 1):
                rrf[int(index)] = rrf.get(int(index), 0.0) + 1/(60+position)
        order = sorted(rrf, key=lambda index: (-rrf[index], tie[index]))
    ranking = []
    for position, index in enumerate(order, 1):
        ranking.append({"physical_record_id": ids[index], "rank": position,
                        "score": float(rrf[index] if fusion else a[index]),
                        "copod_score": float(a[index]),
                        "entity_score": float(b[index]) if fusion and np.isfinite(b[index]) else None,
                        "locator": locators[index]})
    return ranking, {"records": len(ids), "copod_scored": len(ids), "entity_scored": sum(bool(e) for e in entities) if fusion else 0,
                     "candidate_pool": len(ranking), "reference_records": reference_count}
