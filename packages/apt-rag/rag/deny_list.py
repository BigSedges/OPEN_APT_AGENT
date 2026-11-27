"""Build a precise deny list from A-scene label IDs.

The competition ``Label.json`` files contain physical record IDs and storyline
mappings, not free-text answers.  Using those exact IDs plus full scene names
avoids false positives from generic actor names in ATT&CK group pages.

The deny list is an evaluation/security artifact.  Never ingest it into the
knowledge base.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_deny_list(train_dir: str | Path) -> dict[str, Any]:
    train_dir = Path(train_dir)
    if not train_dir.is_dir():
        raise FileNotFoundError(f"training directory not found: {train_dir}")

    scene_dirs = sorted(path for path in train_dir.iterdir() if path.is_dir())
    physical_ids: set[str] = set()
    scenario_names: list[str] = []
    per_scene: dict[str, Any] = {}
    label_hashes: dict[str, str] = {}

    for scene_dir in scene_dirs:
        label_path = scene_dir / "Label.json"
        if not label_path.is_file():
            continue
        data = json.loads(label_path.read_text(encoding="utf-8"))
        direct_ids = {str(item) for item in (data.get("physical_id_set") or [])}
        tactic_ids: set[str] = set()
        for values in (data.get("ta_physical_ids") or {}).values():
            tactic_ids.update(str(item) for item in values)
        storyline_ids: set[str] = set()
        for values in (data.get("storyline_attack_steps") or {}).values():
            storyline_ids.update(str(item) for item in values)
        union = direct_ids | tactic_ids | storyline_ids
        if not union:
            continue
        physical_ids.update(union)
        scenario_names.append(scene_dir.name)
        per_scene[scene_dir.name] = {
            "physical_id_set": len(direct_ids),
            "ta_physical_ids": len(tactic_ids),
            "storyline_attack_steps": len(storyline_ids),
            "union": len(union),
            "tactics": sorted((data.get("ta_physical_ids") or {}).keys()),
            "steps": sorted((data.get("storyline_attack_steps") or {}).keys()),
        }
        label_hashes[f"{scene_dir.name}/Label.json"] = _sha256(label_path)

    if not physical_ids:
        raise ValueError(f"no label IDs found under {train_dir}")

    terms = sorted(physical_ids) + scenario_names
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "train_dir": str(train_dir),
        "policy": "Evaluation/security artifact only; never ingest this file or A labels into the knowledge base.",
        "counts": {
            "physical_ids": len(physical_ids),
            "scenario_names": len(scenario_names),
            "terms": len(terms),
        },
        "groups": {
            "physical_ids": sorted(physical_ids),
            "scenario_names": scenario_names,
        },
        "terms": terms,
        "per_scene": per_scene,
        "label_sha256": label_hashes,
    }
