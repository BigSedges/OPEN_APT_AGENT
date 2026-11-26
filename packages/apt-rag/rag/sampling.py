"""Deterministic stratified sampling for human audit packets."""

from __future__ import annotations

import random
from collections import defaultdict
from typing import Any, Callable, Iterable, Mapping, Sequence


def source_family(chunk_id: str) -> str:
    prefix = str(chunk_id).split("/", 1)[0]
    if prefix.startswith("attack-pattern") or prefix.startswith("x-mitre"):
        return "attack"
    if prefix.startswith("car"):
        return "car"
    if prefix.startswith("ecar"):
        return "ecar"
    if prefix.startswith("sigma"):
        return "sigma"
    if prefix.startswith("sysmon"):
        return "sysmon"
    if prefix.startswith("windows"):
        return "windows"
    if prefix.startswith("zeek"):
        return "zeek"
    return prefix or "unknown"


def stratified_sample(
    rows: Sequence[Mapping[str, Any]],
    *,
    key: Callable[[Mapping[str, Any]], str],
    size: int,
    seed: int = 20261126,
) -> list[dict[str, Any]]:
    if size <= 0 or not rows:
        return []
    rng = random.Random(seed)
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[str(key(row))].append(dict(row))
    for group in groups.values():
        rng.shuffle(group)
    ordered_keys = sorted(groups)
    selected: list[dict[str, Any]] = []
    cursor = {group_key: 0 for group_key in ordered_keys}
    while len(selected) < min(size, len(rows)):
        progressed = False
        for group_key in ordered_keys:
            index = cursor[group_key]
            if index < len(groups[group_key]):
                selected.append(groups[group_key][index])
                cursor[group_key] += 1
                progressed = True
                if len(selected) >= min(size, len(rows)):
                    break
        if not progressed:
            break
    return selected
