"""Inter-judge agreement metrics for 0/1/2 relevance labels."""

from __future__ import annotations

from collections import Counter
from typing import Iterable, Mapping, Sequence


def _pairs(labels_a: Sequence[int], labels_b: Sequence[int]) -> list[tuple[int, int]]:
    if len(labels_a) != len(labels_b):
        raise ValueError("label sequences must have the same length")
    return [(int(a), int(b)) for a, b in zip(labels_a, labels_b)]


def confusion_matrix(labels_a: Sequence[int], labels_b: Sequence[int]) -> dict[str, int]:
    counts = Counter(_pairs(labels_a, labels_b))
    return {f"{a}->{b}": count for (a, b), count in sorted(counts.items())}


def exact_agreement(labels_a: Sequence[int], labels_b: Sequence[int]) -> float | None:
    pairs = _pairs(labels_a, labels_b)
    if not pairs:
        return None
    return sum(a == b for a, b in pairs) / len(pairs)


def cohen_kappa(labels_a: Sequence[int], labels_b: Sequence[int]) -> float | None:
    pairs = _pairs(labels_a, labels_b)
    if not pairs:
        return None
    count = len(pairs)
    observed = sum(a == b for a, b in pairs) / count
    expected = sum(
        (sum(a == value for a, _ in pairs) / count)
        * (sum(b == value for _, b in pairs) / count)
        for value in (0, 1, 2)
    )
    if expected >= 1.0:
        return 1.0
    return (observed - expected) / (1.0 - expected)


def quadratic_weighted_kappa(labels_a: Sequence[int], labels_b: Sequence[int]) -> float | None:
    pairs = _pairs(labels_a, labels_b)
    if not pairs:
        return None
    count = len(pairs)
    observed = [[0.0] * 3 for _ in range(3)]
    row = [0.0] * 3
    column = [0.0] * 3
    for a, b in pairs:
        observed[a][b] += 1.0 / count
        row[a] += 1.0 / count
        column[b] += 1.0 / count
    numerator = 0.0
    denominator = 0.0
    for i in range(3):
        for j in range(3):
            weight = ((i - j) ** 2) / 4.0
            numerator += weight * observed[i][j]
            denominator += weight * row[i] * column[j]
    if denominator == 0:
        return 1.0
    return 1.0 - numerator / denominator


def compare_label_maps(
    labels_a: Mapping[tuple[str, str], int],
    labels_b: Mapping[tuple[str, str], int],
) -> dict:
    common = sorted(set(labels_a) & set(labels_b))
    a_values = [labels_a[key] for key in common]
    b_values = [labels_b[key] for key in common]
    return {
        "common": len(common),
        "only_a": len(set(labels_a) - set(labels_b)),
        "only_b": len(set(labels_b) - set(labels_a)),
        "exact_agreement": exact_agreement(a_values, b_values),
        "cohen_kappa": cohen_kappa(a_values, b_values),
        "quadratic_weighted_kappa": quadratic_weighted_kappa(a_values, b_values),
        "confusion": confusion_matrix(a_values, b_values),
        "label_distribution_a": dict(sorted(Counter(a_values).items())),
        "label_distribution_b": dict(sorted(Counter(b_values).items())),
    }
