"""Retrieval metrics for graded 0/1/2 qrels."""

from __future__ import annotations

import math
import random
from statistics import NormalDist
from typing import Collection, Mapping, Sequence


def infer_platform_filter(text: str) -> tuple[str, ...] | None:
    """Fixed, label-free metadata rule used by the hybrid+metadata baseline."""

    lower = str(text or "").lower()
    if "windows" in lower or "sysmon" in lower:
        return ("Windows",)
    if "linux" in lower:
        return ("Linux",)
    if "macos" in lower or "mac os" in lower:
        return ("macOS",)
    return None


def bootstrap_ci(
    values: Sequence[float],
    *,
    iterations: int = 1000,
    seed: int = 20261126,
    confidence: float = 0.95,
) -> dict[str, float | int] | None:
    clean = [float(value) for value in values if value is not None]
    if not clean:
        return None
    rng = random.Random(seed)
    means = []
    count = len(clean)
    for _ in range(iterations):
        means.append(sum(rng.choice(clean) for _ in range(count)) / count)
    means.sort()
    alpha = (1.0 - confidence) / 2.0
    low = means[int(alpha * (len(means) - 1))]
    high = means[int((1.0 - alpha) * (len(means) - 1))]
    return {
        "mean": sum(clean) / len(clean),
        "ci_low": low,
        "ci_high": high,
        "n": len(clean),
        "iterations": iterations,
    }


def paired_bootstrap_diff(
    a_values: Sequence[float],
    b_values: Sequence[float],
    *,
    iterations: int = 10000,
    seed: int = 20261126,
    confidence: float = 0.95,
) -> dict[str, float | int] | None:
    """Bootstrap the mean paired difference ``a - b``.

    This is deliberately separate from :func:`bootstrap_ci`, which bootstraps
    a single sample mean. Callers must pass one value per query in the same
    order; dropping a pair must happen before this function, not inside it.
    """

    if len(a_values) != len(b_values):
        raise ValueError("paired samples must have equal length")
    diffs = [
        float(a) - float(b)
        for a, b in zip(a_values, b_values, strict=True)
        if a is not None and b is not None
    ]
    if not diffs:
        return None
    rng = random.Random(seed)
    count = len(diffs)
    means = []
    for _ in range(iterations):
        means.append(sum(diffs[rng.randrange(count)] for _ in range(count)) / count)
    means.sort()
    alpha = (1.0 - confidence) / 2.0
    low = means[int(alpha * (len(means) - 1))]
    high = means[int((1.0 - alpha) * (len(means) - 1))]
    return {
        "mean_diff": sum(diffs) / count,
        "ci_low": low,
        "ci_high": high,
        "n": count,
        "iterations": iterations,
        "wins": sum(1 for value in diffs if value > 0),
        "losses": sum(1 for value in diffs if value < 0),
        "ties": sum(1 for value in diffs if value == 0),
    }


def wilson_ci(
    successes: int,
    n: int,
    *,
    confidence: float = 0.95,
) -> dict[str, float | int]:
    """Wilson score interval for a binomial proportion.

    Unlike a normal approximation, this is defined at 0/n and n/n, which is
    the common case for retrieval methods that return no result.
    """

    if n < 0:
        raise ValueError("n must be non-negative")
    if successes < 0 or successes > n:
        raise ValueError("successes must be between 0 and n")
    if n == 0:
        return {"proportion": 0.0, "ci_low": 0.0, "ci_high": 1.0, "n": 0, "successes": 0}
    z = NormalDist().inv_cdf(1.0 - (1.0 - confidence) / 2.0)
    proportion = successes / n
    denominator = 1.0 + z * z / n
    centre = (proportion + z * z / (2.0 * n)) / denominator
    margin = (
        z
        * math.sqrt((proportion * (1.0 - proportion) + z * z / (4.0 * n)) / n)
        / denominator
    )
    return {
        "proportion": proportion,
        "ci_low": max(0.0, centre - margin),
        "ci_high": min(1.0, centre + margin),
        "n": n,
        "successes": successes,
    }


def unjudged_at_k(
    ranking: Sequence[str],
    judged: Collection[str],
    k: int,
) -> dict[str, float | int]:
    """Count unjudged documents in the top-k without treating them as 0."""

    top = list(ranking[: max(0, k)])
    judged_set = set(judged)
    unjudged = sum(1 for doc in top if doc not in judged_set)
    return {
        "k": max(0, k),
        "returned": len(top),
        "judged": len(top) - unjudged,
        "unjudged": unjudged,
        "unjudged_ratio": (unjudged / len(top)) if top else 0.0,
    }


def recall_at_k(
    ranking: Sequence[str],
    grades: Mapping[str, int],
    k: int,
    *,
    threshold: int = 2,
) -> float | None:
    relevant = {doc for doc, grade in grades.items() if grade >= threshold}
    if not relevant:
        return None
    return len(relevant & set(ranking[:k])) / len(relevant)


def precision_at_k(
    ranking: Sequence[str],
    grades: Mapping[str, int],
    k: int,
    *,
    threshold: int = 2,
) -> float:
    if k <= 0:
        return 0.0
    relevant = {doc for doc, grade in grades.items() if grade >= threshold}
    return len(relevant & set(ranking[:k])) / k


def hit_rate_at_k(
    ranking: Sequence[str],
    grades: Mapping[str, int],
    k: int,
    *,
    threshold: int = 2,
) -> float:
    relevant = {doc for doc, grade in grades.items() if grade >= threshold}
    return 1.0 if relevant & set(ranking[:k]) else 0.0


def mrr_at_k(
    ranking: Sequence[str],
    grades: Mapping[str, int],
    k: int,
    *,
    threshold: int = 2,
) -> float:
    relevant = {doc for doc, grade in grades.items() if grade >= threshold}
    for rank, doc in enumerate(ranking[:k], start=1):
        if doc in relevant:
            return 1.0 / rank
    return 0.0


def ndcg_at_k(
    ranking: Sequence[str],
    grades: Mapping[str, int],
    k: int,
) -> float:
    def gain(grade: int) -> float:
        return float((2 ** int(grade)) - 1)

    dcg = 0.0
    for rank, doc in enumerate(ranking[:k], start=1):
        if doc in grades:
            dcg += gain(grades[doc]) / math.log2(rank + 1)
    ideal = sorted((gain(grade) for grade in grades.values() if grade > 0), reverse=True)[:k]
    idcg = sum(value / math.log2(index + 2) for index, value in enumerate(ideal))
    return dcg / idcg if idcg > 0 else 0.0


def evaluate_ranking(
    ranking: Sequence[str],
    grades: Mapping[str, int],
    k: int,
    *,
    threshold: int = 2,
) -> dict[str, float | None]:
    return {
        f"recall@{k}": recall_at_k(ranking, grades, k, threshold=threshold),
        f"precision@{k}": precision_at_k(ranking, grades, k, threshold=threshold),
        f"hit_rate@{k}": hit_rate_at_k(ranking, grades, k, threshold=threshold),
        f"mrr@{k}": mrr_at_k(ranking, grades, k, threshold=threshold),
        f"ndcg@{k}": ndcg_at_k(ranking, grades, k),
    }
