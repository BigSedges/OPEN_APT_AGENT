"""Rank fusion utilities.

The current corpus experiment showed that naive equal-weight RRF can be worse
than dense-only retrieval.  Therefore fusion is explicit, weighted, and always
reported next to the dense baseline.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence


class FusionError(ValueError):
    """Raised for invalid fusion parameters."""


def weighted_reciprocal_rank_fusion(
    rankings: Mapping[str, Sequence[str]],
    weights: Mapping[str, float] | None = None,
    *,
    k: int = 60,
    top_k: int | None = None,
) -> list[tuple[str, float]]:
    """Fuse ranked ID lists with weighted reciprocal-rank fusion.

    Ties are broken by ascending chunk ID for deterministic output.
    """

    if k <= 0:
        raise FusionError("rrf k must be positive")
    if top_k is not None and top_k < 0:
        raise FusionError("top_k must be non-negative")

    scores: dict[str, float] = {}
    for channel, ids in rankings.items():
        weight = 1.0 if weights is None else float(weights.get(channel, 0.0))
        if weight < 0:
            raise FusionError(f"negative fusion weight for channel {channel!r}")
        if weight == 0:
            continue
        for rank, chunk_id in enumerate(ids, start=1):
            identifier = str(chunk_id)
            scores[identifier] = scores.get(identifier, 0.0) + weight / (k + rank)

    fused = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    if top_k is not None:
        return fused[:top_k]
    return fused


rrf = weighted_reciprocal_rank_fusion
