"""Leakage scanning helpers.

The deny list must contain scenario-specific strings from the competition labels
(or other held-out answers).  Generic actor names are not automatically treated
as leakage because ATT&CK group descriptions can legitimately contain them.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence


def normalize_terms(terms: Iterable[str], *, min_length: int = 3) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for term in terms:
        text = str(term).strip()
        if len(text) < min_length:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        normalized.append(text)
    return normalized


def scan_chunks(
    chunks: Sequence[Mapping[str, Any]],
    terms: Iterable[str],
    *,
    max_hits: int = 200,
    context_chars: int = 80,
) -> list[dict[str, Any]]:
    """Return deny-list hits with a short context and stable provenance."""

    cleaned = normalize_terms(terms)
    if not cleaned:
        return []
    hits: list[dict[str, Any]] = []
    for chunk in chunks:
        text = str(chunk.get("text") or "")
        if not text:
            continue
        lower = text.lower()
        for term in cleaned:
            position = lower.find(term.lower())
            if position < 0:
                continue
            start = max(0, position - context_chars)
            end = min(len(text), position + len(term) + context_chars)
            hits.append(
                {
                    "chunk_id": chunk.get("chunk_id"),
                    "document_id": chunk.get("document_id"),
                    "source_family": chunk.get("source_family"),
                    "source_url": chunk.get("source_url"),
                    "term": term,
                    "position": position,
                    "context": text[start:end],
                }
            )
            if len(hits) >= max_hits:
                return hits
    return hits
