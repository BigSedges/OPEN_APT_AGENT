"""Milestone M2 public API: raw evidence ingestion, Label_Index loading, and normalization."""

from __future__ import annotations

from apt_agent.ingestion.normalizer import (
    NormalizationResult,
    Normalizer,
    event_to_parsed_dict,
    format_for_chainsaw,
    format_for_hayabusa,
    format_for_rsigma,
    format_for_zircolite,
)
from apt_agent.ingestion.store import (
    RawEvidenceStore,
    detect_indexed_log_format,
    ingest_records,
    load_indexed_records,
    load_label_index,
)

__all__ = [
    "NormalizationResult",
    "Normalizer",
    "RawEvidenceStore",
    "detect_indexed_log_format",
    "event_to_parsed_dict",
    "format_for_chainsaw",
    "format_for_hayabusa",
    "format_for_rsigma",
    "format_for_zircolite",
    "ingest_records",
    "load_indexed_records",
    "load_label_index",
]
