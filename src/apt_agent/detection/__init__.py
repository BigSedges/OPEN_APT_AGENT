"""Milestone M3 public API: multi-engine Sigma detection and rule coverage tracking."""

from __future__ import annotations

from apt_agent.detection.base import (
    ALL_LOG_FORMATS,
    AdapterOutput,
    DetectionResult,
    EngineAdapter,
    classify_event_format,
    make_hit_id,
    normalize_level,
    normalize_sigma_tags,
)
from apt_agent.detection.chainsaw import ChainsawAdapter
from apt_agent.detection.coordinator import DetectionCoordinator
from apt_agent.detection.hayabusa import HayabusaAdapter
from apt_agent.detection.rsigma import RSigmaAdapter, inspect_sigma_rules
from apt_agent.detection.zircolite import ZircoliteAdapter

__all__ = [
    "ALL_LOG_FORMATS",
    "AdapterOutput",
    "ChainsawAdapter",
    "DetectionCoordinator",
    "DetectionResult",
    "EngineAdapter",
    "HayabusaAdapter",
    "RSigmaAdapter",
    "ZircoliteAdapter",
    "classify_event_format",
    "inspect_sigma_rules",
    "make_hit_id",
    "normalize_level",
    "normalize_sigma_tags",
]
