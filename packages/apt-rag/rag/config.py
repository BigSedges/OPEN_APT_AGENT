"""Configuration loading for the RAG service."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class FusionSettings:
    method: str = "weighted_rrf"
    rrf_k: int = 60
    weights: dict[str, float] = field(default_factory=lambda: {"dense": 0.7, "bm25": 0.3})


@dataclass(frozen=True)
class RagConfig:
    project_root: Path
    corpus_path: Path
    index_pointer: Path
    model_path: Path
    metadata_path: Path | None
    sources_manifest: Path
    bm25_pointer: Path | None
    mode: str
    top_k: int
    max_top_k: int
    dense_candidates: int
    bm25_candidates: int
    max_context_chars: int
    max_chunks_per_document: int
    rerank_enabled: bool
    rerank_model: Path | None
    device: str
    offline: bool
    max_seq_length: int
    fusion: FusionSettings
    bm25_k1: float
    bm25_b: float


def _resolve(root: Path, value: str | None) -> Path | None:
    if value is None:
        return None
    path = Path(value)
    if path.is_absolute():
        return path
    return (root / path).resolve()


def load_config(path: str | Path) -> RagConfig:
    config_path = Path(path)
    if not config_path.is_absolute():
        config_path = (PROJECT_ROOT / config_path).resolve()
    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # noqa: BLE001 - surface a stable configuration error
        raise ValueError(f"cannot read RAG config {config_path}: {exc}") from exc

    root_value = data.get("project_root") or str(PROJECT_ROOT)
    root = Path(root_value)
    if not root.is_absolute():
        root = (PROJECT_ROOT / root).resolve()

    paths = data.get("paths") or {}
    retrieval = data.get("retrieval") or {}
    fusion_data = retrieval.get("fusion") or {}
    rerank_data = retrieval.get("rerank") or {}
    bm25_data = retrieval.get("bm25") or {}
    model_data = data.get("model") or {}

    weights = fusion_data.get("weights") or {"dense": 0.7, "bm25": 0.3}
    weights = {str(name): float(value) for name, value in weights.items()}
    if not weights or any(value < 0 for value in weights.values()) or sum(weights.values()) <= 0:
        raise ValueError("fusion.weights must be non-negative and sum to a positive value")

    mode = str(retrieval.get("mode", "dense")).lower()
    if mode not in {"dense", "hybrid"}:
        raise ValueError("retrieval.mode must be 'dense' or 'hybrid'")

    top_k = int(retrieval.get("top_k", 5))
    max_top_k = int(retrieval.get("max_top_k", 20))
    if top_k < 1 or max_top_k < top_k:
        raise ValueError("retrieval.top_k must be >= 1 and <= retrieval.max_top_k")

    corpus_path = _resolve(root, paths.get("corpus"))
    index_pointer = _resolve(root, paths.get("index_pointer"))
    model_path = _resolve(root, paths.get("model"))
    if corpus_path is None or index_pointer is None or model_path is None:
        raise ValueError("paths.corpus, paths.index_pointer and paths.model are required")

    metadata_path = _resolve(root, paths.get("metadata"))
    sources_manifest = _resolve(root, paths.get("sources_manifest"))
    if sources_manifest is None:
        sources_manifest = (root / "knowledge_base" / "metadata" / "sources.json").resolve()
    bm25_pointer = _resolve(root, paths.get("bm25_pointer"))
    bm25_k1 = float(bm25_data.get("k1", 1.5))
    bm25_b = float(bm25_data.get("b", 0.75))
    if bm25_k1 <= 0 or not 0 <= bm25_b <= 1:
        raise ValueError("retrieval.bm25 requires k1 > 0 and 0 <= b <= 1")

    return RagConfig(
        project_root=root,
        corpus_path=corpus_path,
        index_pointer=index_pointer,
        model_path=model_path,
        metadata_path=metadata_path,
        sources_manifest=sources_manifest,
        bm25_pointer=bm25_pointer,
        mode=mode,
        top_k=top_k,
        max_top_k=max_top_k,
        dense_candidates=int(retrieval.get("dense_candidates", 50)),
        bm25_candidates=int(retrieval.get("bm25_candidates", 50)),
        max_context_chars=int(retrieval.get("max_context_chars", 6000)),
        max_chunks_per_document=int(retrieval.get("max_chunks_per_document", 2)),
        rerank_enabled=bool(rerank_data.get("enabled", False)),
        rerank_model=_resolve(root, rerank_data.get("model")),
        device=str(model_data.get("device", "cuda")),
        offline=bool(model_data.get("offline", True)),
        max_seq_length=int(model_data.get("max_seq_length", 1024)),
        fusion=FusionSettings(
            method=str(fusion_data.get("method", "weighted_rrf")),
            rrf_k=int(fusion_data.get("rrf_k", 60)),
            weights=weights,
        ),
        bm25_k1=bm25_k1,
        bm25_b=bm25_b,
    )
