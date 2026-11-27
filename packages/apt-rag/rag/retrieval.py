"""Dense and hybrid retrieval over the frozen BGE-M3 index."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, Sequence

import numpy as np

from .bm25 import BM25Index, ids_sha256
from .config import RagConfig
from .fusion import FusionError, weighted_reciprocal_rank_fusion
from .store import KnowledgeStore
from .types import RetrievalFilters


class RetrievalError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class QueryEncoder(Protocol):
    def encode(self, query: str) -> np.ndarray: ...


class SentenceTransformerEncoder:
    """Local BGE-M3 query encoder.

    Loading is lazy with respect to the rest of the package: importing
    ``rag.retrieval`` does not import torch or sentence-transformers.
    """

    def __init__(
        self,
        model_path: str | Path,
        *,
        device: str = "cuda",
        offline: bool = True,
        max_seq_length: int = 1024,
    ) -> None:
        model_path = Path(model_path)
        if not model_path.is_dir():
            raise RetrievalError("model_missing", f"embedding model directory not found: {model_path}")
        if offline:
            os.environ["HF_HUB_OFFLINE"] = "1"
            os.environ["TRANSFORMERS_OFFLINE"] = "1"

        import torch
        from sentence_transformers import SentenceTransformer

        self.device = device
        try:
            if device.startswith("cuda"):
                self._model = SentenceTransformer(
                    str(model_path),
                    local_files_only=True,
                    device=device,
                    model_kwargs={"torch_dtype": torch.float16},
                )
            else:
                self._model = SentenceTransformer(
                    str(model_path),
                    local_files_only=True,
                    device=device,
                )
        except Exception as exc:  # noqa: BLE001 - CUDA may be unavailable at runtime
            if device.startswith("cuda"):
                try:
                    self._model = SentenceTransformer(
                        str(model_path),
                        local_files_only=True,
                        device="cpu",
                    )
                except Exception as cpu_exc:  # noqa: BLE001
                    raise RetrievalError(
                        "model_load_failed",
                        f"cannot load embedding model on CUDA or CPU: {type(cpu_exc).__name__}: {cpu_exc}",
                    ) from cpu_exc
                self.device = "cpu"
            else:
                raise RetrievalError(
                    "model_load_failed",
                    f"cannot load embedding model: {type(exc).__name__}: {exc}",
                ) from exc

        self._model.max_seq_length = int(max_seq_length)

    def encode(self, query: str) -> np.ndarray:
        text = str(query or "").strip()
        if not text:
            raise RetrievalError("empty_query", "query must be non-empty")
        try:
            raw = self._model.encode(
                [text],
                normalize_embeddings=False,
                show_progress_bar=False,
            )[0]
        except Exception as exc:  # noqa: BLE001
            raise RetrievalError(
                "encode_failed",
                f"query encoding failed: {type(exc).__name__}: {exc}",
            ) from exc
        vector = np.asarray(raw, dtype=np.float32)
        if vector.ndim != 1:
            raise RetrievalError("invalid_embedding", "query encoder returned a non-vector result")
        norm = float(np.linalg.norm(vector))
        if not np.isfinite(norm) or norm <= 0.0:
            raise RetrievalError("invalid_embedding", "query encoder returned a zero or non-finite vector")
        return vector / norm


@dataclass
class RetrievalOutput:
    hits: list[tuple[str, float]]
    warnings: list[str] = field(default_factory=list)
    mode: str = "dense"
    latency_ms: float = 0.0


class DenseRetriever:
    def __init__(
        self,
        store: KnowledgeStore,
        encoder: QueryEncoder,
        *,
        candidate_depth: int = 50,
    ) -> None:
        self.store = store
        self.encoder = encoder
        self.candidate_depth = max(1, int(candidate_depth))

    def search(
        self,
        query: str,
        *,
        top_k: int = 5,
        filters: RetrievalFilters | None = None,
        candidate_depth: int | None = None,
    ) -> RetrievalOutput:
        started = time.perf_counter()
        text = str(query or "").strip()
        if not text:
            raise RetrievalError("empty_query", "query must be non-empty")
        if top_k < 1:
            raise RetrievalError("invalid_top_k", "top_k must be positive")

        query_vector = self.encoder.encode(text)
        if query_vector.shape[0] != self.store.dimensions:
            raise RetrievalError(
                "dimension_mismatch",
                f"query dimension {query_vector.shape[0]} != index dimension {self.store.dimensions}",
            )

        indices = self.store.filter_indices(filters)
        if indices.size == 0:
            return RetrievalOutput([], ["no_candidates_after_filter"], "dense", (time.perf_counter() - started) * 1000)

        scores = self.store.vectors[indices] @ query_vector
        ranked = [
            (self.store.ids[int(row)], float(score))
            for row, score in zip(indices, scores)
        ]
        ranked.sort(key=lambda item: (-item[1], item[0]))
        depth = max(int(candidate_depth or self.candidate_depth), int(top_k))
        return RetrievalOutput(
            ranked[:depth],
            [],
            "dense",
            (time.perf_counter() - started) * 1000,
        )


class BM25Retriever:
    """Persistent BM25 retrieval aligned with the frozen corpus row order."""

    def __init__(self, store: KnowledgeStore, index: BM25Index) -> None:
        self.store = store
        self.index = index

    @classmethod
    def load(
        cls,
        store: KnowledgeStore,
        pointer_path: str | Path,
        *,
        verify_hashes: bool = True,
    ) -> "BM25Retriever":
        pointer_path = Path(pointer_path)
        try:
            pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
            directory = (pointer_path.parent / pointer["directory"]).resolve()
            manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise RetrievalError("bm25_missing", f"BM25 artifact is missing: {exc.filename}") from exc
        except (KeyError, json.JSONDecodeError, ValueError) as exc:
            raise RetrievalError("bm25_manifest_invalid", str(exc)) from exc

        expected_corpus = (store.manifest.get("config") or {}).get("corpus_sha256")
        if manifest.get("corpus_sha256") != expected_corpus:
            raise RetrievalError(
                "bm25_corpus_mismatch",
                "BM25 index was built from a different corpus snapshot",
            )
        if manifest.get("ids_sha256") != ids_sha256(store.ids):
            raise RetrievalError(
                "bm25_ids_mismatch",
                "BM25 index row IDs do not match the loaded corpus",
            )
        try:
            index = BM25Index.load(directory, verify_hashes=verify_hashes)
        except Exception as exc:  # noqa: BLE001 - surface a stable retrieval error
            raise RetrievalError(
                "bm25_load_failed",
                f"{type(exc).__name__}: {exc}",
            ) from exc
        if index.rows != store.rows:
            raise RetrievalError(
                "bm25_rows_mismatch",
                f"BM25 rows {index.rows} != corpus rows {store.rows}",
            )
        return cls(store, index)

    def search(
        self,
        query: str,
        *,
        top_k: int = 5,
        filters: RetrievalFilters | None = None,
        candidate_depth: int | None = None,
    ) -> RetrievalOutput:
        started = time.perf_counter()
        text = str(query or "").strip()
        if not text:
            raise RetrievalError("empty_query", "query must be non-empty")
        if top_k < 1:
            raise RetrievalError("invalid_top_k", "top_k must be positive")

        indices = self.store.filter_indices(filters)
        if indices.size == 0:
            return RetrievalOutput(
                [],
                ["no_candidates_after_filter"],
                "bm25",
                (time.perf_counter() - started) * 1000,
            )
        depth = max(
            int(candidate_depth) if candidate_depth is not None else int(top_k),
            int(top_k),
        )
        ranked = self.index.search(
            text,
            candidate_indices=indices,
            top_k=depth,
        )
        hits = [(self.store.ids[row], float(score)) for row, score in ranked]
        hits.sort(key=lambda item: (-item[1], item[0]))
        return RetrievalOutput(
            hits,
            [],
            "bm25",
            (time.perf_counter() - started) * 1000,
        )


class HybridRetriever:
    """Weighted dense/BM25 fusion with graceful dense-only fallback."""

    def __init__(
        self,
        dense: DenseRetriever,
        bm25: object | None = None,
        *,
        rrf_k: int = 60,
        weights: dict[str, float] | None = None,
    ) -> None:
        self.dense = dense
        self.bm25 = bm25
        self.rrf_k = int(rrf_k)
        self.weights = weights or {"dense": 0.7, "bm25": 0.3}

    def search(
        self,
        query: str,
        *,
        top_k: int = 5,
        filters: RetrievalFilters | None = None,
        candidate_depth: int | None = None,
    ) -> RetrievalOutput:
        started = time.perf_counter()
        depth = max(int(candidate_depth or self.dense.candidate_depth), int(top_k))
        dense_output = self.dense.search(
            query,
            top_k=top_k,
            filters=filters,
            candidate_depth=depth,
        )
        warnings = list(dense_output.warnings)

        if self.bm25 is None:
            warnings.append("bm25_unavailable_dense_only")
            return RetrievalOutput(
                dense_output.hits[:depth],
                warnings,
                "dense_fallback",
                (time.perf_counter() - started) * 1000,
            )

        try:
            bm25_output = self.bm25.search(
                query,
                top_k=top_k,
                filters=filters,
                candidate_depth=depth,
            )
        except RetrievalError as exc:
            warnings.append(f"bm25_failed:{exc.code}")
            return RetrievalOutput(
                dense_output.hits[:depth],
                warnings,
                "dense_fallback",
                (time.perf_counter() - started) * 1000,
            )

        warnings.extend(bm25_output.warnings)
        rankings = {
            "dense": [chunk_id for chunk_id, _ in dense_output.hits],
            "bm25": [chunk_id for chunk_id, _ in bm25_output.hits],
        }
        try:
            fused = weighted_reciprocal_rank_fusion(
                rankings,
                self.weights,
                k=self.rrf_k,
                top_k=depth,
            )
        except FusionError as exc:
            raise RetrievalError("fusion_failed", str(exc)) from exc
        if not bm25_output.hits:
            warnings.append("bm25_empty")
        return RetrievalOutput(
            fused,
            warnings,
            "hybrid",
            (time.perf_counter() - started) * 1000,
        )


def build_retriever(
    config: RagConfig,
    store: KnowledgeStore,
    *,
    encoder: QueryEncoder | None = None,
    bm25: object | None = None,
):
    if encoder is None:
        encoder = SentenceTransformerEncoder(
            config.model_path,
            device=config.device,
            offline=config.offline,
            max_seq_length=config.max_seq_length,
        )
    dense = DenseRetriever(store, encoder, candidate_depth=config.dense_candidates)
    if config.mode == "dense":
        return dense
    if bm25 is None and config.bm25_pointer is not None:
        try:
            bm25 = BM25Retriever.load(store, config.bm25_pointer)
        except (RetrievalError, FileNotFoundError, ValueError):
            bm25 = None
    return HybridRetriever(
        dense,
        bm25,
        rrf_k=config.fusion.rrf_k,
        weights=config.fusion.weights,
    )
