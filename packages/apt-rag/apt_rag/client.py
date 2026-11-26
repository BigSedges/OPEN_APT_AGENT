"""Stable public client for the local APT RAG knowledge index.

The implementation intentionally delegates retrieval to :mod:`rag`; this module
adds a small, versioned facade plus snapshot metadata and explicit failure
states.  No external service, competition data, or PostgreSQL is required.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rag.config import RagConfig, load_config
from rag.retrieval import (
    BM25Retriever,
    DenseRetriever,
    HybridRetriever,
    RetrievalError,
    SentenceTransformerEncoder,
)
from rag.store import KnowledgeStore, StoreError
from rag.tools import RagTools


class RagClientError(RuntimeError):
    """Configuration or asset-loading error raised before a search starts."""

    def __init__(self, code: str, message: str, *, cause: Exception | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.cause = cause


@dataclass
class RagResult:
    """JSON-friendly result returned by :meth:`RagClient.search`."""

    query: str
    results: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: dict[str, Any] | None = None
    empty: bool = False
    dedup_count: int = 0
    context_chars: int = 0
    mode: str = "dense"
    requested_mode: str = "dense"
    snapshot_id: str = ""
    snapshot: dict[str, Any] = field(default_factory=dict)
    score_semantics: str = "cosine"

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "results": list(self.results),
            "warnings": list(self.warnings),
            "error": self.error,
            "empty": self.empty,
            "dedup_count": self.dedup_count,
            "context_chars": self.context_chars,
            "mode": self.mode,
            "requested_mode": self.requested_mode,
            "snapshot_id": self.snapshot_id,
            "snapshot": dict(self.snapshot),
            "score_semantics": self.score_semantics,
        }


def _score_semantics(mode: str) -> str:
    if mode == "bm25":
        return "bm25"
    if mode == "hybrid":
        return "rrf"
    # dense and dense_fallback both expose cosine scores from the dense path.
    return "cosine"


def _resolve_config_path(value: str | Path) -> Path:
    path = Path(value)
    if not path.is_absolute():
        candidate = (Path.cwd() / path).resolve()
        if candidate.exists():
            return candidate
    return path


def _snapshot(store: KnowledgeStore, config: RagConfig) -> tuple[str, dict[str, Any]]:
    manifest_config = store.manifest.get("config") or {}
    manifest_canonical = json.dumps(store.manifest, ensure_ascii=False, sort_keys=True, default=str)
    payload = {
        "corpus_sha256": manifest_config.get("corpus_sha256") or store.manifest.get("corpus_sha256"),
        "vectors_sha256": store.manifest.get("vectors_sha256"),
        "ids_sha256": store.manifest.get("ids_sha256"),
        "manifest_sha256": hashlib.sha256(manifest_canonical.encode("utf-8")).hexdigest(),
        "rows": store.rows,
        "dimensions": store.dimensions,
        "model_revision": manifest_config.get("model_revision"),
        "max_seq_length": config.max_seq_length,
    }
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16], payload


class RagClient:
    """Small facade over the frozen ``rag`` implementation.

    ``from_config`` validates the configuration and loads the corpus/index; it
    does not load the embedding model.  Dense/hybrid work is loaded lazily on
    first use, while BM25 can be used without a model.
    """

    def __init__(
        self,
        config: RagConfig,
        store: KnowledgeStore,
        *,
        encoder: Any | None = None,
        bm25: Any | None = None,
        reranker: Any | None = None,
    ) -> None:
        self.config = config
        self.store = store
        self._encoder = encoder
        self._bm25 = bm25
        self._reranker = reranker
        self._dense: DenseRetriever | None = None
        self._bm25_cached: BM25Retriever | None = None
        self._tools: dict[str, RagTools] = {}
        self.snapshot_id, self.snapshot = _snapshot(store, config)

    @classmethod
    def from_config(
        cls,
        config_path: str | Path,
        *,
        verify_hashes: bool = True,
        encoder: Any | None = None,
        bm25: Any | None = None,
        reranker: Any | None = None,
    ) -> "RagClient":
        path = _resolve_config_path(config_path)
        try:
            config = load_config(path)
        except Exception as exc:  # noqa: BLE001 - stable package error
            raise RagClientError("config_error", f"cannot load RAG config: {exc}", cause=exc) from exc
        try:
            store = KnowledgeStore.load(config, verify_hashes=verify_hashes)
        except StoreError as exc:
            raise RagClientError("asset_error", str(exc), cause=exc) from exc
        return cls(config, store, encoder=encoder, bm25=bm25, reranker=reranker)

    def _dense_retriever(self) -> DenseRetriever:
        if self._dense is None:
            if self._encoder is None:
                self._encoder = SentenceTransformerEncoder(
                    self.config.model_path,
                    device=self.config.device,
                    offline=self.config.offline,
                    max_seq_length=self.config.max_seq_length,
                )
            self._dense = DenseRetriever(
                self.store,
                self._encoder,
                candidate_depth=self.config.dense_candidates,
            )
        return self._dense

    def _bm25_retriever(self) -> BM25Retriever:
        if self._bm25_cached is None:
            if self._bm25 is not None:
                self._bm25_cached = self._bm25
            elif self.config.bm25_pointer is not None:
                try:
                    self._bm25_cached = BM25Retriever.load(
                        self.store,
                        self.config.bm25_pointer,
                    )
                except (RetrievalError, FileNotFoundError, ValueError) as exc:
                    raise RagClientError("bm25_unavailable", f"cannot load BM25: {exc}", cause=exc) from exc
            else:
                raise RagClientError("bm25_unavailable", "configuration has no BM25 pointer")
        return self._bm25_cached

    def _tools_for(self, mode: str) -> RagTools:
        if mode in self._tools:
            return self._tools[mode]
        if mode == "dense":
            retriever = self._dense_retriever()
        elif mode == "bm25":
            retriever = self._bm25_retriever()
        elif mode == "hybrid":
            dense = self._dense_retriever()
            try:
                bm25 = self._bm25_retriever()
            except RagClientError:
                # Preserve the underlying contract: hybrid degrades explicitly
                # to dense instead of pretending BM25 was used.
                bm25 = None
            retriever = HybridRetriever(
                dense,
                bm25,
                rrf_k=self.config.fusion.rrf_k,
                weights=self.config.fusion.weights,
            )
        else:
            raise RagClientError("invalid_mode", "mode must be dense, bm25, or hybrid")
        tools = RagTools(self.store, retriever, self.config, reranker=self._reranker)
        self._tools[mode] = tools
        return tools

    def search(
        self,
        query: str,
        *,
        top_k: int = 5,
        mode: str | None = None,
    ) -> RagResult:
        requested_mode = str(mode or self.config.mode).lower()
        if requested_mode not in {"dense", "bm25", "hybrid"}:
            raise RagClientError("invalid_mode", "mode must be dense, bm25, or hybrid")
        try:
            tools = self._tools_for(requested_mode)
            response = tools.search_all(query, top_k=top_k)
        except (RagClientError, RetrievalError, StoreError) as exc:
            code = getattr(exc, "code", "retrieval_error")
            return RagResult(
                query=str(query or ""),
                error={"code": str(code), "message": str(exc)},
                empty=False,
                mode=requested_mode,
                requested_mode=requested_mode,
                snapshot_id=self.snapshot_id,
                snapshot=self.snapshot,
                score_semantics=_score_semantics(requested_mode),
            )
        actual_mode = requested_mode if response.error else response.mode
        return RagResult(
            query=response.query,
            results=[item.to_dict() for item in response.results],
            warnings=list(response.warnings),
            error=response.error,
            empty=response.empty,
            dedup_count=response.dedup_count,
            context_chars=response.context_chars,
            mode=actual_mode,
            requested_mode=requested_mode,
            snapshot_id=self.snapshot_id,
            snapshot=self.snapshot,
            score_semantics=_score_semantics(actual_mode),
        )
