"""Optional cross-encoder reranking.

Reranking is disabled by default.  The model is not downloaded yet, and the
4 GB laptop GPU cannot be assumed to host BGE-M3 and a reranker together.
"""

from __future__ import annotations

from typing import Protocol, Sequence

from .config import RagConfig


class RerankError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class Reranker(Protocol):
    def score(self, query: str, texts: Sequence[str]) -> list[float]: ...


class CrossEncoderReranker:
    def __init__(
        self,
        model_path: str,
        *,
        device: str = "cpu",
        max_length: int = 512,
    ) -> None:
        from sentence_transformers import CrossEncoder

        self._model = CrossEncoder(str(model_path), device=device, max_length=max_length)

    def score(self, query: str, texts: Sequence[str]) -> list[float]:
        if not texts:
            return []
        pairs = [(query, text) for text in texts]
        scores = self._model.predict(pairs)
        return [float(score) for score in scores]


def load_reranker(config: RagConfig) -> Reranker | None:
    if not config.rerank_enabled:
        return None
    if config.rerank_model is None or not config.rerank_model.exists():
        raise RerankError(
            "reranker_model_missing",
            "reranking is enabled but the local reranker model is missing; download it only after approval",
        )
    return CrossEncoderReranker(str(config.rerank_model), device="cpu")
