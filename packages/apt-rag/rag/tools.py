"""Stable retrieval tools for log analysis and LangGraph integration."""

from __future__ import annotations

from collections import Counter
from typing import Any, Mapping

from .config import RagConfig
from .query_builder import build_event_query, build_gap_query
from .rerank import RerankError, Reranker, load_reranker
from .retrieval import (
    DenseRetriever,
    RetrievalError,
    RetrievalOutput,
    build_retriever,
)
from .store import KnowledgeStore, StoreError
from .types import (
    RetrievalFilters,
    RetrievalResponse,
    RetrievedChunk,
    build_metadata,
    error_response,
)


class RagTools:
    """Thin, testable facade over the frozen knowledge index.

    Every public method returns a ``RetrievalResponse``; retrieval failures are
    represented as structured errors rather than raw exceptions.
    """

    def __init__(
        self,
        store: KnowledgeStore,
        retriever: Any,
        config: RagConfig,
        *,
        reranker: Reranker | None = None,
    ) -> None:
        self.store = store
        self.retriever = retriever
        self.config = config
        self.reranker = reranker

    @classmethod
    def from_config(
        cls,
        config: RagConfig,
        *,
        verify_hashes: bool = True,
        encoder: Any | None = None,
        bm25: Any | None = None,
        reranker: Reranker | None = None,
    ) -> "RagTools":
        store = KnowledgeStore.load(config, verify_hashes=verify_hashes)
        retriever = build_retriever(config, store, encoder=encoder, bm25=bm25)
        if reranker is None and config.rerank_enabled:
            reranker = load_reranker(config)
        return cls(store, retriever, config, reranker=reranker)

    def _normalize_top_k(self, top_k: int) -> tuple[int, list[str]]:
        warnings: list[str] = []
        try:
            value = int(top_k)
        except (TypeError, ValueError):
            value = self.config.top_k
            warnings.append("invalid_top_k_using_default")
        if value < 1:
            value = 1
            warnings.append("top_k_clamped_to_1")
        if value > self.config.max_top_k:
            value = self.config.max_top_k
            warnings.append(f"top_k_clamped_to_{value}")
        return value, warnings

    def _run_search(
        self,
        query: str,
        *,
        filters: RetrievalFilters | None,
        top_k: int,
        extra_warnings: list[str] | None = None,
    ) -> RetrievalResponse:
        text = str(query or "").strip()
        if not text:
            return error_response(text, "empty_query", "query must be non-empty")

        requested_top_k, warnings = self._normalize_top_k(top_k)
        if extra_warnings:
            warnings.extend(extra_warnings)

        try:
            output: RetrievalOutput = self.retriever.search(
                text,
                top_k=requested_top_k,
                filters=filters,
            )
        except RetrievalError as exc:
            return error_response(text, exc.code, exc.message)
        except StoreError as exc:
            return error_response(text, "store_error", str(exc))

        warnings.extend(output.warnings)
        results: list[RetrievedChunk] = []
        document_counts: Counter[str] = Counter()
        seen_content: set[tuple[str, str]] = set()
        dedup_count = 0
        context_chars = 0

        for chunk_id, score in output.hits:
            if len(results) >= requested_top_k:
                break
            try:
                chunk = self.store.chunk(chunk_id)
            except StoreError:
                warnings.append(f"unknown_chunk:{chunk_id}")
                continue
            metadata = build_metadata(chunk)
            document_id = metadata["document_id"] or chunk_id
            if document_counts[document_id] >= self.config.max_chunks_per_document:
                dedup_count += 1
                continue
            content = str(chunk.get("text") or "")
            if not content:
                continue
            content_key = (document_id, str(metadata.get("content_hash") or content))
            if content_key in seen_content:
                dedup_count += 1
                continue
            remaining = self.config.max_context_chars - context_chars
            if remaining <= 200:
                break
            if len(content) > remaining:
                content = content[:remaining]

            results.append(
                RetrievedChunk(
                    chunk_id=chunk_id,
                    document_id=document_id,
                    content=content,
                    knowledge_type=metadata["knowledge_type"],
                    source_name=metadata["source_name"],
                    source_url=metadata.get("source_url"),
                    source_version=metadata.get("source_version"),
                    attack_technique_ids=list(metadata.get("attack_technique_ids") or []),
                    retrieval_score=float(score),
                    reranking_score=None,
                    title=metadata.get("title"),
                    metadata=metadata,
                )
            )
            document_counts[document_id] += 1
            seen_content.add(content_key)
            context_chars += len(content)

        if self.reranker is not None and results:
            try:
                scores = self.reranker.score(text, [result.content for result in results])
                if len(scores) != len(results):
                    warnings.append("reranker_score_count_mismatch")
                else:
                    for result, score in zip(results, scores):
                        result.reranking_score = float(score)
                    results.sort(
                        key=lambda item: (
                            -(item.reranking_score if item.reranking_score is not None else float("-inf")),
                            -item.retrieval_score,
                            item.chunk_id,
                        )
                    )
            except RerankError as exc:
                warnings.append(f"reranker_failed:{exc.code}")
            except Exception as exc:  # noqa: BLE001 - reranker must not break retrieval
                warnings.append(f"reranker_failed:{type(exc).__name__}")

        if not results and not warnings:
            warnings.append("no_results")
        return RetrievalResponse(
            query=text,
            results=results,
            warnings=warnings,
            error=None,
            dedup_count=dedup_count,
            context_chars=context_chars,
            mode=output.mode,
        )

    # ------------------------------------------------------------------ tools

    def search_attack_techniques(
        self,
        query: str,
        *,
        platform: str | None = None,
        tactic: str | None = None,
        top_k: int = 5,
    ) -> RetrievalResponse:
        warnings: list[str] = []
        if tactic:
            warnings.append("tactic_filter_not_indexed_ignored")
        filters = RetrievalFilters(
            knowledge_types=("attack_technique",),
            source_families=("attack",),
            platforms=(platform,) if platform else (),
        )
        return self._run_search(query, filters=filters, top_k=top_k, extra_warnings=warnings)

    def search_detection_rules(
        self,
        query: str,
        *,
        log_source: str | None = None,
        technique_id: str | None = None,
        level: str | None = None,
        top_k: int = 5,
    ) -> RetrievalResponse:
        warnings: list[str] = []
        if level:
            warnings.append("rule_level_filter_not_indexed_ignored")
        filters = RetrievalFilters(
            knowledge_types=("detection_rule",),
            source_families=("sigma",),
            log_sources=(log_source,) if log_source else (),
            attack_technique_ids=(technique_id,) if technique_id else (),
        )
        return self._run_search(query, filters=filters, top_k=top_k, extra_warnings=warnings)

    def explain_log_event(
        self,
        event: Mapping[str, Any] | Any,
        *,
        top_k: int = 5,
    ) -> RetrievalResponse:
        query = build_event_query(event)
        filters = RetrievalFilters(
            knowledge_types=(
                "log_documentation",
                "detection_rule",
                "attack_technique",
                "behavior_analytic",
            )
        )
        return self._run_search(query, filters=filters, top_k=top_k)

    def search_threat_intelligence(
        self,
        query: str,
        *,
        actor: str | None = None,
        top_k: int = 5,
    ) -> RetrievalResponse:
        warnings: list[str] = []
        if actor:
            warnings.append("actor_filter_not_indexed_ignored")
        filters = RetrievalFilters(knowledge_types=("behavior_analytic", "threat_intelligence"))
        return self._run_search(query, filters=filters, top_k=top_k, extra_warnings=warnings)

    def retrieve_behavior_knowledge(
        self,
        query: str,
        *,
        stage: str | None = None,
        top_k: int = 5,
    ) -> RetrievalResponse:
        warnings: list[str] = []
        if stage:
            warnings.append("attack_stage_filter_not_indexed_ignored")
        filters = RetrievalFilters(knowledge_types=("behavior_analytic", "attack_technique"))
        return self._run_search(query, filters=filters, top_k=top_k, extra_warnings=warnings)

    def suggest_evidence_queries(
        self,
        gap: Mapping[str, Any] | str,
        *,
        top_k: int = 5,
    ) -> RetrievalResponse:
        query = build_gap_query(gap)
        filters = RetrievalFilters(knowledge_types=("log_documentation", "detection_rule"))
        response = self._run_search(query, filters=filters, top_k=top_k)
        for result in response.results:
            log_source = result.metadata.get("log_source") or {}
            parts: list[str] = []
            if isinstance(log_source, Mapping):
                for value in log_source.values():
                    if value:
                        parts.append(str(value))
            event_ids = result.metadata.get("event_ids") or []
            if event_ids:
                parts.append("EventID " + "/".join(str(item) for item in event_ids[:4]))
            if result.title:
                parts.append(str(result.title))
            parts.append(_truncate_text(query, 160))
            result.metadata["suggested_query"] = " ".join(part for part in parts if part)
        return response

    def search_all(self, query: str, *, top_k: int = 5) -> RetrievalResponse:
        return self._run_search(query, filters=None, top_k=top_k)


def _truncate_text(text: str, limit: int) -> str:
    text = " ".join(str(text).split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."
