"""Shared, JSON-friendly types for the APT RAG service."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

SOURCE_NAMES: dict[str, str] = {
    "attack": "MITRE ATT&CK Enterprise",
    "sigma": "Sigma",
    "car": "MITRE CAR",
    "ecar": "MITRE ECAR",
    "sysmon": "Microsoft Sysmon",
    "windows": "Microsoft Windows Security Auditing",
    "zeek": "Zeek",
    "otrf": "OTRF",
    "documents": "Public Documentation",
}

KNOWLEDGE_TYPES: dict[str, str] = {
    "attack": "attack_technique",
    "sigma": "detection_rule",
    "car": "behavior_analytic",
    "ecar": "behavior_analytic",
    "sysmon": "log_documentation",
    "windows": "log_documentation",
    "zeek": "log_documentation",
    "otrf": "threat_intelligence",
    "documents": "reference",
}


def knowledge_type_for(source_family: str | None) -> str:
    family = str(source_family or "unknown").lower()
    return KNOWLEDGE_TYPES.get(family, "unknown")


def source_name_for(source_family: str | None) -> str:
    family = str(source_family or "unknown").lower()
    return SOURCE_NAMES.get(family, family)


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (str, bytes)):
        return [str(value)]
    if isinstance(value, Mapping):
        return [str(item) for item in value.keys()]
    try:
        return [str(item) for item in value]
    except TypeError:
        return [str(value)]


def build_metadata(chunk: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize a corpus chunk into the metadata used for filtering and output."""

    family = str(chunk.get("source_family") or "unknown").lower()
    log_source = chunk.get("log_source")
    if not isinstance(log_source, Mapping):
        log_source = {}
    return {
        "chunk_id": str(chunk.get("chunk_id") or ""),
        "document_id": str(chunk.get("document_id") or ""),
        "title": chunk.get("title"),
        "source_family": family,
        "knowledge_type": knowledge_type_for(family),
        "source_name": source_name_for(family),
        "source_url": chunk.get("source_url"),
        "source_version": chunk.get("source_version"),
        "license_ref": chunk.get("license_ref"),
        "platform": _string_list(chunk.get("platform")),
        "log_source": dict(log_source),
        "event_ids": _string_list(chunk.get("event_ids")),
        "attack_technique_ids": _string_list(chunk.get("attack_ids")),
        "section_path": _string_list(chunk.get("section_path")),
        "token_count": int(chunk.get("token_count") or 0),
        "content_hash": chunk.get("content_hash"),
        "parent_id": chunk.get("parent_id"),
        "metadata_review": chunk.get("metadata_review"),
    }


def _lower_set(values: Sequence[str] | tuple[str, ...] | None) -> set[str]:
    if not values:
        return set()
    return {str(value).strip().lower() for value in values if str(value).strip()}


@dataclass(frozen=True)
class RetrievalFilters:
    """Metadata filters applied before ranking.

    ``tactics`` is accepted for forward compatibility.  The current corpus does
    not carry a tactic field, so callers must not assume it is effective yet.
    """

    knowledge_types: tuple[str, ...] = ()
    source_families: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ()
    log_sources: tuple[str, ...] = ()
    event_ids: tuple[str, ...] = ()
    attack_technique_ids: tuple[str, ...] = ()
    tactics: tuple[str, ...] = ()

    def is_empty(self) -> bool:
        return not any(
            (
                self.knowledge_types,
                self.source_families,
                self.platforms,
                self.log_sources,
                self.event_ids,
                self.attack_technique_ids,
                self.tactics,
            )
        )

    def matches(self, metadata: Mapping[str, Any]) -> bool:
        if self.knowledge_types:
            if str(metadata.get("knowledge_type", "")).lower() not in _lower_set(self.knowledge_types):
                return False
        if self.source_families:
            if str(metadata.get("source_family", "")).lower() not in _lower_set(self.source_families):
                return False
        if self.platforms:
            if not _lower_set(self.platforms).intersection(_lower_set(metadata.get("platform") or [])):
                return False

        if self.log_sources:
            wanted = _lower_set(self.log_sources)
            log_source = metadata.get("log_source") or {}
            observed: list[str] = []
            if isinstance(log_source, Mapping):
                for key, value in log_source.items():
                    observed.append(str(key))
                    if isinstance(value, (list, tuple, set)):
                        observed.extend(str(item) for item in value)
                    elif value is not None:
                        observed.append(str(value))
            elif log_source:
                observed.append(str(log_source))
            if not wanted.intersection(_lower_set(observed)):
                return False

        if self.event_ids:
            if not _lower_set(self.event_ids).intersection(_lower_set(metadata.get("event_ids") or [])):
                return False

        if self.attack_technique_ids:
            wanted = _lower_set(self.attack_technique_ids)
            observed = _lower_set(metadata.get("attack_technique_ids") or [])
            if not any(
                value == wanted_id or value.startswith(wanted_id + ".")
                for value in observed
                for wanted_id in wanted
            ):
                return False

        if self.tactics:
            observed = metadata.get("tactics") or metadata.get("tactic") or []
            if isinstance(observed, str):
                observed = [observed]
            if not _lower_set(self.tactics).intersection(_lower_set(observed)):
                return False
        return True


@dataclass
class RetrievedChunk:
    chunk_id: str
    document_id: str
    content: str
    knowledge_type: str
    source_name: str
    source_url: str | None
    source_version: str | None
    attack_technique_ids: list[str]
    retrieval_score: float
    reranking_score: float | None = None
    title: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "document_id": self.document_id,
            "content": self.content,
            "knowledge_type": self.knowledge_type,
            "source_name": self.source_name,
            "source_url": self.source_url,
            "source_version": self.source_version,
            "attack_technique_ids": list(self.attack_technique_ids),
            "retrieval_score": self.retrieval_score,
            "reranking_score": self.reranking_score,
            "title": self.title,
            "metadata": self.metadata,
        }


@dataclass
class RetrievalResponse:
    query: str
    results: list[RetrievedChunk] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: dict[str, Any] | None = None
    dedup_count: int = 0
    context_chars: int = 0
    mode: str = "dense"

    @property
    def empty(self) -> bool:
        return not self.results and self.error is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "results": [result.to_dict() for result in self.results],
            "warnings": list(self.warnings),
            "error": self.error,
            "empty": self.empty,
            "dedup_count": self.dedup_count,
            "context_chars": self.context_chars,
            "mode": self.mode,
        }


def error_response(query: str, code: str, message: str, *, mode: str = "dense") -> RetrievalResponse:
    return RetrievalResponse(
        query=query,
        error={"code": code, "message": message},
        mode=mode,
    )
