from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Sequence


@dataclass(frozen=True)
class KnowledgeHit:
    source: str
    chunk_id: str
    text: str
    score: float


class KnowledgeIndex(Protocol):
    """Build a knowledge index and retrieve ranked passages with provenance."""

    def build(self, sources: Sequence[Path]) -> None: ...

    def search(self, query: str, *, top_k: int) -> Sequence[KnowledgeHit]: ...
