from typing import Protocol, Sequence

from .models import Case
from .retrieval import KnowledgeHit


class Analyzer(Protocol):
    """Summarize case evidence and retrieved passages for analyst review."""

    def analyze(self, case: Case, passages: Sequence[KnowledgeHit]) -> str: ...
