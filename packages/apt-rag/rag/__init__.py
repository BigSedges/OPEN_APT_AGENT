"""APT RAG knowledge retrieval service.

The package is intentionally thin: it loads the frozen corpus/index produced by
``rag-experiment`` and exposes stable, JSON-friendly retrieval contracts.  It does
not download models, rebuild embeddings, or modify the experiment workspace.
"""

from .config import RagConfig, load_config
from .store import KnowledgeStore, StoreError
from .types import RetrievalFilters, RetrievalResponse, RetrievedChunk

__all__ = [
    "KnowledgeStore",
    "RagConfig",
    "RetrievalFilters",
    "RetrievalResponse",
    "RetrievedChunk",
    "StoreError",
    "load_config",
]
