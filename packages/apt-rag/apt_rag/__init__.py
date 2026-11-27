"""Public Python API for the local APT RAG knowledge index."""

from .client import RagClient, RagClientError, RagResult

__all__ = ["RagClient", "RagClientError", "RagResult"]
__version__ = "0.1.0"
