"""Load and validate the frozen corpus and dense index."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np

from .config import RagConfig
from .types import RetrievalFilters, build_metadata


class StoreError(RuntimeError):
    """Raised when the frozen corpus/index cannot be loaded or verified."""


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(chunk_size), b""):
            digest.update(block)
    return digest.hexdigest()


class KnowledgeStore:
    """Immutable in-memory view over ``chunks.jsonl`` and ``vectors.npy``."""

    def __init__(
        self,
        *,
        config: RagConfig,
        chunks: list[dict[str, Any]],
        ids: list[str],
        vectors: np.ndarray,
        manifest: dict[str, Any],
        index_dir: Path,
    ) -> None:
        self.config = config
        self.chunks = chunks
        self.ids = ids
        self.vectors = vectors
        self.manifest = manifest
        self.index_dir = index_dir
        self._by_id = {chunk["chunk_id"]: chunk for chunk in chunks}
        self._row_by_id = {chunk_id: row for row, chunk_id in enumerate(ids)}
        self._metadata = [build_metadata(chunk) for chunk in chunks]

    @classmethod
    def load(cls, config: RagConfig, *, verify_hashes: bool = True) -> "KnowledgeStore":
        try:
            pointer = json.loads(config.index_pointer.read_text(encoding="utf-8"))
            index_dir = (config.index_pointer.parent / pointer["directory"]).resolve()
            manifest = json.loads((index_dir / "manifest.json").read_text(encoding="utf-8"))
            ids = json.loads((index_dir / "ids.json").read_text(encoding="utf-8"))
            vectors = np.load(index_dir / "vectors.npy")
            chunks = [
                json.loads(line)
                for line in config.corpus_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        except FileNotFoundError as exc:
            raise StoreError(f"required RAG artifact is missing: {exc.filename}") from exc
        except (KeyError, json.JSONDecodeError, ValueError) as exc:
            raise StoreError(f"invalid RAG artifact: {exc}") from exc

        if not isinstance(ids, list) or not all(isinstance(item, str) for item in ids):
            raise StoreError("ids.json must be a list of chunk IDs")
        if vectors.ndim != 2 or vectors.shape[0] != len(ids):
            raise StoreError(
                f"vector row count mismatch: vectors={vectors.shape}, ids={len(ids)}"
            )
        if len(chunks) != len(ids):
            raise StoreError(f"chunk count mismatch: chunks={len(chunks)}, ids={len(ids)}")
        if [chunk.get("chunk_id") for chunk in chunks] != ids:
            raise StoreError("chunk order in chunks.jsonl does not match ids.json")
        if len(set(ids)) != len(ids):
            raise StoreError("ids.json contains duplicate chunk IDs")

        if verify_hashes:
            cls._verify_hashes(config, index_dir, manifest)

        norms = np.linalg.norm(vectors, axis=1)
        if not np.all(np.isfinite(norms)) or float(norms.min()) < 0.99 or float(norms.max()) > 1.01:
            raise StoreError("dense vectors are not approximately L2-normalized")

        return cls(
            config=config,
            chunks=chunks,
            ids=ids,
            vectors=vectors,
            manifest=manifest,
            index_dir=index_dir,
        )

    @staticmethod
    def _verify_hashes(config: RagConfig, index_dir: Path, manifest: dict[str, Any]) -> None:
        expected_config = manifest.get("config") or {}
        checks = [
            ("corpus", config.corpus_path, expected_config.get("corpus_sha256")),
            ("vectors", index_dir / "vectors.npy", manifest.get("vectors_sha256")),
            ("ids", index_dir / "ids.json", manifest.get("ids_sha256")),
        ]
        for name, path, expected in checks:
            if not expected:
                raise StoreError(f"manifest is missing the {name} hash")
            actual = sha256_file(path)
            if actual.lower() != str(expected).lower():
                raise StoreError(
                    f"{name} hash mismatch: actual={actual}, expected={expected}"
                )

    def __len__(self) -> int:
        return len(self.chunks)

    @property
    def rows(self) -> int:
        return len(self.chunks)

    @property
    def dimensions(self) -> int:
        return int(self.vectors.shape[1])

    def chunk(self, chunk_id: str) -> dict[str, Any]:
        try:
            return self._by_id[chunk_id]
        except KeyError as exc:
            raise StoreError(f"unknown chunk ID: {chunk_id}") from exc

    def metadata_for(self, chunk_id: str) -> dict[str, Any]:
        try:
            return self._metadata[self._row_by_id[chunk_id]]
        except KeyError as exc:
            raise StoreError(f"unknown chunk ID: {chunk_id}") from exc

    def row_for(self, chunk_id: str) -> int:
        try:
            return self._row_by_id[chunk_id]
        except KeyError as exc:
            raise StoreError(f"unknown chunk ID: {chunk_id}") from exc

    def filter_indices(self, filters: RetrievalFilters | None) -> np.ndarray:
        if filters is None or filters.is_empty():
            return np.arange(self.rows, dtype=np.int64)
        return np.asarray(
            [row for row, metadata in enumerate(self._metadata) if filters.matches(metadata)],
            dtype=np.int64,
        )
