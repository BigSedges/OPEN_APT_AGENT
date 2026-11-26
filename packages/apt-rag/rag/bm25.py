"""Persistent BM25 index for the frozen APT RAG corpus.

The index stores precomputed per-(document, term) BM25 weights in a CSR matrix.
A query sums the relevant columns, which is equivalent to standard BM25 for
short queries with unit query-term frequency.

The tokenizer is deliberately small and deterministic: lower-case ASCII
alphanumeric tokens, preserving identifiers such as ``T1055.001`` and
``event_id``.  Chinese text is not tokenized here; dense retrieval handles it.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

import numpy as np
from scipy import sparse

TOKEN_RE = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*")
TOKENIZER_NAME = "regex-v1"


def tokenize(text: str) -> list[str]:
    return TOKEN_RE.findall(str(text).lower())


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def ids_sha256(ids: Sequence[str]) -> str:
    payload = json.dumps(list(ids), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class BM25Index:
    def __init__(
        self,
        matrix: sparse.csr_matrix,
        tokens: Sequence[str],
        manifest: dict,
        directory: Path | None = None,
    ) -> None:
        self.matrix = matrix
        self.tokens = list(tokens)
        self.vocab = {token: column for column, token in enumerate(self.tokens)}
        self.manifest = dict(manifest)
        self.directory = directory

    @classmethod
    def build(
        cls,
        ids: Sequence[str],
        texts: Sequence[str],
        *,
        k1: float = 1.5,
        b: float = 0.75,
        corpus_sha256: str = "",
    ) -> "BM25Index":
        if len(ids) != len(texts):
            raise ValueError("ids and texts must have the same length")
        if not texts:
            raise ValueError("cannot build BM25 from an empty corpus")
        if k1 <= 0 or not 0 <= b <= 1:
            raise ValueError("BM25 requires k1 > 0 and 0 <= b <= 1")

        started = time.perf_counter()
        vocab: dict[str, int] = {}
        document_frequency: list[int] = []
        doc_counts: list[Counter[int]] = []
        doc_lengths: list[int] = []
        for text in texts:
            counts: Counter[int] = Counter()
            for token in tokenize(text):
                column = vocab.get(token)
                if column is None:
                    column = len(vocab)
                    vocab[token] = column
                    document_frequency.append(0)
                counts[column] += 1
            for column in counts:
                document_frequency[column] += 1
            doc_counts.append(counts)
            doc_lengths.append(sum(counts.values()))

        rows_count = len(texts)
        average_length = sum(doc_lengths) / rows_count
        if average_length <= 0:
            raise ValueError("BM25 corpus has no tokens")

        rows: list[int] = []
        columns: list[int] = []
        values: list[float] = []
        for row_index, counts in enumerate(doc_counts):
            length = doc_lengths[row_index]
            for column, frequency in counts.items():
                df = document_frequency[column]
                idf = math.log(1.0 + (rows_count - df + 0.5) / (df + 0.5))
                denominator = frequency + k1 * (1.0 - b + b * length / average_length)
                values.append(idf * frequency * (k1 + 1.0) / denominator)
                rows.append(row_index)
                columns.append(column)

        matrix = sparse.coo_matrix(
            (
                np.asarray(values, dtype=np.float32),
                (np.asarray(rows, dtype=np.int32), np.asarray(columns, dtype=np.int32)),
            ),
            shape=(rows_count, len(vocab)),
        ).tocsr()
        tokens = [""] * len(vocab)
        for token, column in vocab.items():
            tokens[column] = token
        manifest = {
            "format": "bm25-csr-v1",
            "tokenizer": TOKENIZER_NAME,
            "rows": rows_count,
            "vocab_size": len(vocab),
            "nnz": int(matrix.nnz),
            "avgdl": average_length,
            "k1": float(k1),
            "b": float(b),
            "corpus_sha256": str(corpus_sha256),
            "ids_sha256": ids_sha256(ids),
            "build_seconds": time.perf_counter() - started,
        }
        return cls(matrix, tokens, manifest)

    def save(self, directory: str | Path) -> None:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        matrix_path = directory / "bm25.npz"
        vocab_path = directory / "vocab.json"
        sparse.save_npz(matrix_path, self.matrix, compressed=True)
        vocab_path.write_text(json.dumps(self.tokens, ensure_ascii=False), encoding="utf-8")
        manifest = dict(self.manifest)
        manifest["generated_at"] = datetime.now(timezone.utc).isoformat()
        manifest["matrix_sha256"] = sha256_file(matrix_path)
        manifest["vocab_sha256"] = sha256_file(vocab_path)
        manifest["bytes"] = {
            "matrix": matrix_path.stat().st_size,
            "vocab": vocab_path.stat().st_size,
        }
        (directory / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        self.manifest = manifest
        self.directory = directory

    @classmethod
    def load(cls, directory: str | Path, *, verify_hashes: bool = True) -> "BM25Index":
        directory = Path(directory)
        manifest_path = directory / "manifest.json"
        matrix_path = directory / "bm25.npz"
        vocab_path = directory / "vocab.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("format") != "bm25-csr-v1":
            raise ValueError(f"unsupported BM25 format: {manifest.get('format')}")
        if verify_hashes:
            if sha256_file(matrix_path) != manifest.get("matrix_sha256"):
                raise ValueError("BM25 matrix hash mismatch")
            if sha256_file(vocab_path) != manifest.get("vocab_sha256"):
                raise ValueError("BM25 vocabulary hash mismatch")
        matrix = sparse.load_npz(matrix_path)
        tokens = json.loads(vocab_path.read_text(encoding="utf-8"))
        expected_shape = (int(manifest["rows"]), int(manifest["vocab_size"]))
        if matrix.shape != expected_shape:
            raise ValueError(f"BM25 shape mismatch: {matrix.shape} != {expected_shape}")
        if len(tokens) != expected_shape[1]:
            raise ValueError("BM25 vocabulary length mismatch")
        if matrix.nnz != int(manifest["nnz"]):
            raise ValueError("BM25 non-zero count mismatch")
        return cls(matrix, tokens, manifest, directory)

    @property
    def rows(self) -> int:
        return int(self.matrix.shape[0])

    def search(
        self,
        query: str,
        *,
        candidate_indices: np.ndarray | None = None,
        top_k: int = 50,
    ) -> list[tuple[int, float]]:
        tokens = tokenize(query)
        if not tokens:
            return []
        columns = sorted({self.vocab[token] for token in tokens if token in self.vocab})
        if not columns:
            return []

        if candidate_indices is not None:
            candidate_rows = np.asarray(candidate_indices, dtype=np.int64)
            if candidate_rows.size == 0:
                return []
            scores = np.asarray(
                self.matrix[candidate_rows][:, columns].sum(axis=1)
            ).ravel()
        else:
            candidate_rows = np.arange(self.rows, dtype=np.int64)
            scores = np.asarray(self.matrix[:, columns].sum(axis=1)).ravel()

        keep = np.flatnonzero(scores > 0)
        if keep.size == 0:
            return []
        limit = max(1, int(top_k))
        order = keep[np.argsort(-scores[keep], kind="stable")[:limit]]
        return [
            (int(candidate_rows[index]), float(scores[index]))
            for index in order
        ]
