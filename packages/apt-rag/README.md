# apt_rag

Local APT RAG knowledge-retrieval facade, version `0.1.0`. It exposes the
existing `rag/` retrieval implementation as a small Python API and CLI. It does
**not** bundle a model, corpus, vector index, BM25 index, competition data, or
credentials.

## Install

Download `apt_rag-0.1.0-py3-none-any.whl` and verify its SHA256 against
`SHA256SUMS.txt`, then install it in your own environment:

```bash
python -m pip install apt_rag-0.1.0-py3-none-any.whl
```

Dense retrieval needs the optional `dense` extras (`sentence-transformers`,
`torch`). BM25 needs `numpy`, `scipy`, and `PyYAML`, which are runtime
dependencies.

Tested on Python 3.11.4; `pyproject.toml` declares `>=3.10`.

## First query

```python
from apt_rag import RagClient

client = RagClient.from_config("examples/rag.yaml")
result = client.search(
    "What fields are recorded in a Sysmon process creation event?",
    top_k=5,
    mode="dense",
)
print(result.to_dict())
```

CLI:

```bash
apt-rag --config examples/rag.yaml --query "Sysmon Event ID 1 process creation" --mode dense --top-k 5
# or
python -m apt_rag --config examples/rag.yaml --query "Sysmon Event ID 1 process creation" --mode dense --top-k 5
```

## External assets

Copy `examples/rag.yaml` and replace the placeholder `project_root` and asset
paths. The package loads:

- corpus JSONL;
- BGE vector index pointer/vectors/ids;
- BM25 pointer/index;
- local BGE-M3 model directory.

No public asset pack is included in this release. If you do not have the
assets, the wheel can be installed but retrieval cannot run.

## Behaviour

- Dense is the default; BM25 and Hybrid are selectable.
- `top_k` is a maximum; document de-duplication and context limits can return
  fewer results.
- Hybrid without BM25 reports `mode="dense_fallback"` with a warning.
- Empty results are `empty=true, error=null`; missing assets/config/query errors
  are structured errors.
- v0.1.0 does not expose metadata filters; it calls the existing `search_all`.
- Scores are mode-specific: cosine for Dense, BM25 for BM25, RRF for Hybrid.

## Evaluation

The Silver retrieval comparison is in
[`docs/retrieval_comparison.md`](docs/retrieval_comparison.md): 49-question main
table, 3,403 historical extension pool, 2,197 four-way union sensitivity,
AiSOC PostgreSQL FTS component, candidate-pool Recall, and graded nDCG.
Labels are Silver; this is not human Gold.

## Scope and licensing

This repository contains software only. Third-party corpora, models, indexes,
and competition data are external and remain subject to their own licenses and
terms. A root software license is still to be confirmed before public release.
