# apt_rag 0.1.0

Stable Python facade over the existing `rag/` implementation. It loads the
frozen local corpus/index assets through a YAML config; it does not download
models, read competition labels, require PostgreSQL, or start AiSOC.

## Python API

```python
from apt_rag import RagClient

client = RagClient.from_config("/path/to/your/rag.yaml")
result = client.search(
    "What fields are recorded in a Sysmon process creation event?",
    top_k=5,
    mode="dense",
)
print(result.to_dict())
```

## v1 contract

### `RagClient.from_config(path, verify_hashes=True)`

- Loads config and corpus/index only; the embedding model is lazy-loaded on
  first Dense/Hybrid search.
- `config_error` (`RagClientError`) for unreadable/invalid config.
- `asset_error` (`RagClientError`) for missing/mismatched corpus, vectors, or IDs.
- Does not start PostgreSQL, AiSOC, or any external service.

### `search(query, top_k=5, mode=None)`

- `mode`: `dense`, `bm25`, or `hybrid`; default is `config.retrieval.mode`.
- `top_k`: requested maximum. Existing `RagTools` clamps to `1..max_top_k`
  (currently 20) and emits warnings; non-integer values use the config default.
- `top_k` is a maximum, not a promise: document de-duplication and
  `max_context_chars` may return fewer results.
- Empty query returns a structured error with `error.code="empty_query"`,
  `empty=false`; it does not raise from `search`.
- Retrieval/asset errors after client creation are returned as
  `RagResult.error`; the caller can inspect `error.code` and `error.message`.
- Normal no-match is `empty=true`, `error=null`.

### Modes and scores

| requested mode | actual mode | `score_semantics` |
|---|---|---|
| dense | dense | cosine |
| bm25 | bm25 | bm25 |
| hybrid | hybrid | rrf |
| hybrid without BM25 | dense_fallback | cosine |

`requested_mode` records what the caller asked for; `mode` records what actually
ran. A Hybrid fallback also carries a warning such as
`bm25_unavailable_dense_only`.

### Snapshot

`snapshot_id` is derived from the loaded manifest's corpus/vector/ID hashes,
manifest SHA256, row/dimension counts, model revision, and max sequence length.
It is not inferred from a path name. `result.snapshot` contains the underlying
hash fields.

### JSON

`result.to_dict()` contains only JSON-serializable values (results are plain
dicts). It preserves chunk text, source fields, document/chunk IDs, snapshot,
actual/requested mode, warnings, error, empty, dedup and context statistics.

### Scope

`filters` are not part of v1; the client currently calls `search_all`. The
`rag` tools still provide their existing filtered methods for direct use.

## CLI

```sh
python -m apt_rag --config /path/to/your/rag.yaml --query "Sysmon Event ID 1 process creation" --mode dense --top-k 5
```

After installation, the same logic is exposed as `apt-rag`. Both entry points
call `apt_rag.cli.main`; stdout is machine-readable JSON, diagnostics go to
stderr.

## Assets and packaging

The wheel contains Python modules only; it bundles no model, corpus, index,
BM25 artifacts, credentials, or competition data. Assets are referenced by
config. `examples/rag.yaml` uses placeholder paths and must be edited before
use. Dense retrieval requires the optional `dense` dependencies
(`sentence-transformers`, `torch`); BM25 requires `numpy`, `scipy`, and
`PyYAML`, which are runtime dependencies.

## Failure semantics

- Empty result: `empty=true`, `error=null`.
- Missing corpus/index/model/BM25: structured `error.code`.
- Hybrid without BM25: `mode="dense_fallback"` plus a warning; it is not
  reported as hybrid.
- Invalid mode/config: `RagClientError` for invalid mode; `from_config` raises
  for config/asset loading.
