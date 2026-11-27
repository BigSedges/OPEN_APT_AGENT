# apt_rag 0.1.0 installation verification

This is a record of the local 0.1.0 build and test, not a GitHub download list.
For the current checkout, see the [quick start and source installation](../README.md).

## Artifact

- Wheel: `apt_rag-0.1.0-py3-none-any.whl`
- SHA256: `0c1580fcaa724ffacb8569a33f29fca45e30e783a66f2cc509e0bb934eb9b734`
- Wheel size: 51,459 bytes
- Source version: 0.1.0
- `Requires-Python`: >=3.10
- Tested Python: 3.11.4

## What was verified

### Package install

The wheel was installed with:

```text
python -m pip install --no-deps --no-index <wheel> --target <isolated-target>
```

The target contained `apt_rag/`, `rag/`, `apt_rag-0.1.0.dist-info/`, and
`bin/apt-rag.exe`.

### Entry points

From a directory outside the project root, with only the target on
`PYTHONPATH` (not the project root):

- `apt-rag.exe --version` -> `apt-rag 0.1.0`
- `python -m apt_rag --version` -> `apt-rag 0.1.0`

### BM25 CLI

An external config (absolute paths) was used with a public query. The CLI
returned exit 0 and stdout parsed as JSON; `mode=bm25`, three results, no error.

### Empty result and config error

- Normal no-match query: exit 0, `empty=true`, `error=null`, `mode=bm25`.
- Missing config: exit 2, JSON `error.code=config_error`.

### Dense API

With the existing local model/index and an external config:

- `RagClient.from_config(...)`
- `search(..., top_k=3, mode="dense")`
- result: `mode=dense`, `requested_mode=dense`, `score_semantics=cosine`,
  `empty=false`, `error=null`, three results, `snapshot_id` present.

## Clean-environment limitation

A freshly created venv accepted the wheel installation, but importing it failed
because that venv did not contain `PyYAML` (and the other runtime dependencies).
No local wheelhouse or network install was used. Therefore the strict
"clean venv with independently installed dependencies" check is **not complete**.

The successful target-install check reused the existing project venv's
dependencies while keeping the package and working directory outside the
project root. To complete strict isolation, install `numpy`, `scipy`, `PyYAML`
(and optional Dense dependencies) into a clean environment from approved local
artifacts, then repeat the same checks.

## Packaging notes

The wheel contains Python modules and metadata only. It does not contain A
data, competition labels, models, indexes, caches, credentials, or virtual
environments. Optional Judge/evaluation modules are present as source under
`rag/` but are not imported by `apt_rag` and are not declared as runtime
dependencies.
