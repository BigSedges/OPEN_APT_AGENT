"""LangGraph investigation tool protocol v1 worker for read-only RAG."""

import contextlib
import hashlib
import json
import os
from pathlib import Path
import sys

from wire import decode

ROOT = Path(__file__).resolve().parents[2]
MAX_REQUEST_BYTES = 32 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
MODES = {"bm25", "dense", "hybrid"}


class ToolError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def fail(request_id, code, message):
    return {"protocol_version": "1.0", "request_id": request_id, "ok": False,
            "error": {"code": code, "message": message, "retryable": False}}


def parse_request(raw):
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError("Request exceeds 32 KiB.")
    request = decode(raw)
    if (
        not isinstance(request, dict)
        or set(request) != {"protocol_version", "request_id", "tool", "tool_version", "context", "arguments"}
        or request["protocol_version"] != "1.0"
        or request["tool"] != "search_knowledge"
        or request["tool_version"] != "1.0.0"
        or not isinstance(request["request_id"], str)
        or not request["request_id"].strip()
    ):
        raise ValueError("Invalid v1 request envelope.")
    return request


def parameters(args):
    if not isinstance(args, dict) or set(args) - {"query", "top_k", "mode"}:
        raise ToolError("INVALID_ARGUMENT", "Expected query with optional top_k and mode.")
    query, top_k, mode = args.get("query"), args.get("top_k", 5), args.get("mode", "bm25")
    if not isinstance(query, str) or not query.strip() or len(query) > 2000:
        raise ToolError("INVALID_ARGUMENT", "query must contain 1 to 2000 characters and be nonblank.")
    if type(top_k) is float and top_k.is_integer():
        top_k = int(top_k)
    if type(top_k) is not int or not 1 <= top_k <= 20:
        raise ToolError("INVALID_ARGUMENT", "top_k must be an integer between 1 and 20.")
    if not isinstance(mode, str) or mode not in MODES:
        raise ToolError("INVALID_ARGUMENT", "mode must be bm25, dense or hybrid.")
    return query, top_k, mode


def knowledge_path(context):
    if not isinstance(context, dict) or any(
        not isinstance(context.get(k), str) or not context[k].strip() for k in ("case_id", "run_id")
    ):
        raise ToolError("DATA_ERROR", "The host must bind case_id, run_id and knowledge.")
    resources = context.get("resources")
    value = resources.get("knowledge") if isinstance(resources, dict) else None
    if not isinstance(value, str) or not value:
        raise ToolError("DATA_ERROR", "Missing host-bound knowledge resource.")
    path = Path(value)
    if not path.is_absolute() or not path.is_file():
        raise ToolError("DATA_ERROR", "The knowledge resource must be an existing absolute file path.")
    return path


def corpus_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def retrieve(path, query, top_k, mode):
    if path.suffix.lower() in {".yaml", ".yml"}:
        from apt_rag import RagClient, RagClientError

        try:
            client = RagClient.from_config(path)
            if mode != "bm25" and not client.config.offline:
                raise ToolError("DATA_ERROR", "Indexed model configuration must use offline mode.")
            result = client.search(query, top_k=top_k, mode=mode)
        except RagClientError as exc:
            print(f"RagClient setup: {exc}", file=sys.stderr)
            raise ToolError("DATA_ERROR", "Cannot load the indexed knowledge snapshot.") from exc
        if result.error:
            print(f"RagClient retrieval: {result.error}", file=sys.stderr)
            raise ToolError("RETRIEVAL_ERROR", "The selected retriever could not run.")
        return result.results, result.snapshot_id, result.mode, result.warnings

    if not path.name.lower().endswith((".jsonl", ".jsonl.gz")):
        raise ToolError("DATA_ERROR", "knowledge must be JSONL, JSONL.GZ or a RAG YAML configuration.")
    if mode != "bm25":
        raise ToolError("MODE_UNAVAILABLE", "Dense and Hybrid require a host-bound indexed YAML configuration.")

    from search_public import search

    return search(query, top_k, path), corpus_hash(path), "bm25", []


def ref(row, snapshot, mode, retrieval_id):
    chunk_id = row["chunk_id"]
    doc_id = row["document_id"]
    text = row.get("content") or row.get("text")
    if not all(isinstance(value, str) and value.strip() for value in (chunk_id, doc_id, text)):
        raise ValueError("Invalid knowledge chunk.")
    if len(chunk_id) > 512 or len(doc_id) > 512:
        raise ValueError("Knowledge chunk identifiers exceed the contract.")
    source_url = row.get("source_url")
    source_url = source_url if isinstance(source_url, str) and 0 < len(source_url) <= 2048 else None
    author = row.get("author")
    match_reason = {
        "bm25": "BM25 term match", "dense": "Dense vector similarity",
        "hybrid": "Dense and BM25 rank fusion", "dense_fallback": "Dense vector fallback",
    }[mode]
    return {
        "retrieval_id": retrieval_id,
        "doc_id": doc_id, "chunk_id": chunk_id,
        "version": str(row.get("source_version") or snapshot)[:512],
        "locator": source_url or f"chunk:{chunk_id}", "excerpt": text[:1200],
        "match_reason": match_reason, "source_url": source_url,
        "author": author[:512] if isinstance(author, str) else None,
    }


def handle(request):
    request_id = request["request_id"]
    try:
        query, top_k, requested_mode = parameters(request["arguments"])
        path = knowledge_path(request["context"])
        rows, snapshot, mode, warnings = retrieve(path, query, top_k, requested_mode)
        retrieval_id = f"rag:{request_id}"
        refs = [ref(row, snapshot, mode, retrieval_id) for row in rows]
    except ToolError as exc:
        return fail(request_id, exc.code, str(exc))
    except ModuleNotFoundError as exc:
        print(f"Optional dependency missing: {exc.name}", file=sys.stderr)
        return fail(request_id, "DEPENDENCY_MISSING", "The selected retriever is missing an installed dependency.")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Knowledge resource: {exc}", file=sys.stderr)
        return fail(request_id, "DATA_ERROR", "The knowledge resource could not be read or parsed.")
    return {
        "protocol_version": "1.0", "request_id": request_id, "ok": True,
        "data": {
            "retrieval_id": retrieval_id, "snapshot_id": snapshot,
            "requested_mode": requested_mode, "mode": mode, "refs": refs,
            "warnings": [str(item)[:512] for item in warnings[:12]],
        },
        "evidence_ids": [],
    }


def main():
    try:
        request = parse_request(sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1))
    except (ValueError, UnicodeError) as exc:
        print(f"Protocol request: {exc}", file=sys.stderr)
        return 2

    sys.path.insert(0, str(ROOT))
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    with contextlib.redirect_stdout(sys.stderr):
        response = handle(request)
    output = json.dumps(response, ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"
    if len(output) > MAX_RESPONSE_BYTES:
        output = json.dumps(fail(request["request_id"], "OUTPUT_LIMIT",
                                 "Response exceeds 1 MiB. Reduce top_k.")).encode("utf-8") + b"\n"
    sys.stdout.buffer.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
