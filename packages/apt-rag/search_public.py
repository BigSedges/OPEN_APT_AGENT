"""Search the bundled public snapshot or a user-provided full v2 asset root."""

import argparse
from collections import Counter
import gzip
import json
import math
from pathlib import Path
import re
import sys
import tempfile


CORPUS = Path(__file__).resolve().parent / "public_kb" / "chunks.jsonl.gz"
TOKEN_RE = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*")


def search(query, top_k=5, corpus=CORPUS):
    """Return up to top_k ranked excerpts from the bundled corpus."""
    terms = set(TOKEN_RE.findall(query.lower()))
    if not terms:
        return []

    # Collect frequencies only for query terms. Lengths still count all tokens.
    candidate_data = []
    query_df = Counter()
    document_count = total_length = 0
    corpus = Path(corpus)
    open_corpus = gzip.open if corpus.suffix == ".gz" else open
    with open_corpus(corpus, "rt", encoding="utf-8") as source:
        for line in source:
            chunk = json.loads(line)
            tokens = TOKEN_RE.findall(chunk["text"].lower())
            document_count += 1
            total_length += len(tokens)
            frequencies = Counter(token for token in tokens if token in terms)
            if frequencies:
                query_df.update(frequencies.keys())
                candidate_data.append((chunk, len(tokens), frequencies))
    if not candidate_data:
        return []

    k1, b = 1.5, 0.75
    avg_length = total_length / document_count
    idf = {word: math.log1p((document_count - df + 0.5) / (df + 0.5))
           for word, df in query_df.items()}
    ranked = []
    for chunk, length, frequencies in candidate_data:
        norm = k1 * (1 - b + b * length / avg_length)
        score = math.fsum(idf[word] * tf * (k1 + 1) / (tf + norm)
                          for word, tf in frequencies.items())
        ranked.append((chunk, score))
    ranked.sort(key=lambda item: (-item[1], item[0]["chunk_id"]))
    return [dict(chunk, score=round(score, 8), excerpt=chunk["text"][:1200])
            for chunk, score in ranked[:top_k]]


def search_full(query, top_k, root, mode, model_dir, device):
    """Use the original retrievers and verified indexes from a local snapshot."""
    from apt_rag import RagClient

    root = Path(root).expanduser().resolve()
    model = Path(model_dir).expanduser().resolve() if model_dir else root / "models/bge-m3"
    if mode != "bm25" and not model.is_dir():
        raise FileNotFoundError(f"BGE-M3 not found at {model}; provide --model-dir")
    config = {
        "project_root": str(root),
        "paths": {
            "corpus": "public-build/corpus-v2-docs-20261126/chunks.jsonl",
            "index_pointer": "indexes/full-current-v2.json",
            "bm25_pointer": "indexes/bm25-current-v2.json",
            "model": str(model),
        },
        "retrieval": {"mode": "dense", "max_context_chars": 6000, "max_chunks_per_document": 2},
        "model": {"device": device, "offline": True, "max_seq_length": 1024},
    }
    with tempfile.TemporaryDirectory(prefix="apt-rag-") as tmp:
        path = Path(tmp) / "rag.yaml"
        # JSON is valid YAML; paths are kept absolute when dependent on the caller.
        path.write_text(json.dumps(config), encoding="utf-8")
        return RagClient.from_config(path).search(query, top_k=top_k, mode=mode).to_dict()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("query", nargs="?", default="Sysmon process creation")
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--json", action="store_true", help="Return JSON with full text and citations.")
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument("--corpus", type=Path, help="Search a local JSONL or JSONL.GZ using portable BM25.")
    inputs.add_argument("--asset-root", type=Path, help="Use a full v2 asset root with the original retrievers.")
    parser.add_argument("--mode", choices=("bm25", "dense", "hybrid"), default="bm25")
    parser.add_argument("--model-dir", type=Path, help="Existing BGE-M3 model for --asset-root.")
    parser.add_argument("--device", default="cpu", help="Embedding device for --asset-root (default: cpu).")
    args = parser.parse_args()
    if not args.query.strip():
        parser.error("query must not be empty")
    if not 1 <= args.top_k <= 20:
        parser.error("--top-k must be between 1 and 20")
    if not args.asset_root and (args.mode != "bm25" or args.model_dir):
        parser.error("Dense/Hybrid and --model-dir require --asset-root")

    # Make non-ASCII source text safe in both Windows shells and UTF-8 terminals.
    sys.stdout.reconfigure(encoding="utf-8")
    try:
        if args.asset_root:
            payload = search_full(args.query, args.top_k, args.asset_root, args.mode, args.model_dir, args.device)
        else:
            payload = {
                "mode": "bm25", "query": args.query,
                "results": search(args.query, args.top_k, args.corpus or CORPUS),
            }
    except ModuleNotFoundError as exc:
        parser.exit(2, f"Missing dependency ({exc.name}). See the full snapshot install instructions.\n")
    except (OSError, RuntimeError, ValueError, KeyError) as exc:
        parser.exit(2, f"Cannot search the selected snapshot: {exc}\n")
    results = payload["results"]
    if args.json:
        print(json.dumps(payload, ensure_ascii=False))
    elif payload.get("error"):
        print(payload["error"], file=sys.stderr)
    elif not results:
        print("No matches in the selected snapshot.")
    else:
        for i, result in enumerate(results, 1):
            score = result.get("score", result.get("retrieval_score", 0))
            print(f"{i}. {result.get('title') or result.get('chunk_id')} [{score:.3f}]")
            print(result.get("source_url") or "")
            if result.get("author"):
                print(f"Author: {result['author']}")
            print(result.get("excerpt") or str(result.get("text", ""))[:1200])
            print()
    return 2 if payload.get("error") else 0


if __name__ == "__main__":
    raise SystemExit(main())
