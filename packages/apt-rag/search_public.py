"""Search the bundled public ATT&CK/CAR snapshot with Python's standard library."""

import argparse
from collections import Counter
import gzip
import json
import math
from pathlib import Path
import re
import sys


CORPUS = Path(__file__).resolve().parent / "public_kb" / "chunks.jsonl.gz"
TOKEN_RE = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*")


def search(query, top_k=5):
    """Return up to top_k ranked excerpts from the bundled corpus."""
    terms = set(TOKEN_RE.findall(query.lower()))
    if not terms:
        return []

    # Collect frequencies only for query terms. Lengths still count all tokens.
    candidate_data = []
    query_df = Counter()
    document_count = total_length = 0
    with gzip.open(CORPUS, "rt", encoding="utf-8") as source:
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("query", nargs="?", default="Sysmon process creation")
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--json", action="store_true", help="Return JSON with full text and citations.")
    args = parser.parse_args()
    if not args.query.strip():
        parser.error("query must not be empty")
    if not 1 <= args.top_k <= 20:
        parser.error("--top-k must be between 1 and 20")

    # Make non-ASCII source text safe in both Windows shells and UTF-8 terminals.
    sys.stdout.reconfigure(encoding="utf-8")
    results = search(args.query, args.top_k)
    if args.json:
        print(json.dumps({"mode": "bm25", "query": args.query, "results": results}, ensure_ascii=False))
    elif not results:
        print("No matches in the bundled ATT&CK/CAR snapshot.")
    else:
        for i, result in enumerate(results, 1):
            print(f"{i}. {result['title']} [{result['score']:.3f}]")
            print(result["source_url"])
            print(result["excerpt"])
            print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
