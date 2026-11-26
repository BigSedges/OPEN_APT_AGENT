"""Command-line interface for apt_rag."""

from __future__ import annotations

import argparse
import json
from importlib.metadata import PackageNotFoundError, version

from .client import RagClient, RagClientError


def _version() -> str:
    try:
        return version("apt-rag")
    except PackageNotFoundError:
        return "0.1.0"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Query the local APT RAG knowledge index")
    parser.add_argument("--config", required=True, help="path to rag.yaml")
    parser.add_argument("--query", required=True, help="natural-language query")
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--mode", choices=("dense", "bm25", "hybrid"), default=None)
    parser.add_argument("--no-verify-hashes", action="store_true", help="skip corpus/index hash verification")
    parser.add_argument("--version", action="version", version=f"apt-rag {_version()}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        client = RagClient.from_config(args.config, verify_hashes=not args.no_verify_hashes)
    except RagClientError as exc:
        print(json.dumps({"error": {"code": exc.code, "message": exc.message}}, ensure_ascii=False, indent=2))
        return 2
    result = client.search(args.query, top_k=args.top_k, mode=args.mode)
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    return 1 if result.error else 0


if __name__ == "__main__":
    raise SystemExit(main())
