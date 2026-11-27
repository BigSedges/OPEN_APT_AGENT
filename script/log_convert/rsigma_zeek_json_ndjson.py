#!/usr/bin/env python3
"""Convert Zeek JSON logs to RSigma UTC-sorted NDJSON."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterator, Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib.common import build_base_parser, collect_input_files, write_jsonl
from lib.formatters import format_rsigma_zeek
from lib.parsers import is_zeek_json_file, parse_zeek_json_file


def convert(
    inputs: list[str],
    output: str,
    case_id: str = "default",
    sort_utc: bool = True,
) -> int:
    files = collect_input_files(inputs, is_zeek_json_file)

    def _iter() -> Iterator[dict[str, Any]]:
        for path in files:
            for parsed in parse_zeek_json_file(path, case_id=case_id):
                yield format_rsigma_zeek(parsed)

    count = write_jsonl(_iter(), output, sort_by_timestamp=sort_utc, timestamp_key="@timestamp")
    print(f"[rsigma_zeek_json_ndjson] Converted {count} events from {len(files)} file(s) -> {output}", file=sys.stderr)
    return count


def main() -> None:
    parser = build_base_parser(
        "Convert Zeek JSONL logs to RSigma UTC-sorted NDJSON with @timestamp and event_id.",
        allow_no_sort=True,
    )
    args = parser.parse_args()
    convert(args.input, args.output, case_id=args.case_id, sort_utc=not args.no_sort)


if __name__ == "__main__":
    main()
