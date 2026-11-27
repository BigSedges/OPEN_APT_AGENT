#!/usr/bin/env python3
"""Convert Apache/Nginx Combined Web Access logs to Chainsaw JSON array (.json)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterator, Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib.common import build_base_parser, collect_input_files, write_json_array
from lib.formatters import format_chainsaw_web_access
from lib.parsers import is_web_access_file, parse_web_access_file


def convert(inputs: list[str], output: str, case_id: str = "default") -> int:
    files = collect_input_files(inputs, is_web_access_file)

    def _iter() -> Iterator[dict[str, Any]]:
        for path in files:
            for parsed in parse_web_access_file(path, case_id=case_id):
                yield format_chainsaw_web_access(parsed)

    count = write_json_array(_iter(), output)
    print(f"[chainsaw_web_access_json] Converted {count} events from {len(files)} file(s) -> {output}", file=sys.stderr)
    return count


def main() -> None:
    parser = build_base_parser(
        "Convert Apache/Nginx Combined web access logs to Chainsaw JSON array with Sigma webserver fields."
    )
    args = parser.parse_args()
    convert(args.input, args.output, case_id=args.case_id)


if __name__ == "__main__":
    main()
