#!/usr/bin/env python3
"""Convert Windows Event XML logs (Security/Sysmon) to Zircolite flat JSONL."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterator, Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib.common import build_base_parser, collect_input_files, write_jsonl
from lib.formatters import format_zircolite_winxml
from lib.parsers import is_winxml_file, parse_winxml_file


def convert(inputs: list[str], output: str, case_id: str = "default") -> int:
    files = collect_input_files(inputs, is_winxml_file)

    def _iter() -> Iterator[dict[str, Any]]:
        for path in files:
            for parsed in parse_winxml_file(path, case_id=case_id):
                yield format_zircolite_winxml(parsed)

    count = write_jsonl(_iter(), output)
    print(f"[zircolite_winxml_jsonl] Converted {count} events from {len(files)} file(s) -> {output}", file=sys.stderr)
    return count


def main() -> None:
    parser = build_base_parser(
        "Convert Windows Event XML logs to Zircolite flat JSONL (--json-input) with event_id."
    )
    args = parser.parse_args()
    convert(args.input, args.output, case_id=args.case_id)


if __name__ == "__main__":
    main()
