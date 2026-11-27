#!/usr/bin/env python3
"""Convert Windows Event XML logs (Security/Sysmon) to Chainsaw JSON array (.json)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterator, Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib.common import build_base_parser, collect_input_files, write_json_array
from lib.formatters import format_chainsaw_winxml
from lib.parsers import is_winxml_file, parse_winxml_file


def convert(inputs: list[str], output: str, case_id: str = "default") -> int:
    files = collect_input_files(inputs, is_winxml_file)

    def _iter() -> Iterator[dict[str, Any]]:
        for path in files:
            for parsed in parse_winxml_file(path, case_id=case_id):
                yield format_chainsaw_winxml(parsed)

    count = write_json_array(_iter(), output)
    print(f"[chainsaw_winxml_json] Converted {count} events from {len(files)} file(s) -> {output}", file=sys.stderr)
    return count


def main() -> None:
    parser = build_base_parser(
        "Convert Windows Event XML logs to Chainsaw JSON array (compatible with sigma-event-logs-json.yml)."
    )
    args = parser.parse_args()
    convert(args.input, args.output, case_id=args.case_id)


if __name__ == "__main__":
    main()
