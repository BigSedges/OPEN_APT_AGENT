#!/usr/bin/env python3
"""Convert Linux bash_history (#epoch + command) files to Chainsaw JSON array (.json)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterator, Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib.common import build_base_parser, collect_input_files, write_json_array
from lib.formatters import format_chainsaw_bash_history
from lib.parsers import is_bash_history_file, parse_bash_history_file


def convert(
    inputs: list[str],
    output: str,
    case_id: str = "default",
    user_override: str | None = None,
) -> int:
    files = collect_input_files(inputs, is_bash_history_file)

    def _iter() -> Iterator[dict[str, Any]]:
        for path in files:
            for parsed in parse_bash_history_file(path, case_id=case_id, user_override=user_override):
                yield format_chainsaw_bash_history(parsed)

    count = write_json_array(_iter(), output)
    print(f"[chainsaw_bash_history_json] Converted {count} events from {len(files)} file(s) -> {output}", file=sys.stderr)
    return count


def main() -> None:
    parser = build_base_parser(
        "Convert GNU bash_history files to Chainsaw JSON array with ISO-8601 timestamp and event_id.",
        allow_user=True,
    )
    args = parser.parse_args()
    convert(args.input, args.output, case_id=args.case_id, user_override=args.user)


if __name__ == "__main__":
    main()
