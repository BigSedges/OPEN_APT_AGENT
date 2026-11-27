#!/usr/bin/env python3
"""Convert Windows Event XML logs (Security/Sysmon) to Hayabusa -J JSONL."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import orjson

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib.common import build_base_parser, collect_input_files
from lib.formatters import format_hayabusa_winxml
from lib.parsers import is_winxml_file, parse_winxml_file


def convert(
    inputs: list[str],
    output: str,
    case_id: str = "default",
    index_out: str | None = None,
) -> int:
    files = collect_input_files(inputs, is_winxml_file)
    count = 0

    idx_fh = None
    if index_out:
        idx_path = Path(index_out)
        idx_path.parent.mkdir(parents=True, exist_ok=True)
        idx_fh = idx_path.open("wb")

    out_fh = None
    try:
        if output == "-":
            stream = sys.stdout.buffer
        else:
            out_path = Path(output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_fh = out_path.open("wb")
            stream = out_fh

        for path in files:
            for parsed in parse_winxml_file(path, case_id=case_id):
                evtx_rec, idx_rec = format_hayabusa_winxml(parsed)
                stream.write(orjson.dumps(evtx_rec) + b"\n")
                if idx_fh is not None:
                    idx_fh.write(orjson.dumps(idx_rec) + b"\n")
                count += 1

        if output == "-":
            stream.flush()
    finally:
        if out_fh is not None:
            out_fh.close()
        if idx_fh is not None:
            idx_fh.close()

    msg = f"[hayabusa_winxml_jsonl] Converted {count} Windows events from {len(files)} file(s) -> {output}"
    if index_out:
        msg += f" (index -> {index_out})"
    print(msg, file=sys.stderr)
    return count


def main() -> None:
    parser = build_base_parser(
        "Convert Windows Event XML logs to Hayabusa v4 -J JSONL for `hayabusa dfir-timeline -J -t jsonl -p super-verbose`.",
        allow_index_out=True,
    )
    args = parser.parse_args()
    convert(args.input, args.output, case_id=args.case_id, index_out=args.index_out)


if __name__ == "__main__":
    main()
