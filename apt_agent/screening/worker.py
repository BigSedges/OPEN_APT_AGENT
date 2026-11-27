"""One EOF-delimited UTF-8 request, one response, no resource writes/network."""
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator
from .core import DataError, rank


def main(name, manifest_path):
    try:
        raw = sys.stdin.buffer.read(1048577)
        if len(raw) > 1048576:
            return 2
        request = json.loads(raw.decode("utf-8"), parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if not isinstance(request, dict) or not isinstance(request.get("request_id"), str) or not request["request_id"]:
            return 2
    except (ValueError, UnicodeError):
        return 2
    def error(code, message):
        return {"protocol_version": "1.0", "request_id": request["request_id"], "ok": False,
                "error": {"code": code, "message": message, "retryable": False}}
    try:
        manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
        if (request.get("protocol_version"), request.get("tool"), request.get("tool_version")) != ("1.0", name, manifest["tool_version"]):
            raise ValueError("Protocol/tool/version mismatch.")
        args = request.get("arguments")
        if not Draft202012Validator(manifest["input_schema"]).is_valid(args):
            raise ValueError("Arguments do not match input_schema.")
        context = request.get("context")
        if not isinstance(context, dict) or any(not isinstance(context.get(k), str) or not context[k] for k in ["case_id", "run_id"]):
            raise ValueError("Missing host case/run context.")
        resources = context.get("resources", {})
        if set(resources) != {"records", "references"} or any(not isinstance(p, str) or not Path(p).is_absolute() for p in resources.values()):
            raise ValueError("Missing absolute host-bound resource paths.")
        ranking, coverage = rank(resources["records"], resources["references"], name == "rank_fused_candidates")
        k, offset, limit = args.get("k", 5000), args.get("offset", 0), args.get("limit", 100)
        selected = ranking[:k]
        page = selected[offset:offset+limit]
        data = {"method": name, "candidates": page, "coverage": coverage, "selected_count": len(selected),
                "offset": offset, "next_offset": offset+len(page) if offset+len(page) < len(selected) else None,
                "score_semantics": "equal_RRF60_not_probability" if name == "rank_fused_candidates" else "frozen_reference_tail_score_not_probability"}
        Draft202012Validator(manifest["output_schema"]).validate(data)
        response = {"protocol_version": "1.0", "request_id": request["request_id"], "ok": True,
                    "data": data, "evidence_ids": [x["physical_record_id"] for x in page]}
    except DataError as exc:
        response = error("DATA_ERROR", str(exc))
    except ValueError as exc:
        response = error("INVALID_REQUEST", str(exc))
    except Exception:
        response = error("INTERNAL_ERROR", "Screening failed; inspect the installed tool and resources.")
    encoded = json.dumps(response, ensure_ascii=True, allow_nan=False).encode("utf-8") + b"\n"
    if len(encoded) > 1048576:
        encoded = json.dumps(error("OUTPUT_LIMIT", "Page exceeds 1 MiB; request a smaller limit.")).encode("utf-8")
    sys.stdout.buffer.write(encoded)
    return 0
