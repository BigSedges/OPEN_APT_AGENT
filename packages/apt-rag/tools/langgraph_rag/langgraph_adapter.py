"""Register a v1 subprocess tool as a LangChain StructuredTool."""

import json
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

from jsonschema import Draft202012Validator
from langchain_core.tools import StructuredTool, ToolException

from wire import decode

MAX_RESPONSE = 1024 * 1024


def failure(request_id, code, message, *, retryable=False):
    return {"protocol_version": "1.0", "request_id": request_id, "ok": False,
            "error": {"code": code, "message": message, "retryable": retryable}}


def validate_response(raw, request_id, output_validator, valid_ids):
    if len(raw) > MAX_RESPONSE:
        return failure(request_id, "OUTPUT_LIMIT", "Tool stdout exceeds 1 MiB.")
    try:
        reply = decode(raw)
        if (not isinstance(reply, dict) or reply.get("protocol_version") != "1.0"
                or reply.get("request_id") != request_id or type(reply.get("ok")) is not bool):
            raise ValueError("invalid response envelope")
        fields = {"protocol_version", "request_id", "ok"}
        if reply["ok"]:
            if set(reply) != fields | {"data", "evidence_ids"}:
                raise ValueError("invalid success fields")
            ids = reply["evidence_ids"]
            if (not isinstance(ids, list) or any(not isinstance(i, str) or not i.strip() for i in ids)
                    or len(ids) != len(set(ids)) or not output_validator.is_valid(reply["data"])):
                raise ValueError("invalid success data")
            if not set(ids).issubset(valid_ids):
                return failure(request_id, "OUT_OF_SCOPE", "Tool result references evidence outside this case.")
        else:
            if set(reply) != fields | {"error"}:
                raise ValueError("invalid failure fields")
            error = reply["error"]
            if (not isinstance(error, dict) or set(error) != {"code", "message", "retryable"}
                    or type(error["retryable"]) is not bool
                    or any(not isinstance(error[k], str) or not error[k].strip() for k in ("code", "message"))):
                raise ValueError("invalid failure data")
        return reply
    except (ValueError, UnicodeError):
        return failure(request_id, "BAD_RESPONSE", "Tool response violates the v1 contract.")


def build_tool(manifest_path, *, case_id, run_id, resources, valid_ids=()):
    """Bind resources by absolute path; only the input schema is visible to the model."""
    path = Path(manifest_path).resolve(strict=True)
    manifest = decode(path.read_bytes())
    if manifest["protocol_version"] != "1.0":
        raise ValueError("Unsupported tool protocol version.")
    if not all(isinstance(x, str) and x.strip() for x in (case_id, run_id)):
        raise ValueError("case_id and run_id must be nonblank strings.")
    if set(resources) != set(manifest["resources"]):
        raise ValueError("Host must bind exactly the declared tool resources.")
    bound = {name: str(Path(value).resolve(strict=True)) for name, value in resources.items()}
    allowed = frozenset(valid_ids)
    if manifest["name"] == "search_knowledge":
        allowed = frozenset()
    argv = list(manifest["argv"])
    if argv[0] == "{python}":
        argv[0] = sys.executable
    elif "/" in argv[0] or "\\" in argv[0]:
        argv[0] = str((path.parent / argv[0]).resolve())
    timeout = manifest["timeout_ms"] / 1000
    inputs, outputs = manifest["input_schema"], manifest["output_schema"]
    for schema in (inputs, outputs):
        Draft202012Validator.check_schema(schema)
    input_validator = Draft202012Validator(inputs)
    output_validator = Draft202012Validator(outputs)

    def invoke(**arguments):
        request_id = uuid4().hex
        if not input_validator.is_valid(arguments):
            reply = failure(request_id, "INVALID_ARGUMENT", "Arguments do not match the input schema.")
        else:
            request = {
                "protocol_version": "1.0", "request_id": request_id, "tool": manifest["name"],
                "tool_version": manifest["tool_version"],
                "context": {"case_id": case_id, "run_id": run_id, "resources": bound},
                "arguments": arguments,
            }
            try:
                process = subprocess.run(
                    argv, cwd=path.parent, shell=False, timeout=timeout, capture_output=True,
                    input=json.dumps(request, ensure_ascii=False, allow_nan=False).encode("utf-8"),
                )
            except subprocess.TimeoutExpired:
                reply = failure(request_id, "TIMEOUT", "Tool invocation timed out.", retryable=True)
            except OSError:
                reply = failure(request_id, "START_ERROR", "Tool process could not be started.")
            else:
                if process.stderr:
                    print(process.stderr[-4096:].decode("utf-8", errors="replace"), file=sys.stderr, end="")
                if process.returncode:
                    reply = failure(request_id, "PROCESS_EXIT", f"Tool exited with status {process.returncode}.")
                else:
                    reply = validate_response(process.stdout, request_id, output_validator, allowed)
        content = json.dumps(reply, ensure_ascii=False)
        if not reply["ok"]:
            raise ToolException(content)
        return content

    return StructuredTool.from_function(
        func=invoke, name=manifest["name"], description=manifest["description"],
        args_schema=inputs, infer_schema=False, handle_tool_error=True,
    )
