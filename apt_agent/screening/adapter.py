"""Host-side v1 transport registered as StructuredTool for a real ToolNode."""
import asyncio
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

from jsonschema import Draft202012Validator
from langchain_core.messages import ToolMessage
from langchain_core.tools import StructuredTool


class ProtocolTool(StructuredTool):
    def invoke(self, input, config=None, **kwargs):
        call = isinstance(input, dict) and input.get("type") == "tool_call"
        arguments = input.get("args") if call else input
        body = self.func(arguments=arguments)
        text = json.dumps(body, ensure_ascii=True, allow_nan=False)
        if call:
            return ToolMessage(content=text, name=self.name, tool_call_id=input["id"], status="success" if body["ok"] else "error")
        return text

    async def ainvoke(self, input, config=None, **kwargs):
        return await asyncio.to_thread(self.invoke, input, config, **kwargs)


def build_tool(manifest_path, *, case_id, run_id, resources, valid_ids, diagnostics=None):
    path = Path(manifest_path).resolve()
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("protocol_version") != "1.0" or not re.fullmatch("[a-z][a-z0-9_]{0,63}", manifest.get("name", "")):
        raise ValueError("Invalid tool manifest.")
    if not isinstance(manifest.get("tool_version"), str) or not manifest["tool_version"]:
        raise ValueError("Missing tool version.")
    if type(manifest.get("timeout_ms")) is not int or manifest["timeout_ms"] <= 0:
        raise ValueError("Invalid timeout_ms.")
    for schema in [manifest["input_schema"], manifest["output_schema"]]:
        Draft202012Validator.check_schema(schema)
        if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
            raise ValueError("Schemas must be closed objects.")
    reserved = {"runtime", "config", "context", "argv", "request_id", "resources"}
    if reserved & manifest["input_schema"].get("properties", {}).keys():
        raise ValueError("Reserved public argument name.")
    if set(resources) != set(manifest["resources"]):
        raise ValueError("Resource binding mismatch.")
    bound = {key: str(Path(value).resolve(strict=True)) for key, value in resources.items()}
    allowed = frozenset(valid_ids)
    argv = manifest.get("argv")
    if not isinstance(argv, list) or not argv or any(not isinstance(x, str) or not x for x in argv):
        raise ValueError("Invalid argv.")
    argv = list(argv)
    if argv[0] == "{python}":
        argv[0] = sys.executable
    elif "/" in argv[0] or "\\" in argv[0]:
        argv[0] = str((path.parent / argv[0]).resolve())
    if not case_id or not run_id:
        raise ValueError("case_id and run_id are required.")

    def execute(*, arguments):
        request_id = uuid.uuid4().hex
        def fail(code, message, retryable=False):
            return {"protocol_version": "1.0", "request_id": request_id, "ok": False,
                    "error": {"code": code, "message": message, "retryable": retryable}}
        if not Draft202012Validator(manifest["input_schema"]).is_valid(arguments):
            return fail("INVALID_ARGUMENT", "Arguments do not match input_schema.")
        request = {"protocol_version": "1.0", "request_id": request_id, "tool": manifest["name"],
                   "tool_version": manifest["tool_version"], "context": {"case_id": case_id, "run_id": run_id, "resources": bound}, "arguments": arguments}
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
        try:
            completed = subprocess.run(argv, input=json.dumps(request).encode("utf-8"), stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, cwd=path.parent, shell=False, timeout=manifest["timeout_ms"]/1000, env=env)
        except subprocess.TimeoutExpired:
            return fail("TIMEOUT", "Tool process timed out.", True)
        except OSError:
            return fail("START_ERROR", "Cannot start installed tool.")
        if diagnostics is not None and completed.stderr:
            diagnostics({"request_id": request_id, "stderr": completed.stderr[:65536].decode("utf-8", errors="replace")})
        if completed.returncode != 0:
            return fail("PROCESS_EXIT", "Tool returned nonzero exit status.")
        if len(completed.stdout) > 1048576:
            return fail("OUTPUT_LIMIT", "Tool response exceeds 1 MiB.")
        try:
            reply = json.loads(completed.stdout.decode("utf-8"), parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            if reply["protocol_version"] != "1.0" or reply["request_id"] != request_id or type(reply["ok"]) is not bool:
                raise ValueError()
            if reply["ok"]:
                if set(reply) != {"protocol_version", "request_id", "ok", "data", "evidence_ids"}:
                    raise ValueError()
                Draft202012Validator(manifest["output_schema"]).validate(reply["data"])
                ids = reply["evidence_ids"]
                if not isinstance(ids, list) or any(not isinstance(x, str) or not x for x in ids) or len(ids) != len(set(ids)):
                    raise ValueError()
                if set(ids) - allowed:
                    return fail("OUT_OF_SCOPE", "Evidence ID outside bound case.")
            elif set(reply) != {"protocol_version", "request_id", "ok", "error"} or set(reply["error"]) != {"code", "message", "retryable"} or any(not isinstance(reply["error"][k], str) or not reply["error"][k] for k in ["code", "message"]) or type(reply["error"]["retryable"]) is not bool:
                raise ValueError()
            return reply
        except Exception:
            return fail("BAD_RESPONSE", "Response violates the installed protocol/schema.")

    return ProtocolTool(name=manifest["name"], description=manifest["description"], args_schema=manifest["input_schema"], func=execute)
