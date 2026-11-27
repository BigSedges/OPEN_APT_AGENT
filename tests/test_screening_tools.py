"""Only synthetic fixtures. Exercise real subprocesses and real ToolNode, no API key."""
import json
import asyncio
import os
from pathlib import Path
import sys
import shutil

os.environ["LANGSMITH_TRACING"] = "false"
os.environ["LANGCHAIN_TRACING_V2"] = "false"
import pytest
from langchain_core.messages import AIMessage
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode
from apt_agent.screening.adapter import build_tool

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def resources(tmp_path):
    def record(rid, value, entity="subject\x1fsynthetic"):
        return {"physical_record_id": rid, "host": "demo-host", "source_type": "synthetic",
                "categories": [value]*7, "numbers": [float(value)]*16, "entity": entity}
    records = tmp_path/"records.jsonl"
    records.write_text("\n".join(json.dumps(record("demo-"+str(i), i+1)) for i in range(5)), encoding="utf-8")
    ref = tmp_path/"reference"
    ref.mkdir()
    (ref/"reference.jsonl").write_text("\n".join(json.dumps(record("ref-"+str(i), i+1)) for i in range(8)), encoding="utf-8")
    return {"records": records, "references": ref}


def call(manifest, resources, args, valid_ids=None):
    tool = build_tool(manifest, case_id="synthetic-case", run_id="synthetic-run", resources=resources,
                      valid_ids={"demo-"+str(i) for i in range(5)} if valid_ids is None else valid_ids)
    graph = StateGraph(MessagesState)
    graph.add_node("tools", ToolNode([tool]))
    graph.add_edge(START, "tools")
    graph.add_edge("tools", END)
    result = graph.compile().invoke({"messages": [AIMessage(content="", tool_calls=[{"id": "call-demo", "type": "tool_call", "name": tool.name, "args": args}])]})
    msg = result["messages"][-1]
    assert msg.tool_call_id == "call-demo"
    data = json.loads(msg.content)
    assert msg.status == ("success" if data["ok"] else "error")
    return data


@pytest.mark.parametrize("method", ["copod", "fusion"])
def test_success_empty_invalid_scope(method, resources):
    manifest = ROOT/"tools"/method/"tool.json"
    reply = call(manifest, resources, {"k": 5, "limit": 2})
    assert reply["ok"] and len(reply["evidence_ids"]) == 2
    assert reply["data"]["next_offset"] == 2
    second = call(manifest, resources, {"k": 5, "offset": 2, "limit": 3})
    assert not set(reply["evidence_ids"]) & set(second["evidence_ids"])
    assert len(second["evidence_ids"]) == 3
    assert call(manifest, resources, {"k": 0})["evidence_ids"] == []
    assert call(manifest, resources, {"k": "5"})["error"]["code"] == "INVALID_ARGUMENT"
    assert call(manifest, resources, {"resources": "model-path"})["error"]["code"] == "INVALID_ARGUMENT"
    assert call(manifest, resources, {"k": 1}, valid_ids=set())["error"]["code"] == "OUT_OF_SCOPE"


def test_bad_resource(resources):
    resources["records"].write_text('{"broken":true}\n', encoding="utf-8")
    assert call(ROOT/"tools/copod/tool.json", resources, {})["error"]["code"] == "DATA_ERROR"


def test_empty_resource(resources):
    resources["records"].write_text('', encoding="utf-8")
    r = call(ROOT/"tools/copod/tool.json", resources, {})
    assert r["ok"] and r["evidence_ids"] == [] and r["data"]["coverage"]["records"] == 0


@pytest.mark.parametrize("mode,expected", [("timeout", "TIMEOUT"), ("exit", "PROCESS_EXIT"), ("noise", "BAD_RESPONSE"), ("id", "BAD_RESPONSE"), ("schema", "BAD_RESPONSE"), ("big", "OUTPUT_LIMIT")])
def test_transport_errors(tmp_path, resources, mode, expected):
    manifest = json.loads((ROOT/"tools/copod/tool.json").read_text(encoding="utf-8"))
    manifest["resources"] = ["records", "references"]
    manifest["argv"] = ["{python}", "fake.py"]
    if mode == "timeout":
        manifest["timeout_ms"] = 20
    bodies = {"timeout": "import time;time.sleep(2)", "exit": "raise SystemExit(3)", "noise": "print('diagnostic on stdout')",
              "id": "import json;print(json.dumps({'protocol_version':'1.0','request_id':'wrong','ok':True}))",
              "schema": "import json,sys;r=json.load(sys.stdin);print(json.dumps({'protocol_version':'1.0','request_id':r['request_id'],'ok':True,'data':{},'evidence_ids':[]}))",
              "big": "print('x'*1048577)"}
    (tmp_path/"fake.py").write_text(bodies[mode])
    path = tmp_path/"tool.json"
    path.write_text(json.dumps(manifest))
    assert call(path, resources, {})["error"]["code"] == expected


def test_business_error_and_duplicate_evidence(tmp_path, resources):
    manifest = json.loads((ROOT/"tools/copod/tool.json").read_text(encoding="utf-8"))
    # Reuse a valid real response, then mutate only the wire contract.
    reply = call(ROOT/"tools/copod/tool.json", resources, {"k": 1})
    reply["evidence_ids"] *= 2
    manifest["argv"] = ["{python}", "fake.py"]
    path = tmp_path/"tool.json"
    path.write_text(json.dumps(manifest))
    (tmp_path/"fake.py").write_text("import json,sys\nr=json.load(sys.stdin)\nx="+repr(reply)+"\nx['request_id']=r['request_id']\nprint(json.dumps(x))\n")
    assert call(path, resources, {})["error"]["code"] == "BAD_RESPONSE"


def test_async_parallel_calls(resources):
    tools = [build_tool(ROOT/"tools"/m/"tool.json", case_id="demo", run_id="r", resources=resources,
                        valid_ids={"demo-"+str(i) for i in range(5)}) for m in ["copod", "fusion"]]
    assert set(tools[0].tool_call_schema["properties"]) == {"k", "offset", "limit"}
    graph = StateGraph(MessagesState)
    graph.add_node("tools", ToolNode(tools))
    graph.add_edge(START, "tools")
    graph.add_edge("tools", END)
    calls = [{"id": "parallel-"+str(i), "name": t.name, "type": "tool_call", "args": {"k": 1}} for i,t in enumerate(tools)]
    result = asyncio.run(graph.compile().ainvoke({"messages": [AIMessage(content="", tool_calls=calls)]}))
    messages = result["messages"][1:]
    assert {m.tool_call_id for m in messages} == {c["id"] for c in calls}
    assert all(m.status == "success" and json.loads(m.content)["ok"] for m in messages)
    assert len({json.loads(m.content)["request_id"] for m in messages}) == 2


def test_start_error(tmp_path, resources):
    manifest = json.loads((ROOT/"tools/copod/tool.json").read_text(encoding="utf-8"))
    manifest["argv"] = ["./missing-program"]
    p = tmp_path/"tool.json"
    p.write_text(json.dumps(manifest), encoding="utf-8")
    assert call(p, resources, {})["error"]["code"] == "START_ERROR"
