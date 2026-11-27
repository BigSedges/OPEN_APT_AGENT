"""Run the tool protocol through a real LangGraph ToolNode without a chat model."""

import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from unittest import TestCase, main

from langchain_core.messages import AIMessage
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode

from langgraph_adapter import build_tool

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "tool.json"
SAMPLE = HERE / "sample_knowledge.jsonl"


def graph_for(tool):
    graph = StateGraph(MessagesState)
    graph.add_node("tools", ToolNode([tool]))
    graph.add_edge(START, "tools")
    graph.add_edge("tools", END)
    return graph.compile()


def bind(path=MANIFEST, knowledge=SAMPLE):
    return graph_for(build_tool(path, case_id="demo", run_id="run-1", resources={"knowledge": knowledge}))


def dispatch(graph, *args):
    calls = [{"name": "search_knowledge", "args": a, "id": f"t{i}", "type": "tool_call"}
             for i, a in enumerate(args)]
    messages = graph.invoke({"messages": [AIMessage(content="", tool_calls=calls)]})["messages"][1:]
    assert {m.tool_call_id for m in messages} == {c["id"] for c in calls}
    return {m.tool_call_id: (m.status, json.loads(m.content)) for m in messages}


class Smoke(TestCase):
    def test_matches_and_empty_parallel(self):
        result = dispatch(bind(), {"query": "demo_event"}, {"query": "no-match-745xz"})
        state, match = result["t0"]
        self.assertEqual(state, "success")
        self.assertTrue(match["ok"])
        self.assertEqual(match["evidence_ids"], [])
        self.assertEqual(match["data"]["refs"][0]["chunk_id"], "kb-demo-1")
        self.assertEqual(match["data"]["refs"][0]["retrieval_id"], match["data"]["retrieval_id"])
        state, empty = result["t1"]
        self.assertEqual(state, "success")
        self.assertTrue(empty["ok"])
        self.assertEqual(empty["data"]["refs"], [])
        self.assertNotEqual(match["request_id"], empty["request_id"])

    def test_argument_and_mode_failures(self):
        graph = bind()
        for arguments, code in [
            ({"query": 1}, "INVALID_ARGUMENT"),
            ({"query": "demo", "top_k": True}, "INVALID_ARGUMENT"),
            ({"query": "demo", "resources": {}}, "INVALID_ARGUMENT"),
            ({"query": "demo", "mode": "dense"}, "MODE_UNAVAILABLE"),
        ]:
            with self.subTest(arguments=arguments):
                status, reply = dispatch(graph, arguments)["t0"]
                self.assertEqual(status, "error")
                self.assertEqual(reply["error"]["code"], code)

    def test_corrupt_resource_returns_business_failure(self):
        with TemporaryDirectory() as folder:
            broken = Path(folder) / "broken.jsonl"
            broken.write_text("{\n", encoding="utf-8")
            status, reply = dispatch(bind(knowledge=broken), {"query": "demo"})["t0"]
        self.assertEqual(status, "error")
        self.assertEqual(reply["error"]["code"], "DATA_ERROR")
        self.assertFalse(reply["error"]["retryable"])

    def test_invalid_wire_input_uses_nonzero_exit(self):
        proc = subprocess.run([sys.executable, "-B", str(HERE / "worker.py")],
                              input=b'{"broken":NaN}', capture_output=True, timeout=10)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, b"")

    def test_host_rejects_broken_process_responses(self):
        original = json.loads(MANIFEST.read_text(encoding="utf-8"))
        with TemporaryDirectory() as folder:
            root = Path(folder)
            for index, (code, program) in enumerate([
                ("PROCESS_EXIT", "raise SystemExit(7)"),
                ("TIMEOUT", "import time; time.sleep(10)"),
                ("BAD_RESPONSE", "print('unexpected stdout')"),
                ("BAD_RESPONSE", "print('{\"protocol_version\":\"1.0\",\"request_id\":\"wrong\",\"ok\":true}')"),
                ("BAD_RESPONSE", "import sys,json; r=json.load(sys.stdin); print(json.dumps(dict(protocol_version='1.0',request_id=r['request_id'],ok=True,data={},evidence_ids=[])))"),
                ("OUTPUT_LIMIT", "print('x' * (1024 * 1024))"),
                ("OUT_OF_SCOPE", "import sys,json; r=json.load(sys.stdin); d=dict(retrieval_id='r',snapshot_id='s',requested_mode='bm25',mode='bm25',refs=[],warnings=[]); print(json.dumps(dict(protocol_version='1.0',request_id=r['request_id'],ok=True,data=d,evidence_ids=['pr-demo'])))"),
            ]):
                with self.subTest(index=index, code=code):
                    worker = root / f"fake{index}.py"
                    worker.write_text(program, encoding="utf-8")
                    manifest = root / "tool.json"
                    manifest.write_text(json.dumps({
                        **original, "argv": ["{python}", "-B", worker.name],
                        "timeout_ms": 250 if code == "TIMEOUT" else 5000,
                    }), encoding="utf-8")
                    status, reply = dispatch(bind(manifest), {"query": "demo"})["t0"]
                    self.assertEqual(status, "error")
                    self.assertEqual(reply["error"]["code"], code)


if __name__ == "__main__":
    main(verbosity=2)
