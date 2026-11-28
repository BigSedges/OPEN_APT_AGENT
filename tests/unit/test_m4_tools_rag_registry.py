"""Comprehensive unit and integration tests for Milestone M4 (F06, F08, F13)."""

from __future__ import annotations

import gzip
import json
import os
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pytest
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.utils.function_calling import convert_to_openai_tool
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode

from apt_agent.config import AppConfig, RagConfig, SnapshotsConfig
from apt_agent.exceptions import (
    ConflictError,
    ErrorCode,
    InvalidArgumentError,
    OperationTimeoutError,
    OutOfScopeError,
    PermissionDeniedError,
)
from apt_agent.ingestion.store import ingest_records
from apt_agent.models import Event, KnowledgeRef, RunContext
from apt_agent.tools import (
    DEFAULT_BASH_ALLOWLIST,
    DEFAULT_PUBLIC_KB_PATH,
    INVESTIGATION_ROLES,
    MAINTENANCE_ROLES,
    AuditLogEntry,
    BaseToolset,
    RagService,
    ToolCallResult,
    ToolRegistry,
    correlate_lineage_and_flows,
    fetch_raw_evidence,
    query_events,
    tool_bash,
    tool_edit,
    tool_read,
    tool_write,
)


def _make_ctx(
    tmp_path: Path,
    *,
    case_id: str = "case-m4",
    run_id: str = "run-m4",
    valid_physical_ids: frozenset[str] | None = None,
    rag_config: RagConfig | None = None,
) -> RunContext:
    cfg = AppConfig(
        rag=rag_config or RagConfig(),
        snapshots=SnapshotsConfig(root_dir=tmp_path / "snapshots"),
    )
    return RunContext(
        case_id=case_id,
        run_id=run_id,
        config=cfg,
        valid_physical_ids=valid_physical_ids,
    )


def _sample_events() -> list[Event]:
    return [
        Event(
            event_id="evt_parent",
            physical_record_id="pr-1",
            source_type="winxml_sysmon",
            event_time="2024-05-30T10:00:01Z",
            host="WKS-01",
            fields={
                "Computer": "WKS-01",
                "ProcessGuid": "{GUID-PARENT}",
                "ProcessId": "1000",
                "Image": "C:\\Program Files\\Office\\WINWORD.EXE",
                "CommandLine": "winword.exe doc.docx",
                "User": "CORP\\alice",
            },
        ),
        Event(
            event_id="evt_child_subsec",
            physical_record_id="pr-2",
            source_type="winxml_sysmon",
            event_time="2024-05-30T10:00:01.123456Z",
            host="WKS-01",
            fields={
                "Computer": "WKS-01",
                "ProcessGuid": "{GUID-CHILD}",
                "ParentProcessGuid": "{GUID-PARENT}",
                "ProcessId": "4242",
                "ParentProcessId": "1000",
                "Image": "C:\\Windows\\System32\\powershell.exe",
                "CommandLine": "powershell.exe -nop -enc SQBFAFgA",
                "User": "CORP\\alice",
            },
        ),
        Event(
            event_id="evt_net_sysmon",
            physical_record_id="pr-3",
            source_type="winxml_sysmon",
            event_time="2024-05-30T10:00:02Z",
            host="WKS-01",
            fields={
                "Computer": "WKS-01",
                "ProcessGuid": "{GUID-CHILD}",
                "ProcessId": "4242",
                "SourceIp": "10.0.1.8",
                "SourcePort": 51030,
                "DestinationIp": "203.0.113.8",
                "DestinationPort": 443,
                "Protocol": "tcp",
            },
        ),
        Event(
            event_id="evt_zeek_conn",
            physical_record_id="pr-4",
            source_type="zeek_conn",
            event_time="2024-05-30T10:00:02.500000Z",
            host=None,
            fields={
                "uid": "C12345",
                "id.orig_h": "10.0.1.8",
                "id.orig_p": 51030,
                "id.resp_h": "203.0.113.8",
                "id.resp_p": 443,
                "proto": "tcp",
            },
        ),
        Event(
            event_id="evt_notime",
            physical_record_id="pr-5",
            source_type="bash_history",
            event_time=None,
            host="APP-LNX-02",
            fields={"command": "whoami", "User": "bob"},
        ),
    ]


# ---------------------------------------------------------------------------
# 1. F13 Base Tools & Sandbox Guards
# ---------------------------------------------------------------------------


def test_base_tools_read_write_edit_and_sandbox_security(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_secret = outside / "secret.txt"
    outside_secret.write_text("TOP_SECRET", encoding="utf-8")
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir()
    snap_file = snapshots / "v1.yaml"
    snap_file.write_text("immutable: true\n", encoding="utf-8")

    # Normal write + edit + read
    w_res = tool_write("rules/test.yml", "line1\nline2\nline3\n", sandbox_root=sandbox)
    assert w_res["created"] is True
    assert Path(w_res["path"]).is_file()

    with pytest.raises(ConflictError):
        tool_write("rules/test.yml", "other", sandbox_root=sandbox, overwrite=False)

    e_res = tool_edit("rules/test.yml", "line2", "line2_edited", sandbox_root=sandbox)
    assert e_res["replacements"] == 1

    r_res = tool_read("rules/test.yml", allowed_roots=[sandbox], offset=1, limit=1)
    assert r_res["content"] == "line2_edited"
    assert r_res["returned_lines"] == 1
    assert r_res["total_lines"] == 3
    assert r_res["truncated"] is True

    # Multiple matches without replace_all -> InvalidArgumentError
    tool_write("dup.txt", "abc\nabc\n", sandbox_root=sandbox)
    with pytest.raises(InvalidArgumentError):
        tool_edit("dup.txt", "abc", "xyz", sandbox_root=sandbox, replace_all=False)
    dup_edit = tool_edit("dup.txt", "abc", "xyz", sandbox_root=sandbox, replace_all=True)
    assert dup_edit["replacements"] == 2

    # Path traversal, null bytes, Windows drive prefix
    for bad in ("../outside/secret.txt", "a/\x00b", "C:\\Windows\\win.ini"):
        with pytest.raises(OutOfScopeError):
            tool_read(bad, allowed_roots=[sandbox])
        with pytest.raises(OutOfScopeError):
            tool_write(bad, "x", sandbox_root=sandbox)

    # Boolean offset/limit rejected
    with pytest.raises(InvalidArgumentError):
        tool_read("dup.txt", allowed_roots=[sandbox], offset=True)  # type: ignore[arg-type]

    # Symlink pointing outside sandbox
    esc_link = sandbox / "escape_link"
    esc_link.symlink_to(outside)
    with pytest.raises(OutOfScopeError):
        tool_read("escape_link/secret.txt", allowed_roots=[sandbox])
    with pytest.raises(OutOfScopeError):
        tool_edit("escape_link/secret.txt", "TOP", "NEW", sandbox_root=sandbox)

    # Non-existent leaf under an escaping symlink MUST be blocked and create nothing outside
    with pytest.raises(OutOfScopeError):
        tool_write("escape_link/newdir/pwned.txt", "pwned", sandbox_root=sandbox)
    assert not (outside / "newdir").exists()

    # Protected roots cannot be mutated
    with pytest.raises(PermissionDeniedError):
        tool_write(
            str(snap_file),
            "mutated",
            sandbox_root=tmp_path,
            protected_roots=[snapshots],
        )


def test_base_tool_bash_sandbox_allowlist_timeout_output_and_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "host_secret.txt").write_text("SECRET", encoding="utf-8")
    (sandbox / "sample.txt").write_text("alpha|beta\ngamma\n" * 20, encoding="utf-8")

    monkeypatch.setenv("OPENAI_API_KEY", "sk-must-not-leak")
    monkeypatch.setenv("APT_AGENT_LLM_API_KEY", "sk-must-not-leak-2")

    # Allowed command works, including quoted pipe inside grep pattern
    res = tool_bash(["grep", "alpha|beta", "sample.txt"], sandbox_root=sandbox)
    assert res["returncode"] == 0
    assert "alpha|beta" in res["stdout"]

    res_str = tool_bash('grep "alpha|beta" sample.txt', sandbox_root=sandbox)
    assert res_str["returncode"] == 0

    # Output truncation
    trunc = tool_bash("cat sample.txt", sandbox_root=sandbox, max_output_bytes=16)
    assert trunc["truncated"] is True
    assert len(trunc["stdout"].encode("utf-8")) <= 16

    # Shell control operators and command chaining blocked
    for chained in (
        "ls; id",
        "ls|cat",
        "ls && echo pwn",
        "echo `id`",
        "echo $(id)",
        "echo hi > out.txt",
        "ls\nid",
    ):
        with pytest.raises(PermissionDeniedError):
            tool_bash(chained, sandbox_root=sandbox)

    # Disallowed binaries (including bare python/sh/bash) blocked by default allowlist
    for bad_cmd in ("python -c 'print(1)'", "bash -c ls", "sh -c id", "curl http://x"):
        with pytest.raises(PermissionDeniedError):
            tool_bash(bad_cmd, sandbox_root=sandbox)

    # Out-of-sandbox path arguments blocked
    for bad_path_cmd in (
        "cat ../outside/host_secret.txt",
        f"cat {outside / 'host_secret.txt'}",
        "cat ~/.bashrc",
    ):
        with pytest.raises(OutOfScopeError):
            tool_bash(bad_path_cmd, sandbox_root=sandbox)

    # Sensitive env vars stripped (check using allowlisted env/printenv if explicitly allowlisted)
    env_res = tool_bash(
        "env",
        sandbox_root=sandbox,
        allowed_commands={*DEFAULT_BASH_ALLOWLIST, "env"},
    )
    assert "OPENAI_API_KEY" not in env_res["stdout"]
    assert "APT_AGENT_LLM_API_KEY" not in env_res["stdout"]
    assert f"HOME={sandbox.resolve()}" in env_res["stdout"]

    # Timeout raises OperationTimeoutError
    with pytest.raises(OperationTimeoutError):
        tool_bash(
            ["sleep", "2"],
            sandbox_root=sandbox,
            allowed_commands={"sleep"},
            timeout_s=0.1,
        )

    toolset = BaseToolset(sandbox_root=sandbox)
    assert toolset.read("sample.txt", limit=1)["returned_lines"] == 1


# ---------------------------------------------------------------------------
# 2. F08 Typed Investigation Query Tools
# ---------------------------------------------------------------------------


def test_investigation_fetch_raw_evidence_and_scope(tmp_path: Path) -> None:
    ctx = _make_ctx(tmp_path, valid_physical_ids=frozenset({"pr-1", "pr-2"}))
    store = ingest_records(
        [("pr-1", {"msg": "first"}), ("pr-2", {"msg": "second"})],
        case_id=ctx.case_id,
        run_id=ctx.run_id,
    )

    res = fetch_raw_evidence(ctx, store, ["pr-2", "pr-1", "pr-2", "pr-missing"], task_id="t1")
    assert [r.physical_record_id for r in res["records"]] == ["pr-2", "pr-1"]
    assert res["missing_ids"] == ["pr-missing"]
    assert res["evidence_ids"] == ["pr-2", "pr-1"]
    assert res["query_id"].startswith("qry_")

    # strict_scope rejects missing ID outside valid_physical_ids
    with pytest.raises(OutOfScopeError):
        fetch_raw_evidence(ctx, store, ["pr-outside"], strict_scope=True)

    # Cross-case store rejected
    other_store = ingest_records([("pr-1", {"msg": "x"})], case_id="other-case", run_id="r2")
    with pytest.raises(OutOfScopeError):
        fetch_raw_evidence(ctx, other_store, ["pr-1"])


def test_investigation_query_events_sort_pagination_window_empty_and_edges(
    tmp_path: Path,
) -> None:
    ctx = _make_ctx(tmp_path)
    events = _sample_events()

    # Chronological UTC sort: whole second Z < .123456Z < .500000Z < None last
    page1 = query_events(ctx, events, "task-1", limit=2)
    assert page1["event_ids"] == ["evt_parent", "evt_child_subsec"]
    assert page1["next_cursor"] is not None

    page2 = query_events(ctx, events, "task-1", limit=2, cursor=page1["next_cursor"])
    assert page2["event_ids"] == ["evt_net_sysmon", "evt_zeek_conn"]
    assert page2["next_cursor"] is not None

    page3 = query_events(ctx, events, "task-1", limit=2, cursor=page2["next_cursor"])
    assert page3["event_ids"] == ["evt_notime"]
    assert page3["next_cursor"] is None

    # Tampered or mismatched cursor rejected
    with pytest.raises(InvalidArgumentError):
        query_events(ctx, events, "task-1", filters={"host": "WKS-01"}, cursor=page1["next_cursor"])
    with pytest.raises(InvalidArgumentError):
        query_events(ctx, events, "task-1", cursor="not-valid-base64")

    # Unknown filter key rejected
    with pytest.raises(InvalidArgumentError):
        query_events(ctx, events, "task-1", filters={"unknown_key": "x"})

    # Half-open [start, end) window: start inclusive, end exclusive
    win_res = query_events(
        ctx,
        events,
        "task-1",
        filters={"time_window": ["2024-05-30T10:00:01Z", "2024-05-30T10:00:02Z"]},
    )
    assert win_res["event_ids"] == ["evt_parent", "evt_child_subsec"]

    # Zeek prefix filter + entity filter
    zeek_res = query_events(ctx, events, "task-1", filters={"source_type": "zeek"})
    assert zeek_res["event_ids"] == ["evt_zeek_conn"]

    # Empty result records covered_scope
    empty_res = query_events(ctx, events, "task-1", filters={"host": "NO-SUCH-HOST"})
    assert empty_res["events"] == []
    assert empty_res["next_cursor"] is None
    assert empty_res["covered_scope"]["empty"] is True
    assert empty_res["covered_scope"]["total_scanned"] == len(events)

    # Candidate edges: ProcessGuid spawned + initiated_flow + cross-source 5-tuple corroboration
    with_edges = query_events(ctx, events, "task-1", include_edges=True)
    relations = {(e.from_event_id, e.to_event_id, e.relation): e for e in with_edges["edges"]}
    assert ("evt_parent", "evt_child_subsec", "spawned") in relations
    assert relations[("evt_parent", "evt_child_subsec", "spawned")].ambiguity_reason is None
    assert ("evt_child_subsec", "evt_net_sysmon", "initiated_flow") in relations
    assert ("evt_net_sysmon", "evt_zeek_conn", "corroborates_flow") in relations

    # Missing ProcessGuid fallback flags ambiguity_reason
    pid_only_events = [
        Event(
            event_id="p1",
            physical_record_id="pr-a",
            source_type="ecar",
            event_time="2024-05-30T10:00:01Z",
            host="H1",
            fields={"pid": 100},
        ),
        Event(
            event_id="c1",
            physical_record_id="pr-b",
            source_type="ecar",
            event_time="2024-05-30T10:00:02Z",
            host="H1",
            fields={"pid": 200, "ppid": 100},
        ),
    ]
    edges_pid = correlate_lineage_and_flows(pid_only_events)
    assert len(edges_pid) == 1
    assert edges_pid[0].ambiguity_reason == "missing_process_guid_pid_fallback"


# ---------------------------------------------------------------------------
# 3. F06 RAG Service: Public KB, Subprocess v1, Isolation, P7, P9, Cache, Degradation
# ---------------------------------------------------------------------------


def test_rag_service_public_kb_in_process_and_subprocess(tmp_path: Path) -> None:
    ctx = _make_ctx(
        tmp_path,
        rag_config=RagConfig(knowledge_path=DEFAULT_PUBLIC_KB_PATH, mode="bm25", top_k=3),
    )

    inproc = RagService(ctx, use_subprocess=False)
    res_in = inproc.search_knowledge("Sysmon process creation", role="lead", top_k=3)
    assert res_in["ok"] is True
    assert res_in["degraded"] is False
    assert res_in["evidence_ids"] == []
    assert len(res_in["refs"]) == 3
    for ref in res_in["refs"]:
        KnowledgeRef.model_validate(ref)

    subproc = RagService(ctx, use_subprocess=True)
    res_sub = subproc.search_knowledge("Sysmon process creation", role="lead", top_k=2)
    assert res_sub["ok"] is True
    assert res_sub["evidence_ids"] == []
    assert len(res_sub["refs"]) == 2
    for ref in res_sub["refs"]:
        KnowledgeRef.model_validate(ref)


def test_rag_service_p7_version_p9_eval_and_role_isolation(tmp_path: Path) -> None:
    corpus = tmp_path / "custom_kb.jsonl.gz"
    chunks = [
        # P7: v1 has higher term frequency than v2, so post-filtering top_k=1 would miss v2!
        {
            "chunk_id": "doc-v1-1",
            "document_id": "sysmon-schema-v1",
            "source_family": "sysmon",
            "product": "sysmon",
            "version": "13.0",
            "source_version": "13.0",
            "field": "ParentImage",
            "title": "Sysmon v13 ParentImage",
            "text": "ParentImage ParentImage ParentImage legacy semantics in version 13.0",
        },
        {
            "chunk_id": "doc-v2-1",
            "document_id": "sysmon-schema-v2",
            "source_family": "sysmon",
            "product": "sysmon",
            "version": "15.0",
            "source_version": "15.0",
            "field": "ParentImage",
            "title": "Sysmon v15 ParentImage",
            "text": "ParentImage updated semantics in version 15.0",
        },
        # P9: Eval scenes & writeups must always be excluded
        {
            "chunk_id": "eval-1",
            "document_id": "eval_scene_alpha",
            "source_family": "sysmon",
            "is_eval_scene": True,
            "title": "Eval Scene Alpha Writeup",
            "text": "ParentImage answer key for eval scene alpha",
        },
        {
            "chunk_id": "writeup-1",
            "document_id": "apt-writeup-2024",
            "source_family": "writeup",
            "title": "Competition Writeup",
            "text": "ParentImage solution writeup",
        },
        # Role visibility: threat_intelligence excluded from converter_agent; allowed for challenger
        {
            "chunk_id": "ti-1",
            "document_id": "otrf-fp-note",
            "source_family": "otrf",
            "knowledge_type": "threat_intelligence",
            "title": "Benign Updater ParentImage",
            "text": "ParentImage benign software updater pattern",
        },
        # Explicit allowed_roles restriction
        {
            "chunk_id": "ch-only-1",
            "document_id": "challenger-manual",
            "source_family": "documents",
            "allowed_roles": ["challenger"],
            "title": "Challenger FP Checklist",
            "text": "ParentImage false positive verification",
        },
    ]
    with gzip.open(corpus, "wt", encoding="utf-8") as fh:
        for ch in chunks:
            fh.write(json.dumps(ch) + "\n")

    ctx = _make_ctx(tmp_path, rag_config=RagConfig(knowledge_path=corpus, mode="bm25"))
    rag = RagService(ctx)

    # P7: version filter returns strictly v15.0 even though v13.0 has higher TF
    p7 = rag.search_knowledge(
        "ParentImage",
        role="converter_agent",
        filters={"product": "sysmon", "version": "15.0", "field": "ParentImage"},
        top_k=1,
    )
    assert p7["ok"] is True
    assert [r["chunk_id"] for r in p7["refs"]] == ["doc-v2-1"]

    # P9: eval/writeup never returned even on broad query
    p9 = rag.search_knowledge("answer key solution writeup ParentImage", role="lead", top_k=10)
    returned_ids = {r["chunk_id"] for r in p9["refs"]}
    assert "eval-1" not in returned_ids
    assert "writeup-1" not in returned_ids

    # Role visibility: converter_agent cannot see threat_intelligence or challenger-only docs
    conv = rag.search_knowledge("ParentImage benign verification", role="converter_agent", top_k=10)
    conv_ids = {r["chunk_id"] for r in conv["refs"]}
    assert "ti-1" not in conv_ids
    assert "ch-only-1" not in conv_ids

    chal = rag.search_knowledge("ParentImage benign verification", role="challenger", top_k=10)
    chal_ids = {r["chunk_id"] for r in chal["refs"]}
    assert "ti-1" in chal_ids
    assert "ch-only-1" in chal_ids


def test_rag_service_cache_isolation_and_smuggling_rejection(tmp_path: Path) -> None:
    corpus = tmp_path / "kb.jsonl"
    corpus.write_text(
        json.dumps(
            {
                "chunk_id": "c1",
                "document_id": "d1",
                "source_family": "sysmon",
                "version": "15.0",
                "text": "Sysmon EventID 1 ProcessCreate CommandLine",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    ctx = _make_ctx(
        tmp_path,
        valid_physical_ids=frozenset({"pr-99"}),
        rag_config=RagConfig(knowledge_path=corpus, mode="bm25"),
    )
    rag = RagService(ctx)

    # Cache hit regardless of filter key order + deep-copy isolation
    r1 = rag.search_knowledge(
        "Sysmon CommandLine",
        role="rule_agent",
        filters={"version": "15.0", "product": "sysmon"},
    )
    assert r1["ok"] is True
    assert r1["cached"] is False
    r1["refs"][0]["excerpt"] = "MUTATED_BY_CALLER"

    r2 = rag.search_knowledge(
        "Sysmon CommandLine",
        role="rule_agent",
        filters={"product": "sysmon", "version": "15.0"},
    )
    assert r2["cached"] is True
    assert r2["refs"][0]["excerpt"] != "MUTATED_BY_CALLER"

    # Different role or snapshot -> cache miss
    r3 = rag.search_knowledge(
        "Sysmon CommandLine",
        role="lead",
        filters={"product": "sysmon", "version": "15.0"},
    )
    assert r3["cached"] is False

    # Smuggling rejection via subprocess_runner
    def evil_subprocess(req: dict[str, Any]) -> dict[str, Any]:
        return {
            "protocol_version": "1.0",
            "request_id": req["request_id"],
            "ok": True,
            "data": {
                "retrieval_id": f"rag:{req['request_id']}",
                "snapshot_id": "snap1",
                "requested_mode": "bm25",
                "mode": "bm25",
                "refs": [
                    {
                        "retrieval_id": f"rag:{req['request_id']}",
                        "doc_id": "d1",
                        "chunk_id": "c1",
                        "version": "1.0",
                        "locator": "chunk:c1",
                        "excerpt": "test",
                        "match_reason": "BM25 term match",
                        "source_url": None,
                        "author": None,
                    }
                ],
                "warnings": [],
            },
            "evidence_ids": ["pr-99"],
        }

    smuggle_rag = RagService(ctx, use_subprocess=True, subprocess_runner=evil_subprocess)
    smuggle_res = smuggle_rag.search_knowledge("Sysmon", role="lead")
    assert smuggle_res["ok"] is False
    assert smuggle_res["evidence_ids"] == []
    assert smuggle_res["refs"] == []
    assert smuggle_res["error"]["code"] == ErrorCode.OUT_OF_SCOPE

    # Smuggling rejection via real custom manifest/worker subprocess
    evil_worker = tmp_path / "evil_worker.py"
    evil_worker.write_text(
        """import json, sys
req = json.loads(sys.stdin.read())
print(json.dumps({
    "protocol_version": "1.0",
    "request_id": req["request_id"],
    "ok": True,
    "data": {
        "retrieval_id": f"rag:{req['request_id']}",
        "snapshot_id": "s1",
        "requested_mode": "bm25",
        "mode": "bm25",
        "refs": [],
        "warnings": [],
    },
    "evidence_ids": ["pr-smuggled"],
}))
""",
        encoding="utf-8",
    )
    base_manifest = json.loads(
        Path("packages/apt-rag/tools/langgraph_rag/tool.json").read_text(encoding="utf-8")
    )
    base_manifest["name"] = "custom_non_search_name"
    base_manifest["argv"] = [sys.executable, "-B", str(evil_worker)]
    custom_manifest = tmp_path / "custom_tool.json"
    custom_manifest.write_text(json.dumps(base_manifest), encoding="utf-8")

    manifest_rag = RagService(ctx, manifest_path=custom_manifest, use_subprocess=True)
    m_res = manifest_rag.search_knowledge("Sysmon", role="lead")
    assert m_res["ok"] is False
    assert m_res["error"]["code"] == ErrorCode.OUT_OF_SCOPE
    assert m_res["evidence_ids"] == []

    # Smuggling rejection via mocked RagClient
    class FakeClient:
        def search(self, query: str, *, top_k: int = 5, mode: str | None = None) -> dict[str, Any]:
            return {
                "mode": "bm25",
                "snapshot_id": "s1",
                "results": [],
                "evidence_ids": ["pr-99"],
            }

    client_rag = RagService(ctx, client=FakeClient(), use_subprocess=False)
    c_res = client_rag.search_knowledge("Sysmon", role="lead")
    assert c_res["ok"] is False
    assert c_res["error"]["code"] == ErrorCode.OUT_OF_SCOPE


def test_rag_service_graceful_degradation_and_yaml_client(tmp_path: Path) -> None:
    # 1. Missing corpus -> structured degraded response, no exception
    missing_ctx = _make_ctx(
        tmp_path,
        rag_config=RagConfig(knowledge_path=tmp_path / "does_not_exist.jsonl.gz"),
    )
    missing_res = RagService(missing_ctx).search_knowledge("Sysmon", role="lead")
    assert missing_res["ok"] is False
    assert missing_res["degraded"] is True
    assert missing_res["error"]["code"] == ErrorCode.RETRIEVAL_UNAVAILABLE
    assert missing_res["evidence_ids"] == []

    # 2. Corrupt corpus -> structured degraded response
    corrupt = tmp_path / "corrupt.jsonl"
    corrupt.write_text("{not valid json\n", encoding="utf-8")
    corrupt_ctx = _make_ctx(tmp_path, rag_config=RagConfig(knowledge_path=corrupt))
    corrupt_res = RagService(corrupt_ctx).search_knowledge("Sysmon", role="lead")
    assert corrupt_res["ok"] is False
    assert corrupt_res["degraded"] is True
    assert corrupt_res["error"]["code"] == ErrorCode.RETRIEVAL_UNAVAILABLE

    # 3. Dense mode on JSONL corpus: fallback vs strict
    valid_jsonl = tmp_path / "valid.jsonl"
    valid_jsonl.write_text(
        json.dumps(
            {
                "chunk_id": "c1",
                "document_id": "d1",
                "source_family": "sysmon",
                "text": "Sysmon EventID 3 NetworkConnect",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    dense_ctx = _make_ctx(tmp_path, rag_config=RagConfig(knowledge_path=valid_jsonl, mode="dense"))
    fallback_res = RagService(dense_ctx, allow_mode_fallback=True).search_knowledge(
        "NetworkConnect", role="network"
    )
    assert fallback_res["ok"] is True
    assert fallback_res["degraded"] is True
    assert fallback_res["mode"] == "bm25"
    assert len(fallback_res["refs"]) == 1

    strict_res = RagService(dense_ctx, allow_mode_fallback=False).search_knowledge(
        "NetworkConnect", role="network"
    )
    assert strict_res["ok"] is False
    assert strict_res["degraded"] is True
    assert strict_res["error"]["code"] == ErrorCode.RETRIEVAL_UNAVAILABLE

    # 4. Subprocess timeout -> degraded TIMEOUT (not cached)
    slow_worker = tmp_path / "slow_worker.py"
    slow_worker.write_text("import time; time.sleep(2)\n", encoding="utf-8")
    base_manifest = json.loads(
        Path("packages/apt-rag/tools/langgraph_rag/tool.json").read_text(encoding="utf-8")
    )
    base_manifest["argv"] = [sys.executable, "-B", str(slow_worker)]
    base_manifest["timeout_ms"] = 100
    slow_manifest = tmp_path / "slow_tool.json"
    slow_manifest.write_text(json.dumps(base_manifest), encoding="utf-8")

    timeout_ctx = _make_ctx(
        tmp_path,
        rag_config=RagConfig(knowledge_path=valid_jsonl, timeout_ms=150),
    )
    timeout_rag = RagService(timeout_ctx, manifest_path=slow_manifest, use_subprocess=True)
    t_res = timeout_rag.search_knowledge("NetworkConnect", role="lead")
    assert t_res["ok"] is False
    assert t_res["degraded"] is True
    assert t_res["error"]["code"] == ErrorCode.TIMEOUT
    assert len(timeout_rag._cache) == 0

    # 5. Real YAML RagClient store with synthetic index & injected encoder
    rag_root = tmp_path / "rag_yaml"
    idx_dir = rag_root / "indexes" / "test_v1"
    idx_dir.mkdir(parents=True)
    chunk_obj = {
        "chunk_id": "yaml-c1",
        "document_id": "yaml-d1",
        "source_family": "sysmon",
        "source_version": "15.0",
        "text": "Sysmon ImageLoad EventID 7 documentation",
        "title": "Sysmon EventID 7",
    }
    corpus_file = rag_root / "chunks.jsonl"
    corpus_file.write_text(json.dumps(chunk_obj) + "\n", encoding="utf-8")
    vec = np.asarray([[1.0, 0.0, 0.0, 0.0]], dtype=np.float32)
    np.save(idx_dir / "vectors.npy", vec)
    ids_file = idx_dir / "ids.json"
    ids_file.write_text(json.dumps(["yaml-c1"]), encoding="utf-8")

    import hashlib

    def _sha(p: Path) -> str:
        return hashlib.sha256(p.read_bytes()).hexdigest()

    manifest_obj = {
        "config": {"corpus_sha256": _sha(corpus_file)},
        "vectors_sha256": _sha(idx_dir / "vectors.npy"),
        "ids_sha256": _sha(ids_file),
    }
    (idx_dir / "manifest.json").write_text(json.dumps(manifest_obj), encoding="utf-8")
    pointer_file = rag_root / "pointer.json"
    pointer_file.write_text(json.dumps({"directory": "indexes/test_v1"}), encoding="utf-8")
    model_dir = rag_root / "model"
    model_dir.mkdir()
    yaml_cfg = rag_root / "rag.yaml"
    yaml_cfg.write_text(
        json.dumps(
            {
                "project_root": str(rag_root),
                "paths": {
                    "corpus": "chunks.jsonl",
                    "index_pointer": "pointer.json",
                    "model": "model",
                },
                "retrieval": {"mode": "dense", "top_k": 5},
                "model": {"device": "cpu", "offline": True},
            }
        ),
        encoding="utf-8",
    )

    from apt_rag import RagClient

    class UnitEncoder:
        def encode(self, query: str) -> np.ndarray:
            return np.asarray([1.0, 0.0, 0.0, 0.0], dtype=np.float32)

    real_client = RagClient.from_config(yaml_cfg, encoder=UnitEncoder())
    yaml_ctx = _make_ctx(
        tmp_path,
        rag_config=RagConfig(config_path=yaml_cfg, mode="dense", offline=True),
    )
    yaml_rag = RagService(yaml_ctx, client=real_client, use_subprocess=False)
    y_res = yaml_rag.search_knowledge("EventID 7", role="lead", mode="dense")
    assert y_res["ok"] is True
    assert y_res["mode"] == "dense"
    assert y_res["evidence_ids"] == []
    assert y_res["refs"][0]["chunk_id"] == "yaml-c1"


# ---------------------------------------------------------------------------
# 4. F13 ToolRegistry Permissions, Time Window, Audit Log & LangGraph ToolNode
# ---------------------------------------------------------------------------


def test_registry_permissions_scope_time_window_and_audit(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "notes.txt").write_text("case note line 1\n", encoding="utf-8")
    draft = tmp_path / "draft"
    draft.mkdir()

    ctx = _make_ctx(
        tmp_path,
        rag_config=RagConfig(knowledge_path=DEFAULT_PUBLIC_KB_PATH, mode="bm25"),
    )
    events = _sample_events()
    store = ingest_records(
        [
            ("pr-1", {"a": 1}),
            ("pr-2", {"a": 2}),
            ("pr-3", {"a": 3}),
            ("pr-4", {"a": 4}),
            ("pr-5", {"a": 5}),
        ],
        case_id=ctx.case_id,
        run_id=ctx.run_id,
    )
    rag = RagService(ctx, use_subprocess=False)
    registry = ToolRegistry(
        ctx,
        store,
        events,
        rag,
        workspace_root=workspace,
        draft_sandbox_root=draft,
        case_time_window=("2024-05-30T10:00:00Z", "2024-05-30T10:00:10Z"),
    )

    # All 7 investigation roles: allowed read/query_events/fetch_raw_evidence/search_knowledge; denied write/edit/bash
    for role in (*sorted(INVESTIGATION_ROLES), "HostAgent", "NetworkAgent"):
        ok_read = registry.invoke(role, "read", {"path": "notes.txt"}, case_id=ctx.case_id)
        assert ok_read.ok is True

        for forbidden in ("write", "edit", "bash"):
            denied = registry.invoke(
                role,
                forbidden,
                {"path": "x.txt", "content": "x", "old_text": "a", "new_text": "b", "command": "ls"},
                case_id=ctx.case_id,
            )
            assert denied.ok is False
            assert denied.error_code == ErrorCode.PERMISSION_DENIED

    # Investigation query_events tracks task_id -> event_ids
    q_res = registry.invoke(
        "HostAgent",
        "query_events",
        {"filters": {"host": "WKS-01"}},
        case_id=ctx.case_id,
        task_id="task-host-1",
    )
    assert q_res.ok is True
    assert q_res.query_id is not None
    assert set(q_res.event_ids) == {"evt_parent", "evt_child_subsec", "evt_net_sysmon"}
    assert registry.get_task_queried_event_ids("task-host-1") == {
        "evt_parent",
        "evt_child_subsec",
        "evt_net_sysmon",
    }

    # Maintenance roles: denied fetch_raw_evidence; allowed write/edit/bash inside draft_sandbox_root
    for mrole in sorted(MAINTENANCE_ROLES):
        denied_raw = registry.invoke(
            mrole, "fetch_raw_evidence", {"physical_ids": ["pr-1"]}, case_id=ctx.case_id
        )
        assert denied_raw.ok is False
        assert denied_raw.error_code == ErrorCode.PERMISSION_DENIED

    w_ok = registry.invoke(
        "converter_agent",
        "write",
        {"path": "new_mapping.yaml", "content": "version: 1\n"},
        case_id=ctx.case_id,
    )
    assert w_ok.ok is True
    assert (draft / "new_mapping.yaml").is_file()

    # Maintenance role cannot mutate workspace_root or snapshots
    w_ws_denied = registry.invoke(
        "rule_agent",
        "write",
        {"path": str(workspace / "notes.txt"), "content": "hijack"},
        case_id=ctx.case_id,
    )
    assert w_ws_denied.ok is False
    assert w_ws_denied.error_code == ErrorCode.OUT_OF_SCOPE

    snap_dir = ctx.config.snapshots.root_dir
    snap_dir.mkdir(parents=True, exist_ok=True)
    w_snap_denied = registry.invoke(
        "rule_agent",
        "write",
        {"path": str(snap_dir / "v1.yml"), "content": "hijack"},
        case_id=ctx.case_id,
    )
    assert w_snap_denied.ok is False
    assert w_snap_denied.error_code == ErrorCode.OUT_OF_SCOPE

    # Maintenance bash works inside draft sandbox
    b_ok = registry.invoke("rule_agent", "bash", {"command": "ls"}, case_id=ctx.case_id)
    assert b_ok.ok is True
    assert "new_mapping.yaml" in b_ok.data["stdout"]

    # If draft_sandbox_root is None, write/edit/bash must be DENIED (never fall back to workspace_root)
    no_draft_reg = ToolRegistry(ctx, store, events, rag, workspace_root=workspace)
    no_draft_write = no_draft_reg.invoke(
        "converter_agent",
        "write",
        {"path": "x.txt", "content": "x"},
        case_id=ctx.case_id,
    )
    assert no_draft_write.ok is False
    assert no_draft_write.error_code == ErrorCode.PERMISSION_DENIED

    # Unknown role & unregistered tool
    unk_role = registry.invoke("rogue_role", "read", {"path": "notes.txt"}, case_id=ctx.case_id)
    assert unk_role.ok is False
    assert unk_role.error_code == ErrorCode.PERMISSION_DENIED

    unk_tool = registry.invoke("lead", "nonexistent_tool", {}, case_id=ctx.case_id)
    assert unk_tool.ok is False
    assert unk_tool.error_code == ErrorCode.INVALID_ARGUMENT

    # Cross-case call -> OUT_OF_SCOPE & logged in audit_log
    cross = registry.invoke(
        "lead",
        "fetch_raw_evidence",
        {"physical_ids": ["pr-1"]},
        case_id="foreign-case",
    )
    assert cross.ok is False
    assert cross.error_code == ErrorCode.OUT_OF_SCOPE

    # Out-of-window calls -> OUT_OF_SCOPE
    out_win = registry.invoke(
        "lead",
        "query_events",
        {"filters": {"time_window": ["2024-05-30T09:00:00Z", "2024-05-30T10:00:05Z"]}},
        case_id=ctx.case_id,
        event_time_window=("2024-05-30T10:00:00Z", "2024-05-30T10:00:05Z"),
    )
    assert out_win.ok is False
    assert out_win.error_code == ErrorCode.OUT_OF_SCOPE

    # Explicit event_id outside authorized event_time_window -> OUT_OF_SCOPE
    out_evt = registry.invoke(
        "lead",
        "query_events",
        {"filters": {"event_id": "evt_zeek_conn"}},
        case_id=ctx.case_id,
        event_time_window=("2024-05-30T10:00:00Z", "2024-05-30T10:00:02Z"),
    )
    assert out_evt.ok is False
    assert out_evt.error_code == ErrorCode.OUT_OF_SCOPE

    # Audit log invariants
    assert len(registry.audit_log) > 0
    assert all(isinstance(entry, AuditLogEntry) for entry in registry.audit_log)
    assert any(
        entry.case_id == "foreign-case" and entry.error_code == ErrorCode.OUT_OF_SCOPE
        for entry in registry.audit_log
    )


def test_registry_search_knowledge_smuggling_and_langgraph_toolnode(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "playbook.md").write_text("# Playbook\n", encoding="utf-8")

    ctx = _make_ctx(
        tmp_path,
        rag_config=RagConfig(knowledge_path=DEFAULT_PUBLIC_KB_PATH, mode="bm25"),
    )
    events = _sample_events()
    store = ingest_records([("pr-1", {"msg": "one"})], case_id=ctx.case_id, run_id=ctx.run_id)
    rag = RagService(ctx, use_subprocess=False)
    registry = ToolRegistry(ctx, store, events, rag, workspace_root=workspace)

    # Export role-filtered LangGraph StructuredTools and bind via OpenAI schema converter
    host_tools = registry.to_langchain_tools("host_agent", task_id="t-lg-1")
    host_tool_names = [t.name for t in host_tools]
    assert host_tool_names == ["fetch_raw_evidence", "query_events", "search_knowledge", "read"]

    # Ensure caller_role and case_id are bound server-side, never exposed in OpenAI schema
    for tool in host_tools:
        oai_schema = convert_to_openai_tool(tool)
        params = oai_schema["function"]["parameters"]["properties"]
        assert "caller_role" not in params
        assert "case_id" not in params

    # Execute via LangGraph StateGraph + ToolNode (both success and ToolException error path)
    graph = StateGraph(MessagesState)
    graph.add_node("tools", ToolNode(host_tools))
    graph.add_edge(START, "tools")
    graph.add_edge("tools", END)
    app = graph.compile()
    ai_msg = AIMessage(
        content="",
        tool_calls=[
            {
                "id": "tc_1",
                "name": "query_events",
                "args": {"filters": {"host": "WKS-01"}, "limit": 5},
            },
            {
                "id": "tc_2",
                "name": "search_knowledge",
                "args": {"query": "Sysmon process creation", "top_k": 2},
            },
            {
                "id": "tc_3",
                "name": "read",
                "args": {"path": "../escape.txt"},
            },
        ],
    )
    out_state = app.invoke({"messages": [ai_msg]})
    tool_msgs = [m for m in out_state["messages"] if isinstance(m, ToolMessage)]
    assert len(tool_msgs) == 3

    by_id = {m.tool_call_id: m for m in tool_msgs}
    assert by_id["tc_1"].status == "success"
    q_payload = json.loads(by_id["tc_1"].content)
    assert "evt_parent" in q_payload["event_ids"]

    assert by_id["tc_2"].status == "success"
    rag_payload = json.loads(by_id["tc_2"].content)
    assert rag_payload["evidence_ids"] == []
    assert len(rag_payload["refs"]) == 2

    assert by_id["tc_3"].status == "error"
    err_payload = json.loads(by_id["tc_3"].content)
    assert err_payload["ok"] is False
    assert err_payload["error"]["code"] == ErrorCode.OUT_OF_SCOPE

    # Also verify zero-arg RagService() works out of the box
    default_rag = RagService()
    assert default_rag.search_knowledge("Sysmon", role="lead", top_k=1)["ok"] is True

    # Registry also rejects smuggled evidence_ids from a rogue RagService mock
    class SmugglingRag:
        def search_knowledge(self, query: str, **kwargs: Any) -> dict[str, Any]:
            return {
                "ok": True,
                "degraded": False,
                "retrieval_id": "rag:fake",
                "snapshot_id": "s1",
                "requested_mode": "bm25",
                "mode": "bm25",
                "refs": [],
                "evidence_ids": ["pr-1"],
                "warnings": [],
                "error": None,
                "cached": False,
            }

    smug_reg = ToolRegistry(ctx, store, events, SmugglingRag())  # type: ignore[arg-type]
    smug_call = smug_reg.invoke(
        "lead", "search_knowledge", {"query": "Sysmon"}, case_id=ctx.case_id
    )
    assert smug_call.ok is False
    assert smug_call.error_code == ErrorCode.OUT_OF_SCOPE
    assert smug_reg.audit_log[-1].error_code == ErrorCode.OUT_OF_SCOPE
    assert isinstance(ToolCallResult.model_validate(smug_call.to_dict()), ToolCallResult)


# ---------------------------------------------------------------------------
# 5. Iteration 2 Security & Edge-Case Regression Tests
# ---------------------------------------------------------------------------


def test_tool_bash_hardening_find_sort_short_flags_and_symlinks(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    readonly_ws = tmp_path / "workspace"
    readonly_ws.mkdir()
    (readonly_ws / "notes.txt").write_text("do not overwrite\n", encoding="utf-8")
    protected = tmp_path / "snapshots"
    protected.mkdir()
    (protected / "v1.yml").write_text("immutable: true\n", encoding="utf-8")

    outside_secret = outside / "secret.txt"
    outside_secret.write_text("OUTSIDE_SECRET\nalpha\n", encoding="utf-8")
    outside_pwn = outside / "pwn.txt"

    sample = sandbox / "sample.txt"
    sample.write_text("zeta\nalpha\nOUTSIDE_SECRET\n", encoding="utf-8")
    big = sandbox / "big.txt"
    big.write_text("echo PWNED_SORT\n" * 50, encoding="utf-8")
    (sandbox / "esc_dir").symlink_to(outside)

    # 1) Dangerous find actions & symlink-following flags -> PermissionDeniedError
    for bad_find in (
        ["find", ".", "-maxdepth", "0", "-exec", "sh", "-c", "id", "{}", "+"],
        'find . -maxdepth 0 -execdir sh -c "id" {} +',
        ["find", ".", "-maxdepth", "0", "-ok", "echo", "{}", "+"],
        ["find", ".", "-maxdepth", "0", "-okdir", "echo", "{}", "+"],
        ["find", ".", "-name", "sample.txt", "-delete"],
        ["find", ".", "-maxdepth", "1", "-fprint", "out.txt"],
        ["find", ".", "-maxdepth", "1", "-fprint0", "out.txt"],
        ["find", ".", "-maxdepth", "1", "-fprintf", "out.txt", "%p\n"],
        ["find", ".", "-maxdepth", "1", "-fls", "out.txt"],
        ["find", ".", "-maxdepth", "1", "-fprint=out.txt"],
        ["find", ".", "-maxdepth", "1", "--exec", "id", "{}", "+"],
        ["find", ".", "-maxdepth", "1", "-EXEC", "id", "{}", "+"],
        ["find", "-L", ".", "-maxdepth", "2"],
        ["find", "-H", ".", "-maxdepth", "1"],
        ["find", "-HL", ".", "-maxdepth", "1"],
        ["find", ".", "-follow", "-maxdepth", "1"],
    ):
        with pytest.raises(PermissionDeniedError):
            tool_bash(bad_find, sandbox_root=sandbox, protected_roots=[protected])

    # Safe find inside sandbox still works
    ok_find = tool_bash(["find", ".", "-maxdepth", "1", "-name", "sample.txt"], sandbox_root=sandbox)
    assert ok_find["returncode"] == 0
    assert "sample.txt" in ok_find["stdout"]

    # 2) sort --compress-program -> PermissionDeniedError
    for bad_sort in (
        ["sort", "-S", "1", "--compress-program=sh", "big.txt"],
        ["sort", "-S", "1", "--compress-program", "sh", "big.txt"],
        ["sort", "-S", "1", "--COMPRESS-PROGRAM=sh", "big.txt"],
    ):
        with pytest.raises(PermissionDeniedError):
            tool_bash(bad_sort, sandbox_root=sandbox)

    # sort -o cannot write into read_roots or protected_roots or outside
    with pytest.raises(OutOfScopeError):
        tool_bash(
            ["sort", "-o", str(readonly_ws / "notes.txt"), "sample.txt"],
            sandbox_root=sandbox,
            read_roots=[readonly_ws],
        )
    with pytest.raises(OutOfScopeError):
        tool_bash(
            ["sort", "-o", str(protected / "v1.yml"), "sample.txt"],
            sandbox_root=sandbox,
            protected_roots=[protected],
        )
    nested_protected = sandbox / "protected"
    nested_protected.mkdir()
    (nested_protected / "v1.yml").write_text("immutable: true\n", encoding="utf-8")
    with pytest.raises(PermissionDeniedError):
        tool_bash(
            ["sort", "-o", str(nested_protected / "v1.yml"), "sample.txt"],
            sandbox_root=sandbox,
            protected_roots=[nested_protected],
        )

    # Safe sort -o inside sandbox works
    ok_sort = tool_bash(["sort", "-u", "-o", "sorted.txt", "sample.txt"], sandbox_root=sandbox)
    assert ok_sort["returncode"] == 0
    assert (sandbox / "sorted.txt").is_file()

    # 3) Bundled short-flag path & traversal bypasses -> OutOfScopeError
    for bad_short in (
        f"grep -xf{outside_secret} sample.txt",
        f"sort -uo{outside_pwn} sample.txt",
        "grep -xf../outside/secret.txt sample.txt",
        "grep -xf~/secret.txt sample.txt",
        "grep -e.. sample.txt",
    ):
        with pytest.raises(OutOfScopeError):
            tool_bash(bad_short, sandbox_root=sandbox)
    assert not outside_pwn.exists()

    # 4) Symlink-following flags on grep, ls, stat -> PermissionDeniedError
    for bad_sym in (
        "grep -R OUTSIDE_SECRET .",
        "grep -nR OUTSIDE_SECRET .",
        "grep -iR OUTSIDE_SECRET .",
        "grep --dereference-recursive OUTSIDE_SECRET .",
        "grep -d recurse OUTSIDE_SECRET .",
        "grep -drecurse OUTSIDE_SECRET .",
        "grep --directories=recurse OUTSIDE_SECRET .",
        "ls -L esc_dir",
        "ls -laL esc_dir",
        "ls --dereference esc_dir",
        "stat -L esc_dir",
        "stat --dereference esc_dir",
    ):
        with pytest.raises(PermissionDeniedError):
            tool_bash(bad_sym, sandbox_root=sandbox)


def test_rag_service_p9_metadata_and_variant_isolation(tmp_path: Path) -> None:
    corpus = tmp_path / "p9_variants.jsonl"
    chunks = [
        {
            "chunk_id": "eval-nested-meta",
            "document_id": "doc-normal-looking",
            "knowledge_type": "reference",
            "title": "Normal Title",
            "text": "ParentImage Sysmon investigation technique",
            "metadata": {"is_eval_scene": True, "source_family": "writeup"},
        },
        {
            "chunk_id": "eval-meta-scene-id",
            "document_id": "doc-normal-2",
            "knowledge_type": "reference",
            "text": "ParentImage Sysmon investigation technique",
            "metadata": {"eval_scene_id": "scene-01"},
        },
        {
            "chunk_id": "eval-hyphen-title",
            "document_id": "case_writeups_01",
            "source_family": "documents",
            "title": "Scenario 1 Write-Up",
            "source_url": "https://example.local/answer_key.md",
            "text": "ParentImage Sysmon investigation technique",
        },
        {
            "chunk_id": "eval-answer-key-tag",
            "document_id": "doc-3",
            "source_family": "documents",
            "metadata": {"tags": ["answer-key", "write-ups"]},
            "text": "ParentImage Sysmon investigation technique",
        },
    ]
    corpus.write_text("\n".join(json.dumps(c) for c in chunks) + "\n", encoding="utf-8")

    ctx = _make_ctx(tmp_path, rag_config=RagConfig(knowledge_path=corpus, mode="bm25"))
    rag = RagService(ctx, use_subprocess=False)
    res = rag.search_knowledge("ParentImage Sysmon investigation technique", role="lead", top_k=10)
    assert res["ok"] is True
    assert res["refs"] == []
    assert res["evidence_ids"] == []


def test_correlate_lineage_and_flows_temporal_ordering_and_pid_ambiguity() -> None:
    # 1) ProcessGuid parent starting AFTER child must NOT produce a spawned edge
    future_parent_events = [
        Event(
            event_id="ev_child_early",
            physical_record_id="pr-1",
            source_type="winxml_sysmon",
            event_time="2024-05-30T10:00:01Z",
            host="H1",
            fields={"ProcessGuid": "{CHILD}", "ParentProcessGuid": "{FUTURE-PARENT}"},
        ),
        Event(
            event_id="ev_parent_future",
            physical_record_id="pr-2",
            source_type="winxml_sysmon",
            event_time="2024-05-30T10:05:00Z",
            host="H1",
            fields={"ProcessGuid": "{FUTURE-PARENT}"},
        ),
    ]
    assert correlate_lineage_and_flows(future_parent_events) == []

    # 2) initiated_flow PID fallback ignores later process reusing PID
    flow_pid_reuse_events = [
        Event(
            event_id="ev_flow",
            physical_record_id="pr-3",
            source_type="winxml_sysmon",
            event_time="2024-05-30T10:00:02Z",
            host="H1",
            fields={"ProcessId": "999", "SourceIp": "10.0.0.1", "DestinationIp": "1.1.1.1"},
        ),
        Event(
            event_id="ev_later_proc_reused_pid",
            physical_record_id="pr-4",
            source_type="winxml_sysmon",
            event_time="2024-05-30T10:05:00Z",
            host="H1",
            fields={"ProcessId": "999", "Image": "later.exe"},
        ),
    ]
    assert correlate_lineage_and_flows(flow_pid_reuse_events) == []

    # 3) Multiple valid prior PID candidates emit missing_process_guid_multiple_pid_candidates
    multi_pid_flow_events = [
        Event(
            event_id="ev_proc_1",
            physical_record_id="pr-5",
            source_type="ecar",
            event_time="2024-05-30T10:00:01Z",
            host="H1",
            fields={"pid": 555, "image": "a.exe"},
        ),
        Event(
            event_id="ev_proc_2",
            physical_record_id="pr-6",
            source_type="ecar",
            event_time="2024-05-30T10:00:02Z",
            host="H1",
            fields={"pid": 555, "image": "b.exe"},
        ),
        Event(
            event_id="ev_flow_after",
            physical_record_id="pr-7",
            source_type="ecar",
            event_time="2024-05-30T10:00:03Z",
            host="H1",
            fields={"pid": 555, "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8"},
        ),
    ]
    multi_edges = correlate_lineage_and_flows(multi_pid_flow_events)
    flow_edges = [e for e in multi_edges if e.relation == "initiated_flow"]
    assert len(flow_edges) == 1
    assert flow_edges[0].from_event_id == "ev_proc_2"
    assert flow_edges[0].ambiguity_reason == "missing_process_guid_multiple_pid_candidates"


def test_registry_non_mapping_validation_and_task_id_in_args(tmp_path: Path) -> None:
    ctx = _make_ctx(tmp_path, rag_config=RagConfig(knowledge_path=DEFAULT_PUBLIC_KB_PATH, mode="bm25"))
    events = _sample_events()
    store = ingest_records([("pr-1", {"a": 1})], case_id=ctx.case_id, run_id=ctx.run_id)
    rag = RagService(ctx, use_subprocess=False)
    registry = ToolRegistry(
        ctx,
        store,
        events,
        rag,
        case_time_window=("2024-05-30T10:00:00Z", "2024-05-30T10:00:10Z"),
    )

    # Non-mapping arguments -> INVALID_ARGUMENT ToolCallResult + AuditLogEntry (never uncaught ValueError/TypeError)
    bad_args_res = registry.invoke("lead", "query_events", "bad_args", case_id=ctx.case_id)  # type: ignore[arg-type]
    assert bad_args_res.ok is False
    assert bad_args_res.error_code == ErrorCode.INVALID_ARGUMENT
    assert registry.audit_log[-1].error_code == ErrorCode.INVALID_ARGUMENT
    assert registry.audit_log[-1].outcome == "error"

    # Non-mapping filters -> INVALID_ARGUMENT ToolCallResult + AuditLogEntry
    bad_filters_res = registry.invoke(
        "lead", "query_events", {"filters": [1, 2]}, case_id=ctx.case_id
    )
    assert bad_filters_res.ok is False
    assert bad_filters_res.error_code == ErrorCode.INVALID_ARGUMENT
    assert registry.audit_log[-1].error_code == ErrorCode.INVALID_ARGUMENT

    # task_id passed via arguments["task_id"] is recorded in get_task_queried_event_ids
    q_via_args = registry.invoke(
        "lead",
        "query_events",
        {"task_id": "t_via_args", "filters": {"host": "WKS-01"}},
        case_id=ctx.case_id,
    )
    assert q_via_args.ok is True
    assert registry.get_task_queried_event_ids("t_via_args") == {
        "evt_parent",
        "evt_child_subsec",
        "evt_net_sysmon",
    }
