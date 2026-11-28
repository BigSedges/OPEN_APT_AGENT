"""Tier 1 opaque-box E2E tests for F06 (RAG), F08 (Query Tools), F13 (Permissions), F14 (Maintenance).

All ``apt_agent`` and ``langgraph_adapter`` imports are kept strictly lazy inside
test functions or local helpers so collection succeeds independently of M3-M6.
"""

from __future__ import annotations

import copy
import inspect
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.tier1


def _field(obj: Any, *names: str, default: Any = None) -> Any:
    for name in names:
        if isinstance(obj, dict) and name in obj:
            return obj[name]
        if not isinstance(obj, dict) and hasattr(obj, name):
            return getattr(obj, name)
    return default


def _error_code(res: Any) -> str | None:
    err = _field(res, "error")
    if isinstance(err, dict):
        return err.get("code")
    if err is not None:
        return _field(err, "code")
    return _field(res, "error_code")


def _audit_allowed(entry: Any) -> bool | None:
    allowed = _field(entry, "allowed")
    if isinstance(allowed, bool):
        return allowed
    ok = _field(entry, "ok")
    if isinstance(ok, bool):
        return ok
    decision = _field(entry, "decision", "status")
    if isinstance(decision, str):
        low = decision.lower()
        if low in {"allow", "allowed", "success"}:
            return True
        if low in {"deny", "denied", "error", "rejected"}:
            return False
    return None


def _stage_passed(stage_val: Any) -> bool | None:
    if isinstance(stage_val, bool):
        return stage_val
    if isinstance(stage_val, dict):
        if "passed" in stage_val:
            val = stage_val["passed"]
            return val if isinstance(val, bool) else False
        if "ok" in stage_val:
            val = stage_val["ok"]
            return val if isinstance(val, bool) else False
        status = stage_val.get("status")
        if isinstance(status, str):
            low = status.lower()
            if low in {"pass", "passed", "ok", "success"}:
                return True
            if low in {"fail", "failed", "error"}:
                return False
        return None
    for attr in ("passed", "ok"):
        if hasattr(stage_val, attr):
            val = getattr(stage_val, attr)
            return val if isinstance(val, bool) else False
    status = getattr(stage_val, "status", None)
    if isinstance(status, str):
        low = status.lower()
        if low in {"pass", "passed", "ok", "success"}:
            return True
        if low in {"fail", "failed", "error"}:
            return False
    return None


def _assert_stages_passed(stage_results: Any, *, min_stages: int = 1) -> None:
    assert isinstance(stage_results, dict) and len(stage_results) >= min_stages
    for stage_name, stage_val in stage_results.items():
        parsed = _stage_passed(stage_val)
        if parsed is not None:
            assert parsed is True, f"Stage {stage_name!r} did not pass: {stage_val!r}"


def _parse_utc(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        sec = float(value) / 1000.0 if float(value) > 1e12 else float(value)
        return datetime.fromtimestamp(sec, tz=timezone.utc)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    return None


def _setup_forensic_registry(
    e2e_fixtures_dir: Path,
    make_app_config: Any,
    make_run_context: Any,
    load_scene_records: Any,
    *,
    case_id: str = "case-e2e-001",
    workspace_root: Path | None = None,
    draft_sandbox_root: Path | None = None,
    knowledge_path: Path | None = None,
) -> tuple[Any, Any, list[Any], Any, Any]:
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.models import Locator
    from apt_agent.tools import RagService, ToolRegistry

    index, records = load_scene_records(e2e_fixtures_dir / "logs")
    cfg = make_app_config(
        knowledge_path=knowledge_path or (e2e_fixtures_dir / "kb" / "synthetic_kb.jsonl"),
    )
    ctx = make_run_context(
        case_id=case_id,
        config=cfg,
        valid_physical_ids=set(index.keys()),
        locator_map=index,
    )
    locators = {pid: Locator(**meta) for pid, meta in index.items()}
    store = ingest_records(
        iter(records),
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        locator_map=locators,
    )
    norm_res = Normalizer().normalize_batch(ctx, store)
    events = list(_field(norm_res, "events", default=[]))
    rag = RagService(config=cfg.rag)
    reg_params = inspect.signature(ToolRegistry).parameters
    reg_kwargs: dict[str, Any] = {"workspace_root": workspace_root}
    if "draft_sandbox_root" in reg_params and draft_sandbox_root is not None:
        reg_kwargs["draft_sandbox_root"] = draft_sandbox_root
    registry = ToolRegistry(ctx, store, events, rag, **reg_kwargs)
    return ctx, store, events, rag, registry


def _instantiate_maintenance_agent(cls: Any, registry: Any, ctx: Any) -> Any:
    sig = inspect.signature(cls)
    params = sig.parameters
    kwargs: dict[str, Any] = {}
    if "registry" in params:
        kwargs["registry"] = registry
    elif "snapshot_registry" in params:
        kwargs["snapshot_registry"] = registry
    if "ctx" in params:
        kwargs["ctx"] = ctx
    if kwargs:
        return cls(**kwargs)
    pos_params = [
        p
        for p in params.values()
        if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    if len(pos_params) >= 2:
        return cls(ctx, registry)
    if len(pos_params) == 1:
        return cls(registry)
    return cls()


def _invoke_maintenance_agent(
    agent: Any,
    *,
    ctx: Any,
    registry: Any,
    kind: str,
    version: str,
    candidate: Any,
    fixtures: dict[str, Any],
    metadata: dict[str, Any],
) -> Any:
    for method_name in ("validate_and_publish", "publish_validated", "draft_and_publish", "run"):
        fn = getattr(agent, method_name, None)
        if not callable(fn):
            continue
        sig = inspect.signature(fn)
        params = sig.parameters
        kwargs: dict[str, Any] = {}
        if "ctx" in params:
            kwargs["ctx"] = ctx
        if "registry" in params:
            kwargs["registry"] = registry
        if "snapshot_registry" in params:
            kwargs["snapshot_registry"] = registry
        if "kind" in params:
            kwargs["kind"] = kind
        if "version" in params:
            kwargs["version"] = version
        elif "target_version" in params:
            kwargs["target_version"] = version
        if "candidate" in params:
            kwargs["candidate"] = candidate
        if "fixtures" in params:
            kwargs["fixtures"] = fixtures
        if "metadata" in params:
            kwargs["metadata"] = metadata
        if kwargs:
            return fn(**kwargs)
        return fn(ctx, version, candidate, fixtures)
    raise AssertionError(f"Agent {type(agent).__name__} lacks validate_and_publish/run method")


# ---------------------------------------------------------------------------
# F06: RAG Tool & Knowledge Isolation (5 tests)
# ---------------------------------------------------------------------------


def test_f06_t1_rag_service_bm25_synthetic_kb_returns_versioned_refs(
    e2e_fixtures_dir: Path,
    make_app_config: Any,
) -> None:
    from apt_agent.tools import RagService

    cfg = make_app_config(
        knowledge_path=e2e_fixtures_dir / "kb" / "synthetic_kb.jsonl",
        rag_mode="bm25",
        rag_top_k=5,
        rag_offline=True,
    )
    rag = RagService(config=cfg.rag)
    res = rag.search_knowledge("creator_pid", role="converter_agent", top_k=5)

    assert res.get("evidence_ids", []) == []
    assert isinstance(res.get("snapshot_id"), str) and res["snapshot_id"].strip() != ""
    assert isinstance(res.get("retrieval_id"), str) and res["retrieval_id"].strip() != ""
    refs = res.get("refs", [])
    assert len(refs) >= 1

    required_keys = ("doc_id", "chunk_id", "version", "locator", "excerpt", "match_reason", "retrieval_id")
    for ref in refs:
        for key in required_keys:
            val = ref.get(key)
            assert isinstance(val, str) and val.strip() != "", f"Missing/blank ref[{key!r}]: {ref!r}"

    chunk_ids = {ref["chunk_id"] for ref in refs}
    assert chunk_ids & {"kb-sensor-v1-creator-pid", "kb-sensor-v2-creator-pid"}


def test_f06_t1_rag_version_scoped_field_lookup_v1_vs_v2(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    make_app_config: Any,
) -> None:
    from apt_agent.tools import RagService

    cfg_v1 = make_app_config(
        base_dir=tmp_path / "kb_v1_env",
        knowledge_path=e2e_fixtures_dir / "kb" / "kb_v1.jsonl",
        rag_mode="bm25",
    )
    cfg_v2 = make_app_config(
        base_dir=tmp_path / "kb_v2_env",
        knowledge_path=e2e_fixtures_dir / "kb" / "kb_v2.jsonl",
        rag_mode="bm25",
    )
    rag_v1 = RagService(config=cfg_v1.rag)
    rag_v2 = RagService(config=cfg_v2.rag)

    r1 = rag_v1.search_knowledge(
        "creator_pid",
        role="converter_agent",
        filters={"version": "v1"},
        top_k=3,
    )
    r2 = rag_v2.search_knowledge(
        "creator_pid",
        role="converter_agent",
        filters={"version": "v2"},
        top_k=3,
    )

    assert r1.get("evidence_ids", []) == []
    assert r2.get("evidence_ids", []) == []
    assert len(r1["refs"]) >= 1
    assert len(r2["refs"]) >= 1

    assert r1["refs"][0]["chunk_id"] == "kb-sensor-v1-creator-pid"
    assert r1["refs"][0]["version"] == "v1"
    assert "ppid" in r1["refs"][0]["excerpt"]

    assert r2["refs"][0]["chunk_id"] == "kb-sensor-v2-creator-pid"
    assert r2["refs"][0]["version"] == "v2"
    assert "RPC broker" in r2["refs"][0]["excerpt"]


def test_f06_t1_rag_zero_match_returns_empty_refs_gracefully(
    e2e_fixtures_dir: Path,
    make_app_config: Any,
) -> None:
    from apt_agent.tools import RagService

    cfg = make_app_config(
        knowledge_path=e2e_fixtures_dir / "kb" / "synthetic_kb.jsonl",
        rag_mode="bm25",
    )
    rag = RagService(config=cfg.rag)
    res = rag.search_knowledge("nonexistent_token_zzqq9911", role="lead", top_k=5)

    assert res["refs"] == []
    assert res.get("evidence_ids", []) == []
    assert isinstance(res.get("retrieval_id"), str) and res["retrieval_id"].strip() != ""


def test_f06_t1_rag_query_cache_reuses_identical_role_filter_snapshot(
    e2e_fixtures_dir: Path,
    make_app_config: Any,
) -> None:
    from apt_agent.tools import RagService

    cfg = make_app_config(
        knowledge_path=e2e_fixtures_dir / "kb" / "synthetic_kb.jsonl",
        rag_mode="bm25",
    )
    rag = RagService(config=cfg.rag)

    r1 = rag.search_knowledge(
        "WINWORD.EXE ProcessGuid",
        role="lead",
        filters={"doc_type": "playbook"},
        top_k=3,
    )
    r1_snapshot = copy.deepcopy(r1)
    r2 = rag.search_knowledge(
        "WINWORD.EXE ProcessGuid",
        role="lead",
        filters={"doc_type": "playbook"},
        top_k=3,
    )
    r3 = rag.search_knowledge(
        "WINWORD.EXE ProcessGuid",
        role="challenger",
        filters={"doc_type": "playbook"},
        top_k=3,
    )

    assert r1.get("evidence_ids", []) == []
    assert r2.get("evidence_ids", []) == []
    assert r3.get("evidence_ids", []) == []

    assert "kb-playbook-e41-pivot" in [ref["chunk_id"] for ref in r1["refs"]]
    assert r1["snapshot_id"] == r2["snapshot_id"]
    assert [ref["chunk_id"] for ref in r1["refs"]] == [ref["chunk_id"] for ref in r2["refs"]]
    assert [ref["excerpt"] for ref in r1["refs"]] == [ref["excerpt"] for ref in r2["refs"]]
    assert "kb-playbook-e41-pivot" in [ref["chunk_id"] for ref in r3["refs"]]
    assert r1["refs"] == r1_snapshot["refs"]


def test_f06_t1_langgraph_v1_parallel_toolnode_search_knowledge_live(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    langgraph_rag_dir = (
        Path(__file__).resolve().parents[2] / "packages" / "apt-rag" / "tools" / "langgraph_rag"
    )
    monkeypatch.syspath_prepend(str(langgraph_rag_dir))

    from langchain_core.messages import AIMessage
    from langgraph.graph import END, START, MessagesState, StateGraph
    from langgraph.prebuilt import ToolNode
    from langgraph_adapter import build_tool

    tool = build_tool(
        langgraph_rag_dir / "tool.json",
        case_id="demo",
        run_id="run-1",
        resources={"knowledge": langgraph_rag_dir / "sample_knowledge.jsonl"},
    )
    graph = StateGraph(MessagesState)
    graph.add_node("tools", ToolNode([tool]))
    graph.add_edge(START, "tools")
    graph.add_edge("tools", END)
    app = graph.compile()

    calls = [
        {"name": "search_knowledge", "args": {"query": "demo_event"}, "id": "t0", "type": "tool_call"},
        {"name": "search_knowledge", "args": {"query": "no-match-745xz"}, "id": "t1", "type": "tool_call"},
    ]
    out_msgs = app.invoke({"messages": [AIMessage(content="", tool_calls=calls)]})["messages"][1:]
    by_id = {m.tool_call_id: (m.status, json.loads(m.content)) for m in out_msgs}
    assert set(by_id) == {"t0", "t1"}

    s0, p0 = by_id["t0"]
    assert s0 == "success"
    assert p0["ok"] is True
    assert p0["evidence_ids"] == []
    assert p0["data"]["refs"][0]["chunk_id"] == "kb-demo-1"
    assert p0["data"]["refs"][0]["retrieval_id"] == p0["data"]["retrieval_id"]

    s1, p1 = by_id["t1"]
    assert s1 == "success"
    assert p1["ok"] is True
    assert p1["evidence_ids"] == []
    assert p1["data"]["refs"] == []
    assert p0["request_id"] != p1["request_id"]


# ---------------------------------------------------------------------------
# F08: Typed Investigation Query Tools (5 tests)
# ---------------------------------------------------------------------------


def test_f08_t1_fetch_raw_evidence_returns_matching_records_and_missing_ids(
    e2e_fixtures_dir: Path,
    make_app_config: Any,
    make_run_context: Any,
    load_scene_records: Any,
) -> None:
    ctx, _store, _events, _rag, registry = _setup_forensic_registry(
        e2e_fixtures_dir,
        make_app_config,
        make_run_context,
        load_scene_records,
    )

    res = registry.invoke(
        "host",
        "fetch_raw_evidence",
        {
            "physical_ids": [
                "pr-000000000000000000000001",
                "pr-000000000000000000000006",
                "pr-does-not-exist",
            ]
        },
        case_id=ctx.case_id,
        task_id="task-f08-1",
    )

    assert _field(res, "ok") is True
    data = _field(res, "data")
    records = _field(data, "records")
    assert len(records) == 2
    got_pids = {_field(rec, "physical_record_id", "raw_id") for rec in records}
    assert got_pids == {"pr-000000000000000000000001", "pr-000000000000000000000006"}
    assert _field(data, "missing_ids") == ["pr-does-not-exist"]
    qid = _field(data, "query_id") or _field(res, "query_id")
    assert isinstance(qid, str) and qid.strip() != ""


def test_f08_t1_query_events_filters_by_host_and_source_type(
    e2e_fixtures_dir: Path,
    make_app_config: Any,
    make_run_context: Any,
    load_scene_records: Any,
) -> None:
    ctx, _store, _events, _rag, registry = _setup_forensic_registry(
        e2e_fixtures_dir,
        make_app_config,
        make_run_context,
        load_scene_records,
    )

    res1 = registry.invoke(
        "host",
        "query_events",
        {"filters": {"host": "H1.example.local"}, "limit": 50},
        case_id=ctx.case_id,
        task_id="task-f08-2",
    )
    res2 = registry.invoke(
        "host",
        "query_events",
        {"filters": {"host": "H1.example.local"}, "limit": 50},
        case_id=ctx.case_id,
        task_id="task-f08-2",
    )

    assert _field(res1, "ok") is True
    assert _field(res2, "ok") is True
    ev1 = _field(_field(res1, "data"), "events")
    ev2 = _field(_field(res2, "data"), "events")
    assert len(ev1) >= 1

    for ev in ev1:
        fields = _field(ev, "fields", default={}) or {}
        host = _field(ev, "host", "hostname") or fields.get("hostname") or fields.get("Computer")
        assert host == "H1.example.local"
        assert isinstance(_field(ev, "event_id"), str) and _field(ev, "event_id").strip() != ""
        assert isinstance(_field(ev, "physical_record_id"), str) and _field(ev, "physical_record_id").strip() != ""

    assert [_field(e, "event_id") for e in ev1] == [_field(e, "event_id") for e in ev2]

    first_source_type = _field(ev1[0], "source_type")
    assert isinstance(first_source_type, str) and first_source_type.strip() != ""
    res_st = registry.invoke(
        "host",
        "query_events",
        {"filters": {"host": "H1.example.local", "source_type": first_source_type}, "limit": 50},
        case_id=ctx.case_id,
        task_id="task-f08-2b",
    )
    assert _field(res_st, "ok") is True
    ev_st = _field(_field(res_st, "data"), "events")
    assert len(ev_st) >= 1
    assert all(_field(e, "source_type") == first_source_type for e in ev_st)


def test_f08_t1_query_events_pagination_cursor_deterministic_and_terminates(
    e2e_fixtures_dir: Path,
    make_app_config: Any,
    make_run_context: Any,
    load_scene_records: Any,
) -> None:
    ctx, _store, _events, _rag, registry = _setup_forensic_registry(
        e2e_fixtures_dir,
        make_app_config,
        make_run_context,
        load_scene_records,
    )

    full_res = registry.invoke(
        "host",
        "query_events",
        {"filters": {}, "limit": 200},
        case_id=ctx.case_id,
        task_id="task-f08-3-full",
    )
    assert _field(full_res, "ok") is True
    full_events = _field(_field(full_res, "data"), "events")
    full_ids = [_field(e, "event_id") for e in full_events]
    assert len(full_ids) >= 3

    def _collect_paged() -> list[str]:
        collected: list[str] = []
        cursor: str | None = None
        pages = 0
        for _ in range(len(full_ids) + 5):
            args: dict[str, Any] = {"filters": {}, "limit": 2}
            if cursor is not None:
                args["cursor"] = cursor
            page = registry.invoke(
                "host",
                "query_events",
                args,
                case_id=ctx.case_id,
                task_id="task-f08-3",
            )
            assert _field(page, "ok") is True
            pdata = _field(page, "data")
            pevents = _field(pdata, "events")
            assert len(pevents) <= 2
            pages += 1
            collected.extend(_field(e, "event_id") for e in pevents)
            next_cursor = _field(pdata, "next_cursor")
            if pages == 1:
                assert next_cursor is not None
            cursor = next_cursor
            if cursor is None:
                assert pages >= 2
                return collected
        raise AssertionError("Pagination cursor did not terminate with next_cursor=None")

    run1 = _collect_paged()
    run2 = _collect_paged()
    assert len(run1) == len(set(run1))
    assert set(run1) == set(full_ids)
    assert run1 == run2


def test_f08_t1_query_events_utc_time_window_filtering(
    e2e_fixtures_dir: Path,
    make_app_config: Any,
    make_run_context: Any,
    load_scene_records: Any,
) -> None:
    ctx, _store, _events, _rag, registry = _setup_forensic_registry(
        e2e_fixtures_dir,
        make_app_config,
        make_run_context,
        load_scene_records,
    )

    win = ("2024-05-30T10:00:00Z", "2024-05-30T10:00:10Z")
    res = registry.invoke(
        "network",
        "query_events",
        {"filters": {"time_window": list(win)}, "limit": 50},
        case_id=ctx.case_id,
        task_id="task-f08-4",
        event_time_window=win,
    )
    assert _field(res, "ok") is True
    events = _field(_field(res, "data"), "events")
    assert len(events) >= 1

    start_dt = datetime(2024, 5, 30, 10, 0, 0, tzinfo=timezone.utc)
    end_dt = datetime(2024, 5, 30, 10, 0, 10, tzinfo=timezone.utc)
    for ev in events:
        fields = _field(ev, "fields", default={}) or {}
        ts_val = _field(ev, "event_time", "timestamp", "@timestamp") or fields.get("@timestamp")
        dt = _parse_utc(ts_val)
        assert dt is not None, f"Event missing parseable UTC timestamp: {ev!r}"
        assert start_dt <= dt < end_dt

    pids = {_field(ev, "physical_record_id") for ev in events}
    assert "pr-000000000000000000000008" not in pids


def test_f08_t1_query_events_empty_result_succeeds_and_audits_provenance(
    e2e_fixtures_dir: Path,
    make_app_config: Any,
    make_run_context: Any,
    load_scene_records: Any,
) -> None:
    ctx, _store, _events, _rag, registry = _setup_forensic_registry(
        e2e_fixtures_dir,
        make_app_config,
        make_run_context,
        load_scene_records,
    )

    res = registry.invoke(
        "host",
        "query_events",
        {"filters": {"host": "NONEXISTENT-HOST-999"}, "limit": 10},
        case_id=ctx.case_id,
        task_id="task-f08-5",
    )

    assert _field(res, "ok") is True
    data = _field(res, "data")
    assert _field(data, "events") == []
    assert _field(data, "next_cursor") is None
    qid = _field(data, "query_id") or _field(res, "query_id")
    assert isinstance(qid, str) and qid.strip() != ""

    assert len(registry.audit_log) == 1
    entry = registry.audit_log[0]
    assert _field(entry, "caller_role", "role") == "host"
    assert _field(entry, "tool_name", "tool") == "query_events"
    assert _field(entry, "case_id") == ctx.case_id
    assert _field(entry, "task_id") == "task-f08-5"
    assert _audit_allowed(entry) is True


# ---------------------------------------------------------------------------
# F13: Base Tools & Role-Scoped Permission Registry (5 tests)
# ---------------------------------------------------------------------------


def test_f13_t1_investigation_role_allowed_read_and_forensic_tools(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    make_app_config: Any,
    make_run_context: Any,
    load_scene_records: Any,
) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir(parents=True, exist_ok=True)
    (sandbox / "notes.txt").write_text("case-note-alpha\n", encoding="utf-8")

    ctx, _store, _events, _rag, registry = _setup_forensic_registry(
        e2e_fixtures_dir,
        make_app_config,
        make_run_context,
        load_scene_records,
        workspace_root=sandbox,
    )

    r_read = registry.invoke(
        "host",
        "read",
        {"path": "notes.txt"},
        case_id=ctx.case_id,
        task_id="task-f13-1",
    )
    r_fetch = registry.invoke(
        "host",
        "fetch_raw_evidence",
        {"physical_ids": ["pr-000000000000000000000001"]},
        case_id=ctx.case_id,
        task_id="task-f13-1",
    )
    r_query = registry.invoke(
        "host",
        "query_events",
        {"filters": {"host": "H1.example.local"}, "limit": 5},
        case_id=ctx.case_id,
        task_id="task-f13-1",
    )
    r_rag = registry.invoke(
        "host",
        "search_knowledge",
        {"query": "creator_pid", "top_k": 2},
        case_id=ctx.case_id,
        task_id="task-f13-1",
    )

    for res in (r_read, r_fetch, r_query, r_rag):
        assert _field(res, "ok") is True

    read_data = _field(r_read, "data")
    assert "case-note-alpha" in str(_field(read_data, "content", "text", default=read_data))
    assert len(registry.audit_log) == 4
    assert all(_audit_allowed(entry) is True for entry in registry.audit_log)


def test_f13_t1_investigation_roles_denied_write_edit_bash_and_audited(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    make_app_config: Any,
    make_run_context: Any,
    load_scene_records: Any,
) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir(parents=True, exist_ok=True)
    notes = sandbox / "notes.txt"
    notes.write_text("immutable-content\n", encoding="utf-8")

    ctx, _store, _events, _rag, registry = _setup_forensic_registry(
        e2e_fixtures_dir,
        make_app_config,
        make_run_context,
        load_scene_records,
        workspace_root=sandbox,
    )

    r_write = registry.invoke(
        "host",
        "write",
        {"path": "new.txt", "content": "x"},
        case_id=ctx.case_id,
        task_id="task-f13-2a",
    )
    r_edit = registry.invoke(
        "network",
        "edit",
        {"path": "notes.txt", "old_text": "immutable", "new_text": "mutated"},
        case_id=ctx.case_id,
        task_id="task-f13-2b",
    )
    r_bash = registry.invoke(
        "lead",
        "bash",
        {"command": "echo hacked"},
        case_id=ctx.case_id,
        task_id="task-f13-2c",
    )

    for res in (r_write, r_edit, r_bash):
        assert _field(res, "ok") is False
        assert _error_code(res) == "PERMISSION_DENIED"

    assert notes.read_text(encoding="utf-8") == "immutable-content\n"
    assert not (sandbox / "new.txt").exists()
    assert len(registry.audit_log) == 3
    assert all(_audit_allowed(entry) is False for entry in registry.audit_log)
    assert all(_error_code(entry) == "PERMISSION_DENIED" for entry in registry.audit_log)


def test_f13_t1_maintenance_role_allowed_write_edit_read_inside_draft_sandbox(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    make_app_config: Any,
    make_run_context: Any,
    load_scene_records: Any,
) -> None:
    draft_sandbox = tmp_path / "draft_sandbox"
    draft_sandbox.mkdir(parents=True, exist_ok=True)

    ctx, _store, _events, _rag, registry = _setup_forensic_registry(
        e2e_fixtures_dir,
        make_app_config,
        make_run_context,
        load_scene_records,
        workspace_root=draft_sandbox,
        draft_sandbox_root=draft_sandbox,
    )

    r1 = registry.invoke(
        "converter_agent",
        "write",
        {"path": "draft_mapping.yaml", "content": "mappings:\n  a: b\n"},
        case_id=ctx.case_id,
        task_id="task-f13-3a",
    )
    r2 = registry.invoke(
        "converter_agent",
        "edit",
        {"path": "draft_mapping.yaml", "old_text": "a: b", "new_text": "creator_pid: ParentProcessId"},
        case_id=ctx.case_id,
        task_id="task-f13-3b",
    )
    r3 = registry.invoke(
        "converter_agent",
        "read",
        {"path": "draft_mapping.yaml"},
        case_id=ctx.case_id,
        task_id="task-f13-3c",
    )
    r4 = registry.invoke(
        "rule_agent",
        "write",
        {"path": "draft_rule.yml", "content": "title: Draft Rule\nstatus: test\n"},
        case_id=ctx.case_id,
        task_id="task-f13-3d",
    )
    r5 = registry.invoke(
        "rule_agent",
        "read",
        {"path": "draft_rule.yml"},
        case_id=ctx.case_id,
        task_id="task-f13-3e",
    )

    for res in (r1, r2, r3, r4, r5):
        assert _field(res, "ok") is True

    assert (draft_sandbox / "draft_mapping.yaml").read_text(encoding="utf-8") == (
        "mappings:\n  creator_pid: ParentProcessId\n"
    )
    assert (draft_sandbox / "draft_rule.yml").read_text(encoding="utf-8") == (
        "title: Draft Rule\nstatus: test\n"
    )
    assert "ParentProcessId" in str(_field(_field(r3, "data"), "content", "text", default=_field(r3, "data")))
    assert len(registry.audit_log) == 5
    assert all(_audit_allowed(entry) is True for entry in registry.audit_log)


def test_f13_t1_maintenance_role_allowed_restricted_bash_in_sandbox(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    make_app_config: Any,
    make_run_context: Any,
    load_scene_records: Any,
) -> None:
    draft_sandbox = tmp_path / "draft_sandbox"
    draft_sandbox.mkdir(parents=True, exist_ok=True)

    ctx, _store, _events, _rag, registry = _setup_forensic_registry(
        e2e_fixtures_dir,
        make_app_config,
        make_run_context,
        load_scene_records,
        workspace_root=draft_sandbox,
        draft_sandbox_root=draft_sandbox,
    )

    res = registry.invoke(
        "rule_agent",
        "bash",
        {"command": "echo maintenance_ok"},
        case_id=ctx.case_id,
        task_id="task-f13-4",
    )

    assert _field(res, "ok") is True
    data = _field(res, "data")
    assert "maintenance_ok" in str(_field(data, "stdout", "output", default=data))
    assert len(registry.audit_log) == 1
    entry = registry.audit_log[0]
    assert _field(entry, "caller_role", "role") == "rule_agent"
    assert _field(entry, "tool_name", "tool") == "bash"
    assert _audit_allowed(entry) is True


def test_f13_t1_audit_log_records_complete_metadata_for_allow_and_deny(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    make_app_config: Any,
    make_run_context: Any,
    load_scene_records: Any,
) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir(parents=True, exist_ok=True)

    ctx, _store, _events, _rag, registry = _setup_forensic_registry(
        e2e_fixtures_dir,
        make_app_config,
        make_run_context,
        load_scene_records,
        workspace_root=sandbox,
    )

    r_ok = registry.invoke(
        "verifier",
        "query_events",
        {"filters": {}, "limit": 5},
        case_id=ctx.case_id,
        task_id="t-audit-allow",
    )
    r_deny = registry.invoke(
        "verifier",
        "write",
        {"path": "x.txt", "content": "x"},
        case_id=ctx.case_id,
        task_id="t-audit-deny",
    )

    assert _field(r_ok, "ok") is True
    assert _field(r_deny, "ok") is False
    assert _error_code(r_deny) == "PERMISSION_DENIED"
    assert len(registry.audit_log) == 2

    e0, e1 = registry.audit_log[0], registry.audit_log[1]
    assert _field(e0, "caller_role", "role") == "verifier"
    assert _field(e0, "tool_name", "tool") == "query_events"
    assert _field(e0, "case_id") == ctx.case_id
    assert _field(e0, "task_id") == "t-audit-allow"
    assert _audit_allowed(e0) is True

    assert _field(e1, "caller_role", "role") == "verifier"
    assert _field(e1, "tool_name", "tool") == "write"
    assert _field(e1, "case_id") == ctx.case_id
    assert _field(e1, "task_id") == "t-audit-deny"
    assert _audit_allowed(e1) is False
    assert _error_code(e1) == "PERMISSION_DENIED"


# ---------------------------------------------------------------------------
# F14: Maintenance Pipeline & SnapshotRegistry (5 tests)
# ---------------------------------------------------------------------------


def test_f14_t1_snapshot_registry_publish_and_get_all_kinds(tmp_path: Path) -> None:
    from apt_agent.maintenance import SnapshotRegistry

    reg = SnapshotRegistry(tmp_path / "snapshots")
    specs = [
        ("mapping", "map-v1", {"zircolite.yaml": "mappings:\n  a: b\n"}, {"source": "e2e"}),
        ("ruleset", "rules-v1", {"rule.yml": "title: Test Rule\n"}, {"engine": "rsigma"}),
        ("knowledge", "kb-v1", {"kb.jsonl": '{"chunk_id":"c1"}\n'}, {"docs": 1}),
    ]
    for kind, version, artifacts, metadata in specs:
        published = reg.publish_snapshot(kind, version, artifacts, metadata)
        fetched = reg.get_snapshot(kind, version)
        for snap in (published, fetched):
            assert _field(snap, "kind") == kind
            assert _field(snap, "version") == version
            assert _field(snap, "artifacts") == artifacts
            assert _field(snap, "metadata") == metadata


def test_f14_t1_validate_candidate_valid_mapping_passes_all_stages(
    e2e_fixtures_dir: Path,
    make_app_config: Any,
    make_run_context: Any,
) -> None:
    from apt_agent.maintenance import validate_candidate

    cfg = make_app_config()
    ctx = make_run_context(config=cfg)
    mapping_text = (e2e_fixtures_dir / "rules" / "mappings" / "valid_zircolite_mapping.yaml").read_text(
        encoding="utf-8"
    )
    samples = json.loads(
        (e2e_fixtures_dir / "rules" / "mappings" / "mapping_samples.json").read_text(encoding="utf-8")
    )
    fixtures = {
        "samples": samples,
        "positive": samples["positive"],
        "negative": samples["negative"],
        "expected_fields": samples["expected_fields"],
    }

    res = validate_candidate(ctx, "mapping", mapping_text, fixtures)

    assert _field(res, "passed") is True
    stage_results = _field(res, "stage_results")
    _assert_stages_passed(stage_results, min_stages=1)
    assert isinstance(_field(res, "replay_diff"), dict)


def test_f14_t1_validate_candidate_valid_single_sigma_rule_passes(
    e2e_fixtures_dir: Path,
    make_app_config: Any,
    make_run_context: Any,
) -> None:
    from apt_agent.maintenance import validate_candidate

    cfg = make_app_config()
    ctx = make_run_context(config=cfg)
    rule_yaml = (e2e_fixtures_dir / "rules" / "valid" / "win_winword_powershell.yml").read_text(
        encoding="utf-8"
    )

    pos_event = {
        "event_id": "evt-pos-1",
        "raw_id": "pr-000000000000000000000006",
        "@timestamp": "2024-05-30T10:00:00.123Z",
        "Computer": "H1.example.local",
        "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -NoP -W Hidden -Enc SQBFAFgA",
    }
    neg_event = {
        "event_id": "evt-neg-1",
        "raw_id": "pr-neg-1",
        "@timestamp": "2024-05-30T10:05:00.000Z",
        "Computer": "H1.example.local",
        "ParentImage": "C:\\Windows\\explorer.exe",
        "Image": "C:\\Windows\\System32\\notepad.exe",
        "CommandLine": "notepad.exe notes.txt",
    }

    res = validate_candidate(
        ctx,
        "sigma_rule",
        rule_yaml,
        {"positive": [pos_event], "negative": [neg_event]},
    )

    assert _field(res, "passed") is True
    stage_results = _field(res, "stage_results")
    _assert_stages_passed(stage_results, min_stages=1)
    replay_diff = _field(res, "replay_diff")
    assert isinstance(replay_diff, dict)


def test_f14_t1_validate_candidate_valid_correlation_rule_passes_via_rsigma(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    make_app_config: Any,
    make_run_context: Any,
) -> None:
    from apt_agent.maintenance import validate_candidate

    rules_dir = tmp_path / "corr_rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    base_p1 = e2e_fixtures_dir / "rules" / "valid" / "win_winword_powershell.yml"
    base_p2 = e2e_fixtures_dir / "rules" / "valid" / "win_powershell_c2_flow.yml"
    corr_p = e2e_fixtures_dir / "rules" / "correlation" / "winword_ps_c2_temporal.yml"
    for src in (base_p1, base_p2, corr_p):
        shutil.copy2(src, rules_dir / src.name)

    cfg = make_app_config(base_dir=tmp_path / "env", rules_dir=rules_dir)
    ctx = make_run_context(config=cfg)

    corr_yaml = corr_p.read_text(encoding="utf-8")
    base_rules = [base_p1.read_text(encoding="utf-8"), base_p2.read_text(encoding="utf-8")]

    e41_event = {
        "event_id": "evt-e41",
        "raw_id": "pr-000000000000000000000006",
        "@timestamp": "2024-05-30T10:00:00.123Z",
        "Computer": "H1.example.local",
        "ProcessGuid": "G7",
        "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    }
    e42_event = {
        "event_id": "evt-e42",
        "raw_id": "pr-000000000000000000000007",
        "@timestamp": "2024-05-30T10:00:03.000Z",
        "Computer": "H1.example.local",
        "ProcessGuid": "G7",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "DestinationIp": "203.0.113.8",
        "DestinationPort": 443,
    }
    neg_event = {
        "event_id": "evt-neg-corr",
        "raw_id": "pr-neg-corr",
        "@timestamp": "2024-05-30T10:15:00.000Z",
        "Computer": "H1.example.local",
        "ProcessGuid": "G-BENIGN",
        "ParentImage": "C:\\Windows\\explorer.exe",
        "Image": "C:\\Windows\\System32\\notepad.exe",
    }

    res = validate_candidate(
        ctx,
        "sigma_rule",
        corr_yaml,
        {
            "positive": [e41_event, e42_event],
            "negative": [neg_event],
            "base_rules": base_rules,
            "rules_dir": str(rules_dir),
        },
    )

    assert _field(res, "passed") is True
    stage_results = _field(res, "stage_results")
    _assert_stages_passed(stage_results, min_stages=2)
    stage_keys_low = [str(k).lower() for k in stage_results]
    assert any(
        any(tok in key for tok in ("replay", "fixture", "sample", "positive", "correlation", "eval", "rsigma"))
        for key in stage_keys_low
    ), f"Expected correlation/replay stage in stage_results, got {list(stage_results)}"
    for stage_val in stage_results.values():
        if isinstance(stage_val, dict):
            if "positive_hits" in stage_val:
                assert stage_val["positive_hits"] >= 1
            if "negative_hits" in stage_val:
                assert stage_val["negative_hits"] == 0
    assert isinstance(_field(res, "replay_diff"), dict)


def test_f14_t1_converter_and_rule_agents_draft_validate_publish_v2(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    make_app_config: Any,
    make_run_context: Any,
) -> None:
    from apt_agent.maintenance import ConverterAgent, RuleAgent, SnapshotRegistry

    scene_dir = e2e_fixtures_dir / "scenarios" / "scene_08_maintenance"
    meta = json.loads((scene_dir / "expected_meta.json").read_text(encoding="utf-8"))
    v1_ver = meta["v1_snapshot"]
    v2_ver = meta["v2_snapshot"]

    mapping_path = (scene_dir / meta["valid_mapping_ref"]).resolve()
    samples_path = (scene_dir / meta["mapping_samples_ref"]).resolve()
    valid_rule_path = (scene_dir / meta["valid_rule_ref"]).resolve()
    corr_rule_path = (scene_dir / meta["correlation_rule_ref"]).resolve()

    mapping_yaml = mapping_path.read_text(encoding="utf-8")
    samples = json.loads(samples_path.read_text(encoding="utf-8"))
    valid_rule_yaml = valid_rule_path.read_text(encoding="utf-8")
    corr_rule_yaml = corr_rule_path.read_text(encoding="utf-8")

    snaps_dir = tmp_path / "snapshots"
    reg = SnapshotRegistry(snaps_dir)
    reg.publish_snapshot("mapping", v1_ver, {"zircolite.yaml": "mappings:\n  EventID: EventID\n"}, {"ver": v1_ver})
    reg.publish_snapshot("ruleset", v1_ver, {"win_winword_powershell.yml": valid_rule_yaml}, {"ver": v1_ver})

    cfg = make_app_config(base_dir=tmp_path / "env", snapshots_dir=snaps_dir)
    ctx = make_run_context(config=cfg, mapping_version=v1_ver, ruleset_version=v1_ver)

    converter = _instantiate_maintenance_agent(ConverterAgent, reg, ctx)
    rule_agent = _instantiate_maintenance_agent(RuleAgent, reg, ctx)

    map_out = _invoke_maintenance_agent(
        converter,
        ctx=ctx,
        registry=reg,
        kind="mapping",
        version=v2_ver,
        candidate=mapping_yaml,
        fixtures={
            "samples": samples,
            "positive": samples["positive"],
            "negative": samples["negative"],
            "expected_fields": samples["expected_fields"],
        },
        metadata={"scene_id": meta["scene_id"], "version": v2_ver},
    )
    map_validation = _field(map_out, "validation", default=map_out)
    assert _field(map_validation, "passed") is True

    rule_out = _invoke_maintenance_agent(
        rule_agent,
        ctx=ctx,
        registry=reg,
        kind="sigma_rule",
        version=v2_ver,
        candidate=valid_rule_yaml,
        fixtures={
            "positive": samples["positive"],
            "negative": samples["negative"],
            "extra_rules": {"winword_ps_c2_temporal.yml": corr_rule_yaml},
        },
        metadata={"scene_id": meta["scene_id"], "version": v2_ver},
    )
    rule_validation = _field(rule_out, "validation", default=rule_out)
    assert _field(rule_validation, "passed") is True

    map_v1 = reg.get_snapshot("mapping", v1_ver)
    map_v2 = reg.get_snapshot("mapping", v2_ver)
    rules_v1 = reg.get_snapshot("ruleset", v1_ver)
    rules_v2 = reg.get_snapshot("ruleset", v2_ver)

    assert _field(map_v1, "version") == v1_ver
    assert _field(map_v2, "version") == v2_ver
    assert _field(rules_v1, "version") == v1_ver
    assert _field(rules_v2, "version") == v2_ver
    assert _field(map_v1, "artifacts") != _field(map_v2, "artifacts")
    assert bool(_field(rules_v1, "artifacts"))
    assert bool(_field(rules_v2, "artifacts"))
