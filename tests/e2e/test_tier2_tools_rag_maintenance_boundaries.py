"""Tier 2 boundary, negative, and live LangGraph v1 wire E2E tests for F06, F08, F13, F14.

All ``apt_agent`` and ``langgraph_adapter`` imports are kept strictly lazy inside
test functions or local helpers so collection succeeds independently of M3-M6.
"""

from __future__ import annotations

import inspect
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.tier2


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


def _iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _setup_forensic_registry(
    e2e_fixtures_dir: Path,
    make_app_config: Any,
    make_run_context: Any,
    load_scene_records: Any,
    *,
    case_id: str = "case-e2e-001",
    workspace_root: Path | None = None,
    draft_sandbox_root: Path | None = None,
    protected_roots: list[Path] | None = None,
    bash_allowlist: tuple[str, ...] | None = None,
    snapshots_dir: Path | None = None,
    timeout_s: float = 15.0,
) -> tuple[Any, Any, list[Any], Any, Any]:
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.models import Locator
    from apt_agent.tools import RagService, ToolRegistry

    index, records = load_scene_records(e2e_fixtures_dir / "logs")
    cfg = make_app_config(
        knowledge_path=e2e_fixtures_dir / "kb" / "synthetic_kb.jsonl",
        snapshots_dir=snapshots_dir,
        timeout_s=timeout_s,
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
    if "protected_roots" in reg_params and protected_roots is not None:
        reg_kwargs["protected_roots"] = protected_roots
    if "bash_allowlist" in reg_params and bash_allowlist is not None:
        reg_kwargs["bash_allowlist"] = bash_allowlist
    if "bash_timeout_s" in reg_params:
        reg_kwargs["bash_timeout_s"] = timeout_s
    registry = ToolRegistry(ctx, store, events, rag, **reg_kwargs)
    return ctx, store, events, rag, registry


def _compile_langgraph_rag_graph(
    monkeypatch: pytest.MonkeyPatch,
    manifest_path: Path,
    knowledge_path: Path,
    *,
    valid_ids: tuple[str, ...] | set[str] = (),
) -> tuple[Any, Any]:
    langgraph_rag_dir = (
        Path(__file__).resolve().parents[2] / "packages" / "apt-rag" / "tools" / "langgraph_rag"
    )
    monkeypatch.syspath_prepend(str(langgraph_rag_dir))

    from langchain_core.messages import AIMessage
    from langgraph.graph import END, START, MessagesState, StateGraph
    from langgraph.prebuilt import ToolNode
    from langgraph_adapter import build_tool

    tool = build_tool(
        manifest_path,
        case_id="demo",
        run_id="run-1",
        resources={"knowledge": knowledge_path},
        valid_ids=valid_ids,
    )
    graph = StateGraph(MessagesState)
    graph.add_node("tools", ToolNode([tool]))
    graph.add_edge(START, "tools")
    graph.add_edge("tools", END)
    return graph.compile(), AIMessage


def _dispatch_v1_call(app: Any, ai_msg_cls: Any, arguments: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    calls = [{"name": "search_knowledge", "args": arguments, "id": "t0", "type": "tool_call"}]
    messages = app.invoke({"messages": [ai_msg_cls(content="", tool_calls=calls)]})["messages"][1:]
    assert len(messages) == 1
    msg = messages[0]
    assert msg.tool_call_id == "t0"
    return msg.status, json.loads(msg.content)


# ---------------------------------------------------------------------------
# F06: RAG Boundaries & Live LangGraph v1 Wire Protocol Errors (6 tests)
# ---------------------------------------------------------------------------


def test_f06_t2_rag_service_corrupt_jsonl_and_timeout_degrade_gracefully(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    make_app_config: Any,
) -> None:
    from apt_agent.tools import RagService

    cfg_corrupt = make_app_config(
        base_dir=tmp_path / "corrupt_env",
        knowledge_path=e2e_fixtures_dir / "kb" / "corrupt_kb.jsonl",
        rag_mode="bm25",
    )
    rag_corrupt = RagService(config=cfg_corrupt.rag)
    r_corrupt = rag_corrupt.search_knowledge("demo", role="lead")

    assert r_corrupt.get("refs", []) == []
    assert r_corrupt.get("evidence_ids", []) == []
    corrupt_err = r_corrupt.get("error")
    assert r_corrupt.get("degraded") is True or bool(corrupt_err) or bool(r_corrupt.get("warnings"))
    if isinstance(corrupt_err, dict) and "code" in corrupt_err:
        assert corrupt_err["code"] in {"DATA_ERROR", "RETRIEVAL_UNAVAILABLE", "TIMEOUT"}

    slow_dir = tmp_path / "slow_rag"
    slow_dir.mkdir(parents=True, exist_ok=True)
    langgraph_rag_dir = (
        Path(__file__).resolve().parents[2] / "packages" / "apt-rag" / "tools" / "langgraph_rag"
    )
    orig_manifest = json.loads((langgraph_rag_dir / "tool.json").read_text(encoding="utf-8"))
    slow_worker = slow_dir / "slow_worker.py"
    slow_worker.write_text("import time\ntime.sleep(5)\n", encoding="utf-8")
    slow_manifest = slow_dir / "tool.json"
    slow_manifest.write_text(
        json.dumps({**orig_manifest, "argv": ["{python}", "-B", slow_worker.name], "timeout_ms": 100}),
        encoding="utf-8",
    )

    cfg_timeout = make_app_config(
        base_dir=tmp_path / "timeout_env",
        knowledge_path=e2e_fixtures_dir / "kb" / "synthetic_kb.jsonl",
        rag_mode="bm25",
        rag_timeout_ms=100,
        rag_offline=False,
        overrides={"rag": {"config_path": str(slow_manifest), "offline": False}},
    )
    rag_params = inspect.signature(RagService).parameters
    to_kwargs: dict[str, Any] = {"config": cfg_timeout.rag}
    if "manifest_path" in rag_params:
        to_kwargs["manifest_path"] = slow_manifest
    if "use_subprocess" in rag_params:
        to_kwargs["use_subprocess"] = True
    rag_timeout = RagService(**to_kwargs)
    r_timeout = rag_timeout.search_knowledge("demo", role="lead")

    assert r_timeout.get("refs", []) == []
    assert r_timeout.get("evidence_ids", []) == []
    to_err = r_timeout.get("error")
    assert r_timeout.get("degraded") is True or bool(to_err) or bool(r_timeout.get("warnings"))
    if isinstance(to_err, dict) and "code" in to_err:
        assert to_err["code"] in {"DATA_ERROR", "RETRIEVAL_UNAVAILABLE", "TIMEOUT"}


def test_f06_t2_rag_role_visibility_filters_and_evidence_ids_always_empty(
    e2e_fixtures_dir: Path,
    make_app_config: Any,
) -> None:
    from apt_agent.tools import RagService

    cfg = make_app_config(
        knowledge_path=e2e_fixtures_dir / "kb" / "synthetic_kb.jsonl",
        rag_mode="bm25",
        rag_top_k=10,
    )
    rag = RagService(config=cfg.rag)

    for role in ("lead", "challenger", "converter_agent"):
        res = rag.search_knowledge("certutil powershell creator_pid", role=role, top_k=10)
        assert res.get("evidence_ids", []) == []
        for ref in res.get("refs", []):
            assert not str(ref.get("chunk_id", "")).startswith(("pr-", "ev-"))
            assert not str(ref.get("doc_id", "")).startswith(("pr-", "ev-"))

    challenger_fp = rag.search_knowledge(
        "powershell.exe",
        role="challenger",
        filters={"doc_type": "fp_reference"},
        top_k=10,
    )
    assert challenger_fp.get("evidence_ids", []) == []
    fp_chunks = {ref["chunk_id"] for ref in challenger_fp.get("refs", [])}
    assert "kb-fp-office-addin" in fp_chunks
    assert "kb-sensor-v1-creator-pid" not in fp_chunks

    conv_v1 = rag.search_knowledge(
        "creator_pid",
        role="converter_agent",
        filters={"doc_type": "field_dict", "version": "v1"},
        top_k=10,
    )
    assert conv_v1.get("evidence_ids", []) == []
    conv_chunks = {ref["chunk_id"] for ref in conv_v1.get("refs", [])}
    assert conv_chunks == {"kb-sensor-v1-creator-pid"}


def test_f06_t2_langgraph_v1_invalid_argument_and_mode_unavailable_live(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    langgraph_rag_dir = (
        Path(__file__).resolve().parents[2] / "packages" / "apt-rag" / "tools" / "langgraph_rag"
    )
    app, ai_msg_cls = _compile_langgraph_rag_graph(
        monkeypatch,
        langgraph_rag_dir / "tool.json",
        langgraph_rag_dir / "sample_knowledge.jsonl",
    )

    for bad_args in (
        {"query": 1},
        {"query": "   \t\n"},
        {"query": "demo", "top_k": True},
        {"query": "demo", "resources": {}},
    ):
        status, reply = _dispatch_v1_call(app, ai_msg_cls, bad_args)
        assert status == "error"
        assert reply["ok"] is False
        assert reply["error"]["code"] == "INVALID_ARGUMENT"

    status, reply = _dispatch_v1_call(app, ai_msg_cls, {"query": "demo", "mode": "dense"})
    assert status == "error"
    assert reply["ok"] is False
    assert reply["error"]["code"] == "MODE_UNAVAILABLE"
    assert reply["error"]["retryable"] is False


def test_f06_t2_langgraph_v1_corrupt_jsonl_and_malformed_wire_inputs_live(
    monkeypatch: pytest.MonkeyPatch,
    e2e_fixtures_dir: Path,
) -> None:
    langgraph_rag_dir = (
        Path(__file__).resolve().parents[2] / "packages" / "apt-rag" / "tools" / "langgraph_rag"
    )
    app, ai_msg_cls = _compile_langgraph_rag_graph(
        monkeypatch,
        langgraph_rag_dir / "tool.json",
        e2e_fixtures_dir / "kb" / "corrupt_kb.jsonl",
    )

    status, reply = _dispatch_v1_call(app, ai_msg_cls, {"query": "demo"})
    assert status == "error"
    assert reply["ok"] is False
    assert reply["error"]["code"] == "DATA_ERROR"
    assert reply["error"]["retryable"] is False

    worker_py = langgraph_rag_dir / "worker.py"
    oversized_payload = b'{"query":"' + (b"a" * 33000) + b'"}'
    malformed_inputs = [
        b'{"broken":NaN}',
        b'{"protocol_version":"1.0","protocol_version":"1.0"}',
        oversized_payload,
    ]
    for raw_in in malformed_inputs:
        proc = subprocess.run(
            [sys.executable, "-B", str(worker_py)],
            input=raw_in,
            capture_output=True,
            timeout=10,
        )
        assert proc.returncode != 0
        assert proc.stdout == b""


def test_f06_t2_langgraph_v1_host_rejects_broken_worker_responses_live(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    langgraph_rag_dir = (
        Path(__file__).resolve().parents[2] / "packages" / "apt-rag" / "tools" / "langgraph_rag"
    )
    original = json.loads((langgraph_rag_dir / "tool.json").read_text(encoding="utf-8"))
    sample_kb = langgraph_rag_dir / "sample_knowledge.jsonl"

    cases: list[tuple[str, str | None, dict[str, Any]]] = [
        ("PROCESS_EXIT", "raise SystemExit(7)", {}),
        ("TIMEOUT", "import time; time.sleep(5)", {"timeout_ms": 200}),
        ("BAD_RESPONSE", "print('unexpected stdout')", {}),
        ("BAD_RESPONSE", 'print(\'{"protocol_version":"1.0","request_id":"wrong","ok":true}\')', {}),
        (
            "BAD_RESPONSE",
            (
                "import sys,json; r=json.load(sys.stdin); "
                "print(json.dumps(dict(protocol_version='1.0',request_id=r['request_id'],"
                "ok=True,data={},evidence_ids=[])))"
            ),
            {},
        ),
        ("OUTPUT_LIMIT", "print('x' * (1024 * 1024))", {}),
        ("START_ERROR", None, {"missing_bin": True}),
    ]

    for idx, (expected_code, program, extra) in enumerate(cases):
        case_dir = tmp_path / f"worker_case_{idx}"
        case_dir.mkdir(parents=True, exist_ok=True)
        manifest = case_dir / "tool.json"
        if extra.get("missing_bin"):
            argv = [str(case_dir / "nonexistent_worker_binary_xyz")]
        else:
            worker = case_dir / f"fake_{idx}.py"
            worker.write_text(program or "", encoding="utf-8")
            argv = ["{python}", "-B", worker.name]

        manifest.write_text(
            json.dumps(
                {
                    **original,
                    "argv": argv,
                    "timeout_ms": extra.get("timeout_ms", 5000),
                }
            ),
            encoding="utf-8",
        )
        app, ai_msg_cls = _compile_langgraph_rag_graph(monkeypatch, manifest, sample_kb)
        status, reply = _dispatch_v1_call(app, ai_msg_cls, {"query": "demo"})
        assert status == "error"
        assert reply["ok"] is False
        assert reply["error"]["code"] == expected_code
        if expected_code == "TIMEOUT":
            assert reply["error"]["retryable"] is True


def test_f06_t2_langgraph_v1_search_knowledge_rejects_nonempty_evidence_ids_live(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    langgraph_rag_dir = (
        Path(__file__).resolve().parents[2] / "packages" / "apt-rag" / "tools" / "langgraph_rag"
    )
    original = json.loads((langgraph_rag_dir / "tool.json").read_text(encoding="utf-8"))
    worker = tmp_path / "leaky_worker.py"
    worker.write_text(
        (
            "import sys, json\n"
            "r = json.load(sys.stdin)\n"
            "d = dict(retrieval_id='r', snapshot_id='s', requested_mode='bm25', "
            "mode='bm25', refs=[], warnings=[])\n"
            "print(json.dumps(dict(protocol_version='1.0', request_id=r['request_id'], "
            "ok=True, data=d, evidence_ids=['pr-demo-1'])))\n"
        ),
        encoding="utf-8",
    )
    manifest = tmp_path / "tool.json"
    manifest.write_text(
        json.dumps({**original, "name": "search_knowledge", "argv": ["{python}", "-B", worker.name]}),
        encoding="utf-8",
    )

    app, ai_msg_cls = _compile_langgraph_rag_graph(
        monkeypatch,
        manifest,
        langgraph_rag_dir / "sample_knowledge.jsonl",
        valid_ids={"pr-demo-1"},
    )
    status, reply = _dispatch_v1_call(app, ai_msg_cls, {"query": "demo"})
    assert status == "error"
    assert reply["ok"] is False
    assert reply["error"]["code"] == "OUT_OF_SCOPE"


# ---------------------------------------------------------------------------
# F08: Investigation Query Tool Boundaries (5 tests)
# ---------------------------------------------------------------------------


def test_f08_t2_fetch_raw_evidence_cross_case_id_rejected_out_of_scope(
    e2e_fixtures_dir: Path,
    make_app_config: Any,
    make_run_context: Any,
    load_scene_records: Any,
) -> None:
    _ctx, _store, _events, _rag, registry = _setup_forensic_registry(
        e2e_fixtures_dir,
        make_app_config,
        make_run_context,
        load_scene_records,
        case_id="case-a",
    )

    res = registry.invoke(
        "host",
        "fetch_raw_evidence",
        {"physical_ids": ["pr-000000000000000000000001"]},
        case_id="case-b",
        task_id="t-xcase",
    )
    assert _field(res, "ok") is False
    assert _error_code(res) == "OUT_OF_SCOPE"
    assert len(registry.audit_log) == 1
    assert _audit_allowed(registry.audit_log[0]) is False
    assert _error_code(registry.audit_log[0]) == "OUT_OF_SCOPE"


def test_f08_t2_query_events_out_of_time_window_rejected_out_of_scope(
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
        "network",
        "query_events",
        {
            "filters": {"time_window": ["2024-05-30T10:05:00Z", "2024-05-30T10:10:00Z"]},
            "limit": 10,
        },
        case_id=ctx.case_id,
        task_id="t-win",
        event_time_window=("2024-05-30T10:00:00Z", "2024-05-30T10:01:00Z"),
    )
    assert _field(res, "ok") is False
    assert _error_code(res) == "OUT_OF_SCOPE"
    assert len(registry.audit_log) == 1
    assert _audit_allowed(registry.audit_log[0]) is False
    assert _error_code(registry.audit_log[0]) == "OUT_OF_SCOPE"


def test_f08_t2_query_events_invalid_limit_and_invalid_cursor_raise_invalid_argument(
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

    invalid_args_list = [
        {"filters": {}, "limit": 0},
        {"filters": {}, "limit": -1},
        {"filters": {}, "limit": True},
        {"filters": {}, "limit": 10, "cursor": "corrupt-$$$"},
    ]
    for idx, args in enumerate(invalid_args_list):
        res = registry.invoke(
            "host",
            "query_events",
            args,
            case_id=ctx.case_id,
            task_id=f"t-inv-{idx}",
        )
        assert _field(res, "ok") is False
        assert _error_code(res) == "INVALID_ARGUMENT"


def test_f08_t2_query_events_half_open_utc_boundary_start_inclusive_end_exclusive(
    e2e_fixtures_dir: Path,
    make_app_config: Any,
    make_run_context: Any,
    load_scene_records: Any,
) -> None:
    ctx, _store, events, _rag, registry = _setup_forensic_registry(
        e2e_fixtures_dir,
        make_app_config,
        make_run_context,
        load_scene_records,
    )

    target_ev = None
    target_dt = None
    for ev in events:
        if _field(ev, "physical_record_id") == "pr-000000000000000000000008":
            fields = _field(ev, "fields", default={}) or {}
            dt = _parse_utc(_field(ev, "event_time", "timestamp", "@timestamp") or fields.get("@timestamp"))
            if dt is not None:
                target_ev = ev
                target_dt = dt
                break
    if target_ev is None or target_dt is None:
        for ev in events:
            fields = _field(ev, "fields", default={}) or {}
            dt = _parse_utc(_field(ev, "event_time", "timestamp", "@timestamp") or fields.get("@timestamp"))
            if dt is not None:
                target_ev = ev
                target_dt = dt
                break

    assert target_ev is not None and target_dt is not None
    target_id = _field(target_ev, "event_id")

    t_exact = _iso_utc(target_dt)
    t_before = _iso_utc(target_dt - timedelta(seconds=1))
    t_after = _iso_utc(target_dt + timedelta(seconds=1))

    res_inc = registry.invoke(
        "host",
        "query_events",
        {"filters": {"time_window": [t_exact, t_after]}, "limit": 100},
        case_id=ctx.case_id,
        task_id="t-half-open-inc",
        event_time_window=(t_exact, t_after),
    )
    assert _field(res_inc, "ok") is True
    ids_inc = {_field(e, "event_id") for e in _field(_field(res_inc, "data"), "events")}
    assert target_id in ids_inc

    res_exc = registry.invoke(
        "host",
        "query_events",
        {"filters": {"time_window": [t_before, t_exact]}, "limit": 100},
        case_id=ctx.case_id,
        task_id="t-half-open-exc",
        event_time_window=(t_before, t_exact),
    )
    assert _field(res_exc, "ok") is True
    ids_exc = {_field(e, "event_id") for e in _field(_field(res_exc, "data"), "events")}
    assert target_id not in ids_exc


def test_f08_t2_fetch_raw_evidence_missing_id_and_invalid_type_boundaries(
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

    r_missing = registry.invoke(
        "host",
        "fetch_raw_evidence",
        {"physical_ids": ["pr-nonexistent-999"]},
        case_id=ctx.case_id,
        task_id="t-missing-id",
    )
    assert _field(r_missing, "ok") is True
    mdata = _field(r_missing, "data")
    assert _field(mdata, "records") == []
    assert _field(mdata, "missing_ids") == ["pr-nonexistent-999"]

    r_bad_type = registry.invoke(
        "host",
        "fetch_raw_evidence",
        {"physical_ids": [123]},
        case_id=ctx.case_id,
        task_id="t-bad-type",
    )
    assert _field(r_bad_type, "ok") is False
    assert _error_code(r_bad_type) == "INVALID_ARGUMENT"


# ---------------------------------------------------------------------------
# F13: Base Tools, Sandboxing & Permission Matrix Boundaries (6 tests)
# ---------------------------------------------------------------------------


def test_f13_t2_all_seven_investigation_roles_denied_write_edit_bash(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    make_app_config: Any,
    make_run_context: Any,
    load_scene_records: Any,
) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir(parents=True, exist_ok=True)
    (sandbox / "notes.txt").write_text("immutable\n", encoding="utf-8")

    ctx, _store, _events, _rag, registry = _setup_forensic_registry(
        e2e_fixtures_dir,
        make_app_config,
        make_run_context,
        load_scene_records,
        workspace_root=sandbox,
    )

    roles = ("lead", "host", "network", "challenger", "verifier", "repair", "ranker")
    tool_args = {
        "write": {"path": "x.txt", "content": "x"},
        "edit": {"path": "notes.txt", "old_text": "immutable", "new_text": "changed"},
        "bash": {"command": "echo denied"},
    }
    for role in roles:
        for tool_name, args in tool_args.items():
            res = registry.invoke(
                role,
                tool_name,
                args,
                case_id=ctx.case_id,
                task_id=f"t-deny-{role}-{tool_name}",
            )
            assert _field(res, "ok") is False
            assert _error_code(res) == "PERMISSION_DENIED"

    assert len(registry.audit_log) == 21
    assert all(_audit_allowed(e) is False and _error_code(e) == "PERMISSION_DENIED" for e in registry.audit_log)


def test_f13_t2_unknown_role_and_unknown_tool_denied_and_audited(
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

    r_role = registry.invoke(
        "unknown_role",
        "read",
        {"path": "x"},
        case_id=ctx.case_id,
        task_id="t-unk-role",
    )
    r_tool = registry.invoke(
        "host",
        "no_such_tool",
        {},
        case_id=ctx.case_id,
        task_id="t-unk-tool",
    )

    assert _field(r_role, "ok") is False
    assert _error_code(r_role) in {"PERMISSION_DENIED", "INVALID_ARGUMENT"}
    assert _field(r_tool, "ok") is False
    assert _error_code(r_tool) in {"PERMISSION_DENIED", "INVALID_ARGUMENT"}

    assert len(registry.audit_log) == 2
    assert all(_audit_allowed(entry) is False for entry in registry.audit_log)


def test_f13_t2_read_and_write_path_traversal_dotdot_and_absolute_escape_denied(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    make_app_config: Any,
    make_run_context: Any,
    load_scene_records: Any,
) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir(parents=True, exist_ok=True)
    outside_secret = tmp_path / "outside_secret.txt"
    outside_secret.write_text("TOP_SECRET_VALUE\n", encoding="utf-8")

    ctx, _store, _events, _rag, registry = _setup_forensic_registry(
        e2e_fixtures_dir,
        make_app_config,
        make_run_context,
        load_scene_records,
        workspace_root=sandbox,
        draft_sandbox_root=sandbox,
    )

    attempts = [
        ("host", "read", {"path": "../outside_secret.txt"}),
        ("host", "read", {"path": str(outside_secret)}),
        ("rule_agent", "write", {"path": "../escape.txt", "content": "pwn"}),
        ("rule_agent", "write", {"path": str(tmp_path / "abs_escape.txt"), "content": "pwn"}),
    ]
    for idx, (role, tool_name, args) in enumerate(attempts):
        res = registry.invoke(
            role,
            tool_name,
            args,
            case_id=ctx.case_id,
            task_id=f"t-trav-{idx}",
        )
        assert _field(res, "ok") is False
        assert _error_code(res) == "OUT_OF_SCOPE"
        assert "TOP_SECRET_VALUE" not in str(_field(res, "data", default=""))

    assert not (tmp_path / "escape.txt").exists()
    assert not (tmp_path / "abs_escape.txt").exists()
    assert len(registry.audit_log) == 4
    assert all(_audit_allowed(e) is False and _error_code(e) == "OUT_OF_SCOPE" for e in registry.audit_log)


def test_f13_t2_symlink_escape_outside_sandbox_denied(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    make_app_config: Any,
    make_run_context: Any,
    load_scene_records: Any,
) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir(parents=True, exist_ok=True)
    outside_target = tmp_path / "outside_target.txt"
    outside_target.write_text("OUTSIDE_ORIGINAL\n", encoding="utf-8")
    (sandbox / "link.txt").symlink_to(outside_target)

    ctx, _store, _events, _rag, registry = _setup_forensic_registry(
        e2e_fixtures_dir,
        make_app_config,
        make_run_context,
        load_scene_records,
        workspace_root=sandbox,
        draft_sandbox_root=sandbox,
    )

    r_read = registry.invoke(
        "host",
        "read",
        {"path": "link.txt"},
        case_id=ctx.case_id,
        task_id="t-sym-read",
    )
    r_write = registry.invoke(
        "converter_agent",
        "write",
        {"path": "link.txt", "content": "OVERWRITTEN"},
        case_id=ctx.case_id,
        task_id="t-sym-write",
    )

    for res in (r_read, r_write):
        assert _field(res, "ok") is False
        assert _error_code(res) == "OUT_OF_SCOPE"

    assert outside_target.read_text(encoding="utf-8") == "OUTSIDE_ORIGINAL\n"
    assert len(registry.audit_log) == 2
    assert all(_audit_allowed(e) is False for e in registry.audit_log)


def test_f13_t2_maintenance_role_cannot_write_active_snapshot_or_raw_store(
    tmp_path: Path,
    e2e_fixtures_dir: Path,
    make_app_config: Any,
    make_run_context: Any,
    load_scene_records: Any,
) -> None:
    snapshots_dir = tmp_path / "snapshots"
    active_rule = snapshots_dir / "ruleset" / "v1" / "rule.yml"
    active_rule.parent.mkdir(parents=True, exist_ok=True)
    active_rule.write_text("title: Active v1 Rule\n", encoding="utf-8")

    raw_store_dir = tmp_path / "raw_store"
    raw_store_dir.mkdir(parents=True, exist_ok=True)
    raw_file = raw_store_dir / "raw.json"
    raw_file.write_text('{"id":"raw-1"}\n', encoding="utf-8")

    draft_sandbox = tmp_path / "draft_sandbox"
    draft_sandbox.mkdir(parents=True, exist_ok=True)

    ctx, _store, _events, _rag, registry = _setup_forensic_registry(
        e2e_fixtures_dir,
        make_app_config,
        make_run_context,
        load_scene_records,
        workspace_root=draft_sandbox,
        draft_sandbox_root=draft_sandbox,
        protected_roots=[snapshots_dir, raw_store_dir],
        snapshots_dir=snapshots_dir,
    )

    r1 = registry.invoke(
        "rule_agent",
        "write",
        {"path": str(active_rule), "content": "tampered"},
        case_id=ctx.case_id,
        task_id="t-snap-w",
    )
    r2 = registry.invoke(
        "rule_agent",
        "edit",
        {"path": str(active_rule), "old_text": "Active v1 Rule", "new_text": "Tampered"},
        case_id=ctx.case_id,
        task_id="t-snap-e",
    )
    r3 = registry.invoke(
        "converter_agent",
        "write",
        {"path": str(raw_file), "content": "tampered"},
        case_id=ctx.case_id,
        task_id="t-raw-w",
    )

    for res in (r1, r2, r3):
        assert _field(res, "ok") is False
        assert _error_code(res) in {"OUT_OF_SCOPE", "PERMISSION_DENIED"}

    assert active_rule.read_text(encoding="utf-8") == "title: Active v1 Rule\n"
    assert raw_file.read_text(encoding="utf-8") == '{"id":"raw-1"}\n'
    assert len(registry.audit_log) == 3
    assert all(_audit_allowed(e) is False for e in registry.audit_log)


def test_f13_t2_maintenance_bash_case_mismatch_timeout_and_raw_store_deny(
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
        bash_allowlist=("echo", "sleep"),
        timeout_s=0.25,
    )

    r_case = registry.invoke(
        "converter_agent",
        "bash",
        {"command": "echo hi"},
        case_id="wrong-case",
        task_id="t-maint-xcase",
    )
    r_timeout = registry.invoke(
        "rule_agent",
        "bash",
        {"command": "sleep 3", "timeout_s": 0.2},
        case_id=ctx.case_id,
        task_id="t-maint-timeout",
    )
    r_raw = registry.invoke(
        "converter_agent",
        "fetch_raw_evidence",
        {"physical_ids": ["pr-000000000000000000000001"]},
        case_id=ctx.case_id,
        task_id="t-maint-raw",
    )

    assert _field(r_case, "ok") is False and _error_code(r_case) == "OUT_OF_SCOPE"
    assert _field(r_timeout, "ok") is False and _error_code(r_timeout) == "TIMEOUT"
    assert _field(r_raw, "ok") is False and _error_code(r_raw) == "PERMISSION_DENIED"
    assert len(registry.audit_log) == 3
    assert [_audit_allowed(e) for e in registry.audit_log] == [False, True, False]
    assert registry.audit_log[1].outcome == "error"


# ---------------------------------------------------------------------------
# F14: Snapshot Immutability & Maintenance Validation Rejection (5 tests)
# ---------------------------------------------------------------------------


def test_f14_t2_snapshot_registry_rejects_overwrite_of_existing_version(tmp_path: Path) -> None:
    from apt_agent.maintenance import SnapshotRegistry

    reg = SnapshotRegistry(tmp_path / "snapshots")
    reg.publish_snapshot("ruleset", "v1", {"r.yml": "orig"}, {"author": "e2e"})

    with pytest.raises(Exception):
        reg.publish_snapshot("ruleset", "v1", {"r.yml": "new"}, {"author": "e2e"})

    snap = reg.get_snapshot("ruleset", "v1")
    assert _field(snap, "artifacts") == {"r.yml": "orig"}


def test_f14_t2_publishing_v2_snapshot_does_not_mutate_running_v1_case_context(
    tmp_path: Path,
    make_app_config: Any,
    make_run_context: Any,
) -> None:
    from apt_agent.maintenance import SnapshotRegistry

    snaps_dir = tmp_path / "snapshots"
    reg = SnapshotRegistry(snaps_dir)
    reg.publish_snapshot("mapping", "v1", {"map.yaml": "v1_map"}, {"ver": "v1"})
    reg.publish_snapshot("ruleset", "v1", {"rule.yml": "v1_rule"}, {"ver": "v1"})

    cfg = make_app_config(base_dir=tmp_path / "env", snapshots_dir=snaps_dir)
    ctx_v1 = make_run_context(config=cfg, mapping_version="v1", ruleset_version="v1")

    reg.publish_snapshot("mapping", "v2", {"map.yaml": "v2_map"}, {"ver": "v2"})
    reg.publish_snapshot("ruleset", "v2", {"rule.yml": "v2_rule"}, {"ver": "v2"})

    assert ctx_v1.mapping_version == "v1"
    assert ctx_v1.ruleset_version == "v1"
    assert _field(reg.get_snapshot("mapping", "v1"), "artifacts") == {"map.yaml": "v1_map"}
    assert _field(reg.get_snapshot("ruleset", "v1"), "artifacts") == {"rule.yml": "v1_rule"}
    assert _field(reg.get_snapshot("mapping", "v2"), "artifacts") == {"map.yaml": "v2_map"}
    assert _field(reg.get_snapshot("ruleset", "v2"), "artifacts") == {"rule.yml": "v2_rule"}


def test_f14_t2_validate_candidate_rejects_invalid_sigma_syntax_and_bad_correlation(
    e2e_fixtures_dir: Path,
    make_app_config: Any,
    make_run_context: Any,
) -> None:
    from apt_agent.maintenance import validate_candidate

    cfg = make_app_config()
    ctx = make_run_context(config=cfg)

    bad_syntax = (e2e_fixtures_dir / "rules" / "invalid" / "bad_syntax.yml").read_text(encoding="utf-8")
    bad_corr = (e2e_fixtures_dir / "rules" / "invalid" / "bad_correlation.yml").read_text(encoding="utf-8")

    r_syn = validate_candidate(ctx, "sigma_rule", bad_syntax, {"positive": [], "negative": []})
    r_corr = validate_candidate(ctx, "sigma_rule", bad_corr, {"positive": [], "negative": []})

    for res in (r_syn, r_corr):
        assert _field(res, "passed") is False
        diag = _field(res, "diagnostics", default=[])
        assert isinstance(diag, list) and len(diag) >= 1


def test_f14_t2_validate_candidate_rejects_invalid_mapping_missing_timestamp_and_excluded_event_id(
    e2e_fixtures_dir: Path,
    make_app_config: Any,
    make_run_context: Any,
) -> None:
    from apt_agent.maintenance import validate_candidate

    cfg = make_app_config()
    ctx = make_run_context(config=cfg)

    invalid_mapping = (e2e_fixtures_dir / "rules" / "mappings" / "invalid_mapping_missing_ts.yaml").read_text(
        encoding="utf-8"
    )
    samples = json.loads(
        (e2e_fixtures_dir / "rules" / "mappings" / "mapping_samples.json").read_text(encoding="utf-8")
    )

    res = validate_candidate(
        ctx,
        "mapping",
        invalid_mapping,
        {
            "samples": samples,
            "positive": samples["positive"],
            "negative": samples["negative"],
            "expected_fields": samples["expected_fields"],
        },
    )

    assert _field(res, "passed") is False
    diag = _field(res, "diagnostics", default=[])
    assert isinstance(diag, list) and len(diag) >= 1
    diag_text = " ".join(str(d) for d in diag)
    assert "@timestamp" in diag_text or "event_id" in diag_text


def test_f14_t2_validate_candidate_rejects_negative_sample_false_positive_and_records_replay_diff(
    e2e_fixtures_dir: Path,
    make_app_config: Any,
    make_run_context: Any,
) -> None:
    from apt_agent.maintenance import validate_candidate

    cfg = make_app_config()
    ctx = make_run_context(config=cfg)

    baseline_rule = (e2e_fixtures_dir / "rules" / "valid" / "win_winword_powershell.yml").read_text(
        encoding="utf-8"
    )
    overly_broad_rule = "\n".join(
        [
            "title: Overly Broad EXE Rule",
            "id: 99999999-0000-0000-0000-000000000099",
            "status: test",
            "logsource:",
            "  category: process_creation",
            "  product: windows",
            "detection:",
            "  selection:",
            "    Image|endswith: '.exe'",
            "  condition: selection",
            "level: low",
        ]
    )

    pos_event = {
        "event_id": "evt-fp-pos",
        "raw_id": "pr-000000000000000000000006",
        "@timestamp": "2024-05-30T10:00:00.123Z",
        "Computer": "H1.example.local",
        "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    }
    neg_event = {
        "event_id": "evt-fp-neg",
        "raw_id": "pr-neg-fp",
        "@timestamp": "2024-05-30T10:05:00.000Z",
        "Computer": "H1.example.local",
        "ParentImage": "C:\\Windows\\explorer.exe",
        "Image": "C:\\Windows\\System32\\notepad.exe",
    }

    res = validate_candidate(
        ctx,
        "sigma_rule",
        overly_broad_rule,
        {
            "positive": [pos_event],
            "negative": [neg_event],
            "baseline_rules": [baseline_rule],
        },
    )

    assert _field(res, "passed") is False
    diag = _field(res, "diagnostics", default=[])
    stage_results = _field(res, "stage_results", default={})
    has_failed_stage = isinstance(stage_results, dict) and any(
        _stage_passed(v) is False for v in stage_results.values()
    )
    has_neg_diag = isinstance(diag, list) and any(
        any(tok in str(d).lower() for tok in ("negative", "false", "fp", "replay", "diff", "broad", "match"))
        for d in diag
    )
    assert has_failed_stage or has_neg_diag, (
        f"Expected negative/replay failure in diagnostics or stage_results, got stage_results={stage_results!r}, diagnostics={diag!r}"
    )
    replay_diff = _field(res, "replay_diff")
    assert isinstance(replay_diff, dict) and len(replay_diff) >= 1
    assert any(bool(v) for v in replay_diff.values()), f"Expected populated replay_diff, got {replay_diff!r}"
