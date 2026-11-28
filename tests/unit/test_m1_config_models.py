"""Unit tests for M1 exceptions, configuration, domain models, and package root."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

import apt_agent
from apt_agent import (
    AppConfig,
    AptAgentError,
    AttackChain,
    BudgetExhaustedError,
    CaseResult,
    CaseRun,
    ConfigError,
    ConflictError,
    Edge,
    EngineError,
    ErrorCode,
    Event,
    Finding,
    GraphState,
    Hit,
    InvalidArgumentError,
    KnowledgeRef,
    LLMConfig,
    Locator,
    MergeReceipt,
    OperationTimeoutError,
    OutOfScopeError,
    PermissionDeniedError,
    Prediction,
    RawRecord,
    RejectedRef,
    RetrievalUnavailableError,
    RuleRun,
    RunContext,
    Submission,
    Task,
    analyze_records,
    exception_from_error_code,
    load_config,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("exc_cls", "expected_code", "expected_retryable"),
    [
        (OutOfScopeError, ErrorCode.OUT_OF_SCOPE, False),
        (PermissionDeniedError, ErrorCode.PERMISSION_DENIED, False),
        (InvalidArgumentError, ErrorCode.INVALID_ARGUMENT, False),
        (EngineError, ErrorCode.ENGINE_ERROR, False),
        (RetrievalUnavailableError, ErrorCode.RETRIEVAL_UNAVAILABLE, True),
        (BudgetExhaustedError, ErrorCode.BUDGET_EXHAUSTED, False),
        (ConflictError, ErrorCode.CONFLICT_ERROR, False),
        (ConfigError, ErrorCode.CONFIG_ERROR, False),
        (OperationTimeoutError, ErrorCode.TIMEOUT, True),
    ],
)
def test_exceptions_canonical_defaults(
    exc_cls: type[AptAgentError],
    expected_code: ErrorCode,
    expected_retryable: bool,
) -> None:
    err = exc_cls("failure")
    assert err.code == expected_code
    assert err.retryable is expected_retryable
    assert err.details == {}
    assert err.to_wire_error() == {
        "code": str(expected_code),
        "message": "failure",
        "retryable": expected_retryable,
    }
    assert err.to_envelope() == {"error": err.to_wire_error()}


def test_exceptions_override_retryable_and_isolated_details() -> None:
    err1 = EngineError("boom", retryable=True, details={"engine": "zircolite"})
    err2 = EngineError("other")
    err1.details["extra"] = 1
    assert err1.retryable is True
    assert err2.details == {}
    full = err1.to_error_dict(include_details=True)
    assert set(full) == {"code", "message", "retryable", "details"}
    assert full["details"] == {"engine": "zircolite", "extra": 1}
    assert set(err1.to_error_dict(include_details=False)) == {"code", "message", "retryable"}

    with pytest.raises(ValueError):
        AptAgentError("bad", code="   ")
    with pytest.raises(ValueError):
        AptAgentError("bad", code=123)  # type: ignore[arg-type]

    nested_input = {"nested": [1, 2], "meta": {"k": "v"}}
    err_nested = EngineError("nested boom", details=nested_input)
    nested_input["nested"].append(99)
    nested_input["meta"]["k"] = "mutated"
    assert err_nested.details == {"nested": [1, 2], "meta": {"k": "v"}}

    exported = err_nested.to_error_dict(include_details=True)
    exported["details"]["nested"].append(42)
    exported["details"]["meta"]["k"] = "changed"
    assert err_nested.details == {"nested": [1, 2], "meta": {"k": "v"}}


def test_exception_from_error_code_mapping() -> None:
    canonical = exception_from_error_code("OUT_OF_SCOPE", "cross-case id")
    assert isinstance(canonical, OutOfScopeError)

    worker_engine = exception_from_error_code("PROCESS_EXIT", "exit 7")
    assert isinstance(worker_engine, EngineError)
    assert worker_engine.details["raw_code"] == "PROCESS_EXIT"

    worker_rag = exception_from_error_code("MODE_UNAVAILABLE", "dense offline")
    assert isinstance(worker_rag, RetrievalUnavailableError)
    assert worker_rag.details["raw_code"] == "MODE_UNAVAILABLE"

    custom = exception_from_error_code("CUSTOM_CODE", "custom", retryable=True)
    assert type(custom) is AptAgentError
    assert custom.code == "CUSTOM_CODE"
    assert custom.retryable is True

    for bad_code in (None, 123, "", "   "):
        with pytest.raises(ValueError):
            exception_from_error_code(bad_code, "bad code")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def test_config_defaults_and_portability() -> None:
    cfg = AppConfig()
    assert set(type(cfg.engines).model_fields) == {
        "zircolite",
        "hayabusa",
        "takajo",
        "chainsaw",
        "rsigma",
        "pysigma",
    }
    assert (
        cfg.budget.max_tasks_per_round,
        cfg.budget.max_rounds,
        cfg.budget.max_steps_per_task,
        cfg.budget.max_challenger_rounds,
        cfg.budget.max_repair_rounds,
        cfg.budget.wall_clock_s,
        cfg.budget.max_tokens,
        cfg.budget.reserve_ratio,
    ) == (3, 5, 8, 1, 1, 300.0, 120000, 0.8)
    assert cfg.rag.offline is True
    assert cfg.rag.mode == "bm25"
    assert cfg.rag.timeout_ms == 60000
    assert cfg.llm.enabled is True
    assert cfg.llm.api_key is None
    assert cfg.llm.is_configured is False
    assert cfg.snapshots.root_dir == Path(".apt_agent/snapshots")

    dumped = cfg.model_dump_json()
    assert "/home/" not in dumped
    assert "starter" not in dumped


def test_config_example_templates_validate() -> None:
    default_cfg = load_config(REPO_ROOT / "config" / "default.example.yaml", env={})
    assert default_cfg.llm.enabled is False
    assert default_cfg.rag.timeout_ms == 60000
    assert default_cfg.snapshots.root_dir == Path(".apt_agent/snapshots")
    assert default_cfg.engines.zircolite.config_path == Path(
        "script/log_convert/configs/zircolite_config.yaml"
    )

    local_cfg = load_config(REPO_ROOT / "config" / "local.example.yaml", env={})
    assert local_cfg.engines.takajo.working_dir is not None
    assert local_cfg.engines.hayabusa.rules_dir is not None
    assert local_cfg.engines.hayabusa.config_path is not None


def test_config_env_vars_and_precedence(tmp_path: Path) -> None:
    yaml_file = tmp_path / "cfg.yaml"
    yaml_file.write_text(
        """
engines:
  zircolite:
    bin_path: "/opt/yaml/zircolite"
    timeout_s: 90
llm:
  enabled: false
  model: "yaml-model"
  api_key: "yaml-secret"
rag:
  top_k: 7
snapshots:
  root_dir: "/var/yaml/snaps"
""",
        encoding="utf-8",
    )

    # 1) Load via APT_AGENT_CONFIG + OPENAI_* defaults
    cfg_openai = load_config(
        env={
            "APT_AGENT_CONFIG": str(yaml_file),
            "OPENAI_API_KEY": "openai-key",
            "OPENAI_BASE_URL": "https://example.invalid/v1",
            "OPENAI_MODEL": "gpt-4o-mini",
            "APT_AGENT_LLM__ENABLED": "true",
        }
    )
    assert cfg_openai.llm.api_key == "openai-key"
    assert cfg_openai.llm.model == "gpt-4o-mini"
    assert cfg_openai.llm.is_configured is True
    assert cfg_openai.engines.zircolite.timeout_s == 90.0

    # 2) Flat aliases + nested APT_AGENT_* + overrides precedence + deep merge preservation
    cfg_full = load_config(
        yaml_file,
        env={
            "OPENAI_API_KEY": "openai-key",
            "OPENAI_MODEL": "openai-model",
            "APT_AGENT_LLM_MODEL": "flat-model",
            "APT_AGENT_LLM__API_KEY": "nested-secret",
            "APT_AGENT_LLM__ENABLED": "yes",
            "APT_AGENT_ENGINES__ZIRCOLITE__BIN_PATH": "",
            "APT_AGENT_RAG_MODE": "hybrid",
            "APT_AGENT_RAG_KNOWLEDGE_PATH": "/tmp/kb.jsonl.gz",
            "APT_AGENT_SNAPSHOTS_ROOT": "/var/env/snaps",
        },
        overrides={
            "llm": {"model": "override-model"},
            "budget": {"max_rounds": 9},
        },
    )
    assert cfg_full.llm.model == "override-model"
    assert cfg_full.llm.api_key == "nested-secret"
    assert cfg_full.llm.enabled is True
    assert cfg_full.engines.zircolite.bin_path is None
    assert cfg_full.engines.zircolite.timeout_s == 90.0
    assert cfg_full.rag.mode == "hybrid"
    assert cfg_full.rag.top_k == 7
    assert cfg_full.rag.knowledge_path == Path("/tmp/kb.jsonl.gz")
    assert cfg_full.snapshots.root_dir == Path("/var/env/snaps")
    assert cfg_full.budget.max_rounds == 9
    assert cfg_full.budget.max_tasks_per_round == 3


def test_config_redaction_and_repr() -> None:
    cfg = load_config(
        env={
            "OPENAI_API_KEY": "sk-super-secret-value",
            "OPENAI_MODEL": "gpt-4o",
        }
    )
    assert cfg.llm.is_configured is True
    assert "sk-super-secret-value" not in repr(cfg.llm)
    redacted = cfg.redacted_dump()
    assert redacted["llm"]["api_key"] == "***"


def test_config_validation_errors(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_config(tmp_path / "missing.yaml", env={})

    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("llm: [unterminated\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(bad_yaml, env={})

    non_mapping = tmp_path / "list.yaml"
    non_mapping.write_text("- item1\n- item2\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(non_mapping, env={})

    with pytest.raises(ConfigError):
        load_config(overrides={"unknown_section": {}}, env={})

    with pytest.raises(ConfigError):
        load_config(overrides={"budget": {"reserve_ratio": 1.5}}, env={})

    with pytest.raises(ConfigError):
        load_config(overrides={"rag": {"top_k": 25}}, env={})

    with pytest.raises(ConfigError):
        load_config(env={"APT_AGENT_LLM__ENABLED": "maybe"})

    with pytest.raises(ConfigError):
        load_config(overrides={"budget": {"max_rounds": True}}, env={})


def test_config_llm_whitespace_normalization_and_env_example() -> None:
    ws_direct = LLMConfig(enabled=True, model="   ", base_url="   ", api_key="  ")
    assert ws_direct.model is None
    assert ws_direct.base_url is None
    assert ws_direct.api_key is None
    assert ws_direct.is_configured is False

    ws_no_auth = LLMConfig(enabled=True, model="gpt-4o", base_url="   ", api_key="   ")
    assert ws_no_auth.is_configured is False

    trimmed = LLMConfig(enabled=True, model=" gpt-4o ", base_url=" https://example.invalid/v1 ")
    assert trimmed.model == "gpt-4o"
    assert trimmed.base_url == "https://example.invalid/v1"
    assert trimmed.is_configured is True

    cfg_ws = load_config(
        overrides={"llm": {"enabled": True, "model": "   ", "base_url": "   "}},
        env={},
    )
    assert cfg_ws.llm.model is None
    assert cfg_ws.llm.base_url is None
    assert cfg_ws.llm.is_configured is False

    # Verify .env.example keeps APT_AGENT_LLM__{API_KEY,BASE_URL,MODEL} commented out
    # so sourcing .env alongside OPENAI_* fallbacks does not clobber OPENAI_API_KEY with None.
    env_text = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    active_env: dict[str, str] = {}
    for line in env_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, _, val = stripped.partition("=")
        active_env[key.strip()] = val.strip()

    assert "APT_AGENT_LLM__API_KEY" not in active_env
    assert "APT_AGENT_LLM__BASE_URL" not in active_env
    assert "APT_AGENT_LLM__MODEL" not in active_env

    merged_env = {
        **active_env,
        "APT_AGENT_LLM__ENABLED": "true",
        "OPENAI_API_KEY": "sk-from-openai-env",
        "OPENAI_MODEL": "gpt-4o-mini",
    }
    cfg_from_env = load_config(env=merged_env)
    assert cfg_from_env.llm.api_key == "sk-from-openai-env"
    assert cfg_from_env.llm.model == "gpt-4o-mini"
    assert cfg_from_env.llm.is_configured is True


# ---------------------------------------------------------------------------
# Domain Models
# ---------------------------------------------------------------------------


def test_models_locator_and_run_context() -> None:
    loc = Locator(filepath="logs/sysmon.xml", linenumber=42)
    assert loc.linenumber == 42

    for bad_line in (0, -5, True):
        with pytest.raises(ValidationError):
            Locator(filepath="logs/sysmon.xml", linenumber=bad_line)  # type: ignore[arg-type]

    with pytest.raises(ValidationError):
        Locator(filepath="   ", linenumber=1)

    assert CaseRun is RunContext
    ctx = RunContext(case_id="case-1", run_id="run-1")
    with pytest.raises(ValidationError):
        ctx.case_id = "other"  # type: ignore[misc]
    copied = ctx.model_copy(update={"run_id": "run-2"})
    assert copied.run_id == "run-2"

    with pytest.raises(ValidationError):
        RunContext(case_id=" ", run_id="run-1")

    for bad_ids in ({""}, {"pr-1", "   "}):
        with pytest.raises(ValidationError):
            RunContext(case_id="case-1", run_id="run-1", valid_physical_ids=frozenset(bad_ids))

    valid_ctx = RunContext(
        case_id="case-1", run_id="run-1", valid_physical_ids=frozenset({"pr-1", "pr-2"})
    )
    assert valid_ctx.valid_physical_ids == frozenset({"pr-1", "pr-2"})


def test_models_raw_record_and_event() -> None:
    caller_payload: dict[str, object] = {"EventID": 1, "nested": {"tags": ["a"]}}
    raw = RawRecord(physical_record_id="pr-001", payload=caller_payload)
    assert raw.raw_id == "pr-001"
    caller_payload["EventID"] = 999
    caller_payload["nested"]["tags"].append("mutated")  # type: ignore[index]
    assert raw.payload == {"EventID": 1, "nested": {"tags": ["a"]}}

    evt_z = Event(
        event_id="evt-1",
        physical_record_id="pr-001",
        event_time="2024-05-30T10:00:00Z",
    )
    assert evt_z.raw_id == "pr-001"
    assert evt_z.event_time == "2024-05-30T10:00:00Z"

    evt_offset = Event(
        event_id="evt-2",
        physical_record_id="pr-002",
        event_time="2024-05-30T10:00:00+00:00",
    )
    assert evt_offset.event_time == "2024-05-30T10:00:00Z"

    evt_tz_plus8 = Event(
        event_id="evt-2b",
        physical_record_id="pr-002b",
        event_time="2024-05-30T12:00:00+08:00",
    )
    assert evt_tz_plus8.event_time == "2024-05-30T04:00:00Z"

    evt_none = Event(event_id="evt-3", physical_record_id="pr-003", event_time="")
    assert evt_none.event_time is None

    with pytest.raises(ValidationError):
        Event(
            event_id="evt-bad",
            physical_record_id="pr-004",
            event_time="2024-05-30T10:00:00",
        )


def test_models_hit_rule_run_and_blackboard_types() -> None:
    lead = Hit(hit_id="h1", rule_id="r1", engine="rsigma", event_ids=[])
    assert lead.is_lead_only is True

    direct = Hit(hit_id="h2", rule_id="r2", engine="zircolite", event_ids=["evt-1"])
    assert direct.is_lead_only is False

    for status in ("ran", "partial", "skipped", "failed"):
        rr = RuleRun(rule_id="r1", engine="zircolite", status=status)  # type: ignore[arg-type]
        assert rr.status == status

    with pytest.raises(ValidationError):
        RuleRun(rule_id="r1", engine="zircolite", status="ran", hit_count=True)  # type: ignore[arg-type]

    kref = KnowledgeRef(
        retrieval_id="ret-1",
        doc_id="doc-1",
        chunk_id="chunk-1",
        version="v1",
        locator="line:1",
        excerpt="Sysmon EID 1",
        match_reason="bm25",
    )
    finding = Finding(
        finding_id="f-1",
        claim="PowerShell spawned by WinWord",
        status="observed",
        evidence_event_ids=["evt-1"],
        knowledge_refs=[kref],
        tactic_ids=["TA0002"],
    )
    edge = Edge(
        from_event_id="evt-1",
        to_event_id="evt-2",
        relation="spawned",
        evidence_event_ids=["evt-1", "evt-2"],
    )
    assert edge.dedup_key == ("evt-1", "evt-2", "spawned")

    sub1 = Submission(
        case_id="c1",
        run_id="r1",
        task_id="t1",
        submission_id="s1",
        query_ids=["q1"],
        findings=[finding],
        edges=[edge],
    )
    sub2 = Submission(
        case_id="c1",
        run_id="r1",
        task_id="t1",
        submission_id="s1",
        query_ids=["q1"],
        findings=[finding.model_copy(update={"claim": "Modified claim"})],
        edges=[edge],
    )
    assert sub1.content_digest() == sub1.content_digest()
    assert sub1.content_digest() != sub2.content_digest()

    receipt = MergeReceipt(
        submission_id="s1",
        accepted_event_ids=["evt-1"],
        rejected_refs=[RejectedRef(ref="kb-1", reason="knowledge ref not evidence")],
        state_version=1,
    )
    assert receipt.rejected_refs[0].ref == "kb-1"

    state = GraphState(case_id="c1", run_id="r1")
    state.round = 1
    state.findings.append(finding)
    assert state.round == 1

    c_best = AttackChain(
        chain_id="c-b",
        critical_relations_clean=True,
        corroborated_critical_count=2,
        direct_evidence_stages=3,
    )
    c_tie = AttackChain(
        chain_id="c-a",
        critical_relations_clean=True,
        corroborated_critical_count=2,
        direct_evidence_stages=3,
    )
    c_lower = AttackChain(
        chain_id="c-0",
        critical_relations_clean=False,
        corroborated_critical_count=5,
        direct_evidence_stages=5,
    )
    ordered = sorted([c_lower, c_best, c_tie], key=lambda c: c.sort_key())
    assert [c.chain_id for c in ordered] == ["c-a", "c-b", "c-0"]

    res = CaseResult(case_id="c1", run_id="r1")
    res.stop_reason = "completed"
    assert res.stop_reason == "completed"

    task = Task(task_id="t1", role="host", question="Trace parent PID")
    assert task.priority == 0


# ---------------------------------------------------------------------------
# Prediction Contract (S7.2 & S7.3)
# ---------------------------------------------------------------------------


def test_prediction_strict_validation_and_empty() -> None:
    empty = Prediction.empty()
    assert empty.to_dict() == {"physical_id_set": [], "ta_physical_ids": {}}

    with pytest.raises(ValidationError):
        Prediction.model_validate(
            {"physical_id_set": [], "ta_physical_ids": {}, "extra": 1}
        )

    for bad_key in ("T1059", "ta0002", "TA002", "execution", "TA0002\n", "TA٠١٢٣"):
        with pytest.raises(ValidationError):
            Prediction(physical_id_set=["pr-1"], ta_physical_ids={bad_key: ["pr-1"]})
        with pytest.raises(ValidationError):
            Prediction.model_validate_json(
                json.dumps({"physical_id_set": ["pr-1"], "ta_physical_ids": {bad_key: ["pr-1"]}})
            )
        with pytest.raises(ValueError):
            Prediction.from_candidates(["pr-1"], {bad_key: ["pr-1"]})

    for bad_limit in (0, -1, True, 1.5):
        with pytest.raises(ValueError):
            Prediction.from_candidates(["pr-1"], {"TA0002": ["pr-1"]}, ta_limit=bad_limit)  # type: ignore[arg-type]

    # Empty list, >3 items, duplicates, subset violation
    with pytest.raises(ValidationError):
        Prediction(physical_id_set=["pr-1"], ta_physical_ids={"TA0002": []})
    with pytest.raises(ValidationError):
        Prediction(
            physical_id_set=["pr-1", "pr-2", "pr-3", "pr-4"],
            ta_physical_ids={"TA0002": ["pr-1", "pr-2", "pr-3", "pr-4"]},
        )
    with pytest.raises(ValidationError):
        Prediction(
            physical_id_set=["pr-1", "pr-2"],
            ta_physical_ids={"TA0002": ["pr-1", "pr-1"]},
        )
    with pytest.raises(ValidationError):
        Prediction(
            physical_id_set=["pr-1"],
            ta_physical_ids={"TA0002": ["pr-1", "pr-2"]},
        )

    deduped_sorted = Prediction(physical_id_set=["pr-3", "pr-1", "pr-3", "pr-2"])
    assert deduped_sorted.physical_id_set == ["pr-1", "pr-2", "pr-3"]


def test_prediction_from_candidates_s73_dedup_before_truncate_and_scope() -> None:
    # 4 candidates where 2 share pr-1 -> dedup first so all 3 distinct IDs fit top-3
    pred = Prediction.from_candidates(
        physical_ids=["pr-1", "pr-2", "pr-3", "pr-4", "pr-5"],
        ta_candidates={
            "TA0002": ["pr-1", "pr-1", "pr-2", "pr-3"],
            "TA0003": ["pr-5", "pr-4", "pr-3", "pr-2", "pr-1"],
            "TA0005": [],
            "TA0006": ["cross-case-99"],
        },
        valid_physical_ids={"pr-1", "pr-2", "pr-3", "pr-4", "pr-5"},
    )
    assert pred.ta_physical_ids == {
        "TA0002": ["pr-1", "pr-2", "pr-3"],
        "TA0003": ["pr-5", "pr-4", "pr-3"],
    }
    assert pred.physical_id_set == ["pr-1", "pr-2", "pr-3", "pr-4", "pr-5"]


# ---------------------------------------------------------------------------
# Package Root
# ---------------------------------------------------------------------------


def test_package_root_exports_and_analyze_records_stub() -> None:
    assert apt_agent.__version__ == "0.1.0"
    with pytest.raises(NotImplementedError):
        analyze_records(iter([]))
