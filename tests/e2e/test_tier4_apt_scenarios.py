"""Tier 4 opaque-box E2E tests: 9 realistic multi-format APT and benign scenarios.

Matches ``TEST_INFRA.md § Real-World Application Scenarios (Tier 4)`` and
``tests/fixtures/e2e/scenarios/scene_01..scene_09``. All ``apt_agent`` imports
are kept lazy inside test/helper functions so collection and static hygiene
checks succeed independently of M3-M6 implementation state.
"""

from __future__ import annotations

import inspect
import json
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest

_E2E_DIR = str(Path(__file__).resolve().parent)
if _E2E_DIR not in sys.path:
    sys.path.insert(0, _E2E_DIR)

import _helpers  # noqa: E402

pytestmark = pytest.mark.tier4


# ---------------------------------------------------------------------------
# Pure-stdlib / lazy-import module helpers
# ---------------------------------------------------------------------------


def _field(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _locator_map(index: dict[str, dict[str, Any]]) -> dict[str, Any]:
    from apt_agent.models import Locator

    return {
        pid: Locator(filepath=entry["filepath"], linenumber=entry["linenumber"])
        for pid, entry in index.items()
    }


def _load_scene(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    scene_name: str,
) -> tuple[
    Path,
    dict[str, dict[str, Any]],
    list[tuple[str, dict[str, Any]]],
    dict[str, Any],
]:
    scene_dir = (e2e_fixtures_dir / "scenarios" / scene_name).resolve()
    index, records = load_scene_records(scene_dir)
    meta = json.loads((scene_dir / "expected_meta.json").read_text(encoding="utf-8"))
    return scene_dir, index, records, meta


def _make_rag_service(cfg: Any) -> Any:
    from apt_agent.tools import RagService

    try:
        return RagService(cfg)
    except (TypeError, ValueError):
        return RagService(cfg.rag)


def _events_by_pid(events: list[Any]) -> dict[str, list[Any]]:
    grouped: dict[str, list[Any]] = {}
    for ev in events:
        grouped.setdefault(ev.physical_record_id, []).append(ev)
    return grouped


def _extract_edges(state_or_result: Any) -> list[Any]:
    edges = _field(state_or_result, "edges")
    if edges:
        return list(edges)
    chains = _field(state_or_result, "chains", []) or []
    collected: list[Any] = []
    for ch in chains:
        ch_edges = _field(ch, "edges", []) or []
        collected.extend(ch_edges)
    return collected


def _event_to_sample_dict(ev: Any) -> dict[str, Any]:
    fields = dict(_field(ev, "fields", {}) or {})
    fields.setdefault("event_id", _field(ev, "event_id"))
    fields.setdefault(
        "raw_id", _field(ev, "raw_id") or _field(ev, "physical_record_id")
    )
    if _field(ev, "event_time") is not None:
        fields.setdefault("@timestamp", _field(ev, "event_time"))
    return fields


def _probe_budget_and_investigation(
    ctx: Any,
    cfg: Any,
    store: Any,
    events: list[Any],
    det_res: Any,
    *,
    rag_svc: Any = None,
    registry: Any = None,
    blackboard: Any = None,
) -> tuple[Any | None, Any | None]:
    import apt_agent.agents as agents_mod

    bm: Any | None = None
    bm_cls = getattr(agents_mod, "BudgetManager", None)
    if bm_cls is not None:
        bm = bm_cls(cfg.budget)
        reserve_tokens = int(cfg.budget.max_tokens * cfg.budget.reserve_ratio) + 1
        for consume_name in ("consume", "consume_tokens", "record_tokens"):
            consume_fn = getattr(bm, consume_name, None)
            if callable(consume_fn):
                params = inspect.signature(consume_fn).parameters
                if "tokens" in params:
                    ckw: dict[str, Any] = {"tokens": reserve_tokens}
                    if "rounds" in params:
                        ckw["rounds"] = 1
                    consume_fn(**ckw)
                else:
                    consume_fn(reserve_tokens)
                break
        for round_name in ("advance_round", "record_round"):
            round_fn = getattr(bm, round_name, None)
            if callable(round_fn):
                round_fn()
                break
        for stop_name in ("should_stop_expansion", "should_stop", "check_stop"):
            stop_fn = getattr(bm, stop_name, None)
            if callable(stop_fn):
                stopped = stop_fn()
                assert bool(stopped) is True
                break
        if hasattr(bm, "stop_reason"):
            sr_attr = getattr(bm, "stop_reason")
            sr_val = sr_attr() if callable(sr_attr) else sr_attr
            if sr_val is not None:
                assert isinstance(sr_val, str) and sr_val.strip() != ""

    runner_fn = getattr(agents_mod, "run_investigation", None)
    if not callable(runner_fn):
        return bm, None

    candidate_args: dict[str, Any] = {
        "ctx": ctx,
        "context": ctx,
        "config": cfg,
        "cfg": cfg,
        "store": store,
        "raw_store": store,
        "events": events,
        "det_res": det_res,
        "detection": det_res,
        "detection_result": det_res,
        "hits": _field(det_res, "hits", []),
        "coverage": _field(det_res, "coverage", []),
        "leads": _field(det_res, "leads", []),
        "rag_service": rag_svc,
        "rag": rag_svc,
        "registry": registry,
        "tool_registry": registry,
        "blackboard": blackboard,
        "bb": blackboard,
        "budget_manager": bm,
        "budget": bm,
    }
    sig = inspect.signature(runner_fn)
    pos_args: list[Any] = []
    kwargs: dict[str, Any] = {}
    for pname, param in sig.parameters.items():
        if param.kind in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        ):
            continue
        if pname in candidate_args and candidate_args[pname] is not None:
            if param.kind == inspect.Parameter.POSITIONAL_ONLY:
                pos_args.append(candidate_args[pname])
            else:
                kwargs[pname] = candidate_args[pname]
        elif param.default is inspect.Parameter.empty:
            return bm, None
    case_res = runner_fn(*pos_args, **kwargs)
    return bm, case_res


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
        if p.kind
        in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
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
    for method_name in (
        "validate_and_publish",
        "publish_validated",
        "draft_and_publish",
        "run",
    ):
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
    raise AssertionError(
        f"Agent {type(agent).__name__} lacks validate_and_publish/run method"
    )


def _write_lateral_movement_rules(rules_dir: Path) -> None:
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / "lat_sec_logon.yml").write_text(
        "\n".join(
            [
                "title: Synthetic Lateral Movement Network Logon",
                "id: 22222222-3333-4444-5555-666666666601",
                "status: test",
                "description: Detects Security 4624/4625 network logon type 3.",
                "author: OPEN_APT_AGENT E2E",
                "date: 2024-05-30",
                "logsource:",
                "  product: windows",
                "  service: security",
                "detection:",
                "  selection:",
                "    EventID:",
                "      - 4624",
                "      - 4625",
                "    LogonType: 3",
                "  condition: selection",
                "level: high",
                "tags:",
                "  - attack.lateral_movement",
                "  - attack.t1021.002",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (rules_dir / "lat_services_exec.yml").write_text(
        "\n".join(
            [
                "title: Synthetic Services Spawning Remote Shell",
                "id: 22222222-3333-4444-5555-666666666602",
                "status: test",
                "description: Detects services.exe spawning cmd.exe or powershell.exe.",
                "author: OPEN_APT_AGENT E2E",
                "date: 2024-05-30",
                "logsource:",
                "  product: windows",
                "  category: process_creation",
                "detection:",
                "  selection:",
                "    ParentImage|endswith: '\\services.exe'",
                "    Image|endswith:",
                "      - '\\cmd.exe'",
                "      - '\\powershell.exe'",
                "  condition: selection",
                "level: high",
                "tags:",
                "  - attack.execution",
                "  - attack.t1569.002",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (rules_dir / "lat_zeek_smb.yml").write_text(
        "\n".join(
            [
                "title: Synthetic Zeek SMB Lateral Movement Flow",
                "id: 22222222-3333-4444-5555-666666666603",
                "status: test",
                "description: Detects Zeek SMB connection on port 445.",
                "author: OPEN_APT_AGENT E2E",
                "date: 2024-05-30",
                "logsource:",
                "  product: zeek",
                "  service: conn",
                "detection:",
                "  selection:",
                "    zeek_log_type: 'conn'",
                "    service: 'smb'",
                "    dst_port: 445",
                "  condition: selection",
                "level: high",
                "tags:",
                "  - attack.lateral_movement",
                "  - attack.t1021.002",
                "",
            ]
        ),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Tier 4 Scenarios (1..9)
# ---------------------------------------------------------------------------


def test_tier4_01_phishing_winword_powershell_c2(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_app_config: Any,
    make_run_context: Any,
) -> None:
    """Scenario 1: Phishing WINWORD -> powershell (G7) -> Zeek C2 conn/dns/http."""
    from apt_agent import analyze_records
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.detection import DetectionCoordinator
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.models import Edge, Finding, Submission

    _, index, records, meta = _load_scene(
        e2e_fixtures_dir, load_scene_records, "scene_01_phishing_c2"
    )
    cfg = make_app_config(llm_enabled=False)
    loc_map = _locator_map(index)

    pred = analyze_records(
        iter(records),
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=loc_map,
    )
    _helpers.assert_valid_prediction(pred, set(index))
    assert set(meta["expected_chain_pids"]) <= set(pred["physical_id_set"])
    assert set(meta["expected_tactics"]) <= set(pred["ta_physical_ids"].keys())

    # Intermediate contract verification: E41/E42 ProcessGuid G7 + E42/E43 5-tuple
    ctx = make_run_context(
        case_id=meta["scene_id"],
        run_id="run-tier4-01",
        config=cfg,
        valid_physical_ids=frozenset(index),
        locator_map=loc_map,
    )
    store = ingest_records(
        iter(records),
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        locator_map=loc_map,
    )
    norm = Normalizer.normalize_batch(ctx, store)
    assert norm.gaps == []
    by_pid = _events_by_pid(norm.events)
    ev_e41 = by_pid[meta["e41_pid"]][0]
    ev_e42 = by_pid[meta["e42_pid"]][0]
    ev_e43 = by_pid[meta["e43_pid"]][0]

    assert ev_e41.fields.get("ProcessGuid") == "G7"
    assert ev_e42.fields.get("ProcessGuid") == "G7"
    assert (
        ev_e42.fields.get("SourceIp"),
        int(ev_e42.fields.get("SourcePort")),
        ev_e42.fields.get("DestinationIp"),
        int(ev_e42.fields.get("DestinationPort")),
    ) == ("10.0.1.8", 51030, "203.0.113.8", 443)
    assert (
        ev_e43.fields.get("src_ip"),
        int(ev_e43.fields.get("src_port")),
        ev_e43.fields.get("dst_ip"),
        int(ev_e43.fields.get("dst_port")),
    ) == ("10.0.1.8", 51030, "203.0.113.8", 443)

    det = DetectionCoordinator(cfg).detect(ctx, norm.events)
    hits = _field(det, "hits", [])
    coverage = _field(det, "coverage", [])
    hit_event_ids = {eid for h in hits for eid in _field(h, "event_ids", [])}
    assert {ev_e41.event_id, ev_e42.event_id} <= hit_event_ids

    bb = Blackboard(
        ctx,
        valid_event_ids={ev.event_id for ev in norm.events},
        valid_physical_ids=set(index),
    )
    bb.record_task_query("t-host-01", "q-host-01", {ev_e41.event_id, ev_e42.event_id})
    bb.record_task_query("t-net-01", "q-net-01", {ev_e43.event_id})

    bb.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="t-host-01",
            submission_id="sub-host-01",
            query_ids=["q-host-01"],
            findings=[
                Finding(
                    finding_id="f-e41",
                    claim="WINWORD spawned powershell with ProcessGuid G7",
                    status="observed",
                    evidence_event_ids=[ev_e41.event_id],
                    tactic_ids=["TA0002"],
                ),
                Finding(
                    finding_id="f-e42",
                    claim="PowerShell G7 opened TCP connection to 203.0.113.8:443",
                    status="observed",
                    evidence_event_ids=[ev_e42.event_id],
                    tactic_ids=["TA0011"],
                ),
            ],
            edges=[
                Edge(
                    from_event_id=ev_e41.event_id,
                    to_event_id=ev_e42.event_id,
                    relation="process_net_pivot",
                    join_keys={"Computer": "H1.example.local", "ProcessGuid": "G7"},
                    evidence_event_ids=[ev_e41.event_id, ev_e42.event_id],
                    status="proposed",
                )
            ],
        ),
    )
    bb.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="t-net-01",
            submission_id="sub-net-01",
            query_ids=["q-net-01"],
            findings=[
                Finding(
                    finding_id="f-e43",
                    claim="Zeek conn corroborated 5-tuple 10.0.1.8:51030->203.0.113.8:443",
                    status="observed",
                    evidence_event_ids=[ev_e43.event_id],
                    tactic_ids=["TA0011"],
                )
            ],
            edges=[
                Edge(
                    from_event_id=ev_e42.event_id,
                    to_event_id=ev_e43.event_id,
                    relation="flow_corroboration",
                    join_keys={
                        "src_ip": "10.0.1.8",
                        "src_port": 51030,
                        "dst_ip": "203.0.113.8",
                        "dst_port": 443,
                        "proto": "tcp",
                    },
                    evidence_event_ids=[ev_e42.event_id, ev_e43.event_id],
                    status="proposed",
                )
            ],
        ),
    )

    v_res = verify(ctx, bb)
    verified_state = _field(v_res, "verified_state")
    assert (_field(v_res, "errors", []) or []) == []
    assert (_field(v_res, "unresolved", []) or []) == []
    assert meta["ambiguous_edges"] == []

    case_res = rank(ctx, verified_state, store, hits, coverage)
    assert (_field(case_res, "unresolved", []) or []) == []
    disputed_edges = [
        e for e in _extract_edges(verified_state) if _field(e, "status") == "disputed"
    ]
    assert disputed_edges == []
    assert set(meta["expected_chain_pids"]) <= {
        norm.event_to_physical[eid]
        for eid in _field(case_res, "attack_event_ids", [])
        if eid in norm.event_to_physical
    }


def test_tier4_02_lateral_movement_security_sysmon_zeek(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_app_config: Any,
    make_run_context: Any,
    tmp_path: Path,
) -> None:
    """Scenario 2: Lateral movement (Security 4624/4625/4688 + Sysmon + Zeek SMB)."""
    from apt_agent import analyze_records
    from apt_agent.ingestion import Normalizer, ingest_records

    _, index, records, meta = _load_scene(
        e2e_fixtures_dir, load_scene_records, "scene_02_lateral_movement"
    )

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    for yml in (e2e_fixtures_dir / "rules" / "valid").glob("*.yml"):
        shutil.copy2(yml, rules_dir / yml.name)
    _write_lateral_movement_rules(rules_dir)

    cfg = make_app_config(rules_dir=rules_dir, llm_enabled=False)
    loc_map = _locator_map(index)

    ctx = make_run_context(
        case_id=meta["scene_id"],
        run_id="run-tier4-02",
        config=cfg,
        valid_physical_ids=frozenset(index),
        locator_map=loc_map,
    )
    store = ingest_records(
        iter(records),
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        locator_map=loc_map,
    )
    norm = Normalizer.normalize_batch(ctx, store)
    assert norm.gaps == []
    observed_hosts = {
        ev.fields.get("Computer")
        for ev in norm.events
        if ev.fields.get("Computer") is not None
    }
    assert set(meta["expected_hosts"]) <= observed_hosts

    pred = analyze_records(
        iter(records),
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=loc_map,
    )
    _helpers.assert_valid_prediction(pred, set(index))
    assert set(meta["expected_pids"]) <= set(pred["physical_id_set"])
    assert {"TA0008", "TA0002"} <= set(pred["ta_physical_ids"].keys())


def test_tier4_03_web_exploit_to_webshell_and_bash_persistence(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_app_config: Any,
    make_run_context: Any,
) -> None:
    """Scenario 3: Web SQLi exploit -> eCAR webshell write -> bash_history curl."""
    from apt_agent import analyze_records
    from apt_agent.ingestion import Normalizer, ingest_records

    _, index, records, meta = _load_scene(
        e2e_fixtures_dir, load_scene_records, "scene_03_web_to_shell"
    )
    cfg = make_app_config(llm_enabled=False)
    loc_map = _locator_map(index)

    ctx = make_run_context(
        case_id=meta["scene_id"],
        run_id="run-tier4-03",
        config=cfg,
        valid_physical_ids=frozenset(index),
        locator_map=loc_map,
    )
    store = ingest_records(
        iter(records),
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        locator_map=loc_map,
    )
    norm = Normalizer.normalize_batch(ctx, store)
    assert norm.gaps == []
    by_pid = _events_by_pid(norm.events)
    assert by_pid["pr-s03-0001"][0].source_type == "web_access"
    assert by_pid["pr-s03-0003"][0].source_type == "ecar"
    assert by_pid["pr-s03-0004"][0].source_type == "bash_history"
    assert by_pid["pr-s03-0004"][0].fields.get("Image") == "curl"

    pred = analyze_records(
        iter(records),
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=loc_map,
    )
    _helpers.assert_valid_prediction(pred, set(index))
    assert set(meta["expected_pids"]) <= set(pred["physical_id_set"])
    assert set(meta["expected_tactics"]) <= set(pred["ta_physical_ids"].keys())


def test_tier4_04_dns_tunneling_ssl_x509_and_ssh_bruteforce(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_app_config: Any,
    make_run_context: Any,
) -> None:
    """Scenario 4: Zeek DNS TXT + SSL/X509 + Linux syslog RFC 5424/3164 SSH brute force."""
    from apt_agent import analyze_records
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.tools import ToolRegistry

    _, index, records, meta = _load_scene(
        e2e_fixtures_dir, load_scene_records, "scene_04_dns_tunnel_ssh"
    )
    cfg = make_app_config(llm_enabled=False)
    loc_map = _locator_map(index)

    ctx = make_run_context(
        case_id=meta["scene_id"],
        run_id="run-tier4-04",
        config=cfg,
        valid_physical_ids=frozenset(index),
        locator_map=loc_map,
    )
    store = ingest_records(
        iter(records),
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        locator_map=loc_map,
    )
    norm = Normalizer.normalize_batch(ctx, store)
    assert norm.gaps == []
    assert len(norm.events) == 5
    assert {"zeek_dns", "zeek_ssl", "zeek_x509", "syslog"} <= {
        ev.source_type for ev in norm.events
    }

    registry = ToolRegistry(ctx, store, norm.events, _make_rag_service(cfg))
    q_res = registry.invoke(
        "network",
        "query_events",
        {"filters": {}, "limit": 20},
        case_id=ctx.case_id,
        task_id="t-net-dns-04",
    )
    assert _field(q_res, "ok", True) is not False
    q_data = _field(q_res, "data", q_res)
    queried_events = _field(q_data, "events", []) or []
    serialized = json.dumps(
        [
            _field(e, "fields", e)
            if not isinstance(e, dict)
            else e
            for e in queried_events
        ],
        ensure_ascii=False,
    )
    assert "a9f4c2e1b8d700112233.c2.evil-example.test" in serialized
    assert "c2.evil-example.test" in serialized

    pred = analyze_records(
        iter(records),
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=loc_map,
    )
    _helpers.assert_valid_prediction(pred, set(index))
    assert set(meta["expected_pids"]) <= set(pred["physical_id_set"])
    assert set(meta["expected_tactics"]) <= set(pred["ta_physical_ids"].keys())


def test_tier4_05_full_16_log_types_and_ta0002_top3_dedup(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_app_config: Any,
    make_run_context: Any,
) -> None:
    """Scenario 5: Full 16-log-type APT telemetry & TA0002 top-3 deduplication."""
    from apt_agent import analyze_records
    from apt_agent.ingestion import Normalizer, ingest_records

    _, index, records, meta = _load_scene(
        e2e_fixtures_dir, load_scene_records, "scene_05_full_16_types"
    )
    cfg = make_app_config(llm_enabled=False)
    loc_map = _locator_map(index)

    ctx = make_run_context(
        case_id=meta["scene_id"],
        run_id="run-tier4-05",
        config=cfg,
        valid_physical_ids=frozenset(index),
        locator_map=loc_map,
    )
    store = ingest_records(
        iter(records),
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        locator_map=loc_map,
    )
    norm = Normalizer.normalize_batch(ctx, store)
    assert norm.gaps == []
    assert len(norm.source_type_counts) == meta["log_type_count"] == 16
    assert len({ev.source_type for ev in norm.events}) == 16

    pred = analyze_records(
        iter(records),
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=loc_map,
    )
    _helpers.assert_valid_prediction(pred, set(index))
    assert "TA0002" in pred["ta_physical_ids"]
    ta0002_ids = pred["ta_physical_ids"]["TA0002"]
    assert len(ta0002_ids) == meta["ta0002_max_len"] == 3
    assert len(set(ta0002_ids)) == 3
    assert set(meta["s7_3_ta0002_candidates"]) <= set(pred["physical_id_set"])


def test_tier4_06_nat_ambiguous_egress_partial_verified_chain(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_app_config: Any,
    make_run_context: Any,
) -> None:
    """Scenario 6: Ambiguous NAT egress without translation log yields partial verified chain."""
    from apt_agent import analyze_records
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.detection import DetectionCoordinator
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.models import Edge, Finding, Submission
    from apt_agent.pipeline import to_prediction

    _, index, records, meta = _load_scene(
        e2e_fixtures_dir, load_scene_records, "scene_06_nat_ambiguous"
    )
    cfg = make_app_config(llm_enabled=False)
    loc_map = _locator_map(index)

    pred = analyze_records(
        iter(records),
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=loc_map,
    )
    _helpers.assert_valid_prediction(pred, set(index))
    assert set(meta["verified_pids"]) <= set(pred["physical_id_set"])
    assert set(meta["disputed_pids"]).isdisjoint(set(pred["physical_id_set"]))

    # Intermediate Blackboard + Verifier + Ranker check for E42->E43 NAT ambiguity
    ctx = make_run_context(
        case_id=meta["scene_id"],
        run_id="run-tier4-06",
        config=cfg,
        valid_physical_ids=frozenset(index),
        locator_map=loc_map,
    )
    store = ingest_records(
        iter(records),
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        locator_map=loc_map,
    )
    norm = Normalizer.normalize_batch(ctx, store)
    by_pid = _events_by_pid(norm.events)
    ev_e41 = by_pid["pr-s06-0001"][0]
    ev_e42 = by_pid["pr-s06-0002"][0]
    ev_e43 = by_pid["pr-s06-0003"][0]

    det = DetectionCoordinator(cfg).detect(ctx, norm.events)
    hits = _field(det, "hits", [])
    coverage = _field(det, "coverage", [])

    bb = Blackboard(
        ctx,
        valid_event_ids={ev.event_id for ev in norm.events},
        valid_physical_ids=set(index),
    )
    bb.record_task_query("t-host-06", "q-host-06", {ev_e41.event_id, ev_e42.event_id})
    bb.record_task_query("t-net-06", "q-net-06", {ev_e43.event_id})

    bb.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="t-host-06",
            submission_id="sub-host-06",
            query_ids=["q-host-06"],
            findings=[
                Finding(
                    finding_id="f-06-e41",
                    claim="WINWORD spawned powershell G7",
                    status="observed",
                    evidence_event_ids=[ev_e41.event_id],
                    tactic_ids=["TA0002"],
                ),
                Finding(
                    finding_id="f-06-e42",
                    claim="PowerShell G7 initiated outbound 10.0.1.8:51030->203.0.113.8:443",
                    status="observed",
                    evidence_event_ids=[ev_e42.event_id],
                    tactic_ids=["TA0011"],
                ),
            ],
            edges=[
                Edge(
                    from_event_id=ev_e41.event_id,
                    to_event_id=ev_e42.event_id,
                    relation="process_net_pivot",
                    join_keys={"Computer": "H1.example.local", "ProcessGuid": "G7"},
                    evidence_event_ids=[ev_e41.event_id, ev_e42.event_id],
                    status="proposed",
                )
            ],
        ),
    )
    bb.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="t-net-06",
            submission_id="sub-net-06",
            query_ids=["q-net-06"],
            findings=[
                Finding(
                    finding_id="f-06-e43",
                    claim="NAT egress flow 198.51.100.10:61002->203.0.113.8:443 lacks NAT translation log",
                    status="disputed",
                    evidence_event_ids=[ev_e43.event_id],
                    tactic_ids=["TA0011"],
                )
            ],
            edges=[
                Edge(
                    from_event_id=ev_e42.event_id,
                    to_event_id=ev_e43.event_id,
                    relation="flow_corroboration",
                    join_keys={
                        "host_src_ip": "10.0.1.8",
                        "nat_src_ip": "198.51.100.10",
                        "dst_ip": "203.0.113.8",
                        "dst_port": 443,
                        "reason": meta["reason"],
                    },
                    evidence_event_ids=[ev_e42.event_id, ev_e43.event_id],
                    status="disputed",
                )
            ],
        ),
    )

    v_res = verify(ctx, bb)
    verified_state = _field(v_res, "verified_state")
    for edge in _extract_edges(verified_state):
        if (
            _field(edge, "from_event_id") == ev_e42.event_id
            and _field(edge, "to_event_id") == ev_e43.event_id
        ):
            assert _field(edge, "status") in ("proposed", "disputed")
            assert _field(edge, "status") != "verified"

    case_res = rank(ctx, verified_state, store, hits, coverage)
    pred_mid = to_prediction(ctx, case_res, valid_physical_ids=set(index))
    _helpers.assert_valid_prediction(pred_mid, set(index))
    assert set(meta["verified_pids"]) <= set(pred_mid["physical_id_set"])
    assert set(meta["disputed_pids"]).isdisjoint(set(pred_mid["physical_id_set"]))


def test_tier4_07_degraded_engine_crash_rag_timeout_budget_reserve(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_app_config: Any,
    make_run_context: Any,
    tmp_path: Path,
) -> None:
    """Scenario 7: Engine crash + corrupt/short-timeout RAG + 80% budget reserve."""
    from apt_agent import analyze_records
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.detection import DetectionCoordinator
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.models import Finding, Submission
    from apt_agent.pipeline import to_prediction
    from apt_agent.tools import ToolRegistry

    _, index, records, meta = _load_scene(
        e2e_fixtures_dir, load_scene_records, "scene_07_degraded"
    )
    fi = meta["fault_injection"]
    # AppConfig enforces rag.timeout_ms >= 100 while expected_meta records 1ms;
    # clamp to 100ms alongside corrupt_kb.jsonl to exercise graceful RAG degradation.
    cfg = make_app_config(
        base_dir=tmp_path / "degraded_run",
        engine_modes=fi["engine_modes"],
        enabled_engines={"zircolite", "hayabusa", "rsigma", "pysigma"},
        rag_timeout_ms=max(100, int(fi["rag_timeout_ms"])),
        knowledge_path=e2e_fixtures_dir / "kb" / "corrupt_kb.jsonl",
        budget_overrides={
            "reserve_ratio": fi["reserve_ratio"],
            "max_rounds": fi["max_rounds"],
            "max_tokens": 1000,
        },
        llm_enabled=False,
    )
    loc_map = _locator_map(index)
    ctx = make_run_context(
        case_id=meta["scene_id"],
        run_id="run-tier4-07",
        config=cfg,
        valid_physical_ids=frozenset(index),
        locator_map=loc_map,
    )

    store = ingest_records(
        iter(records),
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        locator_map=loc_map,
    )
    norm = Normalizer.normalize_batch(ctx, store)
    det = DetectionCoordinator(cfg).detect(ctx, norm.events)
    hits = _field(det, "hits", [])
    coverage = _field(det, "coverage", [])
    statuses = {_field(r, "status") for r in coverage}
    assert set(meta["expected_coverage_states"]) <= statuses

    rag_svc = _make_rag_service(cfg)
    rag_res = rag_svc.search_knowledge(
        "WINWORD powershell pivot", role="lead", top_k=5
    )
    assert isinstance(rag_res, dict)
    assert _field(rag_res, "refs", []) == []
    assert (
        _field(rag_res, "degraded") is True
        or _field(rag_res, "error") is not None
        or bool(_field(rag_res, "warnings"))
    )

    pred = analyze_records(
        iter(records),
        config=cfg,
        valid_physical_ids=set(index),
        locator_map=loc_map,
    )
    _helpers.assert_valid_prediction(pred, set(index))
    assert {"pr-s07-0001", "pr-s07-0002"} <= set(pred["physical_id_set"])

    cfg_min_budget = make_app_config(
        base_dir=tmp_path / "min_budget_run",
        engine_modes=fi["engine_modes"],
        enabled_engines={"zircolite", "hayabusa", "rsigma", "pysigma"},
        rag_timeout_ms=max(100, int(fi["rag_timeout_ms"])),
        knowledge_path=e2e_fixtures_dir / "kb" / "corrupt_kb.jsonl",
        budget_overrides={
            "reserve_ratio": fi["reserve_ratio"],
            "max_rounds": 1,
            "max_tokens": 1,
        },
        llm_enabled=False,
    )
    pred_min = analyze_records(
        iter(records),
        config=cfg_min_budget,
        valid_physical_ids=set(index),
        locator_map=loc_map,
    )
    _helpers.assert_valid_prediction(pred_min, set(index))
    assert {"pr-s07-0001", "pr-s07-0002"} <= set(pred_min["physical_id_set"])

    # Contracted Blackboard -> Verifier -> Ranker -> to_prediction on real queried evidence
    by_pid = _events_by_pid(norm.events)
    ev_s1 = by_pid["pr-s07-0001"][0].event_id
    ev_s2 = by_pid["pr-s07-0002"][0].event_id

    bb = Blackboard(
        ctx,
        valid_event_ids={ev.event_id for ev in norm.events},
        valid_physical_ids=set(index),
    )
    bb.record_task_query("t-degraded", "q-degraded", {ev_s1, ev_s2})
    bb.submit_findings(
        ctx,
        Submission(
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            task_id="t-degraded",
            submission_id="sub-degraded-01",
            query_ids=["q-degraded"],
            findings=[
                Finding(
                    finding_id="f-s07-01",
                    claim="WINWORD spawned powershell under degraded multi-engine run",
                    status="observed",
                    evidence_event_ids=[ev_s1],
                    tactic_ids=["TA0002"],
                ),
                Finding(
                    finding_id="f-s07-02",
                    claim="PowerShell connected to external C2 203.0.113.8:443",
                    status="observed",
                    evidence_event_ids=[ev_s2],
                    tactic_ids=["TA0011"],
                ),
            ],
            edges=[],
        ),
    )
    v_res = verify(ctx, bb)
    verified_state = _field(v_res, "verified_state")
    case_res_contract = rank(ctx, verified_state, store, hits, coverage)
    assert set(meta["expected_coverage_states"]) <= {
        _field(r, "status") for r in (_field(case_res_contract, "coverage", []) or [])
    }
    pred_contract = to_prediction(ctx, case_res_contract, valid_physical_ids=set(index))
    _helpers.assert_valid_prediction(pred_contract, set(index))
    assert {"pr-s07-0001", "pr-s07-0002"} <= set(pred_contract["physical_id_set"])

    # Probe genuine BudgetManager / run_investigation stop_reason without fabrication
    _bm, inv_res = _probe_budget_and_investigation(
        ctx,
        cfg,
        store,
        norm.events,
        det,
        rag_svc=rag_svc,
        registry=ToolRegistry(ctx, store, norm.events, rag_svc),
        blackboard=bb,
    )
    if inv_res is not None and meta["expect_nonempty_stop_reason"]:
        inv_stop = _field(inv_res, "stop_reason", "")
        assert isinstance(inv_stop, str) and inv_stop.strip() != "", (
            f"Expected genuine non-empty stop_reason from run_investigation, got {inv_res!r}"
        )
        pred_inv = to_prediction(ctx, inv_res, valid_physical_ids=set(index))
        _helpers.assert_valid_prediction(pred_inv, set(index))
        assert "stop_reason" not in pred_inv


def test_tier4_08_maintenance_validate_candidate_v2_concurrent_with_v1(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_app_config: Any,
    make_run_context: Any,
    tmp_path: Path,
) -> None:
    """Scenario 8: Mapping & Sigma rule validation -> v2 snapshot concurrent with v1."""
    from apt_agent import analyze_records
    from apt_agent.blackboard import Blackboard, rank, verify
    from apt_agent.detection import DetectionCoordinator
    from apt_agent.ingestion import Normalizer, ingest_records
    from apt_agent.maintenance import SnapshotRegistry, validate_candidate
    from apt_agent.pipeline import to_prediction

    scene_dir, index, records, meta = _load_scene(
        e2e_fixtures_dir, load_scene_records, "scene_08_maintenance"
    )
    loc_map = _locator_map(index)

    valid_mapping_path = (scene_dir / meta["valid_mapping_ref"]).resolve()
    invalid_mapping_path = (scene_dir / meta["invalid_mapping_ref"]).resolve()
    samples_path = (scene_dir / meta["mapping_samples_ref"]).resolve()
    valid_rule_path = (scene_dir / meta["valid_rule_ref"]).resolve()
    corr_rule_path = (scene_dir / meta["correlation_rule_ref"]).resolve()
    benign_rule_path = (
        e2e_fixtures_dir / "rules" / "valid" / "benign_no_match.yml"
    ).resolve()
    c2_rule_path = (
        e2e_fixtures_dir / "rules" / "valid" / "win_powershell_c2_flow.yml"
    ).resolve()

    v1_rules_dir = tmp_path / "rules_v1"
    v1_rules_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(benign_rule_path, v1_rules_dir / benign_rule_path.name)

    v2_rules_dir = tmp_path / "rules_v2"
    v2_rules_dir.mkdir(parents=True, exist_ok=True)
    for yml in (e2e_fixtures_dir / "rules" / "valid").glob("*.yml"):
        shutil.copy2(yml, v2_rules_dir / yml.name)
    shutil.copy2(corr_rule_path, v2_rules_dir / corr_rule_path.name)

    snaps_dir = tmp_path / "snapshots"
    registry = SnapshotRegistry(snaps_dir)
    registry.publish_snapshot(
        "ruleset",
        meta["v1_snapshot"],
        {benign_rule_path.name: benign_rule_path.read_text(encoding="utf-8")},
        {"description": "baseline v1 benign ruleset"},
    )
    registry.publish_snapshot(
        "mapping",
        meta["v1_snapshot"],
        {"baseline_mapping.yaml": "mappings:\n  '@timestamp': 'SystemTime'\n"},
        {"description": "baseline v1 mapping"},
    )

    cfg_v1 = make_app_config(
        base_dir=tmp_path / "v1_work",
        rules_dir=v1_rules_dir,
        snapshots_dir=snaps_dir,
        llm_enabled=False,
    )
    pred_v1 = analyze_records(
        iter(records),
        config=cfg_v1,
        valid_physical_ids=set(index),
        locator_map=loc_map,
    )
    _helpers.assert_valid_prediction(pred_v1, set(index))
    assert pred_v1 == {"physical_id_set": [], "ta_physical_ids": {}}

    ctx_v1 = make_run_context(
        case_id=meta["scene_id"],
        run_id="run-tier4-08-v1",
        mapping_version=meta["v1_snapshot"],
        ruleset_version=meta["v1_snapshot"],
        config=cfg_v1,
        valid_physical_ids=frozenset(index),
        locator_map=loc_map,
    )
    store_v1 = ingest_records(
        iter(records),
        case_id=ctx_v1.case_id,
        run_id=ctx_v1.run_id,
        locator_map=loc_map,
    )
    norm_v1 = Normalizer.normalize_batch(ctx_v1, store_v1)
    det_v1 = DetectionCoordinator(cfg_v1).detect(ctx_v1, norm_v1.events)
    bb_v1 = Blackboard(
        ctx_v1,
        valid_event_ids={ev.event_id for ev in norm_v1.events},
        valid_physical_ids=set(index),
    )
    v_res_v1 = verify(ctx_v1, bb_v1)
    saved_v1_state = _field(v_res_v1, "verified_state")

    # Validate invalid vs valid mappings
    mapping_samples = json.loads(samples_path.read_text(encoding="utf-8"))
    bad_map_res = validate_candidate(
        ctx_v1,
        "mapping",
        invalid_mapping_path.read_text(encoding="utf-8"),
        mapping_samples,
    )
    assert _field(bad_map_res, "passed") is False
    assert len(_field(bad_map_res, "diagnostics", []) or []) > 0

    good_map_res = validate_candidate(
        ctx_v1,
        "mapping",
        valid_mapping_path.read_text(encoding="utf-8"),
        mapping_samples,
    )
    assert _field(good_map_res, "passed") is True

    # Validate single-event Sigma rule & correlation rule against scene_08 fixtures
    by_pid = _events_by_pid(norm_v1.events)
    sysmon_e41 = by_pid["pr-s08-0003"][0]
    sysmon_e42 = by_pid["pr-s08-0004"][0]
    ecar_neg = by_pid["pr-s08-0002"][0]
    pos_e41_dict = _event_to_sample_dict(sysmon_e41)
    pos_e42_dict = _event_to_sample_dict(sysmon_e42)
    neg_ecar_dict = _event_to_sample_dict(ecar_neg)

    single_rule_res = validate_candidate(
        ctx_v1,
        "sigma_rule",
        valid_rule_path.read_text(encoding="utf-8"),
        {
            "positive": [pos_e41_dict],
            "negative": [neg_ecar_dict],
        },
    )
    assert _field(single_rule_res, "passed") is True

    corr_rule_res = validate_candidate(
        ctx_v1,
        "sigma_rule",
        corr_rule_path.read_text(encoding="utf-8"),
        {
            "positive": [pos_e41_dict, pos_e42_dict],
            "negative": [neg_ecar_dict],
            "base_rules": [
                valid_rule_path.read_text(encoding="utf-8"),
                c2_rule_path.read_text(encoding="utf-8"),
            ],
        },
    )
    assert _field(corr_rule_res, "passed") is True

    # Publish v2 snapshots without mutating v1
    registry.publish_snapshot(
        "mapping",
        meta["v2_snapshot"],
        {valid_mapping_path.name: valid_mapping_path.read_text(encoding="utf-8")},
        {"description": "validated v2 zircolite mapping"},
    )
    registry.publish_snapshot(
        "ruleset",
        meta["v2_snapshot"],
        {
            valid_rule_path.name: valid_rule_path.read_text(encoding="utf-8"),
            c2_rule_path.name: c2_rule_path.read_text(encoding="utf-8"),
            corr_rule_path.name: corr_rule_path.read_text(encoding="utf-8"),
        },
        {"description": "validated v2 ruleset with correlation rule"},
    )

    with pytest.raises(Exception):
        registry.publish_snapshot(
            "ruleset",
            meta["v1_snapshot"],
            {"overwrite.yml": "title: illegal overwrite\n"},
            {},
        )

    # Re-verify & re-rank saved v1 snapshot -> reproduces pred_v1 exactly
    re_rank_v1 = rank(
        ctx_v1,
        saved_v1_state,
        store_v1,
        _field(det_v1, "hits", []),
        _field(det_v1, "coverage", []),
    )
    assert to_prediction(ctx_v1, re_rank_v1, valid_physical_ids=set(index)) == pred_v1

    # Rerun under v2 under a new run_id -> detects Sysmon chain while v1 stays intact
    cfg_v2 = make_app_config(
        base_dir=tmp_path / "v2_work",
        rules_dir=v2_rules_dir,
        snapshots_dir=snaps_dir,
        llm_enabled=False,
    )
    pred_v2 = analyze_records(
        iter(records),
        config=cfg_v2,
        valid_physical_ids=set(index),
        locator_map=loc_map,
    )
    _helpers.assert_valid_prediction(pred_v2, set(index))
    assert {"pr-s08-0003", "pr-s08-0004"} <= set(pred_v2["physical_id_set"])
    assert registry.get_snapshot("ruleset", meta["v1_snapshot"]) is not None

    # Exercise ConverterAgent and RuleAgent maintenance workflows on v2-agent
    import apt_agent.maintenance as maint_mod

    converter_cls = getattr(maint_mod, "ConverterAgent", None)
    rule_agent_cls = getattr(maint_mod, "RuleAgent", None)
    if converter_cls is not None and rule_agent_cls is not None:
        agent_version = f"{meta['v2_snapshot']}-agent"
        converter = _instantiate_maintenance_agent(converter_cls, registry, ctx_v1)
        rule_agent = _instantiate_maintenance_agent(rule_agent_cls, registry, ctx_v1)
        map_out = _invoke_maintenance_agent(
            converter,
            ctx=ctx_v1,
            registry=registry,
            kind="mapping",
            version=agent_version,
            candidate=valid_mapping_path.read_text(encoding="utf-8"),
            fixtures={
                "samples": mapping_samples,
                "positive": mapping_samples["positive"],
                "negative": mapping_samples["negative"],
                "expected_fields": mapping_samples["expected_fields"],
            },
            metadata={"scene_id": meta["scene_id"], "version": agent_version},
        )
        map_val = _field(map_out, "validation", default=map_out)
        assert _field(map_val, "passed") is True

        rule_out = _invoke_maintenance_agent(
            rule_agent,
            ctx=ctx_v1,
            registry=registry,
            kind="sigma_rule",
            version=agent_version,
            candidate=valid_rule_path.read_text(encoding="utf-8"),
            fixtures={
                "positive": [pos_e41_dict],
                "negative": [neg_ecar_dict],
            },
            metadata={"scene_id": meta["scene_id"], "version": agent_version},
        )
        rule_val = _field(rule_out, "validation", default=rule_out)
        assert _field(rule_val, "passed") is True
        assert registry.get_snapshot("ruleset", meta["v1_snapshot"]) is not None


def test_tier4_09_benign_admin_workload_empty_prediction(
    e2e_fixtures_dir: Path,
    load_scene_records: Any,
    make_app_config: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Scenario 9: Benign admin & noisy FP workload via single-arg analyze_records."""
    from apt_agent import analyze_records

    _, index, records, meta = _load_scene(
        e2e_fixtures_dir, load_scene_records, "scene_09_benign"
    )
    cfg_dict = make_app_config(llm_enabled=False, as_dict=True)
    cfg_path = tmp_path / "cfg.yaml"
    cfg_path.write_text(json.dumps(cfg_dict, indent=2), encoding="utf-8")
    monkeypatch.setenv("APT_AGENT_CONFIG", str(cfg_path))

    pred = analyze_records(iter(records))
    _helpers.assert_valid_prediction(pred, set(index))
    assert pred == meta["expected_prediction"] == {
        "physical_id_set": [],
        "ta_physical_ids": {},
    }
