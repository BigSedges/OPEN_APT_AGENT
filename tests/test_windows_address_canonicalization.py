"""Windows engine inputs must give equivalent IPv4 addresses equivalent meaning."""
from copy import deepcopy
from pathlib import Path

import pytest

from apt_agent.config import EngineConfig
from apt_agent.detection.hayabusa import HayabusaAdapter
from apt_agent.ingestion import Normalizer, ingest_records
from apt_agent.ingestion.normalizer import (
    format_for_chainsaw, format_for_hayabusa, format_for_rsigma, format_for_zircolite,
)
from apt_agent.models import RunContext


def windows_record(address, number=1):
    return {"raw_text": f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID>
<TimeCreated SystemTime="2024-01-01T00:00:00Z"/><EventRecordID>{number}</EventRecordID>
<Channel>Security</Channel><Computer>host.example</Computer></System>
<EventData><Data Name="LogonType">3</Data><Data Name="IpAddress">{address}</Data>
<Data Name="CommandLine">echo ::ffff:10.1.2.3</Data></EventData></Event>'''}


def normalized(address, number=1):
    store = ingest_records([(f"pr-{number}", windows_record(address, number))],
                           case_id="address-case", run_id="run")
    ctx = RunContext(case_id=store.case_id, run_id=store.run_id)
    return ctx, store, Normalizer.normalize_batch(ctx, store).events


@pytest.mark.parametrize("address,expected", [
    ("::ffff:10.1.2.3", "10.1.2.3"), ("::FFFF:a01:203", "10.1.2.3"),
    ("::ffff:192.168.1.2", "192.168.1.2"), ("::ffff:8.8.8.8", "8.8.8.8"),
    ("::1", "::1"), ("2001:4860:4860::8888", "2001:4860:4860::8888"),
    ("10.1.2.3", "10.1.2.3"), ("-", "-"), ("not-an-ip", "not-an-ip"),
])
def test_all_windows_engine_inputs_preserve_evidence(address, expected):
    _, store, events = normalized(address)
    before = deepcopy(events[0].model_dump())
    rows, index = format_for_hayabusa(events)
    assert rows[0]["IpAddress"] == expected
    assert format_for_chainsaw(events)[0]["Event"]["EventData"]["IpAddress"] == expected
    assert format_for_rsigma(events)[0]["IpAddress"] == expected
    assert format_for_zircolite(events)[0]["IpAddress"] == expected
    assert rows[0]["CommandLine"] == "echo ::ffff:10.1.2.3"
    assert index[0]["event_id"] == events[0].event_id
    assert events[0].model_dump() == before
    assert store.get("pr-1").payload == windows_record(address)


def test_real_hayabusa_cidr_replay_when_configured(tmp_path):
    """Optional native-engine replay against a self-contained CIDR rule."""
    import os
    binary = os.environ.get("APT_TEST_HAYABUSA_BIN")
    config_dir = os.environ.get("APT_TEST_HAYABUSA_CONFIG")
    if not binary or not config_dir:
        pytest.skip("Native Hayabusa fixture is not configured")
    rule_id = "870d6880-ad88-4513-8c0b-eefc87d097cd"
    (tmp_path / "rule.yml").write_text(f'''title: Public Address Fixture
id: {rule_id}
status: test
author: OPEN_APT_AGENT
date: 2026-11-28
description: Self-contained CIDR replay fixture
ruletype: Sigma
logsource:
  product: windows
  service: security
detection:
  selection:
    Channel: Security
    EventID: 4624
    LogonType: 3
  private:
    IpAddress|cidr:
      - 10.0.0.0/8
      - 192.168.0.0/16
      - ::1/128
  condition: selection and not private
level: high
''')
    samples = ["10.1.2.3", "::ffff:10.1.2.3", "::ffff:192.168.1.2",
               "8.8.8.8", "::ffff:8.8.8.8", "2001:4860:4860::8888", "::1"]
    store = ingest_records([(f"pr-{i}", windows_record(address, i))
                            for i, address in enumerate(samples, 1)],
                           case_id="replay", run_id="run")
    ctx = RunContext(case_id=store.case_id, run_id=store.run_id)
    events = Normalizer.normalize_batch(ctx, store).events
    output = HayabusaAdapter().run(ctx, events, EngineConfig(
        bin_path=Path(binary), rules_dir=tmp_path, config_path=Path(config_dir)),
        ruleset_version="fixture")
    assert output.hits, [run.model_dump() for run in output.coverage]
    assert {eid for hit in output.hits for eid in hit.event_ids} == {
        event.event_id for event in events if event.physical_record_id in {"pr-4", "pr-5", "pr-6"}
    }
