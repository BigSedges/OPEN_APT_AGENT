"""Typed ECAR mapping must preserve event semantics and source evidence."""
from copy import deepcopy

import pytest

from apt_agent.detection.routing import Logsource
from apt_agent.ingestion import Normalizer, ingest_records
from apt_agent.ingestion.normalizer import format_for_rsigma
from apt_agent.models import RunContext


def normalize(obj, action, **extra):
    payload = {"id": "raw-event", "hostname": "endpoint", "timestamp_ms": 1700000000000,
               "object": obj, "action": action, "objectID": "object-uuid",
               "actorID": "actor-uuid", "properties": {"image_path": r"C:\Windows\tool.exe"}, **extra}
    before = deepcopy(payload)
    store = ingest_records([("pr-one", payload)], case_id="case", run_id="run")
    ctx = RunContext(case_id=store.case_id, run_id=store.run_id)
    event = Normalizer.normalize_batch(ctx, store).events[0]
    assert store.get("pr-one").payload == before
    return event


def test_process_lifecycle_and_parent_are_not_file_ids():
    created = normalize("PROCESS", "CREATE")
    assert created.fields["ProcessGuid"] == "object-uuid"
    assert created.fields["ParentProcessGuid"] == "actor-uuid"
    terminated = normalize("PROCESS", "TERMINATE")
    assert terminated.fields["ProcessGuid"] == "object-uuid"
    assert "ParentProcessGuid" not in terminated.fields
    file = normalize("FILE", "CREATE")
    assert file.fields["ProcessGuid"] == "actor-uuid"
    assert "ParentProcessGuid" not in file.fields
    assert Logsource("windows", "", "process_creation").matches(created)
    assert not Logsource("windows", "", "process_creation").matches(file)
    assert not Logsource("windows", "sysmon", "process_creation").matches(created)


@pytest.mark.parametrize("obj,action,property_name,value,target,category", [
    ("MODULE", "LOAD", "file_path", r"C:\module.dll", "ImageLoaded", "image_load"),
    ("REGISTRY", "MODIFY", "registry_key", r"HKLM\Software\Example", "TargetObject", "registry_set"),
    ("PROCESS", "OPEN", "granted_access", "0x1fffff", "GrantedAccess", "process_access"),
    ("THREAD", "REMOTE_CREATE", "target_process_uuid", "target-uuid", "TargetProcessGUID", "create_remote_thread"),
])
def test_event_specific_fields_and_rsigma_round_trip(obj, action, property_name, value, target, category):
    event = normalize(obj, action, properties={"image_path": r"C:\Windows\tool.exe", property_name: value})
    assert event.fields[target] == value
    assert format_for_rsigma([event])[0][target] == value
    assert Logsource("windows", "", category).matches(event)
    assert not Logsource("windows", "", "process_creation").matches(event)


def test_unknown_event_does_not_fabricate_process_identity_or_category():
    event = normalize("UNRECOGNIZED", "CREATE")
    assert "ProcessGuid" not in event.fields
    assert event.fields["event_categories"] == []
    assert not Logsource("windows", "", "process_creation").matches(event)


def test_explicit_guid_takes_precedence_over_generic_object_identity():
    event = normalize("PROCESS", "CREATE", properties={
        "process_guid": "provider-process", "parent_process_guid": "provider-parent"})
    assert event.fields["ProcessGuid"] == "provider-process"
    assert event.fields["ParentProcessGuid"] == "provider-parent"


@pytest.mark.parametrize("seed_index", [0, 1])
def test_confirmed_process_recovers_its_context_without_adopting_children(seed_index):
    from apt_agent.agents import run_investigation
    from apt_agent.detection.base import DetectionResult
    from apt_agent.models import Hit
    from apt_agent.tools.investigation import correlate_lineage_and_flows
    records = []
    for number, obj, action, process, actor, host in [
        (1, "PROCESS", "CREATE", "proc-instance", "parent-instance", "host"),
        (2, "MODULE", "LOAD", "dll-object", "proc-instance", "host"),
        (3, "FILE", "CREATE", "file-object", "proc-instance", "host"),
        (4, "PROCESS", "TERMINATE", "proc-instance", None, "host"),
        (5, "FILE", "CREATE", "post-exit", "proc-instance", "host"),
        (6, "FILE", "CREATE", "other-host", "proc-instance", "unrelated-host"),
        (7, "PROCESS", "CREATE", "child-instance", "proc-instance", "host"),
    ]:
        records.append((f"pr-{number}", {"id": str(number), "hostname": host,
            "timestamp_ms": 1700000000000 + number * 1000,
            "object": obj, "action": action, "objectID": process, "actorID": actor,
            "properties": {"image_path": r"C:\tool.exe"}}))
    store = ingest_records(records, case_id="case", run_id="run")
    ctx = RunContext(case_id=store.case_id, run_id=store.run_id)
    events = Normalizer.normalize_batch(ctx, store).events
    seed = events[seed_index]
    detection = DetectionResult(hits=[Hit(hit_id="confirmed", rule_id="fixture",
        engine="fixture", level="high", event_ids=[seed.event_id])])
    case = run_investigation(ctx, store, events, detection)
    predicted = {case.event_to_physical[eid] for eid in case.attack_event_ids}
    assert predicted == {"pr-1", "pr-2", "pr-3", "pr-4"}
    edges = correlate_lineage_and_flows(list(reversed(events)))
    assert sorted(edge.dedup_key for edge in edges) == sorted(
        edge.dedup_key for edge in correlate_lineage_and_flows(events))


def test_native_rsigma_ecar_categories_when_configured(tmp_path):
    import os
    from pathlib import Path
    from apt_agent.config import AppConfig, EngineConfig
    from apt_agent.detection.coordinator import DetectionCoordinator
    from apt_agent.detection.rsigma import RSigmaAdapter
    binary = os.environ.get("APT_TEST_RSIGMA_BIN")
    if not binary:
        pytest.skip("Native RSigma fixture is not configured")
    rule = "ab6180ef-00f8-42be-b2c7-081179704bdf"
    (tmp_path / "module.yml").write_text(f'''title: Staged Module Fixture
id: {rule}
status: test
logsource:
  product: windows
  category: image_load
detection:
  selection:
    ImageLoaded|endswith: '\\staged.dll'
  condition: selection
level: high
''')
    (tmp_path / "category.yml").write_text('''title: Module Category Fixture
id: bc6180ef-00f8-42be-b2c7-081179704bdf
status: test
logsource:
  product: windows
  category: image_load
detection:
  selection:
    Image|endswith: '\\tool.exe'
  condition: selection
level: high
''')
    module = normalize("MODULE", "LOAD", properties={
        "image_path": r"C:\Windows\tool.exe", "file_path": r"C:\Temp\staged.dll"})
    file = normalize("FILE", "CREATE", properties={
        "image_path": r"C:\Windows\tool.exe", "file_path": r"C:\Temp\staged.dll"})
    # Both records share the process Image. A native match on that field must
    # still satisfy the module rule's observation category.
    file = file.model_copy(update={"event_id": "file-event", "physical_record_id": "pr-file"})
    cfg = AppConfig()
    cfg.engines.rsigma = EngineConfig(bin_path=Path(binary), rules_dir=tmp_path)
    cfg.engines.pysigma.enabled = False
    ctx = RunContext(case_id="case", run_id="run", config=cfg)
    result = DetectionCoordinator(cfg, adapters=[RSigmaAdapter()]).detect(ctx, [module, file])
    assert {eid for hit in result.hits for eid in hit.event_ids} == {module.event_id}, result.coverage
    assert any(trace["event_id"] == "file-event" and not trace["accepted"] for trace in result.hit_trace)
