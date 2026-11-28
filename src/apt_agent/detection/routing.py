"""Check detector matches against the rule's declared Sigma log source."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

import yaml

from apt_agent.detection.base import AdapterOutput, resolve_rule_files
from apt_agent.models import Event

_YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def _key(value: object) -> str:
    return str(value or "").strip().casefold()


@dataclass(frozen=True)
class Logsource:
    product: str
    service: str
    category: str = ""

    def matches(self, event: Event) -> bool:
        products, services = _event_scope(event)
        return (
            (not self.product or self.product in products)
            and (not self.service or self.service in services)
            and (not self.category or event.source_type != "ecar"
                 or self.category in event.fields.get("event_categories", ()))
        )


def _event_scope(event: Event) -> tuple[set[str], set[str]]:
    source = event.source_type or ""
    fields = event.fields
    if source.startswith("winxml"):
        channel = _key(fields.get("Channel"))
        service = source.removeprefix("winxml_")
        aliases = {
            "microsoft-windows-sysmon/operational": "sysmon",
            "microsoft-windows-powershell/operational": "powershell",
            "windows powershell": "powershell",
            "microsoft-windows-windows defender/operational": "windefend",
            "microsoft-windows-taskscheduler/operational": "taskscheduler",
        }
        return {"windows"}, {service, channel, aliases.get(channel, "")}
    if source.startswith("zeek_"):
        service = source.removeprefix("zeek_")
        services = {service, "zeek"}
        if service == "ssl":
            services.add("tls")
        return {"zeek"}, services
    if source == "syslog":
        program = _key(fields.get("program") or fields.get("app_name") or fields.get("service"))
        return {"linux"}, {"syslog", program}
    if source == "bash_history":
        return {"linux"}, {"bash", "bash_history"}
    if source == "web_access":
        return {"apache", "nginx", "iis"}, {"http", "access", "webserver"}
    if source == "ecar":
        products = {"ecar"}
        platform = _key(fields.get("platform") or fields.get("os"))
        if platform in {"windows", "linux", "macos"}:
            products.add(platform)
        else:
            for name in ("Image", "ParentImage", "TargetFilename", "image_path"):
                path = fields.get(name)
                if not isinstance(path, str) or not path:
                    continue
                if PureWindowsPath(path).drive or path.startswith("\\"):
                    products.add("windows")
                    break
                if path.startswith("/"):
                    products.add("linux")
                    break
        return products, {"ecar"}
    return set(), set()


def read_rule_logsources(rules_path: Path | None) -> dict[str, Logsource]:
    """Read scope metadata from YAML rules without interpreting detections."""
    scopes = {}
    for path in resolve_rule_files(rules_path):
        if path.suffix.lower() not in {".yaml", ".yml"}:
            continue
        try:
            docs = list(yaml.load_all(path.read_text(encoding="utf-8-sig"), Loader=_YAML_LOADER))
        except (OSError, UnicodeError, yaml.YAMLError):
            continue
        for doc in docs:
            if not isinstance(doc, dict) or not isinstance(doc.get("logsource"), dict):
                continue
            source = doc["logsource"]
            scope = Logsource(_key(source.get("product")), _key(source.get("service")),
                              _key(source.get("category")))
            if scope.product or scope.service or scope.category:
                for rule_id in (doc.get("id"), doc.get("title")):
                    if isinstance(rule_id, str) and rule_id:
                        scopes[rule_id] = scope
    return scopes


def scope_detector_output(
    output: AdapterOutput, scopes: dict[str, Logsource], events: dict[str, Event]
) -> AdapterOutput:
    """Drop detections from mismatched sources while retaining the coverage record."""
    if not scopes:
        return output
    rejected: Counter[str] = Counter()
    accepted: Counter[str] = Counter()
    hits = []
    for hit in output.hits:
        scope = scopes.get(hit.rule_id)
        if scope is None or hit.is_lead_only:
            hits.append(hit)
            continue
        ids = [
            event_id for event_id in hit.event_ids
            if event_id in events and scope.matches(events[event_id])
        ]
        rejected[hit.rule_id] += len(hit.event_ids) - len(ids)
        if ids:
            hits.append(hit if ids == hit.event_ids else hit.model_copy(update={"event_ids": ids}))
            accepted[hit.rule_id] += 1

    coverage = [
        run.model_copy(update={
            "status": "partial" if accepted[run.rule_id] else "skipped",
            "reason": "detector_matches_outside_rule_logsource",
            "hit_count": accepted[run.rule_id],
        }) if rejected[run.rule_id] and run.status in {"ran", "partial"} else run
        for run in output.coverage
    ]
    return output.model_copy(update={"hits": hits, "coverage": coverage})
