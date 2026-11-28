"""Validate defensive Sigma and mapping changes and publish immutable snapshots."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
from tempfile import NamedTemporaryFile, TemporaryDirectory
from typing import Any, Literal

import yaml

from apt_agent.config import AppConfig
from apt_agent.detection.base import build_exec_argv, run_cli_readonly
from apt_agent.detection.rsigma import inspect_sigma_rules
from apt_agent.exceptions import AptAgentError, ConflictError, InvalidArgumentError
from apt_agent.models import RunContext

_SNAPSHOT_KINDS = {"mapping", "ruleset", "knowledge"}
_VERSION = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]*")


@dataclass(frozen=True)
class Snapshot:
    kind: str
    version: str
    artifacts: dict[str, Any]
    metadata: dict[str, Any]


class SnapshotRegistry:
    """Store each version as one complete manifest and reject replacement."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def _path(self, kind: str, version: str) -> Path:
        if kind not in _SNAPSHOT_KINDS or not _VERSION.fullmatch(version):
            raise InvalidArgumentError("Invalid snapshot kind or version.")
        return self.root / kind / f"{version}.json"

    def publish_snapshot(
        self,
        kind: str,
        version: str,
        artifacts: Mapping[str, Any],
        metadata: Mapping[str, Any] | None = None,
    ) -> Snapshot:
        destination = self._path(kind, version)
        snapshot = Snapshot(kind, version, dict(artifacts), dict(metadata or {}))
        payload = json.dumps(snapshot.__dict__, ensure_ascii=False, sort_keys=True)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=destination.parent, delete=False
        ) as stream:
            temp = Path(stream.name)
            try:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            except BaseException:
                temp.unlink(missing_ok=True)
                raise
        try:
            os.link(temp, destination)
        except FileExistsError as exc:
            raise ConflictError(f"Snapshot {kind}/{version} already exists.") from exc
        finally:
            temp.unlink(missing_ok=True)
        return Snapshot(**json.loads(payload))

    def get_snapshot(self, kind: str, version: str) -> Snapshot | None:
        path = self._path(kind, version)
        try:
            return Snapshot(**json.loads(path.read_text(encoding="utf-8")))
        except FileNotFoundError:
            return None


@dataclass(frozen=True)
class ValidationResult:
    passed: bool
    diagnostics: list[str]
    stage_results: dict[str, dict[str, Any]]
    replay_diff: dict[str, Any]


def _validate_mapping(
    candidate: dict[str, Any], fixtures: Mapping[str, Any]
) -> ValidationResult:
    mapping = candidate.get("mappings")
    diagnostics = []
    if isinstance(mapping, dict):
        aliases = dict(mapping)
        if "@timestamp" not in aliases:
            diagnostics.append("Mapping must retain @timestamp.")
    elif isinstance(candidate.get("groups"), list) and candidate["groups"]:
        groups = candidate["groups"]
        if any(not isinstance(group, dict) or not group.get("timestamp") for group in groups):
            return ValidationResult(False, ["Each mapping group requires a timestamp."], {}, {})
        aliases = {
            entry["from"]: entry["to"]
            for group in groups
            for entry in group.get("fields", [])
            if isinstance(entry, dict) and "from" in entry and "to" in entry
        }
    else:
        return ValidationResult(False, ["Expected a mappings object or Chainsaw groups."], {}, {})

    samples = fixtures.get("samples", fixtures)
    expected = fixtures.get("expected_fields", samples.get("expected_fields", {}))
    if not isinstance(expected, Mapping):
        return ValidationResult(False, ["expected_fields must be an object."], {}, {})
    required = set(expected.get("required_preserved", ["event_id", "raw_id", "@timestamp"]))
    excluded = set(candidate.get("exclusions", [])) | set(candidate.get("useless", []))
    if missing := required & excluded:
        diagnostics.append(f"Mapping drops required fields: {sorted(missing)}.")
    if any(not isinstance(key, str) or not isinstance(value, str) for key, value in aliases.items()):
        return ValidationResult(False, ["Mapping fields must be strings."], {}, {})
    for source, target in expected.items():
        if source != "required_preserved" and aliases.get(source) != target:
            diagnostics.append(f"Expected field mapping {source} -> {target}.")

    checked = 0
    for label in ("positive", "negative"):
        for row in fixtures.get(label, samples.get(label, [])):
            if not isinstance(row, Mapping):
                diagnostics.append(f"{label} sample must be an object.")
                continue
            checked += 1
            mapped = {key: value for key, value in row.items() if key not in excluded}
            for source, target in aliases.items():
                if source in mapped:
                    mapped[target] = mapped[source]
            for field in sorted(required):
                if field not in row or field not in mapped or mapped[field] != row[field]:
                    diagnostics.append(f"{label} sample {checked} loses {field}.")
            for source, target in expected.items():
                if source != "required_preserved" and source in row:
                    wanted = row.get(target, row[source])
                    if type(mapped.get(target)) is not type(wanted) or mapped.get(target) != wanted:
                        diagnostics.append(f"{label} sample {checked} changes {target}.")
    if not checked:
        diagnostics.append("Mapping validation requires replay samples.")
    return ValidationResult(
        not diagnostics, diagnostics,
        {"mapping_replay": {"passed": not diagnostics, "samples": checked}}, {},
    )


def _replay(
    ctx: RunContext, rules: Path, events: list[dict[str, Any]], work: Path
) -> dict[str, set[str]]:
    cfg = (ctx.config or AppConfig()).engines.rsigma
    if not cfg.enabled or cfg.bin_path is None:
        raise InvalidArgumentError("Configure RSigma to validate Sigma fixtures.")
    if len({row.get("event_id") for row in events}) != len(events) or any(
        not isinstance(row.get("event_id"), str) or not row["event_id"].strip()
        for row in events
    ):
        raise InvalidArgumentError("Replay samples require unique event_id values.")
    sample_path = work / "events.ndjson"
    sample_path.write_text(
        "".join(json.dumps(row) + "\n" for row in events), encoding="utf-8"
    )
    args = [
        "engine", "eval", "-r", str(rules), "-e", f"@{sample_path}",
        "--include-event", "--emit-detections", "--timestamp-field", "@timestamp",
        "--correlation-event-mode", "full", "--output-format", "ndjson",
        "--max-correlation-events", str(len(events)), "-q",
    ]
    process = run_cli_readonly(
        build_exec_argv(cfg.bin_path, args), cwd=cfg.working_dir, timeout_s=cfg.timeout_s
    )
    if process.returncode:
        raise InvalidArgumentError(f"RSigma replay failed: {process.stderr.strip()[:500]}")
    groups: dict[str, set[str]] = {}
    for line in process.stdout.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        event_rows = [row["event"]] if isinstance(row.get("event"), dict) else row.get("events", [])
        groups.setdefault(str(row["rule_id"]), set()).update(
            event["event_id"] for event in event_rows if isinstance(event, dict) and "event_id" in event
        )
    return groups


def _validate_rules(
    ctx: RunContext, candidate: str, fixtures: Mapping[str, Any]
) -> ValidationResult:
    docs = [doc for doc in yaml.safe_load_all(candidate) if doc is not None]
    if not docs or any(not isinstance(doc, dict) or not doc.get("id") for doc in docs):
        raise InvalidArgumentError("Each candidate Sigma rule must declare an ID.")
    target_ids = {str(doc["id"]) for doc in docs}
    if len(target_ids) != len(docs):
        raise InvalidArgumentError("Candidate Sigma rule IDs must be unique.")
    positive, negative = (list(fixtures.get(key, [])) for key in ("positive", "negative"))
    stages: dict[str, dict[str, Any]] = {}
    with TemporaryDirectory(prefix="apt-agent-maintenance-") as temp:
        work = Path(temp)
        rules = work / "rules"
        rules.mkdir()
        (rules / "candidate.yml").write_text(candidate, encoding="utf-8")
        for index, base in enumerate(fixtures.get("base_rules", ())):
            (rules / f"base-{index}.yml").write_text(base, encoding="utf-8")
        failures = [
            entry.reason or "Sigma rule validation failed."
            for entry in inspect_sigma_rules(rules)
            if entry.status == "failed"
        ]
        stages["pysigma"] = {"passed": not failures}
        if failures:
            return ValidationResult(False, failures, stages, {})
        if not positive or not negative:
            return ValidationResult(
                False, ["Supply positive and negative replay samples."], stages, {}
            )
        positive_hits = _replay(ctx, rules, positive, work)
        negative_hits = _replay(ctx, rules, negative, work)
        missing = target_ids - {rid for rid, events in positive_hits.items() if events}
        false_positives = target_ids & negative_hits.keys()
        replay = {
            "positive_event_ids": sorted({
                eid for rid in target_ids for eid in positive_hits.get(rid, ())
            }),
            "negative_event_ids": sorted({
                eid for rid in target_ids for eid in negative_hits.get(rid, ())
            }),
            "missing_positive_rules": sorted(missing),
            "negative_matching_rules": sorted(false_positives),
        }
        baseline_rules = fixtures.get("baseline_rules")
        if baseline_rules:
            baseline = work / "baseline"
            baseline.mkdir()
            for index, rule in enumerate(baseline_rules):
                (baseline / f"rule-{index}.yml").write_text(rule, encoding="utf-8")
            for label, samples in (("positive", positive), ("negative", negative)):
                old_hits = _replay(ctx, baseline, samples, work)
                previous = {eid for ids in old_hits.values() for eid in ids}
                updated = set(replay[f"{label}_event_ids"])
                replay[f"{label}_added"] = sorted(updated - previous)
                replay[f"{label}_removed"] = sorted(previous - updated)
    diagnostics = []
    if missing:
        diagnostics.append("No evidence-bearing positive matches for: " + ", ".join(sorted(missing)))
    if false_positives:
        diagnostics.append("Negative fixtures matched: " + ", ".join(sorted(false_positives)))
    stages["rsigma_replay"] = {
        "passed": not diagnostics,
        "positive_hits": len(replay["positive_event_ids"]),
        "negative_hits": len(replay["negative_event_ids"]),
    }
    return ValidationResult(not diagnostics, diagnostics, stages, replay)


def validate_candidate(
    ctx: RunContext,
    kind: Literal["mapping", "sigma_rule"],
    candidate: str,
    fixtures: Mapping[str, Any],
) -> ValidationResult:
    """Validate candidate text and replay supplied case-independent fixtures."""
    try:
        if kind == "mapping":
            document = yaml.safe_load(candidate)
            if not isinstance(document, dict):
                raise InvalidArgumentError("Mapping candidate must be a YAML object.")
            return _validate_mapping(document, fixtures)
        if kind == "sigma_rule":
            return _validate_rules(ctx, candidate, fixtures)
        raise InvalidArgumentError(f"Unsupported candidate kind: {kind!r}.")
    except (AptAgentError, OSError, ValueError, TypeError, KeyError, yaml.YAMLError) as exc:
        return ValidationResult(False, [str(exc)], {}, {})


@dataclass(frozen=True)
class PublicationResult:
    validation: ValidationResult
    snapshot: Snapshot | None = None


class ConverterAgent:
    """Publish caller-supplied mapping changes after local validation."""

    def __init__(self, registry: SnapshotRegistry) -> None:
        self.registry = registry

    def validate_and_publish(
        self, ctx: RunContext, version: str, candidate: str, fixtures: Mapping[str, Any],
        metadata: Mapping[str, Any] | None = None,
    ) -> PublicationResult:
        outcome = validate_candidate(ctx, "mapping", candidate, fixtures)
        if not outcome.passed:
            return PublicationResult(outcome)
        snapshot = self.registry.publish_snapshot(
            "mapping", version, {"mapping.yaml": candidate}, metadata
        )
        return PublicationResult(outcome, snapshot)


class RuleAgent:
    """Publish caller-supplied Sigma changes after local validation."""

    def __init__(self, registry: SnapshotRegistry) -> None:
        self.registry = registry

    def validate_and_publish(
        self, ctx: RunContext, version: str, candidate: str, fixtures: Mapping[str, Any],
        metadata: Mapping[str, Any] | None = None,
    ) -> PublicationResult:
        outcome = validate_candidate(ctx, "sigma_rule", candidate, fixtures)
        if not outcome.passed:
            return PublicationResult(outcome)
        artifacts = {"candidate.yml": candidate}
        artifacts.update({
            f"base-{index}.yml": rule
            for index, rule in enumerate(fixtures.get("base_rules", ()))
        })
        snapshot = self.registry.publish_snapshot("ruleset", version, artifacts, metadata)
        return PublicationResult(outcome, snapshot)

@contextmanager
def bind_snapshot_assets(config: AppConfig) -> Iterator[AppConfig]:
    """Pin published snapshot contents for paths that the operator left unset."""
    versions = config.snapshots
    registry = SnapshotRegistry(versions.root_dir)
    engines = config.engines
    rule_engines = ("zircolite", "hayabusa", "rsigma", "chainsaw", "pysigma")
    need_rules = [name for name in rule_engines if getattr(engines, name).rules_dir is None]
    def find(kind: str, version: str) -> Snapshot | None:
        return registry.get_snapshot(kind, version) if _VERSION.fullmatch(version) else None

    rules = find("ruleset", versions.ruleset_version) if need_rules else None
    mappings = find("mapping", versions.mapping_version)
    knowledge = (
        find("knowledge", versions.knowledge_snapshot_id)
        if config.rag.knowledge_path is None else None
    )
    if rules is mappings is knowledge is None:
        yield config
        return

    with TemporaryDirectory(prefix="apt-agent-snapshot-") as directory:
        config = config.model_copy(deep=True)
        root = Path(directory)
        rule_files = _write_snapshot_assets(root / "rules", rules, {".yaml", ".yml"})
        if rule_files:
            for name in need_rules:
                getattr(config.engines, name).rules_dir = root / "rules"

        for mapping_path in _write_snapshot_assets(root / "mappings", mappings, {".yaml", ".yml"}):
            document = yaml.safe_load(mapping_path.read_text(encoding="utf-8"))
            if not isinstance(document, dict):
                continue
            if "mappings" in document and config.engines.zircolite.config_path is None:
                config.engines.zircolite.config_path = mapping_path
            if "groups" in document and config.engines.chainsaw.config_path is None:
                config.engines.chainsaw.config_path = mapping_path

        corpora = _write_snapshot_assets(root / "knowledge", knowledge, {".jsonl"})
        if len(corpora) > 1:
            raise InvalidArgumentError("A knowledge snapshot must contain a single JSONL corpus.")
        if corpora:
            config.rag.knowledge_path = corpora[0]
        yield config


def _write_snapshot_assets(
    directory: Path, snapshot: Snapshot | None, suffixes: set[str]
) -> list[Path]:
    if snapshot is None:
        return []
    assets = []
    for name, value in sorted(snapshot.artifacts.items()):
        path = Path(name)
        if (
            path.name != name or "\\" in name or path.suffix.lower() not in suffixes
            or not isinstance(value, str)
        ):
            continue
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / name
        target.write_text(value, encoding="utf-8")
        assets.append(target)
    return assets
