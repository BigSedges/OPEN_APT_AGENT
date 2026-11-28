"""RSigma CLI adapter and pySigma static rule-coverage inspector."""

from __future__ import annotations

import json
import tempfile
from collections import defaultdict
from collections.abc import Sequence
from collections.abc import Set as AbstractSet
from pathlib import Path
from typing import Any

import orjson
import yaml

from apt_agent.config import EngineConfig
from apt_agent.detection.base import (
    ALL_LOG_FORMATS,
    AdapterOutput,
    build_exec_argv,
    classify_event_format,
    extract_version_text,
    make_hit_id,
    make_lead_id,
    normalize_level,
    normalize_sigma_tags,
    parse_utc_timestamp,
    probe_engine_version,
    resolve_config_path,
    resolve_rule_files,
    run_cli_readonly,
    validate_event_ids,
)
from apt_agent.exceptions import EngineError, OperationTimeoutError
from apt_agent.ingestion import format_for_rsigma
from apt_agent.models import Event, Hit, RuleRun, RunContext

_DEFAULT_RSIGMA_PIPELINE_REL = "script/log_convert/configs/rsigma_pipeline.yml"


def _logsource_compatible_formats(logsource: Any) -> set[str]:
    """Map a pySigma `SigmaLogSource` to compatible normalized format keys."""
    if logsource is None:
        return set(ALL_LOG_FORMATS)
    product = (getattr(logsource, "product", None) or "").strip().lower()
    category = (getattr(logsource, "category", None) or "").strip().lower()
    service = (getattr(logsource, "service", None) or "").strip().lower()

    if not product and not category and not service:
        return set(ALL_LOG_FORMATS)

    if product in {"windows", "linux"} and category and not service:
        # Generic endpoint categories can be supplied by typed ECAR telemetry.
        return {"winxml", "ecar_json"} if product == "windows" else {"bash_history", "syslog", "ecar_json"}
    if product == "windows" or service in {"sysmon", "security", "system", "powershell", "windefend"}:
        return {"winxml"}
    if product == "zeek" or service == "zeek":
        return {"zeek_json"}
    if product == "ecar" or service == "ecar":
        return {"ecar_json"}
    if product == "linux":
        if service in {"syslog", "auth", "auditd"}:
            return {"syslog"}
        if service == "bash" or category == "process_creation":
            return {"bash_history", "syslog"}
        return {"bash_history", "syslog"}
    if service == "syslog" or category == "syslog":
        return {"syslog"}
    if category in {"webserver", "proxy"} or product in {"apache", "nginx", "iis"}:
        return {"web_access"}

    return set(ALL_LOG_FORMATS)


def inspect_sigma_rules(
    rules_dir: Path | None,
    *,
    engine_cfg: EngineConfig | None = None,
    batch_formats: AbstractSet[str] | None = None,
    ruleset_version: str = "v1",
) -> list[RuleRun]:
    """Statically inspect Sigma YAML rules using `pySigma` for coverage & compatibility."""
    if engine_cfg is not None and not engine_cfg.enabled:
        return [
            RuleRun(
                rule_id="pysigma.batch",
                engine="pysigma",
                rule_version=ruleset_version,
                status="skipped",
                reason="engine_disabled",
            )
        ]
    if rules_dir is None:
        return [
            RuleRun(
                rule_id="pysigma.batch",
                engine="pysigma",
                rule_version=ruleset_version,
                status="skipped",
                reason="rules_not_configured",
            )
        ]
    if not rules_dir.exists():
        return [
            RuleRun(
                rule_id="pysigma.batch",
                engine="pysigma",
                rule_version=ruleset_version,
                status="skipped",
                reason=f"rules_not_found:{rules_dir}",
            )
        ]

    from importlib.metadata import PackageNotFoundError, version as pkg_version
    from sigma.backends.sqlite import sqliteBackend
    from sigma.collection import SigmaCollection
    from sigma.correlations import SigmaCorrelationRule
    from sigma.exceptions import SigmaError
    from sigma.rule import SigmaRule

    try:
        pysigma_ver = pkg_version("pysigma")
    except PackageNotFoundError:
        pysigma_ver = "unknown"

    if rules_dir.is_file():
        yaml_files = [rules_dir] if rules_dir.suffix.lower() in {".yml", ".yaml"} else []
    else:
        yaml_files = [
            p
            for p in sorted(rules_dir.rglob("*"))
            if p.is_file() and p.suffix.lower() in {".yml", ".yaml"}
        ]

    if not yaml_files:
        return [
            RuleRun(
                rule_id="pysigma.batch",
                engine="pysigma",
                engine_version=pysigma_ver,
                rule_version=ruleset_version,
                status="skipped",
                reason="no_sigma_yaml_files",
            )
        ]

    coverage: list[RuleRun] = []
    valid_docs: list[dict[str, Any]] = []

    for yf in yaml_files:
        try:
            text = yf.read_text(encoding="utf-8")
            docs = [d for d in yaml.safe_load_all(text) if d is not None]
        except (OSError, yaml.YAMLError) as exc:
            coverage.append(
                RuleRun(
                    rule_id=yf.stem,
                    engine="pysigma",
                    engine_version=pysigma_ver,
                    rule_version=ruleset_version,
                    status="failed",
                    reason=f"parse_error:{type(exc).__name__}:{exc}",
                )
            )
            continue

        if not docs:
            continue

        for doc in docs:
            if not isinstance(doc, dict):
                coverage.append(
                    RuleRun(
                        rule_id=yf.stem,
                        engine="pysigma",
                        engine_version=pysigma_ver,
                        rule_version=ruleset_version,
                        status="failed",
                        reason="parse_error:non_mapping_yaml_document",
                    )
                )
                continue
            try:
                if "correlation" in doc:
                    SigmaCorrelationRule.from_dict(doc)
                else:
                    SigmaRule.from_dict(doc)
                valid_docs.append(doc)
            except (SigmaError, ValueError, TypeError) as exc:
                rid = str(doc.get("id") or doc.get("title") or yf.stem)
                coverage.append(
                    RuleRun(
                        rule_id=rid,
                        engine="pysigma",
                        engine_version=pysigma_ver,
                        rule_version=ruleset_version,
                        status="failed",
                        reason=f"parse_error:{type(exc).__name__}:{exc}",
                    )
                )

    if not valid_docs:
        return coverage

    base_docs = [d for d in valid_docs if "correlation" not in d]
    corr_docs = [d for d in valid_docs if "correlation" in d]
    ordered_docs = [*base_docs, *corr_docs]

    try:
        collection = SigmaCollection.from_dicts(ordered_docs)
        rules_to_inspect = list(collection.rules)
    except (SigmaError, ValueError, TypeError):
        # Fallback if a correlation rule has an unresolved reference:
        # resolve single rules first, then resolve correlation rules individually.
        rules_to_inspect = []
        if base_docs:
            rules_to_inspect.extend(SigmaCollection.from_dicts(base_docs).rules)
        resolved_corr_docs: list[dict[str, Any]] = []
        pending: list[dict[str, Any]] = list(corr_docs)
        last_errors: dict[int, Exception] = {}

        while pending:
            next_pending: list[dict[str, Any]] = []
            progress = False
            for cdoc in pending:
                try:
                    sub_coll = SigmaCollection.from_dicts(
                        [*base_docs, *resolved_corr_docs, cdoc]
                    )
                    target_id = cdoc.get("id")
                    target_title = cdoc.get("title")
                    matched_corr = [
                        r
                        for r in sub_coll.rules
                        if isinstance(r, SigmaCorrelationRule)
                        and (
                            (
                                target_id is not None
                                and str(getattr(r, "id", "")) == str(target_id)
                            )
                            or (
                                target_id is None
                                and getattr(r, "title", None) == target_title
                            )
                        )
                    ]
                    if matched_corr:
                        rules_to_inspect.extend(matched_corr)
                    resolved_corr_docs.append(cdoc)
                    progress = True
                except (SigmaError, ValueError, TypeError) as exc:
                    last_errors[id(cdoc)] = exc
                    next_pending.append(cdoc)
            pending = next_pending
            if not progress:
                break

        for cdoc in pending:
            exc = last_errors[id(cdoc)]
            rid = str(cdoc.get("id") or cdoc.get("title") or "pysigma.correlation")
            coverage.append(
                RuleRun(
                    rule_id=rid,
                    engine="pysigma",
                    engine_version=pysigma_ver,
                    rule_version=ruleset_version,
                    status="failed",
                    reason=f"correlation_ref_error:{type(exc).__name__}:{exc}",
                )
            )

    backend = sqliteBackend()
    for rule in rules_to_inspect:
        rid = str(getattr(rule, "id", None) or getattr(rule, "title", None) or "pysigma.unknown")
        rver = str(
            getattr(rule, "modified", None)
            or getattr(rule, "date", None)
            or ruleset_version
        )

        if isinstance(rule, SigmaCorrelationRule):
            compat_formats: set[str] = set()
            ref_rules: list[Any] = []
            seen_refs: set[int] = set()

            def _collect_refs(
                corr_rule: SigmaCorrelationRule,
                out_refs: list[Any],
                out_formats: set[str],
                seen: set[int],
            ) -> None:
                refs = getattr(corr_rule, "referenced_rules", None) or getattr(corr_rule, "rules", ()) or ()
                for ref in refs:
                    target = getattr(ref, "rule", None)
                    if target is None or id(target) in seen:
                        continue
                    seen.add(id(target))
                    if isinstance(target, SigmaCorrelationRule):
                        _collect_refs(target, out_refs, out_formats, seen)
                    else:
                        out_formats.update(
                            _logsource_compatible_formats(getattr(target, "logsource", None))
                        )
                    out_refs.append(target)

            _collect_refs(rule, ref_rules, compat_formats, seen_refs)
            if not compat_formats:
                compat_formats = set(ALL_LOG_FORMATS)
        else:
            compat_formats = _logsource_compatible_formats(getattr(rule, "logsource", None))
            ref_rules = []

        if batch_formats is not None and not (compat_formats & set(batch_formats)):
            reason = (
                "no_compatible_events"
                if not batch_formats
                else f"incompatible_logsource:{','.join(sorted(compat_formats))}"
            )
            coverage.append(
                RuleRun(
                    rule_id=rid,
                    engine="pysigma",
                    engine_version=pysigma_ver,
                    rule_version=rver,
                    status="skipped",
                    reason=reason,
                    hit_count=0,
                )
            )
            continue

        try:
            if isinstance(rule, SigmaCorrelationRule):
                sub_coll = SigmaCollection([*ref_rules, rule])
                backend.convert(sub_coll)
            else:
                backend.convert_rule(rule)
        except (SigmaError, NotImplementedError, ValueError, TypeError) as exc:
            coverage.append(
                RuleRun(
                    rule_id=rid,
                    engine="pysigma",
                    engine_version=pysigma_ver,
                    rule_version=rver,
                    status="partial",
                    reason=f"backend_unsupported:{type(exc).__name__}:{exc}",
                    hit_count=0,
                )
            )
            continue

        coverage.append(
            RuleRun(
                rule_id=rid,
                engine="pysigma",
                engine_version=pysigma_ver,
                rule_version=rver,
                status="ran",
                reason=None,
                hit_count=0,
            )
        )

    return coverage


class RSigmaAdapter:
    """Adapter invoking RSigma (`engine eval`) with UTC-sorted NDJSON."""

    engine_name: str = "rsigma"
    supported_formats: frozenset[str] = ALL_LOG_FORMATS

    def run(
        self,
        ctx: RunContext,
        events: Sequence[Event],
        engine_cfg: EngineConfig,
        *,
        ruleset_version: str,
    ) -> AdapterOutput:
        if not engine_cfg.enabled:
            return AdapterOutput(
                engine=self.engine_name,
                coverage=[
                    RuleRun(
                        rule_id="rsigma.batch",
                        engine=self.engine_name,
                        rule_version=ruleset_version,
                        status="skipped",
                        reason="engine_disabled",
                    )
                ],
            )
        if engine_cfg.bin_path is None:
            return AdapterOutput(
                engine=self.engine_name,
                coverage=[
                    RuleRun(
                        rule_id="rsigma.batch",
                        engine=self.engine_name,
                        rule_version=ruleset_version,
                        status="skipped",
                        reason="binary_not_configured",
                    )
                ],
            )
        if not engine_cfg.bin_path.is_file():
            return AdapterOutput(
                engine=self.engine_name,
                coverage=[
                    RuleRun(
                        rule_id="rsigma.batch",
                        engine=self.engine_name,
                        rule_version=ruleset_version,
                        status="skipped",
                        reason=f"binary_not_found:{engine_cfg.bin_path}",
                    )
                ],
            )
        if engine_cfg.rules_dir is None:
            return AdapterOutput(
                engine=self.engine_name,
                coverage=[
                    RuleRun(
                        rule_id="rsigma.batch",
                        engine=self.engine_name,
                        rule_version=ruleset_version,
                        status="skipped",
                        reason="rules_not_configured",
                    )
                ],
            )
        if not engine_cfg.rules_dir.exists():
            return AdapterOutput(
                engine=self.engine_name,
                coverage=[
                    RuleRun(
                        rule_id="rsigma.batch",
                        engine=self.engine_name,
                        rule_version=ruleset_version,
                        status="skipped",
                        reason=f"rules_not_found:{engine_cfg.rules_dir}",
                    )
                ],
            )

        pipeline_path, pipeline_err = resolve_config_path(
            engine_cfg.config_path,
            _DEFAULT_RSIGMA_PIPELINE_REL,
        )
        if pipeline_err is not None:
            return AdapterOutput(
                engine=self.engine_name,
                coverage=[
                    RuleRun(
                        rule_id="rsigma.batch",
                        engine=self.engine_name,
                        rule_version=ruleset_version,
                        status="skipped",
                        reason=pipeline_err,
                    )
                ],
            )

        routable = [
            ev for ev in events if classify_event_format(ev) in self.supported_formats
        ]
        if not routable:
            return AdapterOutput(
                engine=self.engine_name,
                coverage=[
                    RuleRun(
                        rule_id="rsigma.batch",
                        engine=self.engine_name,
                        rule_version=ruleset_version,
                        status="skipped",
                        reason="no_compatible_events",
                    )
                ],
            )

        records = format_for_rsigma(routable, sort_utc=True)
        valid_event_ids = {ev.event_id for ev in routable}
        line_to_event_id: dict[int, str] = {
            idx: str(rec.get("event_id") or "")
            for idx, rec in enumerate(records, start=1)
            if rec.get("event_id")
        }

        rule_inventory = inspect_sigma_rules(
            engine_cfg.rules_dir,
            batch_formats={classify_event_format(event) for event in routable},
            ruleset_version=ruleset_version,
        )
        invalid_ids = {item.rule_id for item in rule_inventory if item.status == "failed"}

        with tempfile.TemporaryDirectory(prefix="apt_rsigma_") as tmp_dir_str:
            work_dir = Path(tmp_dir_str)
            events_ndjson = work_dir / "events.ndjson"
            out_ndjson = work_dir / "detections.ndjson"

            with events_ndjson.open("wb") as fh:
                for rec in records:
                    fh.write(orjson.dumps(rec))
                    fh.write(b"\n")

            version = probe_engine_version(engine_cfg.bin_path, cwd=work_dir)

            rules_path = engine_cfg.rules_dir
            if invalid_ids:
                rules_path = work_dir / "rules"
                rules_path.mkdir()
                for index, rule_file in enumerate(resolve_rule_files(engine_cfg.rules_dir)):
                    if rule_file.suffix.lower() not in {".yml", ".yaml"}:
                        continue
                    try:
                        docs = list(yaml.safe_load_all(rule_file.read_text(encoding="utf-8")))
                    except (OSError, yaml.YAMLError):
                        continue
                    valid = [
                        doc for doc in docs if isinstance(doc, dict)
                        and str(doc.get("id") or doc.get("title") or rule_file.stem) not in invalid_ids
                    ]
                    if valid:
                        (rules_path / f"{index}.yml").write_text(
                            yaml.safe_dump_all(valid), encoding="utf-8"
                        )

            args: list[str] = [
                "engine",
                "eval",
                "-r",
                str(rules_path),
            ]
            if pipeline_path is not None:
                args.extend(["-p", str(pipeline_path)])
            args.extend(
                [
                    "-e",
                    f"@{events_ndjson}",
                    "--emit-detections",
                    "--include-event",
                    "--correlation-event-mode",
                    "full",
                    "--output-format",
                    "ndjson",
                    "-q",
                    "-o",
                    str(out_ndjson),
                ]
            )

            argv = build_exec_argv(engine_cfg.bin_path, args)
            try:
                proc = run_cli_readonly(
                    argv,
                    timeout_s=engine_cfg.timeout_s,
                    cwd=work_dir,
                )
            except (OperationTimeoutError, EngineError) as exc:
                return AdapterOutput(
                    engine=self.engine_name,
                    engine_version=version,
                    coverage=[
                        RuleRun(
                            rule_id="rsigma.batch",
                            engine=self.engine_name,
                            engine_version=version,
                            rule_version=ruleset_version,
                            status="failed",
                            reason=exc.message,
                        )
                    ],
                )

            if version == "unknown":
                detected_ver = extract_version_text(
                    "\n".join(p for p in (proc.stdout, proc.stderr) if p)
                )
                if detected_ver:
                    version = detected_ver

            if proc.returncode != 0:
                err_detail = (proc.stderr or proc.stdout or "").strip()[:300]
                reason = f"exit_{proc.returncode}:{err_detail}" if err_detail else f"exit_{proc.returncode}"
                return AdapterOutput(
                    engine=self.engine_name,
                    engine_version=version,
                    coverage=[
                        RuleRun(
                            rule_id="rsigma.batch",
                            engine=self.engine_name,
                            engine_version=version,
                            rule_version=ruleset_version,
                            status="failed",
                            reason=reason,
                        )
                    ],
                )

            if not out_ndjson.is_file():
                return AdapterOutput(
                    engine=self.engine_name,
                    engine_version=version,
                    coverage=[
                        RuleRun(
                            rule_id="rsigma.batch",
                            engine=self.engine_name,
                            engine_version=version,
                            rule_version=ruleset_version,
                            status="failed",
                            reason="missing_output_file",
                        )
                    ],
                )

            try:
                parsed_rows: list[dict[str, Any]] = []
                with out_ndjson.open(encoding="utf-8") as rows:
                    for line in rows:
                        stripped = line.strip()
                        if not stripped:
                            continue
                        obj = json.loads(stripped)
                        if not isinstance(obj, dict):
                            raise ValueError("RSigma NDJSON line must be a JSON object.")
                        if not any(key in obj for key in (
                            "correlation_type", "events", "matched_events", "aggregated_value"
                        )) and isinstance(obj.get("event"), dict):
                            # The raw evidence store already owns the full record.
                            # Ordinary hits need only these two event fields below.
                            event = obj["event"]
                            obj["event"] = {key: event[key] for key in ("event_id", "@timestamp")
                                            if key in event}
                        parsed_rows.append(obj)
            except (OSError, ValueError) as exc:
                return AdapterOutput(
                    engine=self.engine_name,
                    engine_version=version,
                    coverage=[
                        RuleRun(
                            rule_id="rsigma.batch",
                            engine=self.engine_name,
                            engine_version=version,
                            rule_version=ruleset_version,
                            status="failed",
                            reason=f"invalid_ndjson_output:{exc}",
                        )
                    ],
                )

        hits: list[Hit] = []
        leads: list[dict[str, Any]] = []
        rule_hit_counts: dict[str, int] = defaultdict(int)
        rule_versions: dict[str, str] = {}
        rule_partial_reasons: dict[str, str] = {}

        for idx, obj in enumerate(parsed_rows):
            rule_id = str(
                obj.get("rule_id")
                or obj.get("id")
                or obj.get("rule_title")
                or "rsigma.unknown"
            )
            rule_version = str(
                obj.get("rule_version")
                or obj.get("date")
                or ruleset_version
            )
            rule_versions[rule_id] = rule_version
            level = normalize_level(obj.get("level"))
            tactic_ids, technique_ids = normalize_sigma_tags(obj.get("tags") or [])

            is_correlation = (
                "correlation_type" in obj
                or "events" in obj
                or "matched_events" in obj
                or "aggregated_value" in obj
            )

            if is_correlation:
                raw_events = obj.get("events")
                if not raw_events and obj.get("matched_events") is not None:
                    raw_events = obj.get("matched_events")
                raw_eids: list[Any] = []
                if isinstance(raw_events, list):
                    for item in raw_events:
                        if isinstance(item, dict):
                            if item.get("event_id") is not None:
                                raw_eids.append(item.get("event_id"))
                            else:
                                for key in ("line_number", "record_index"):
                                    line_num = item.get(key)
                                    if (
                                        isinstance(line_num, int)
                                        and not isinstance(line_num, bool)
                                    ):
                                        mapped = line_to_event_id.get(line_num)
                                        if mapped:
                                            raw_eids.append(mapped)
                                            break
                        elif isinstance(item, str):
                            raw_eids.append(item)
                raw_event_ids_field = obj.get("event_ids")
                if not raw_eids and isinstance(raw_event_ids_field, list):
                    raw_eids.extend(raw_event_ids_field)

                had_explicit_refs = (
                    bool(raw_eids)
                    or (isinstance(raw_events, list) and len(raw_events) > 0)
                    or (
                        isinstance(raw_event_ids_field, list)
                        and len(raw_event_ids_field) > 0
                    )
                )
                resolved_eids = validate_event_ids(raw_eids, valid_event_ids)
                if had_explicit_refs and not resolved_eids:
                    continue
                agg_val = obj.get("aggregated_value")
                event_times: list[str] = []
                if isinstance(raw_events, list):
                    for item in raw_events:
                        if isinstance(item, dict):
                            ts = parse_utc_timestamp(
                                item.get("@timestamp") or item.get("timestamp")
                            )
                            if ts:
                                event_times.append(ts)
                matched_time = min(event_times) if event_times else parse_utc_timestamp(obj.get("timestamp"))

                matched_fields: dict[str, Any] = {
                    "rule_title": obj.get("rule_title"),
                    "correlation_type": obj.get("correlation_type"),
                    "group_key": obj.get("group_key"),
                    "aggregated_value": agg_val,
                    "timespan_secs": obj.get("timespan_secs"),
                }
                if obj.get("event_sources") is not None:
                    matched_fields["event_sources"] = obj.get("event_sources")

                if not resolved_eids:
                    matched_fields["count_only"] = True
                    hit_id = make_hit_id(
                        self.engine_name,
                        rule_id,
                        [],
                        f"corr:{idx}:{json.dumps(obj.get('group_key'), sort_keys=True, default=str)}",
                    )
                    hits.append(
                        Hit(
                            hit_id=hit_id,
                            rule_id=rule_id,
                            rule_version=rule_version,
                            engine=self.engine_name,
                            engine_version=version,
                            event_ids=[],
                            tactic_ids=tactic_ids,
                            technique_ids=technique_ids,
                            matched_time=matched_time,
                            level=level,
                            matched_fields=matched_fields,
                        )
                    )
                    leads.append(
                        {
                            "lead_id": make_lead_id(
                                self.engine_name,
                                "correlation_count_only",
                                f"{rule_id}:{idx}:{obj.get('group_key')}",
                            ),
                            "kind": "correlation_count_only",
                            "engine": self.engine_name,
                            "rule_id": rule_id,
                            "rule_version": rule_version,
                            "tactic_ids": tactic_ids,
                            "technique_ids": technique_ids,
                            "correlation_type": obj.get("correlation_type"),
                            "group_key": obj.get("group_key"),
                            "aggregated_value": agg_val,
                            "count": agg_val,
                            "reason": "count_only_correlation",
                        }
                    )
                    rule_hit_counts[rule_id] += 1
                else:
                    if (
                        isinstance(agg_val, (int, float))
                        and not isinstance(agg_val, bool)
                        and agg_val > len(resolved_eids)
                    ):
                        matched_fields["truncated_correlation"] = True
                        rule_partial_reasons[rule_id] = "correlation_events_truncated"

                    hit_id = make_hit_id(
                        self.engine_name,
                        rule_id,
                        resolved_eids,
                        f"corr:{idx}",
                    )
                    hits.append(
                        Hit(
                            hit_id=hit_id,
                            rule_id=rule_id,
                            rule_version=rule_version,
                            engine=self.engine_name,
                            engine_version=version,
                            event_ids=resolved_eids,
                            tactic_ids=tactic_ids,
                            technique_ids=technique_ids,
                            matched_time=matched_time,
                            level=level,
                            matched_fields=matched_fields,
                        )
                    )
                    rule_hit_counts[rule_id] += 1
            else:
                ev_obj = obj.get("event") if isinstance(obj.get("event"), dict) else {}
                cand: list[Any] = []
                if ev_obj.get("event_id") is not None:
                    cand.append(ev_obj.get("event_id"))
                elif obj.get("event_id") is not None:
                    cand.append(obj.get("event_id"))
                elif isinstance(obj.get("matched_fields"), dict) and obj["matched_fields"].get("event_id") is not None:
                    cand.append(obj["matched_fields"].get("event_id"))
                else:
                    line_num = obj.get("line_number")
                    if isinstance(line_num, int) and not isinstance(line_num, bool):
                        mapped = line_to_event_id.get(line_num)
                        if mapped:
                            cand.append(mapped)

                resolved_eids = validate_event_ids(cand, valid_event_ids)
                if not resolved_eids:
                    continue

                matched_time = parse_utc_timestamp(
                    ev_obj.get("@timestamp") or obj.get("timestamp")
                )
                matched_fields = {
                    "rule_title": obj.get("rule_title"),
                    "matched_selections": obj.get("matched_selections"),
                    "matched_fields": obj.get("matched_fields"),
                }
                hit_id = make_hit_id(self.engine_name, rule_id, resolved_eids, str(idx))
                hits.append(
                    Hit(
                        hit_id=hit_id,
                        rule_id=rule_id,
                        rule_version=rule_version,
                        engine=self.engine_name,
                        engine_version=version,
                        event_ids=resolved_eids,
                        tactic_ids=tactic_ids,
                        technique_ids=technique_ids,
                        matched_time=matched_time,
                        level=level,
                        matched_fields=matched_fields,
                    )
                )
                rule_hit_counts[rule_id] += 1

        combined_diag = "\n".join(p for p in (proc.stderr, proc.stdout) if p).lower()
        partial_warning = any(
            marker in combined_diag
            for marker in ("parse error", "parse errors", "compile error", "warning:")
        )

        coverage: list[RuleRun] = []
        if rule_hit_counts:
            for rid, count in sorted(rule_hit_counts.items()):
                partial_reason = rule_partial_reasons.get(rid)
                coverage.append(
                    RuleRun(
                        rule_id=rid,
                        engine=self.engine_name,
                        engine_version=version,
                        rule_version=rule_versions.get(rid, ruleset_version),
                        status="partial" if partial_reason else "ran",
                        reason=partial_reason,
                        hit_count=count,
                    )
                )
            if partial_warning:
                coverage.append(
                    RuleRun(
                        rule_id="rsigma.batch",
                        engine=self.engine_name,
                        engine_version=version,
                        rule_version=ruleset_version,
                        status="partial",
                        reason="partial_rule_parse_errors",
                        hit_count=len(hits),
                    )
                )
        else:
            coverage.append(
                RuleRun(
                    rule_id="rsigma.batch",
                    engine=self.engine_name,
                    engine_version=version,
                    rule_version=ruleset_version,
                    status="partial" if partial_warning else "ran",
                    reason="partial_rule_parse_errors" if partial_warning else None,
                    hit_count=0,
                )
            )

        for item in rule_inventory:
            if item.rule_id in rule_hit_counts or item.rule_id == "pysigma.batch":
                continue
            status = item.status if item.status in {"failed", "skipped"} else "ran"
            coverage.append(RuleRun(
                rule_id=item.rule_id, engine=self.engine_name, engine_version=version,
                rule_version=item.rule_version, status=status,
                reason=item.reason if status != "ran" else None,
            ))

        return AdapterOutput(
            engine=self.engine_name,
            engine_version=version,
            hits=hits,
            coverage=coverage,
            leads=leads,
        )


__all__ = ["RSigmaAdapter", "inspect_sigma_rules"]
