"""Zircolite detection engine adapter."""

from __future__ import annotations

import json
import re
import tempfile
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import orjson

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
    run_cli_readonly,
    validate_event_ids,
)
from apt_agent.exceptions import EngineError, OperationTimeoutError
from apt_agent.ingestion import format_for_zircolite
from apt_agent.models import Event, Hit, RuleRun, RunContext

_DEFAULT_ZIRCOLITE_CONFIG_REL = "script/log_convert/configs/zircolite_config.yaml"
_ZIRCOLITE_ROW_KEY_RE = re.compile(r"\d+:\d+")


def _parse_zircolite_output(raw_text: str) -> list[dict[str, Any]]:
    stripped = raw_text.strip()
    if not stripped:
        return []
    if stripped.startswith("["):
        parsed = json.loads(stripped)
        if not isinstance(parsed, list):
            raise ValueError("Expected JSON array in Zircolite output.")
        return [item for item in parsed if isinstance(item, dict)]
    # Fallback: JSONL / single JSON object
    items: list[dict[str, Any]] = []
    for line in stripped.splitlines():
        line_str = line.strip()
        if not line_str:
            continue
        obj = json.loads(line_str)
        if isinstance(obj, list):
            items.extend(x for x in obj if isinstance(x, dict))
        elif isinstance(obj, dict):
            items.append(obj)
        else:
            raise ValueError("Unexpected JSON item type in Zircolite output.")
    return items


def _resolve_match_row_id(
    row: dict[str, Any],
    line_to_event_id: dict[int, str],
) -> str | None:
    for key in ("row_id", "record_index", "line_number"):
        val = row.get(key)
        if isinstance(val, int) and not isinstance(val, bool) and val in line_to_event_id:
            return line_to_event_id[val]
    return None


class ZircoliteAdapter:
    """Adapter invoking Zircolite via `shell=False` in an isolated temporary workspace."""

    engine_name: str = "zircolite"
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
                        rule_id="zircolite.batch",
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
                        rule_id="zircolite.batch",
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
                        rule_id="zircolite.batch",
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
                        rule_id="zircolite.batch",
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
                        rule_id="zircolite.batch",
                        engine=self.engine_name,
                        rule_version=ruleset_version,
                        status="skipped",
                        reason=f"rules_not_found:{engine_cfg.rules_dir}",
                    )
                ],
            )

        config_path, config_err = resolve_config_path(
            engine_cfg.config_path,
            _DEFAULT_ZIRCOLITE_CONFIG_REL,
        )
        if config_err is not None:
            return AdapterOutput(
                engine=self.engine_name,
                coverage=[
                    RuleRun(
                        rule_id="zircolite.batch",
                        engine=self.engine_name,
                        rule_version=ruleset_version,
                        status="skipped",
                        reason=config_err,
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
                        rule_id="zircolite.batch",
                        engine=self.engine_name,
                        rule_version=ruleset_version,
                        status="skipped",
                        reason="no_compatible_events",
                    )
                ],
            )

        records = format_for_zircolite(routable)
        valid_event_ids = {ev.event_id for ev in routable}
        line_to_event_id: dict[int, str] = {
            idx: str(rec.get("event_id") or "")
            for idx, rec in enumerate(records, start=1)
            if rec.get("event_id")
        }

        with tempfile.TemporaryDirectory(prefix="apt_zirc_") as tmp_dir_str:
            work_dir = Path(tmp_dir_str)
            events_jsonl = work_dir / "events.jsonl"
            out_json = work_dir / "detections.json"
            log_path = work_dir / "zircolite.log"

            with events_jsonl.open("wb") as fh:
                for rec in records:
                    fh.write(orjson.dumps(rec))
                    fh.write(b"\n")

            # Run --version inside work_dir so Zircolite never creates zircolite.log in repo root.
            version = probe_engine_version(engine_cfg.bin_path, cwd=work_dir)

            args: list[str] = [
                "-j",
                "-e",
                str(events_jsonl),
                "-r",
                str(engine_cfg.rules_dir),
                "-o",
                str(out_json),
                "-l",
                str(log_path),
                "-q",
                "--no-auto-mode",
            ]
            if config_path is not None:
                args.extend(["-c", str(config_path)])

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
                            rule_id="zircolite.batch",
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
                            rule_id="zircolite.batch",
                            engine=self.engine_name,
                            engine_version=version,
                            rule_version=ruleset_version,
                            status="failed",
                            reason=reason,
                        )
                    ],
                )

            if not out_json.is_file():
                return AdapterOutput(
                    engine=self.engine_name,
                    engine_version=version,
                    coverage=[
                        RuleRun(
                            rule_id="zircolite.batch",
                            engine=self.engine_name,
                            engine_version=version,
                            rule_version=ruleset_version,
                            status="failed",
                            reason="missing_output_file",
                        )
                    ],
                )

            try:
                raw_out = out_json.read_text(encoding="utf-8")
                rule_entries = _parse_zircolite_output(raw_out)
            except (OSError, ValueError) as exc:
                return AdapterOutput(
                    engine=self.engine_name,
                    engine_version=version,
                    coverage=[
                        RuleRun(
                            rule_id="zircolite.batch",
                            engine=self.engine_name,
                            engine_version=version,
                            rule_version=ruleset_version,
                            status="failed",
                            reason=f"invalid_json_output:{exc}",
                        )
                    ],
                )

        hits: list[Hit] = []
        leads: list[dict[str, Any]] = []
        rule_hit_counts: dict[str, int] = defaultdict(int)
        rule_versions: dict[str, str] = {}
        rule_partial_reasons: dict[str, str] = {}

        for entry in rule_entries:
            rule_id = str(
                entry.get("id")
                or entry.get("rule_id")
                or entry.get("title")
                or "zircolite.unknown"
            )
            rule_version = str(
                entry.get("date")
                or entry.get("modified")
                or entry.get("rule_version")
                or ruleset_version
            )
            rule_versions[rule_id] = rule_version
            level = normalize_level(entry.get("rule_level") or entry.get("level"))
            tactic_ids, technique_ids = normalize_sigma_tags(entry.get("tags") or [])
            matches = entry.get("matches")
            if matches is None:
                matches = entry.get("matched_on")
            if not isinstance(matches, list):
                matches = []

            is_corr_entry = entry.get("result_type") == "correlation"

            for idx, match in enumerate(matches):
                if not isinstance(match, dict):
                    continue
                is_corr = is_corr_entry or (match.get("result_type") == "correlation")

                if is_corr:
                    candidate_eids: list[str] = []
                    had_explicit_refs = False
                    evidence = match.get("evidence")
                    has_evidence = isinstance(evidence, list) and len(evidence) > 0
                    if has_evidence:
                        had_explicit_refs = True
                        for ev_item in evidence:
                            if not isinstance(ev_item, dict):
                                continue
                            ev_obj = ev_item.get("event")
                            if isinstance(ev_obj, dict):
                                if isinstance(ev_obj.get("event_id"), str):
                                    candidate_eids.append(ev_obj["event_id"])
                                else:
                                    fallback_eid = _resolve_match_row_id(
                                        ev_obj, line_to_event_id
                                    )
                                    if fallback_eid:
                                        candidate_eids.append(fallback_eid)
                            elif (
                                isinstance(ev_item.get("event_id"), str)
                                and not _ZIRCOLITE_ROW_KEY_RE.fullmatch(ev_item["event_id"])
                            ):
                                candidate_eids.append(ev_item["event_id"])
                    match_event = match.get("event")
                    if isinstance(match_event, dict) and match_event:
                        had_explicit_refs = True
                        if not candidate_eids:
                            ev_eid = match_event.get("event_id")
                            if isinstance(ev_eid, str):
                                candidate_eids.append(ev_eid)
                            else:
                                fallback_eid = _resolve_match_row_id(
                                    match_event, line_to_event_id
                                )
                                if fallback_eid:
                                    candidate_eids.append(fallback_eid)
                    if isinstance(match.get("event_id"), str):
                        had_explicit_refs = True
                        if not candidate_eids:
                            candidate_eids.append(match["event_id"])
                    match_eids = match.get("event_ids")
                    if not has_evidence and isinstance(match_eids, list) and len(match_eids) > 0:
                        had_explicit_refs = True
                        if not candidate_eids:
                            for raw_eid in match_eids:
                                if (
                                    isinstance(raw_eid, str)
                                    and not _ZIRCOLITE_ROW_KEY_RE.fullmatch(raw_eid)
                                ):
                                    candidate_eids.append(raw_eid)

                    resolved_eids = validate_event_ids(candidate_eids, valid_event_ids)
                    if had_explicit_refs and not resolved_eids:
                        continue
                    matched_time = parse_utc_timestamp(
                        match.get("SystemTime")
                        or match.get("@timestamp")
                        or match.get("occurrence_time")
                    )
                    expected_count = entry.get("event_count")
                    if expected_count is None:
                        expected_count = match.get("event_count")

                    matched_fields: dict[str, Any] = {
                        "title": entry.get("title"),
                        "result_type": "correlation",
                    }
                    if match.get("alert_id") is not None:
                        matched_fields["alert_id"] = match.get("alert_id")
                    if match.get("group_keys") is not None:
                        matched_fields["group_keys"] = match.get("group_keys")
                    if expected_count is not None:
                        matched_fields["event_count"] = expected_count

                    if not resolved_eids:
                        matched_fields["count_only"] = True
                        hit_id = make_hit_id(
                            self.engine_name,
                            rule_id,
                            [],
                            f"corr:{match.get('alert_id', idx)}",
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
                                    f"{rule_id}:{match.get('alert_id', idx)}",
                                ),
                                "kind": "correlation_count_only",
                                "engine": self.engine_name,
                                "rule_id": rule_id,
                                "rule_version": rule_version,
                                "tactic_ids": tactic_ids,
                                "technique_ids": technique_ids,
                                "group_keys": match.get("group_keys"),
                                "count": expected_count or entry.get("count"),
                                "reason": "count_only_correlation",
                            }
                        )
                        rule_hit_counts[rule_id] += 1
                    else:
                        if (
                            isinstance(expected_count, int)
                            and not isinstance(expected_count, bool)
                            and expected_count > len(resolved_eids)
                        ):
                            matched_fields["truncated_correlation"] = True
                            rule_partial_reasons[rule_id] = "correlation_events_truncated"
                        hit_id = make_hit_id(
                            self.engine_name,
                            rule_id,
                            resolved_eids,
                            f"corr:{match.get('alert_id', idx)}",
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
                    cand: list[str] = []
                    if isinstance(match.get("event_id"), str):
                        cand.append(match["event_id"])
                    else:
                        fallback_eid = _resolve_match_row_id(match, line_to_event_id)
                        if fallback_eid:
                            cand.append(fallback_eid)
                    resolved_eids = validate_event_ids(cand, valid_event_ids)
                    if not resolved_eids:
                        continue
                    matched_time = parse_utc_timestamp(
                        match.get("SystemTime") or match.get("@timestamp")
                    )
                    matched_fields = {
                        k: v
                        for k, v in match.items()
                        if k not in {"row_id"} and v is not None
                    }
                    if entry.get("title"):
                        matched_fields.setdefault("title", entry.get("title"))
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
            for marker in ("parse error", "error loading", "skipped", "ignored rule")
        )

        coverage: list[RuleRun] = []
        if rule_hit_counts:
            for rid, count in sorted(rule_hit_counts.items()):
                partial_reason = rule_partial_reasons.get(rid)
                status = "partial" if partial_reason else "ran"
                coverage.append(
                    RuleRun(
                        rule_id=rid,
                        engine=self.engine_name,
                        engine_version=version,
                        rule_version=rule_versions.get(rid, ruleset_version),
                        status=status,  # type: ignore[arg-type]
                        reason=partial_reason,
                        hit_count=count,
                    )
                )
            if partial_warning:
                coverage.append(
                    RuleRun(
                        rule_id="zircolite.batch",
                        engine=self.engine_name,
                        engine_version=version,
                        rule_version=ruleset_version,
                        status="partial",
                        reason="partial_rule_load_errors",
                        hit_count=len(hits),
                    )
                )
        else:
            coverage.append(
                RuleRun(
                    rule_id="zircolite.batch",
                    engine=self.engine_name,
                    engine_version=version,
                    rule_version=ruleset_version,
                    status="partial" if partial_warning else "ran",
                    reason="partial_rule_load_errors" if partial_warning else None,
                    hit_count=0,
                )
            )

        return AdapterOutput(
            engine=self.engine_name,
            engine_version=version,
            hits=hits,
            coverage=coverage,
            leads=leads,
        )


__all__ = ["ZircoliteAdapter"]
