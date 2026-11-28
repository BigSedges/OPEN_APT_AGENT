"""Chainsaw detection engine adapter with Windows vs non-Windows JSON partitioning."""

from __future__ import annotations

import json
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
    normalize_level,
    normalize_sigma_tags,
    parse_utc_timestamp,
    probe_engine_version,
    resolve_config_path,
    run_cli_readonly,
    validate_event_ids,
)
from apt_agent.exceptions import EngineError, OperationTimeoutError
from apt_agent.ingestion import format_for_chainsaw
from apt_agent.models import Event, Hit, RuleRun, RunContext

_DEFAULT_CHAINSAW_CUSTOM_MAPPING_REL = "script/log_convert/configs/chainsaw_custom_mapping.yml"


def _parse_chainsaw_output(raw_text: str) -> list[dict[str, Any]]:
    stripped = raw_text.strip()
    if not stripped:
        return []
    if stripped.startswith("["):
        parsed = json.loads(stripped)
        if not isinstance(parsed, list):
            raise ValueError("Expected JSON array in Chainsaw output.")
        return [item for item in parsed if isinstance(item, dict)]
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
            raise ValueError("Unexpected JSON item type in Chainsaw output.")
    return items


class ChainsawAdapter:
    """Adapter invoking Chainsaw (`hunt --json --skip-errors`) per schema partition."""

    engine_name: str = "chainsaw"
    supported_formats: frozenset[str] = ALL_LOG_FORMATS

    def _run_partition(
        self,
        *,
        partition_name: str,
        part_events: Sequence[Event],
        map_path: Path,
        engine_cfg: EngineConfig,
        version: str,
        ruleset_version: str,
        work_dir: Path,
    ) -> tuple[list[Hit], list[RuleRun], str]:
        records = format_for_chainsaw(part_events)
        valid_event_ids = {ev.event_id for ev in part_events}

        in_json = work_dir / f"chainsaw_{partition_name}.json"
        out_json = work_dir / f"chainsaw_{partition_name}_out.json"
        in_json.write_bytes(orjson.dumps(records))

        args: list[str] = [
            "hunt",
            "-s",
            str(engine_cfg.rules_dir),
            "-m",
            str(map_path),
            "--json",
            "--skip-errors",
            "-q",
            "-o",
            str(out_json),
            str(in_json),
        ]
        argv = build_exec_argv(engine_cfg.bin_path, args)  # type: ignore[arg-type]

        try:
            proc = run_cli_readonly(
                argv,
                timeout_s=engine_cfg.timeout_s,
                cwd=work_dir,
            )
        except (OperationTimeoutError, EngineError) as exc:
            return (
                [],
                [
                    RuleRun(
                        rule_id=f"chainsaw.{partition_name}",
                        engine=self.engine_name,
                        engine_version=version,
                        rule_version=ruleset_version,
                        status="failed",
                        reason=exc.message,
                    )
                ],
                version,
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
            return (
                [],
                [
                    RuleRun(
                        rule_id=f"chainsaw.{partition_name}",
                        engine=self.engine_name,
                        engine_version=version,
                        rule_version=ruleset_version,
                        status="failed",
                        reason=reason,
                    )
                ],
                version,
            )

        if not out_json.is_file():
            return (
                [],
                [
                    RuleRun(
                        rule_id=f"chainsaw.{partition_name}",
                        engine=self.engine_name,
                        engine_version=version,
                        rule_version=ruleset_version,
                        status="failed",
                        reason="missing_output_file",
                    )
                ],
                version,
            )

        try:
            entries = _parse_chainsaw_output(out_json.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return (
                [],
                [
                    RuleRun(
                        rule_id=f"chainsaw.{partition_name}",
                        engine=self.engine_name,
                        engine_version=version,
                        rule_version=ruleset_version,
                        status="failed",
                        reason=f"invalid_json_output:{exc}",
                    )
                ],
                version,
            )

        hits: list[Hit] = []
        rule_hit_counts: dict[str, int] = defaultdict(int)

        for idx, item in enumerate(entries):
            doc = item.get("document")
            doc_data = doc.get("data") if isinstance(doc, dict) else None
            cand: list[Any] = []
            if isinstance(doc_data, dict) and doc_data.get("event_id") is not None:
                cand.append(doc_data.get("event_id"))
            elif item.get("event_id") is not None:
                cand.append(item.get("event_id"))

            resolved_eids = validate_event_ids(cand, valid_event_ids)
            if not resolved_eids:
                continue

            rule_id = str(
                item.get("id")
                or item.get("rule_id")
                or item.get("name")
                or "chainsaw.unknown"
            )
            level = normalize_level(item.get("level"))
            tactic_ids, technique_ids = normalize_sigma_tags(item.get("tags") or [])
            matched_time = parse_utc_timestamp(item.get("timestamp"))

            matched_fields: dict[str, Any] = {}
            for k in ("name", "group", "kind", "source", "status", "logsource", "authors"):
                if item.get(k) is not None:
                    matched_fields[k] = item.get(k)
            matched_fields["partition"] = partition_name

            hits.append(
                Hit(
                    hit_id=make_hit_id(
                        self.engine_name, rule_id, resolved_eids, f"{partition_name}:{idx}"
                    ),
                    rule_id=rule_id,
                    rule_version=ruleset_version,
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
            for marker in ("skipping", "skipped", "unsupported", "could not parse")
        )

        coverage: list[RuleRun] = []
        if rule_hit_counts:
            for rid, count in sorted(rule_hit_counts.items()):
                coverage.append(
                    RuleRun(
                        rule_id=rid,
                        engine=self.engine_name,
                        engine_version=version,
                        rule_version=ruleset_version,
                        status="ran",
                        reason=None,
                        hit_count=count,
                    )
                )
            if partial_warning:
                coverage.append(
                    RuleRun(
                        rule_id=f"chainsaw.{partition_name}",
                        engine=self.engine_name,
                        engine_version=version,
                        rule_version=ruleset_version,
                        status="partial",
                        reason="partial_rules_skipped",
                        hit_count=len(hits),
                    )
                )
        else:
            coverage.append(
                RuleRun(
                    rule_id=f"chainsaw.{partition_name}",
                    engine=self.engine_name,
                    engine_version=version,
                    rule_version=ruleset_version,
                    status="partial" if partial_warning else "ran",
                    reason="partial_rules_skipped" if partial_warning else None,
                    hit_count=0,
                )
            )

        return hits, coverage, version

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
                        rule_id="chainsaw.batch",
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
                        rule_id="chainsaw.batch",
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
                        rule_id="chainsaw.batch",
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
                        rule_id="chainsaw.batch",
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
                        rule_id="chainsaw.batch",
                        engine=self.engine_name,
                        rule_version=ruleset_version,
                        status="skipped",
                        reason=f"rules_not_found:{engine_cfg.rules_dir}",
                    )
                ],
            )

        win_events: list[Event] = []
        nonwin_events: list[Event] = []
        for ev in events:
            fmt = classify_event_format(ev)
            if fmt == "winxml":
                win_events.append(ev)
            elif fmt in self.supported_formats:
                nonwin_events.append(ev)

        if not win_events and not nonwin_events:
            return AdapterOutput(
                engine=self.engine_name,
                coverage=[
                    RuleRun(
                        rule_id="chainsaw.batch",
                        engine=self.engine_name,
                        rule_version=ruleset_version,
                        status="skipped",
                        reason="no_compatible_events",
                    )
                ],
            )

        all_hits: list[Hit] = []
        all_coverage: list[RuleRun] = []

        with tempfile.TemporaryDirectory(prefix="apt_chainsaw_") as tmp_dir_str:
            work_dir = Path(tmp_dir_str)
            version = probe_engine_version(engine_cfg.bin_path, cwd=work_dir)

            if win_events:
                if engine_cfg.mapping_path is None:
                    all_coverage.append(
                        RuleRun(
                            rule_id="chainsaw.windows",
                            engine=self.engine_name,
                            engine_version=version,
                            rule_version=ruleset_version,
                            status="skipped",
                            reason="mapping_not_configured",
                        )
                    )
                elif not engine_cfg.mapping_path.is_file():
                    all_coverage.append(
                        RuleRun(
                            rule_id="chainsaw.windows",
                            engine=self.engine_name,
                            engine_version=version,
                            rule_version=ruleset_version,
                            status="skipped",
                            reason=f"mapping_not_found:{engine_cfg.mapping_path}",
                        )
                    )
                else:
                    p_hits, p_cov, version = self._run_partition(
                        partition_name="windows",
                        part_events=win_events,
                        map_path=engine_cfg.mapping_path,
                        engine_cfg=engine_cfg,
                        version=version,
                        ruleset_version=ruleset_version,
                        work_dir=work_dir,
                    )
                    all_hits.extend(p_hits)
                    all_coverage.extend(p_cov)

            if nonwin_events:
                custom_map, map_err = resolve_config_path(
                    engine_cfg.config_path,
                    _DEFAULT_CHAINSAW_CUSTOM_MAPPING_REL,
                )
                if custom_map is None:
                    all_coverage.append(
                        RuleRun(
                            rule_id="chainsaw.non_windows",
                            engine=self.engine_name,
                            engine_version=version,
                            rule_version=ruleset_version,
                            status="skipped",
                            reason=map_err or "custom_mapping_not_configured",
                        )
                    )
                else:
                    p_hits, p_cov, version = self._run_partition(
                        partition_name="non_windows",
                        part_events=nonwin_events,
                        map_path=custom_map,
                        engine_cfg=engine_cfg,
                        version=version,
                        ruleset_version=ruleset_version,
                        work_dir=work_dir,
                    )
                    all_hits.extend(p_hits)
                    all_coverage.extend(p_cov)

        return AdapterOutput(
            engine=self.engine_name,
            engine_version=version,
            hits=all_hits,
            coverage=all_coverage,
            leads=[],
        )


__all__ = ["ChainsawAdapter"]
