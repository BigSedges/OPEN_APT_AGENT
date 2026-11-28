"""Hayabusa + Takajo detection engine adapter for Windows Event XML logs."""

from __future__ import annotations

import csv
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
    run_cli_readonly,
    validate_event_ids,
)
from apt_agent.exceptions import EngineError, OperationTimeoutError
from apt_agent.ingestion import format_for_hayabusa
from apt_agent.models import Event, Hit, RuleRun, RunContext

_HAYABUSA_VERSION_RE = re.compile(r"(?:Hayabusa\s+v?|Version:\s*)(\d+\.\d+\.\d+(?:[-.\w]+)?)", re.I)

_TAKAJO_SUBCOMMANDS: tuple[tuple[str, str], ...] = (
    ("timeline-suspicious-processes", "timeline_suspicious_processes.csv"),
    ("stack-processes", "stack_processes.csv"),
    ("stack-cmdlines", "stack_cmdlines.csv"),
    ("ttp-summary", "ttp_summary.csv"),
)


def _resolve_hayabusa_config_args(
    bin_path: Path,
    rules_dir: Path,
    configured_config_path: Path | None,
) -> tuple[list[str], str | None]:
    """Resolve Hayabusa `-c` rules-config directory safely.

    Checks `channel_eid_info.txt` in `configured_config_path`, then falls back to
    `rules_dir / "config"` or `bin_path.parent / "rules" / "config"`.
    If `configured_config_path` is explicitly provided without a fallback and exists
    on disk (e.g., synthetic tests), passes `-c <configured_config_path>`.
    """
    candidates = [
        rules_dir / "config",
        bin_path.parent / "rules" / "config",
    ]
    if configured_config_path is not None:
        if not configured_config_path.exists():
            return [], f"config_not_found:{configured_config_path}"
        if (configured_config_path / "channel_eid_info.txt").is_file():
            return ["-c", str(configured_config_path)], None
        for fallback in candidates:
            if (fallback / "channel_eid_info.txt").is_file():
                return ["-c", str(fallback)], None
        return ["-c", str(configured_config_path)], None

    for fallback in candidates:
        if (fallback / "channel_eid_info.txt").is_file():
            return ["-c", str(fallback)], None
    return [], None


def _build_index_lookup(index_records: Sequence[dict[str, Any]]) -> dict[tuple[str, str, str], str]:
    lookup: dict[tuple[str, str, str], str] = {}
    for rec in index_records:
        eid = rec.get("event_id")
        if not isinstance(eid, str) or not eid:
            continue
        comp = str(rec.get("Computer") or "").strip().lower()
        chan = str(rec.get("Channel") or "").strip().lower()
        rec_id = str(rec.get("RecordID") or "").strip()
        if rec_id:
            lookup[(comp, chan, rec_id)] = eid
            if comp:
                lookup[("", chan, rec_id)] = eid
    return lookup


def _resolve_hayabusa_event_id(
    row: dict[str, Any],
    index_lookup: dict[tuple[str, str, str], str],
    valid_event_ids: set[str],
) -> str | None:
    extra = row.get("ExtraFieldInfo")
    extra_dict = extra if isinstance(extra, dict) else {}
    all_fields = row.get("AllFieldInfo")
    all_dict = all_fields if isinstance(all_fields, dict) else {}

    for cand in (
        row.get("event_id"),
        extra_dict.get("event_id"),
        all_dict.get("event_id"),
    ):
        if isinstance(cand, str) and cand.strip() in valid_event_ids:
            return cand.strip()

    comp = str(
        row.get("Computer")
        or row.get("Hostname")
        or extra_dict.get("Hostname")
        or extra_dict.get("Computer")
        or ""
    ).strip().lower()
    chan = str(extra_dict.get("Channel") or row.get("Channel") or "").strip().lower()
    rec_raw = (
        row.get("RecordID")
        if row.get("RecordID") is not None
        else (
            row.get("RecordNumber")
            if row.get("RecordNumber") is not None
            else (
                row.get("EventRecordID")
                if row.get("EventRecordID") is not None
                else (
                    extra_dict.get("RecordNumber")
                    if extra_dict.get("RecordNumber") is not None
                    else extra_dict.get("EventRecordID")
                )
            )
        )
    )
    if rec_raw is not None:
        rec_str = str(rec_raw).strip()
        for key in ((comp, chan, rec_str), ("", chan, rec_str)):
            eid = index_lookup.get(key)
            if eid and eid in valid_event_ids:
                return eid
    return None


def _run_takajo_enrichment(
    takajo_cfg: EngineConfig,
    hayabusa_jsonl: Path,
    work_dir: Path,
    *,
    ruleset_version: str,
) -> tuple[list[dict[str, Any]], list[RuleRun]]:
    if not takajo_cfg.enabled:
        return [], [
            RuleRun(
                rule_id="takajo.batch",
                engine="takajo",
                rule_version=ruleset_version,
                status="skipped",
                reason="engine_disabled",
            )
        ]
    if takajo_cfg.bin_path is None:
        return [], [
            RuleRun(
                rule_id="takajo.batch",
                engine="takajo",
                rule_version=ruleset_version,
                status="skipped",
                reason="binary_not_configured",
            )
        ]
    if not takajo_cfg.bin_path.is_file():
        return [], [
            RuleRun(
                rule_id="takajo.batch",
                engine="takajo",
                rule_version=ruleset_version,
                status="skipped",
                reason=f"binary_not_found:{takajo_cfg.bin_path}",
            )
        ]
    if not hayabusa_jsonl.is_file() or not hayabusa_jsonl.read_text(encoding="utf-8").strip():
        return [], [
            RuleRun(
                rule_id="takajo.batch",
                engine="takajo",
                rule_version=ruleset_version,
                status="skipped",
                reason="empty_hayabusa_output",
            )
        ]

    takajo_cwd = takajo_cfg.working_dir or takajo_cfg.bin_path.parent
    version = probe_engine_version(takajo_cfg.bin_path, cwd=takajo_cwd)

    leads: list[dict[str, Any]] = []
    coverage: list[RuleRun] = []

    for subcmd, out_name in _TAKAJO_SUBCOMMANDS:
        out_csv = work_dir / out_name
        argv = build_exec_argv(
            takajo_cfg.bin_path,
            [subcmd, "-t", str(hayabusa_jsonl), "-s", "-q", "-o", str(out_csv)],
        )
        try:
            proc = run_cli_readonly(
                argv,
                timeout_s=takajo_cfg.timeout_s,
                cwd=takajo_cwd,
            )
        except (OperationTimeoutError, EngineError) as exc:
            coverage.append(
                RuleRun(
                    rule_id=f"takajo.{subcmd}",
                    engine="takajo",
                    engine_version=version,
                    rule_version=ruleset_version,
                    status="failed",
                    reason=exc.message,
                )
            )
            continue

        if proc.returncode != 0:
            err_detail = (proc.stderr or proc.stdout or "").strip()[:240]
            coverage.append(
                RuleRun(
                    rule_id=f"takajo.{subcmd}",
                    engine="takajo",
                    engine_version=version,
                    rule_version=ruleset_version,
                    status="failed",
                    reason=f"exit_{proc.returncode}:{err_detail}" if err_detail else f"exit_{proc.returncode}",
                )
            )
            continue

        row_count = 0
        if out_csv.is_file():
            try:
                with out_csv.open("r", encoding="utf-8", newline="") as fh:
                    reader = csv.DictReader(fh)
                    for idx, row in enumerate(reader):
                        clean_row = {
                            k: v for k, v in row.items() if k is not None and v is not None
                        }
                        if not clean_row:
                            continue
                        row_count += 1
                        leads.append(
                            {
                                "lead_id": make_lead_id(
                                    "takajo", subcmd, f"{idx}:{json.dumps(clean_row, sort_keys=True)}"
                                ),
                                "engine": "takajo",
                                "engine_version": version,
                                "kind": f"takajo_{subcmd.replace('-', '_')}",
                                "subcommand": subcmd,
                                "data": clean_row,
                            }
                        )
            except (OSError, csv.Error) as exc:
                coverage.append(
                    RuleRun(
                        rule_id=f"takajo.{subcmd}",
                        engine="takajo",
                        engine_version=version,
                        rule_version=ruleset_version,
                        status="failed",
                        reason=f"csv_parse_error:{exc}",
                    )
                )
                continue

        coverage.append(
            RuleRun(
                rule_id=f"takajo.{subcmd}",
                engine="takajo",
                engine_version=version,
                rule_version=ruleset_version,
                status="ran",
                reason=None,
                hit_count=row_count,
            )
        )

    return leads, coverage


class HayabusaAdapter:
    """Adapter invoking Hayabusa (`winxml*` only) and optional Takajo lead enrichment."""

    engine_name: str = "hayabusa"
    supported_formats: frozenset[str] = frozenset({"winxml"})

    def run(
        self,
        ctx: RunContext,
        events: Sequence[Event],
        engine_cfg: EngineConfig,
        *,
        ruleset_version: str,
        takajo_cfg: EngineConfig | None = None,
    ) -> AdapterOutput:
        if not engine_cfg.enabled:
            return AdapterOutput(
                engine=self.engine_name,
                coverage=[
                    RuleRun(
                        rule_id="hayabusa.batch",
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
                        rule_id="hayabusa.batch",
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
                        rule_id="hayabusa.batch",
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
                        rule_id="hayabusa.batch",
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
                        rule_id="hayabusa.batch",
                        engine=self.engine_name,
                        rule_version=ruleset_version,
                        status="skipped",
                        reason=f"rules_not_found:{engine_cfg.rules_dir}",
                    )
                ],
            )

        win_events = [ev for ev in events if classify_event_format(ev) == "winxml"]
        hayabusa_records, index_records = (
            format_for_hayabusa(win_events) if win_events else ([], [])
        )
        if not hayabusa_records:
            cov = [
                RuleRun(
                    rule_id="hayabusa.batch",
                    engine=self.engine_name,
                    rule_version=ruleset_version,
                    status="skipped",
                    reason="no_compatible_events",
                )
            ]
            if takajo_cfg is not None and (not takajo_cfg.enabled or takajo_cfg.bin_path is not None):
                cov.append(
                    RuleRun(
                        rule_id="takajo.batch",
                        engine="takajo",
                        rule_version=ruleset_version,
                        status="skipped",
                        reason="engine_disabled" if not takajo_cfg.enabled else "no_compatible_events",
                    )
                )
            return AdapterOutput(
                engine=self.engine_name,
                coverage=cov,
            )

        c_args, c_err = _resolve_hayabusa_config_args(
            engine_cfg.bin_path,
            engine_cfg.rules_dir,
            engine_cfg.config_path,
        )
        if c_err is not None:
            return AdapterOutput(
                engine=self.engine_name,
                coverage=[
                    RuleRun(
                        rule_id="hayabusa.batch",
                        engine=self.engine_name,
                        rule_version=ruleset_version,
                        status="skipped",
                        reason=c_err,
                    )
                ],
            )

        valid_event_ids = {
            str(r["event_id"]) for r in index_records if isinstance(r.get("event_id"), str)
        }
        index_lookup = _build_index_lookup(index_records)

        with tempfile.TemporaryDirectory(prefix="apt_haya_") as tmp_dir_str:
            work_dir = Path(tmp_dir_str)
            in_jsonl = work_dir / "hayabusa_input.jsonl"
            out_jsonl = work_dir / "hayabusa_timeline.jsonl"

            with in_jsonl.open("wb") as fh:
                for rec in hayabusa_records:
                    fh.write(orjson.dumps(rec))
                    fh.write(b"\n")

            args: list[str] = [
                "dfir-timeline",
                "-J",
                "-f",
                str(in_jsonl),
                "-r",
                str(engine_cfg.rules_dir),
                *c_args,
                "-t",
                "jsonl",
                "-p",
                "super-verbose",
                "-w",
                "-U",
                "-O",
                "-b",
                "-C",
                "-Q",
                "-q",
                "-N",
                "-K",
                "-o",
                str(out_jsonl),
            ]
            argv = build_exec_argv(engine_cfg.bin_path, args)
            run_cwd = engine_cfg.working_dir or work_dir

            try:
                proc = run_cli_readonly(
                    argv,
                    timeout_s=engine_cfg.timeout_s,
                    cwd=run_cwd,
                )
            except (OperationTimeoutError, EngineError) as exc:
                return AdapterOutput(
                    engine=self.engine_name,
                    coverage=[
                        RuleRun(
                            rule_id="hayabusa.batch",
                            engine=self.engine_name,
                            rule_version=ruleset_version,
                            status="failed",
                            reason=exc.message,
                        )
                    ],
                )

            combined_out = "\n".join(p for p in (proc.stdout, proc.stderr) if p)
            ver_match = _HAYABUSA_VERSION_RE.search(combined_out)
            version = (
                ver_match.group(1)
                if ver_match
                else (extract_version_text(proc.stdout) or "unknown")
            )

            if proc.returncode != 0:
                err_detail = (proc.stderr or proc.stdout or "").strip()[:300]
                reason = f"exit_{proc.returncode}:{err_detail}" if err_detail else f"exit_{proc.returncode}"
                return AdapterOutput(
                    engine=self.engine_name,
                    engine_version=version,
                    coverage=[
                        RuleRun(
                            rule_id="hayabusa.batch",
                            engine=self.engine_name,
                            engine_version=version,
                            rule_version=ruleset_version,
                            status="failed",
                            reason=reason,
                        )
                    ],
                )

            if not out_jsonl.is_file():
                return AdapterOutput(
                    engine=self.engine_name,
                    engine_version=version,
                    coverage=[
                        RuleRun(
                            rule_id="hayabusa.batch",
                            engine=self.engine_name,
                            engine_version=version,
                            rule_version=ruleset_version,
                            status="failed",
                            reason="missing_output_file",
                        )
                    ],
                )

            hits: list[Hit] = []
            rule_hit_counts: dict[str, int] = defaultdict(int)
            rule_versions: dict[str, str] = {}

            try:
                raw_lines = out_jsonl.read_text(encoding="utf-8").splitlines()
                for idx, line in enumerate(raw_lines):
                    stripped = line.strip()
                    if not stripped:
                        continue
                    row = json.loads(stripped)
                    if not isinstance(row, dict):
                        raise ValueError("Hayabusa JSONL line is not a JSON object.")

                    resolved_eid = _resolve_hayabusa_event_id(
                        row, index_lookup, valid_event_ids
                    )
                    if resolved_eid is None:
                        continue
                    validated_eids = validate_event_ids([resolved_eid], valid_event_ids)
                    if not validated_eids:
                        continue

                    rule_id = str(
                        row.get("RuleID")
                        or row.get("RuleTitle")
                        or row.get("RuleFile")
                        or "hayabusa.unknown"
                    )
                    rule_version = str(
                        row.get("RuleModifiedDate")
                        or row.get("RuleCreationDate")
                        or ruleset_version
                    )
                    rule_versions[rule_id] = rule_version

                    level = normalize_level(row.get("Level"))
                    tactic_ids, technique_ids = normalize_sigma_tags(
                        row.get("OtherTags") or [],
                        mitre_tactics=row.get("MitreTactics") or [],
                        mitre_tags=row.get("MitreTags") or [],
                    )
                    matched_time = parse_utc_timestamp(row.get("Timestamp"))

                    matched_fields: dict[str, Any] = {}
                    for k in (
                        "RuleTitle",
                        "RuleFile",
                        "Computer",
                        "Channel",
                        "EventID",
                        "RecordID",
                        "Provider",
                        "Status",
                        "Details",
                    ):
                        if row.get(k) is not None:
                            matched_fields[k] = row.get(k)

                    hits.append(
                        Hit(
                            hit_id=make_hit_id(self.engine_name, rule_id, validated_eids, str(idx)),
                            rule_id=rule_id,
                            rule_version=rule_version,
                            engine=self.engine_name,
                            engine_version=version,
                            event_ids=validated_eids,
                            tactic_ids=tactic_ids,
                            technique_ids=technique_ids,
                            matched_time=matched_time,
                            level=level,
                            matched_fields=matched_fields,
                        )
                    )
                    rule_hit_counts[rule_id] += 1
            except (OSError, ValueError) as exc:
                return AdapterOutput(
                    engine=self.engine_name,
                    engine_version=version,
                    coverage=[
                        RuleRun(
                            rule_id="hayabusa.batch",
                            engine=self.engine_name,
                            engine_version=version,
                            rule_version=ruleset_version,
                            status="failed",
                            reason=f"invalid_jsonl_output:{exc}",
                        )
                    ],
                )

            takajo_leads: list[dict[str, Any]] = []
            takajo_coverage: list[RuleRun] = []
            if takajo_cfg is not None:
                takajo_leads, takajo_coverage = _run_takajo_enrichment(
                    takajo_cfg,
                    out_jsonl,
                    work_dir,
                    ruleset_version=ruleset_version,
                )

        partial_warning = "rule parsing errors" in combined_out.lower()
        coverage: list[RuleRun] = []
        if rule_hit_counts:
            for rid, count in sorted(rule_hit_counts.items()):
                coverage.append(
                    RuleRun(
                        rule_id=rid,
                        engine=self.engine_name,
                        engine_version=version,
                        rule_version=rule_versions.get(rid, ruleset_version),
                        status="ran",
                        reason=None,
                        hit_count=count,
                    )
                )
            if partial_warning:
                coverage.append(
                    RuleRun(
                        rule_id="hayabusa.batch",
                        engine=self.engine_name,
                        engine_version=version,
                        rule_version=ruleset_version,
                        status="partial",
                        reason="rule_parsing_errors",
                        hit_count=len(hits),
                    )
                )
        else:
            coverage.append(
                RuleRun(
                    rule_id="hayabusa.batch",
                    engine=self.engine_name,
                    engine_version=version,
                    rule_version=ruleset_version,
                    status="partial" if partial_warning else "ran",
                    reason="rule_parsing_errors" if partial_warning else None,
                    hit_count=0,
                )
            )

        coverage.extend(takajo_coverage)

        return AdapterOutput(
            engine=self.engine_name,
            engine_version=version,
            hits=hits,
            coverage=coverage,
            leads=takajo_leads,
        )


__all__ = ["HayabusaAdapter"]
