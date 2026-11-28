"""Per-run evidence provenance, deterministic merging, and chain ranking."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable, Sequence, Set
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
import json
from threading import Lock
from typing import Any

from apt_agent.exceptions import ConflictError, OutOfScopeError
from apt_agent.detection.base import severity_rank
from apt_agent.ingestion import Normalizer, RawEvidenceStore
from apt_agent.models import (
    TACTIC_ID_PATTERN,
    AttackChain,
    CaseResult,
    Edge,
    Event,
    Finding,
    GraphState,
    Hit,
    MergeReceipt,
    RejectedRef,
    RuleRun,
    RunContext,
    Submission,
)
from apt_agent.tools.investigation import (
    _event_sort_key,
    _extract_dst_ips,
    _extract_dst_ports,
    _extract_host,
    _extract_parent_process_guids,
    _extract_process_guids,
    _extract_protocols,
    _extract_src_ips,
    _extract_src_ports,
)

_PROCESS_RELATIONS = {"same_process_guid", "process_net_pivot", "initiated_flow", "spawned"}
_FLOW_RELATIONS = {"network_5tuple_flow", "flow_corroboration", "corroborates_flow"}
_FLOW_EXTRACTORS = {
    "src_ip": _extract_src_ips,
    "src_port": _extract_src_ports,
    "dst_ip": _extract_dst_ips,
    "dst_port": _extract_dst_ports,
    "protocol": _extract_protocols,
}


def _assert_scope(ctx: RunContext, case_id: str, run_id: str) -> None:
    if (ctx.case_id, ctx.run_id) != (case_id, run_id):
        raise OutOfScopeError("Evidence belongs to another case or run.")


@dataclass(frozen=True)
class VerificationResult:
    verified_state: GraphState
    errors: list[dict[str, Any]]
    unresolved: list[dict[str, Any]]


class Blackboard:
    """Accept submissions whose event references were returned by their own queries."""

    def __init__(
        self,
        ctx: RunContext,
        valid_event_ids: Set[str],
        valid_physical_ids: Set[str] | None = None,
        *,
        events: Sequence[Event] = (),
    ) -> None:
        self.ctx = ctx
        self.events = {event.event_id: event for event in events}
        scope = ctx.valid_physical_ids
        if valid_physical_ids is not None:
            scope = frozenset(valid_physical_ids) if scope is None else scope & valid_physical_ids
        self._valid_events = frozenset(
            event_id for event_id in valid_event_ids
            if scope is None or event_id not in self.events
            or self.events[event_id].physical_record_id in scope
        )
        self._queries: dict[str, dict[str, frozenset[str]]] = defaultdict(dict)
        self._submissions: dict[str, tuple[str, MergeReceipt, list[Finding], list[Edge]]] = {}
        self._lock = Lock()

    def record_task_query(self, task_id: str, query_id: str, event_ids: Iterable[str]) -> None:
        """Record event IDs from a successful, case-scoped forensic tool result."""
        ids = frozenset(event_ids) & self._valid_events
        with self._lock:
            queries = self._queries[task_id]
            if query_id in queries and queries[query_id] != ids:
                raise ConflictError(f"Query {query_id!r} already has a different result.")
            queries[query_id] = ids

    def submit_findings(self, ctx: RunContext, submission: Submission) -> MergeReceipt:
        _assert_scope(ctx, self.ctx.case_id, self.ctx.run_id)
        _assert_scope(ctx, submission.case_id, submission.run_id)
        submission = submission.model_copy(deep=True)
        digest = submission.content_digest()
        with self._lock:
            previous = self._submissions.get(submission.submission_id)
            if previous is not None:
                previous_digest, receipt, _, _ = previous
                if previous_digest != digest:
                    raise ConflictError(f"Submission {submission.submission_id!r} changed on retry.")
                return receipt.model_copy(deep=True, update={"replayed": True})

            queries = self._queries.get(submission.task_id, {})
            authorized = set().union(*(queries.get(qid, ()) for qid in submission.query_ids))
            rejected: dict[str, RejectedRef] = {}
            accepted: set[str] = set()

            def select(refs: Iterable[str], *, endpoints: Set[str] = frozenset()) -> list[str]:
                allowed = []
                for ref in sorted(set(refs)):
                    if ref in authorized:
                        allowed.append(ref)
                        accepted.add(ref)
                    elif ref not in endpoints or ref not in self._valid_events:
                        reason = (
                            "Event was outside the current case."
                            if ref not in self._valid_events
                            else "Event was absent from the submitted task queries."
                        )
                        rejected[ref] = RejectedRef(ref=ref, reason=reason)
                return allowed

            findings = []
            for finding in submission.findings:
                evidence = select(finding.evidence_event_ids)
                opposition = select(finding.opposing_event_ids)
                if finding.status == "observed" and not evidence:
                    continue
                findings.append(finding.model_copy(update={
                    "evidence_event_ids": evidence,
                    "opposing_event_ids": opposition,
                    "task_id": submission.task_id,
                    "query_ids": sorted(set(submission.query_ids)),
                    "submitted_by": submission.submitted_by,
                    "sources": sorted({submission.submitted_by, *finding.sources}),
                }))

            edges = []
            for edge in submission.edges:
                endpoints = {edge.from_event_id, edge.to_event_id}
                evidence = select(edge.evidence_event_ids, endpoints=endpoints)
                opposition = select(edge.opposing_evidence_ids)
                missing = endpoints - self._valid_events
                for ref in sorted(missing):
                    rejected[ref] = RejectedRef(ref=ref, reason="Edge endpoint was outside the case.")
                if not missing and (evidence or opposition):
                    edges.append(edge.model_copy(update={
                        "evidence_event_ids": evidence,
                        "opposing_evidence_ids": opposition,
                        "sources": sorted({submission.submitted_by, *edge.sources}),
                    }))

            receipt = MergeReceipt(
                submission_id=submission.submission_id,
                accepted_event_ids=sorted(accepted),
                rejected_refs=sorted(rejected.values(), key=lambda ref: ref.ref),
                state_version=len(self._submissions) + 1,
            )
            self._submissions[submission.submission_id] = (digest, receipt, findings, edges)
            return receipt.model_copy(deep=True)

    def snapshot(self) -> GraphState:
        with self._lock:
            entries = sorted(self._submissions.items())
            edges_by_key: dict[tuple[str, str, str], list[Edge]] = defaultdict(list)
            state = GraphState(
                case_id=self.ctx.case_id,
                run_id=self.ctx.run_id,
                state_version=len(entries),
                stop_reason=self.ctx.stop_reason,
            )
            for submission_id, (_, receipt, findings, edges) in entries:
                state.findings.extend(finding.model_copy(deep=True) for finding in findings)
                for edge in edges:
                    edges_by_key[edge.dedup_key].append(edge)
                for event_id in receipt.accepted_event_ids:
                    event = self.events.get(event_id)
                    state.verified_event_refs[event_id] = (
                        event.model_dump(mode="json") if event else {"event_id": event_id}
                    )
                for ref in receipt.rejected_refs:
                    state.validation_errors.append({
                        **ref.model_dump(),
                        "submission_id": submission_id,
                    })
                state.investigation_ledger.append(receipt.model_dump(mode="json"))

            state.candidate_edges = [
                _merge_edges(edges) for _, edges in sorted(edges_by_key.items())
            ]
            return state


def _merge_edges(edges: Sequence[Edge]) -> Edge:
    keys: dict[str, Any] = {}
    reasons = set()
    for edge in edges:
        for key, value in edge.join_keys.items():
            if key in keys and keys[key] != value:
                reasons.add("conflicting_join_keys")
            keys.setdefault(key, value)
        if edge.ambiguity_reason:
            reasons.add(edge.ambiguity_reason)
    opposed = {eid for edge in edges for eid in edge.opposing_evidence_ids}
    disputed = bool(reasons or opposed or any(edge.status == "disputed" for edge in edges))
    return edges[0].model_copy(deep=True, update={
        "join_keys": keys,
        "evidence_event_ids": sorted({eid for edge in edges for eid in edge.evidence_event_ids}),
        "opposing_evidence_ids": sorted(opposed),
        "sources": sorted({source for edge in edges for source in edge.sources}),
        "status": "disputed" if disputed else (
            "verified" if any(edge.status == "verified" for edge in edges) else "proposed"
        ),
        "ambiguity_reason": "; ".join(sorted(reasons)) or None,
    })


def _flow_keys(event: Event) -> dict[str, str | int]:
    return {
        key: values[0] for key, extractor in _FLOW_EXTRACTORS.items()
        if (values := extractor(event))
    }


def _edge_issue(
    edge: Edge, known: Set[str], events: dict[str, Event]
) -> str | None:
    if edge.ambiguity_reason or edge.status == "disputed" or edge.opposing_evidence_ids:
        return edge.ambiguity_reason or "disputed_relation"
    if not {edge.from_event_id, edge.to_event_id} <= known:
        return "unverified_endpoint"
    if not set(edge.evidence_event_ids) <= known or not edge.evidence_event_ids:
        return "missing_edge_evidence"

    if edge.time_window is not None:
        try:
            start, end = (datetime.fromisoformat(value) for value in edge.time_window)
            if start.tzinfo is None or end.tzinfo is None or start >= end:
                return "invalid_relation_time_window"
        except ValueError:
            return "invalid_relation_time_window"

    left, right = events.get(edge.from_event_id), events.get(edge.to_event_id)
    keys = {key.lower().replace("_", ""): value for key, value in edge.join_keys.items()}
    if edge.relation == "self_anchor" and edge.from_event_id == edge.to_event_id:
        return None

    if edge.relation in _PROCESS_RELATIONS:
        guid = str(keys.get("processguid") or "").casefold()
        if not guid:
            return "missing_process_guid"
        if left is not None and right is not None:
            target_guids = (
                _extract_parent_process_guids(right) if edge.relation == "spawned"
                else _extract_process_guids(right)
            )
            left_host, right_host = _extract_host(left), _extract_host(right)
            if (
                not left_host or not right_host or left_host.casefold() != right_host.casefold()
                or guid not in {value.casefold() for value in _extract_process_guids(left)}
                or guid not in {value.casefold() for value in target_guids}
            ):
                return "process_guid_or_host_mismatch"
    elif edge.relation in _FLOW_RELATIONS:
        if left is not None and right is not None:
            left_flow, right_flow = _flow_keys(left), _flow_keys(right)
            if (
                len(left_flow) != 5 or left_flow != right_flow
                or left.source_type == right.source_type
                or not left.event_time or not right.event_time
            ):
                return "incomplete_or_mismatched_flow"
            elapsed = abs((
                datetime.fromisoformat(right.event_time) - datetime.fromisoformat(left.event_time)
            ).total_seconds())
            if elapsed > 5:
                return "flow_outside_time_window"
        elif not {"srcip", "srcport", "dstip", "dstport"} <= keys.keys():
            return "incomplete_flow_keys"
    else:
        return "unsupported_relation"

    if left is not None and right is not None and left.event_time and right.event_time:
        if datetime.fromisoformat(left.event_time) > datetime.fromisoformat(right.event_time):
            return "time_reversed_relation"
    return None


def _verify_edges(
    state: GraphState, events: dict[str, Event]
) -> tuple[list[Edge], list[dict[str, Any]]]:
    verified, unresolved = [], []
    known = state.verified_event_refs.keys()
    for edge in state.candidate_edges:
        issue = _edge_issue(edge, known, events)
        if issue:
            unresolved.append({"edge": list(edge.dedup_key), "reason": issue})
            status = "disputed" if edge.status == "disputed" else "proposed"
        else:
            status = "verified" if edge.from_event_id in events and edge.to_event_id in events else edge.status
        verified.append(edge.model_copy(update={"status": status}))
    return verified, unresolved


def verify(ctx: RunContext, blackboard: Blackboard | GraphState) -> VerificationResult:
    """Check evidence references and relationships in an isolated state snapshot."""
    if isinstance(blackboard, Blackboard):
        state = blackboard.snapshot()
        events = blackboard.events
    else:
        state = blackboard.model_copy(deep=True)
        events = {
            eid: Event.model_validate(data)
            for eid, data in state.verified_event_refs.items()
            if "physical_record_id" in data
        }
    _assert_scope(ctx, state.case_id, state.run_id)
    state.candidate_edges, unresolved = _verify_edges(state, events)
    opposing = defaultdict(set)
    for finding in state.findings:
        if finding.verdict_malicious is not None and finding.status == "observed":
            for event_id in set(finding.evidence_event_ids) & state.verified_event_refs.keys():
                opposing[event_id].add(finding.verdict_malicious)
    for event_id, verdicts in sorted(opposing.items()):
        if len(verdicts) > 1:
            conflict = {"event_id": event_id, "reason": "conflicting_findings"}
            if conflict not in state.disputed_items:
                state.disputed_items.append(conflict)
    unresolved.extend(state.disputed_items)
    return VerificationResult(state, state.validation_errors, unresolved)


def rank(
    ctx: RunContext,
    verified_state: GraphState,
    store: RawEvidenceStore,
    hits: Sequence[Hit],
    coverage: Sequence[RuleRun],
    *,
    events: Sequence[Event] | None = None,
) -> CaseResult:
    """Replay relationships against normalized evidence and rank event chains."""
    _assert_scope(ctx, verified_state.case_id, verified_state.run_id)
    _assert_scope(ctx, store.case_id, store.run_id)
    if events is None:
        events = Normalizer.normalize_batch(ctx, store).events
    by_id = {
        event.event_id: event for event in events
        if event.physical_record_id in store
        and (ctx.valid_physical_ids is None or event.physical_record_id in ctx.valid_physical_ids)
    }
    state = verified_state.model_copy(deep=True)
    state.verified_event_refs = {
        eid: data for eid, data in state.verified_event_refs.items() if eid in by_id
    }
    state.candidate_edges, unresolved = _verify_edges(state, by_id)
    unresolved.extend(state.disputed_items)

    direct: dict[str, set[str]] = defaultdict(set)
    rule_sources: dict[str, set[str]] = defaultdict(set)
    tactics: dict[str, set[str]] = defaultdict(set)
    finding_sources: dict[str, set[str]] = defaultdict(set)
    expansion_level = ctx.config.minimum_expansion_level if ctx.config is not None else None
    expansion_seeds: set[str] = set()
    explicit_malicious: set[str] = set()
    benign_ids: set[str] = set()
    decisions: dict[str, dict[str, Any]] = {}
    context_rules = ctx.config.context_only_rules if ctx.config is not None else {}
    minimum = severity_rank(ctx.config.minimum_seed_level) if ctx.config is not None else 0
    for hit in hits:
        contributors = hit.matched_fields.get("contributing_sources")
        sources = contributors or [{"rule_id": hit.rule_id, "level": hit.level,
                                     "tactic_ids": hit.tactic_ids}]
        eligible = [source for source in sources
                    if source.get("rule_id") not in context_rules
                    and (not contributors or severity_rank(source.get("level")) >= minimum)]
        context_ids = sorted({source["rule_id"] for source in sources
                              if source.get("rule_id") in context_rules})
        for event_id in set(hit.event_ids) & by_id.keys():
            if not eligible:
                decisions.setdefault(event_id, {"classification": "context", "reason": ("context_only_rule" if context_ids else "no_eligible_rule_source"),
                    "policy_reasons": {rule: context_rules[rule] for rule in context_ids}, "can_expand": False})
                continue
            direct[event_id].update(str(source.get("rule_id") or hit.rule_id) for source in eligible)
            rule_sources[event_id].update(hit.matched_fields.get("rule_ids", ()))
            tactics[event_id].update(tactic for source in eligible for tactic in source.get("tactic_ids", ()))
            if expansion_level is None or any(
                severity_rank(source.get("level")) >= severity_rank(expansion_level) for source in eligible
            ):
                expansion_seeds.add(event_id)

    attack_ids = set(direct)
    observed_ids: set[str] = set()
    disputed_ids = {item.get("event_id") for item in state.disputed_items}
    for finding in state.findings:
        if finding.status != "observed":
            continue
        for event_id in set(finding.evidence_event_ids) & state.verified_event_refs.keys():
            if event_id not in by_id:
                continue
            observed_ids.add(event_id)
            if finding.verdict_malicious is False:
                benign_ids.add(event_id)
                continue
            if event_id in disputed_ids:
                continue
            if finding.verdict_malicious is True:
                attack_ids.add(event_id)
                explicit_malicious.add(event_id)
            tactics[event_id].update(finding.tactic_ids)
            finding_sources[event_id].update(finding.sources)

    blocked_ids = benign_ids | disputed_ids
    attack_ids.difference_update(blocked_ids)
    expansion_seeds = (expansion_seeds | explicit_malicious) - blocked_ids
    for event_id in direct:
        decisions[event_id] = {"classification": "attack", "reason": "direct_detection_seed",
                               "can_expand": event_id in expansion_seeds}
    for event_id in explicit_malicious:
        decisions[event_id] = {"classification": "attack", "reason": "explicit_malicious_finding",
                               "can_expand": event_id in expansion_seeds}
    for event_id in sorted(blocked_ids & by_id.keys()):
        decisions[event_id] = {"classification": "context", "reason": (
            "conflicting_findings" if event_id in disputed_ids else "explicit_benign_finding"
        ), "can_expand": False}

    adjacency: dict[str, list[Edge]] = defaultdict(list)
    unresolved_by_id: dict[str, set[str]] = defaultdict(set)
    for edge in state.candidate_edges:
        if edge.status == "verified":
            adjacency[edge.from_event_id].append(edge)
            adjacency[edge.to_event_id].append(edge)
        else:
            for eid in (edge.from_event_id, edge.to_event_id):
                unresolved_by_id[eid].add(edge.relation)

    reached = set(expansion_seeds)
    pending_attack = deque(sorted(expansion_seeds))
    while pending_attack:
        event_id = pending_attack.popleft()
        for edge in adjacency[event_id]:
            if edge.from_event_id == event_id and (
                edge.relation in _FLOW_RELATIONS or edge.relation in _PROCESS_RELATIONS - {"spawned"}
            ):
                next_id = edge.to_event_id
            elif edge.relation in _FLOW_RELATIONS or edge.relation == "same_process_guid":
                next_id = edge.from_event_id
            else:
                continue
            if next_id not in blocked_ids and next_id not in reached:
                reached.add(next_id)
                attack_ids.add(next_id)
                if decisions.get(next_id, {}).get("classification") != "attack":
                    decisions[next_id] = {"classification": "attack", "reason": "verified_expansion",
                                          "from_event_id": event_id, "can_expand": True}
                else:
                    decisions[next_id]["can_expand"] = True
                    decisions[next_id]["expansion_from_event_id"] = event_id
                pending_attack.append(next_id)

    for event_id in observed_ids - attack_ids - blocked_ids:
        decisions.setdefault(event_id, {"classification": "context", "reason": "no_qualifying_expansion_seed",
                                        "can_expand": False})

    chains = []
    seen: set[str] = set()
    for seed in sorted(attack_ids | observed_ids):
        if seed in seen:
            continue
        pending = deque([seed])
        seen.add(seed)
        members: set[str] = set()
        relations: dict[tuple[str, str, str], Edge] = {}
        while pending:
            event_id = pending.popleft()
            members.add(event_id)
            for edge in adjacency[event_id]:
                other = (
                    edge.to_event_id if edge.from_event_id == event_id else edge.from_event_id
                )
                relations[edge.dedup_key] = edge
                if other not in seen:
                    seen.add(other)
                    pending.append(other)
        event_ids = sorted(members, key=lambda eid: _event_sort_key(by_id[eid]))
        rule_ids = {rule_id for eid in members for rule_id in direct[eid] | rule_sources[eid]}
        stages = set()
        for eid in members:
            if not direct[eid]:
                continue
            flow = _flow_keys(by_id[eid])
            identity = tuple(flow.items()) if len(flow) == 5 else eid
            stages.update((rule_id, identity) for rule_id in direct[eid])
        unresolved_rels = {relation for eid in members for relation in unresolved_by_id[eid]}
        chain_id = sha256(json.dumps([sorted(members), sorted(relations)]).encode()).hexdigest()[:20]
        independent = {
            (edge.relation, json.dumps(edge.join_keys, sort_keys=True))
            if edge.relation in _FLOW_RELATIONS else edge.dedup_key
            for edge in relations.values()
            if len(edge.sources) > 1
            or by_id[edge.from_event_id].source_type != by_id[edge.to_event_id].source_type
        }
        chains.append(AttackChain(
            chain_id=f"chain-{chain_id}",
            event_ids=event_ids,
            edge_keys=sorted(relations),
            critical_relations_clean=not unresolved_rels and not members & disputed_ids,
            corroborated_critical_count=len(independent),
            direct_evidence_stages=len(stages),
            tactic_ids=sorted({tag for eid in members for tag in tactics[eid]}),
            rule_ids=sorted(rule_ids),
            locators=[store.get_locator(by_id[eid].physical_record_id) for eid in event_ids],
            unresolved_items=sorted(unresolved_rels),
        ))

    tactic_candidates: dict[str, list[str]] = defaultdict(list)
    for event_id in attack_ids:
        for tactic_id in tactics[event_id]:
            if TACTIC_ID_PATTERN.fullmatch(tactic_id):
                tactic_candidates[tactic_id].append(event_id)
    for event_ids in tactic_candidates.values():
        event_ids.sort(key=lambda eid: (
            not direct[eid], -len(finding_sources[eid]), eid
        ))
    tactic_top_k = {
        tactic: list(dict.fromkeys(by_id[eid].physical_record_id for eid in event_ids))[:3]
        for tactic, event_ids in sorted(tactic_candidates.items())
    }
    return CaseResult(
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        chains=sorted(chains, key=AttackChain.sort_key),
        attack_event_ids=sorted(attack_ids),
        attack_decisions=decisions,
        tactic_ranked_event_ids=dict(sorted(tactic_candidates.items())),
        tactic_top_k=tactic_top_k,
        unresolved=unresolved,
        findings=state.findings,
        edges=state.candidate_edges,
        coverage=list(coverage),
        stop_reason=state.stop_reason or ctx.stop_reason,
        snapshot_refs={
            "data_snapshot_id": ctx.data_snapshot_id,
            "mapping_version": ctx.mapping_version,
            "ruleset_version": ctx.ruleset_version,
            "knowledge_snapshot_id": ctx.knowledge_snapshot_id,
        },
        event_to_physical={eid: event.physical_record_id for eid, event in by_id.items()},
    )
