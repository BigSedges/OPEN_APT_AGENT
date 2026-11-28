"""Read-only RAG service with knowledge isolation, metadata filtering, cache, and degradation (F06)."""

from __future__ import annotations

import copy
import gzip
import hashlib
import importlib
import inspect
import json
import math
import re
import subprocess
import sys
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from uuid import uuid4

from jsonschema import Draft202012Validator

from apt_agent.config import AppConfig, RagConfig
from apt_agent.models import KnowledgeRef, RunContext

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_PUBLIC_KB_PATH = REPO_ROOT / "packages" / "apt-rag" / "public_kb" / "chunks.jsonl.gz"
DEFAULT_MANIFEST_PATH = (
    REPO_ROOT / "packages" / "apt-rag" / "tools" / "langgraph_rag" / "tool.json"
)
APT_RAG_ROOT = REPO_ROOT / "packages" / "apt-rag"

TOKEN_RE = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*")
_EVAL_WRITEUP_PATTERN = re.compile(
    r"(?:^|[/_\-.\s])(eval[-_ ]?scenes?|write[-_ ]?ups?|answer[-_ ]?keys?|label[-_ ]?index|ground[-_ ]?truth)(?:$|[/_\-.\s])",
    re.IGNORECASE,
)

_EVAL_SOURCE_FAMILIES = frozenset(
    {
        "eval",
        "eval_scene",
        "eval_scenes",
        "writeup",
        "writeups",
        "write-up",
        "write_up",
        "answer_key",
        "label",
        "label_index",
        "ground_truth",
    }
)
_EVAL_KNOWLEDGE_TYPES = frozenset(
    {
        "eval_scene",
        "eval_scenes",
        "writeup",
        "writeups",
        "write-up",
        "write_up",
        "answer_key",
        "answer_keys",
        "label_index",
        "ground_truth",
    }
)

_VALID_MODES = frozenset({"bm25", "dense", "hybrid"})

_SOURCE_FAMILY_TO_KNOWLEDGE_TYPE: dict[str, str] = {
    "attack": "attack_technique",
    "sigma": "detection_rule",
    "car": "behavior_analytic",
    "ecar": "behavior_analytic",
    "sysmon": "log_documentation",
    "windows": "log_documentation",
    "zeek": "log_documentation",
    "otrf": "threat_intelligence",
    "documents": "reference",
}

_KNOWLEDGE_TYPE_ALIASES = {"field_dict": "field_dictionary", "fp_reference": "false_positive"}

_MATCH_REASONS: dict[str, str] = {
    "bm25": "BM25 term match",
    "dense": "Dense vector similarity",
    "hybrid": "Dense and BM25 rank fusion",
    "dense_fallback": "Dense vector fallback",
}

_ROLE_ALIASES: dict[str, str] = {
    "lead": "lead",
    "lead_agent": "lead",
    "leadagent": "lead",
    "host": "host",
    "host_agent": "host",
    "hostagent": "host",
    "network": "network",
    "network_agent": "network",
    "networkagent": "network",
    "challenger": "challenger",
    "challenger_agent": "challenger",
    "challengeragent": "challenger",
    "verifier": "verifier",
    "verifier_agent": "verifier",
    "verifieragent": "verifier",
    "repair": "repair",
    "repair_agent": "repair",
    "repairagent": "repair",
    "ranker": "ranker",
    "ranker_agent": "ranker",
    "rankeragent": "ranker",
    "converter": "converter_agent",
    "converter_agent": "converter_agent",
    "converteragent": "converter_agent",
    "rule": "rule_agent",
    "rule_agent": "rule_agent",
    "ruleagent": "rule_agent",
}

ROLE_KB_POLICY: dict[str, frozenset[str]] = {
    "converter_agent": frozenset(
        {"log_documentation", "reference", "field_dictionary", "mapping", "unknown"}
    ),
    "rule_agent": frozenset(
        {"detection_rule", "log_documentation", "behavior_analytic", "attack_technique", "reference", "field_dictionary", "unknown"}
    ),
    "lead": frozenset(
        {
            "attack_technique",
            "behavior_analytic",
            "detection_rule",
            "log_documentation",
            "threat_intelligence",
            "reference",
            "playbook",
            "historical_case",
            "unknown",
        }
    ),
    "host": frozenset(
        {
            "attack_technique",
            "behavior_analytic",
            "detection_rule",
            "log_documentation",
            "reference",
            "playbook",
            "unknown",
        }
    ),
    "network": frozenset(
        {
            "attack_technique",
            "behavior_analytic",
            "detection_rule",
            "log_documentation",
            "reference",
            "playbook",
            "unknown",
        }
    ),
    "challenger": frozenset(
        {
            "behavior_analytic",
            "threat_intelligence",
            "log_documentation",
            "detection_rule",
            "reference",
            "playbook",
            "historical_case",
            "false_positive",
            "unknown",
        }
    ),
    "verifier": frozenset(
        {"attack_technique", "behavior_analytic", "detection_rule", "log_documentation", "reference", "unknown"}
    ),
    "repair": frozenset(
        {"attack_technique", "behavior_analytic", "detection_rule", "log_documentation", "reference", "unknown"}
    ),
    "ranker": frozenset(
        {"attack_technique", "behavior_analytic", "detection_rule", "log_documentation", "reference", "unknown"}
    ),
}

_ALLOWED_RAG_FILTER_KEYS: frozenset[str] = frozenset(
    {
        "knowledge_type",
        "knowledge_types",
        "doc_type",
        "source_family",
        "source_families",
        "product",
        "products",
        "version",
        "versions",
        "source_version",
        "product_version",
        "logsource",
        "log_source",
        "log_sources",
        "rule_id",
        "doc_id",
        "document_id",
        "field",
        "field_name",
        "fields",
        "platform",
        "platforms",
        "technique_id",
        "technique_ids",
        "attack_technique_id",
        "attack_technique_ids",
        "event_id",
        "event_ids",
    }
)


def normalize_rag_role(role: str) -> str:
    """Normalize role string (including aliases like `HostAgent` -> `host`)."""
    if not isinstance(role, str) or not role.strip():
        raise ValueError("role must be a non-blank string.")
    key = role.strip().lower().replace("-", "_").replace(" ", "_")
    if key in _ROLE_ALIASES:
        return _ROLE_ALIASES[key]
    raise PermissionError(f"Unrecognized caller role for RAG access: {role!r}")


def _freeze_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return tuple(
            (str(k).strip().lower(), _freeze_value(v))
            for k, v in sorted(value.items(), key=lambda item: str(item[0]).lower())
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_value(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return tuple(sorted(_freeze_value(item) for item in value))
    if isinstance(value, str):
        return value.strip()
    return value


def _str_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        stripped = value.strip()
        return [stripped] if stripped else []
    if isinstance(value, Mapping):
        out: list[str] = []
        for v in value.values():
            out.extend(_str_values(v))
        return out
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray)):
        out = []
        for item in value:
            out.extend(_str_values(item))
        return out
    text = str(value).strip()
    return [text] if text else []


def _lower_values(value: Any) -> set[str]:
    return {item.lower() for item in _str_values(value)}


def _normalize_rag_filters(filters: Mapping[str, Any] | None) -> dict[str, Any]:
    if filters is None:
        return {}
    if not isinstance(filters, Mapping):
        raise ValueError("filters must be a mapping.")
    unknown = sorted(str(k) for k in filters.keys() if k not in _ALLOWED_RAG_FILTER_KEYS)
    if unknown:
        raise ValueError(f"Unsupported RAG filter key(s): {unknown}")

    norm: dict[str, Any] = {}

    def _merge(target_key: str, *source_keys: str) -> None:
        vals: set[str] = set()
        for sk in source_keys:
            if sk in filters and filters[sk] is not None:
                vals.update(_lower_values(filters[sk]))
        if vals:
            norm[target_key] = sorted(vals)

    _merge("knowledge_types", "knowledge_type", "knowledge_types", "doc_type")
    if "knowledge_types" in norm:
        norm["knowledge_types"] = sorted({
            _KNOWLEDGE_TYPE_ALIASES.get(value, value) for value in norm["knowledge_types"]
        })
    _merge("source_families", "source_family", "source_families")
    _merge("products", "product", "products")
    _merge("versions", "version", "versions", "source_version", "product_version")
    _merge("rule_ids", "rule_id", "doc_id", "document_id")
    _merge("fields", "field", "field_name", "fields")
    _merge("platforms", "platform", "platforms")
    _merge(
        "technique_ids",
        "technique_id",
        "technique_ids",
        "attack_technique_id",
        "attack_technique_ids",
    )
    _merge("event_ids", "event_id", "event_ids")

    log_vals: set[str] = set()
    for sk in ("logsource", "log_source", "log_sources"):
        raw = filters.get(sk)
        if raw is not None:
            if isinstance(raw, Mapping):
                for v in raw.values():
                    log_vals.update(_lower_values(v))
            else:
                log_vals.update(_lower_values(raw))
    if log_vals:
        norm["log_sources"] = sorted(log_vals)

    return norm


def _is_eval_or_writeup(
    chunk: Mapping[str, Any],
    *,
    exclude_scene_ids: frozenset[str],
) -> bool:
    meta = chunk.get("metadata")
    sources: tuple[Mapping[str, Any], ...] = (
        (chunk, meta) if isinstance(meta, Mapping) else (chunk,)
    )

    for src in sources:
        if (
            src.get("is_eval_scene") is True
            or src.get("is_writeup") is True
            or src.get("eval_only") is True
        ):
            return True

        source_family = str(src.get("source_family") or "").strip().lower()
        if source_family in _EVAL_SOURCE_FAMILIES or (
            source_family and _EVAL_WRITEUP_PATTERN.search(source_family)
        ):
            return True

        knowledge_type = str(
            src.get("knowledge_type") or src.get("doc_type") or ""
        ).strip().lower()
        if knowledge_type in _EVAL_KNOWLEDGE_TYPES or (
            knowledge_type and _EVAL_WRITEUP_PATTERN.search(knowledge_type)
        ):
            return True

        for scene_key in ("eval_scene_id", "scene_id"):
            scene_val = src.get(scene_key)
            if scene_val is not None and str(scene_val).strip():
                return True

        if exclude_scene_ids:
            for key in ("case_id", "scene_id", "eval_scene_id", "doc_id", "document_id", "chunk_id"):
                val = src.get(key)
                if isinstance(val, str) and val.strip() in exclude_scene_ids:
                    return True

        for key in ("chunk_id", "document_id", "doc_id", "source_url", "title", "locator"):
            val = src.get(key)
            if isinstance(val, str) and _EVAL_WRITEUP_PATTERN.search(val):
                return True

        tags = src.get("tags")
        for tag in _str_values(tags):
            if _EVAL_WRITEUP_PATTERN.search(tag):
                return True

    return False


def _chunk_matches_policy(
    chunk: Mapping[str, Any],
    *,
    role_key: str,
    norm_filters: Mapping[str, Any],
    exclude_scene_ids: frozenset[str],
) -> bool:
    if _is_eval_or_writeup(chunk, exclude_scene_ids=exclude_scene_ids):
        return False

    explicit_roles = _lower_values(chunk.get("allowed_roles") or chunk.get("visible_roles"))
    if explicit_roles:
        canonical_allowed = set()
        for r in explicit_roles:
            canonical_allowed.add(_ROLE_ALIASES.get(r, r))
        if role_key not in canonical_allowed:
            return False

    meta = chunk.get("metadata") if isinstance(chunk.get("metadata"), Mapping) else {}
    source_family = str(
        chunk.get("source_family") or meta.get("source_family") or ""
    ).strip().lower()
    derived_kt = _SOURCE_FAMILY_TO_KNOWLEDGE_TYPE.get(source_family, "unknown")
    knowledge_type = str(
        chunk.get("knowledge_type")
        or chunk.get("doc_type")
        or meta.get("knowledge_type")
        or derived_kt
    ).strip().lower()

    knowledge_type = _KNOWLEDGE_TYPE_ALIASES.get(knowledge_type, knowledge_type)
    allowed_kts = ROLE_KB_POLICY.get(role_key)
    if allowed_kts is not None and knowledge_type not in allowed_kts:
        return False

    if "knowledge_types" in norm_filters:
        if knowledge_type not in norm_filters["knowledge_types"]:
            return False

    if "source_families" in norm_filters:
        if not source_family or source_family not in norm_filters["source_families"]:
            return False

    if "products" in norm_filters:
        log_src = chunk.get("log_source") or chunk.get("logsource") or meta.get("log_source")
        prod_candidates: set[str] = set()
        prod_candidates.update(_lower_values(chunk.get("product")))
        prod_candidates.update(_lower_values(chunk.get("products")))
        prod_candidates.update(_lower_values(meta.get("product")))
        if source_family:
            prod_candidates.add(source_family)
        if isinstance(log_src, Mapping):
            prod_candidates.update(_lower_values(log_src.get("product")))
        if not prod_candidates.intersection(norm_filters["products"]):
            return False

    if "versions" in norm_filters:
        ver_candidates: set[str] = set()
        for vk in ("version", "source_version", "product_version"):
            ver_candidates.update(_lower_values(chunk.get(vk)))
            ver_candidates.update(_lower_values(meta.get(vk)))
        if not ver_candidates.intersection(norm_filters["versions"]):
            return False

    if "log_sources" in norm_filters:
        ls_candidates: set[str] = set()
        for lsk in ("log_source", "logsource"):
            val = chunk.get(lsk) or meta.get(lsk)
            if isinstance(val, Mapping):
                ls_candidates.update(_lower_values(val))
            else:
                ls_candidates.update(_lower_values(val))
        if source_family:
            ls_candidates.add(source_family)
        if not ls_candidates.intersection(norm_filters["log_sources"]):
            return False

    if "rule_ids" in norm_filters:
        id_candidates = (
            _lower_values(chunk.get("rule_id"))
            | _lower_values(chunk.get("document_id"))
            | _lower_values(chunk.get("doc_id"))
            | _lower_values(chunk.get("id"))
        )
        if not id_candidates.intersection(norm_filters["rule_ids"]):
            return False

    if "fields" in norm_filters:
        explicit_fields = (
            _lower_values(chunk.get("field"))
            | _lower_values(chunk.get("field_name"))
            | _lower_values(chunk.get("fields"))
            | _lower_values(meta.get("fields"))
        )
        if explicit_fields:
            if not explicit_fields.intersection(norm_filters["fields"]):
                return False
        else:
            prose = " ".join(
                [
                    str(chunk.get("title") or ""),
                    str(chunk.get("text") or chunk.get("content") or chunk.get("excerpt") or ""),
                ]
            ).lower()
            tokens = set(TOKEN_RE.findall(prose))
            if not any(
                f in tokens or f in prose for f in norm_filters["fields"]
            ):
                return False

    if "platforms" in norm_filters:
        plats = _lower_values(chunk.get("platform") or meta.get("platform"))
        if not plats.intersection(norm_filters["platforms"]):
            return False

    if "technique_ids" in norm_filters:
        techs = (
            _lower_values(chunk.get("attack_ids"))
            | _lower_values(chunk.get("attack_technique_ids"))
            | _lower_values(chunk.get("technique_id"))
            | _lower_values(meta.get("attack_technique_ids"))
        )
        if not any(
            t == want or t.startswith(want + ".")
            for t in techs
            for want in norm_filters["technique_ids"]
        ):
            return False

    if "event_ids" in norm_filters:
        eids = _lower_values(chunk.get("event_ids") or meta.get("event_ids"))
        if not eids.intersection(norm_filters["event_ids"]):
            return False

    return True


def _normalize_knowledge_ref(
    row: Mapping[str, Any],
    *,
    snapshot_id: str,
    actual_mode: str,
    retrieval_id: str,
) -> dict[str, Any]:
    chunk_id = str(row.get("chunk_id") or "").strip()
    doc_id = str(row.get("doc_id") or row.get("document_id") or chunk_id).strip()
    version = str(
        row.get("version") or row.get("source_version") or snapshot_id or "unknown"
    ).strip()[:512]
    source_url_raw = row.get("source_url")
    source_url = (
        source_url_raw.strip()[:2048]
        if isinstance(source_url_raw, str) and source_url_raw.strip()
        else None
    )
    locator = str(
        row.get("locator") or source_url or f"chunk:{chunk_id}"
    ).strip()[:2048]
    excerpt = str(
        row.get("excerpt") or row.get("content") or row.get("text") or ""
    ).strip()[:1200]
    if not excerpt:
        excerpt = str(row.get("title") or chunk_id).strip()[:1200]
    match_reason = str(
        row.get("match_reason") or _MATCH_REASONS.get(actual_mode, "BM25 term match")
    ).strip()[:512]

    meta = row.get("metadata") if isinstance(row.get("metadata"), Mapping) else {}
    author_raw = row.get("author") or meta.get("author")
    author = (
        author_raw.strip()[:512]
        if isinstance(author_raw, str) and author_raw.strip()
        else None
    )

    ref = KnowledgeRef(
        retrieval_id=retrieval_id,
        doc_id=doc_id,
        chunk_id=chunk_id,
        version=version,
        locator=locator,
        excerpt=excerpt,
        match_reason=match_reason,
        source_url=source_url,
        author=author,
    )
    return ref.model_dump(mode="json")


@contextmanager
def _prepend_sys_path(directory: Path):
    path_str = str(directory)
    inserted = False
    if path_str not in sys.path:
        sys.path.insert(0, path_str)
        inserted = True
    try:
        yield
    finally:
        if inserted and path_str in sys.path:
            sys.path.remove(path_str)


def _corpus_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class RagService:
    """Case-isolated, role-filtered, cached, gracefully-degrading RAG retrieval service."""

    def __init__(
        self,
        ctx: RunContext | AppConfig | RagConfig | None = None,
        *,
        config: RagConfig | None = None,
        manifest_path: Path | str | None = None,
        use_subprocess: bool | None = None,
        client: Any | None = None,
        subprocess_runner: Callable[..., Any] | None = None,
        allow_mode_fallback: bool = True,
        exclude_scene_ids: Sequence[str] = (),
    ) -> None:
        if isinstance(ctx, (AppConfig, RagConfig)):
            if config is None:
                config = ctx.rag if isinstance(ctx, AppConfig) else ctx
            ctx = None
        self.ctx = ctx
        if config is not None:
            self.config = config
        elif ctx is not None and ctx.config is not None:
            self.config = ctx.config.rag
        else:
            self.config = RagConfig()

        self._manifest_explicit = manifest_path is not None
        self.manifest_path = (
            self._resolve_path(Path(manifest_path))
            if manifest_path is not None
            else DEFAULT_MANIFEST_PATH
        )
        self.use_subprocess = (
            bool(use_subprocess)
            if use_subprocess is not None
            else bool(manifest_path is not None or subprocess_runner is not None)
        )
        self._client = client
        self._subprocess_runner = subprocess_runner
        self._allow_mode_fallback = bool(allow_mode_fallback)

        excluded = {str(s).strip() for s in exclude_scene_ids if str(s).strip()}
        if ctx is not None and ctx.case_id:
            excluded.add(ctx.case_id)
        self._exclude_scene_ids = frozenset(excluded)
        self._valid_physical_ids = (
            ctx.valid_physical_ids if ctx is not None else None
        )

        self._resource_path = self._resolve_resource_path()
        self._cache: dict[tuple[Any, ...], dict[str, Any]] = {}
        self._corpus_cache: dict[Path, tuple[tuple[int, int], str, list[dict[str, Any]]]] = {}
        self._lock = threading.Lock()
        self.stats: dict[str, Any] = {
            "calls": 0,
            "cache_hits": 0,
            "degraded_calls": 0,
            "rejected_smuggling": 0,
            "total_latency_ms": 0.0,
        }

    @staticmethod
    def _resolve_path(path: Path) -> Path:
        if path.is_absolute():
            return path
        cwd_candidate = (Path.cwd() / path).resolve()
        if cwd_candidate.exists():
            return cwd_candidate
        repo_candidate = (REPO_ROOT / path).resolve()
        if repo_candidate.exists():
            return repo_candidate
        return cwd_candidate

    def _resolve_resource_path(self) -> Path:
        if self.config.config_path is not None:
            return self._resolve_path(Path(self.config.config_path))
        if self.config.knowledge_path is not None:
            return self._resolve_path(Path(self.config.knowledge_path))
        return DEFAULT_PUBLIC_KB_PATH

    def _default_snapshot_id(self, override: str | None) -> str:
        if override is not None and override.strip():
            return override.strip()
        if self.ctx is not None and self.ctx.knowledge_snapshot_id:
            return self.ctx.knowledge_snapshot_id
        return "public_kb"

    def _make_response(
        self,
        *,
        ok: bool,
        degraded: bool,
        retrieval_id: str,
        snapshot_id: str,
        requested_mode: str,
        mode: str,
        refs: list[dict[str, Any]] | None = None,
        warnings: list[str] | None = None,
        error: dict[str, Any] | None = None,
        cached: bool = False,
    ) -> dict[str, Any]:
        return {
            "ok": ok,
            "degraded": degraded,
            "retrieval_id": retrieval_id,
            "snapshot_id": snapshot_id,
            "requested_mode": requested_mode,
            "mode": mode,
            "refs": refs or [],
            "evidence_ids": [],
            "warnings": warnings or [],
            "error": error,
            "cached": cached,
        }

    def _check_evidence_smuggling(
        self,
        raw_evidence_ids: Any,
        items: Sequence[Mapping[str, Any]],
    ) -> str | None:
        if raw_evidence_ids is not None:
            if not isinstance(raw_evidence_ids, list) or len(raw_evidence_ids) > 0:
                return (
                    f"Knowledge backend returned forbidden non-empty evidence_ids: "
                    f"{raw_evidence_ids!r}"
                )
        for item in items:
            if item.get("record_type") == "raw_evidence":
                return "Knowledge item is tagged as raw_evidence."
            if self._valid_physical_ids:
                for key in ("chunk_id", "doc_id", "document_id"):
                    val = item.get(key)
                    if isinstance(val, str) and val in self._valid_physical_ids:
                        return (
                            f"Knowledge item identifier {val!r} collides with case physical_record_id."
                        )
        return None

    def _load_jsonl_corpus(self, path: Path) -> tuple[str, list[dict[str, Any]]]:
        st = path.stat()
        sig = (st.st_mtime_ns, st.st_size)
        with self._lock:
            cached = self._corpus_cache.get(path)
            if cached is not None and cached[0] == sig:
                return cached[1], cached[2]

        opener = gzip.open if path.suffix == ".gz" else open
        chunks: list[dict[str, Any]] = []
        with opener(path, "rt", encoding="utf-8") as fh:
            for line_no, raw_line in enumerate(fh, 1):
                stripped = raw_line.strip()
                if not stripped:
                    continue
                obj = json.loads(stripped)
                if not isinstance(obj, dict):
                    raise ValueError(f"Line {line_no} in corpus is not a JSON object.")
                text = obj.get("text") or obj.get("content") or ""
                chunk_id = obj.get("chunk_id")
                doc_id = obj.get("document_id") or obj.get("doc_id")
                if not all(isinstance(v, str) and v.strip() for v in (text, chunk_id, doc_id)):
                    raise ValueError(f"Line {line_no} in corpus is missing required fields.")
                chunks.append(obj)

        digest = _corpus_sha256(path)
        with self._lock:
            self._corpus_cache[path] = (sig, digest, chunks)
        return digest, chunks

    def _search_bm25_jsonl(
        self,
        *,
        path: Path,
        query: str,
        top_k: int,
        role_key: str,
        norm_filters: Mapping[str, Any],
        retrieval_id: str,
        requested_mode: str,
        snapshot_override: str | None,
    ) -> dict[str, Any]:
        warnings: list[str] = []
        actual_mode = requested_mode
        degraded = False

        if requested_mode != "bm25":
            if not self._allow_mode_fallback:
                return self._make_response(
                    ok=False,
                    degraded=True,
                    retrieval_id=retrieval_id,
                    snapshot_id=self._default_snapshot_id(snapshot_override),
                    requested_mode=requested_mode,
                    mode="unavailable",
                    warnings=[f"MODE_UNAVAILABLE: {requested_mode} requires indexed YAML config"],
                    error={
                        "code": "RETRIEVAL_UNAVAILABLE",
                        "message": f"Mode {requested_mode!r} is unavailable for JSONL corpus.",
                        "retryable": False,
                    },
                )
            actual_mode = "bm25"
            degraded = True
            warnings.append(
                f"MODE_UNAVAILABLE: {requested_mode} unavailable on JSONL corpus; degraded to bm25"
            )

        if not path.is_file():
            return self._make_response(
                ok=False,
                degraded=True,
                retrieval_id=retrieval_id,
                snapshot_id=self._default_snapshot_id(snapshot_override),
                requested_mode=requested_mode,
                mode="unavailable",
                warnings=[f"rag_degraded:DATA_ERROR:corpus missing at {path}"],
                error={
                    "code": "RETRIEVAL_UNAVAILABLE",
                    "message": f"Knowledge corpus does not exist: {path}",
                    "retryable": False,
                },
            )

        try:
            corpus_digest, chunks = self._load_jsonl_corpus(path)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, gzip.BadGzipFile) as exc:
            return self._make_response(
                ok=False,
                degraded=True,
                retrieval_id=retrieval_id,
                snapshot_id=self._default_snapshot_id(snapshot_override),
                requested_mode=requested_mode,
                mode="unavailable",
                warnings=[f"rag_degraded:DATA_ERROR:{exc}"],
                error={
                    "code": "RETRIEVAL_UNAVAILABLE",
                    "message": f"Failed to read or parse knowledge corpus: {exc}",
                    "retryable": False,
                },
            )

        snapshot_id = snapshot_override or corpus_digest
        filtered_chunks = [
            chunk
            for chunk in chunks
            if _chunk_matches_policy(
                chunk,
                role_key=role_key,
                norm_filters=norm_filters,
                exclude_scene_ids=self._exclude_scene_ids,
            )
        ]

        smuggling_msg = self._check_evidence_smuggling(None, filtered_chunks)
        if smuggling_msg:
            return self._make_response(
                ok=False,
                degraded=True,
                retrieval_id=retrieval_id,
                snapshot_id=snapshot_id,
                requested_mode=requested_mode,
                mode="unavailable",
                warnings=[f"OUT_OF_SCOPE: {smuggling_msg}"],
                error={"code": "OUT_OF_SCOPE", "message": smuggling_msg, "retryable": False},
            )

        terms = set(TOKEN_RE.findall(query.lower()))
        if not terms or not filtered_chunks:
            return self._make_response(
                ok=True,
                degraded=degraded,
                retrieval_id=retrieval_id,
                snapshot_id=snapshot_id,
                requested_mode=requested_mode,
                mode=actual_mode,
                refs=[],
                warnings=warnings,
            )

        # Pre-filtered BM25 using exact search_public.py parameters (k1=1.5, b=0.75).
        candidate_data: list[tuple[dict[str, Any], int, Counter[str]]] = []
        query_df: Counter[str] = Counter()
        doc_count = 0
        total_len = 0
        for chunk in filtered_chunks:
            text_val = str(chunk.get("text") or chunk.get("content") or "")
            tokens = TOKEN_RE.findall(text_val.lower())
            doc_count += 1
            total_len += len(tokens)
            freqs = Counter(tok for tok in tokens if tok in terms)
            if freqs:
                query_df.update(freqs.keys())
                candidate_data.append((chunk, len(tokens), freqs))

        if not candidate_data:
            return self._make_response(
                ok=True,
                degraded=degraded,
                retrieval_id=retrieval_id,
                snapshot_id=snapshot_id,
                requested_mode=requested_mode,
                mode=actual_mode,
                refs=[],
                warnings=warnings,
            )

        k1, b = 1.5, 0.75
        avg_len = total_len / doc_count
        idf = {
            word: math.log1p((doc_count - df + 0.5) / (df + 0.5))
            for word, df in query_df.items()
        }
        ranked: list[tuple[dict[str, Any], float]] = []
        for chunk, length, freqs in candidate_data:
            norm = k1 * (1.0 - b + b * length / avg_len) if avg_len > 0 else k1
            score = math.fsum(
                idf[word] * tf * (k1 + 1.0) / (tf + norm) for word, tf in freqs.items()
            )
            ranked.append((chunk, score))

        ranked.sort(key=lambda item: (-item[1], str(item[0]["chunk_id"])))
        refs = [
            _normalize_knowledge_ref(
                chunk,
                snapshot_id=snapshot_id,
                actual_mode=actual_mode,
                retrieval_id=retrieval_id,
            )
            for chunk, _ in ranked[:top_k]
        ]

        return self._make_response(
            ok=True,
            degraded=degraded,
            retrieval_id=retrieval_id,
            snapshot_id=snapshot_id,
            requested_mode=requested_mode,
            mode=actual_mode,
            refs=refs,
            warnings=warnings,
        )

    def _get_or_load_client(self, path: Path) -> Any:
        if self._client is not None:
            return self._client
        if not path.is_file():
            raise FileNotFoundError(f"RAG YAML config not found: {path}")
        from apt_rag import RagClient

        self._client = RagClient.from_config(path)
        return self._client

    def _search_yaml_client(
        self,
        *,
        path: Path,
        query: str,
        top_k: int,
        role_key: str,
        norm_filters: Mapping[str, Any],
        retrieval_id: str,
        requested_mode: str,
        snapshot_override: str | None,
    ) -> dict[str, Any]:
        try:
            client = self._get_or_load_client(path)
        except Exception as exc:  # noqa: BLE001
            return self._make_response(
                ok=False,
                degraded=True,
                retrieval_id=retrieval_id,
                snapshot_id=self._default_snapshot_id(snapshot_override),
                requested_mode=requested_mode,
                mode="unavailable",
                warnings=[f"rag_degraded:CONFIG_ERROR:{exc}"],
                error={
                    "code": "RETRIEVAL_UNAVAILABLE",
                    "message": f"Failed to initialize RAG client: {exc}",
                    "retryable": False,
                },
            )

        if requested_mode != "bm25" and hasattr(client, "config"):
            offline_flag = getattr(client.config, "offline", True)
            if self.config.offline and not offline_flag:
                return self._make_response(
                    ok=False,
                    degraded=True,
                    retrieval_id=retrieval_id,
                    snapshot_id=self._default_snapshot_id(snapshot_override),
                    requested_mode=requested_mode,
                    mode="unavailable",
                    warnings=["rag_degraded:DATA_ERROR:non_offline_rag_config_rejected"],
                    error={
                        "code": "RETRIEVAL_UNAVAILABLE",
                        "message": "Non-offline RAG model configuration is forbidden when offline=True.",
                        "retryable": False,
                    },
                )

        overfetch_k = min(20, max(top_k * 4, 20)) if norm_filters or role_key != "lead" else top_k
        try:
            raw_res = client.search(query, top_k=overfetch_k, mode=requested_mode)
        except Exception as exc:  # noqa: BLE001
            return self._make_response(
                ok=False,
                degraded=True,
                retrieval_id=retrieval_id,
                snapshot_id=self._default_snapshot_id(snapshot_override),
                requested_mode=requested_mode,
                mode="unavailable",
                warnings=[f"rag_degraded:RETRIEVAL_ERROR:{exc}"],
                error={
                    "code": "RETRIEVAL_UNAVAILABLE",
                    "message": f"RAG client search failed: {exc}",
                    "retryable": True,
                },
            )

        if isinstance(raw_res, Mapping):
            raw_evidence_ids = raw_res.get("evidence_ids")
            raw_error = raw_res.get("error")
            raw_results = list(raw_res.get("results") or raw_res.get("refs") or [])
            warnings = [str(w) for w in (raw_res.get("warnings") or [])]
            actual_mode = str(raw_res.get("mode") or requested_mode)
            snapshot_id = snapshot_override or str(
                raw_res.get("snapshot_id") or self._default_snapshot_id(None)
            )
        else:
            raw_evidence_ids = getattr(raw_res, "evidence_ids", None)
            raw_error = getattr(raw_res, "error", None)
            raw_results = list(getattr(raw_res, "results", []) or [])
            warnings = [str(w) for w in (getattr(raw_res, "warnings", []) or [])]
            actual_mode = str(getattr(raw_res, "mode", requested_mode) or requested_mode)
            snapshot_id = snapshot_override or str(
                getattr(raw_res, "snapshot_id", None) or self._default_snapshot_id(None)
            )

        smuggling_msg = self._check_evidence_smuggling(raw_evidence_ids, raw_results)
        if smuggling_msg:
            return self._make_response(
                ok=False,
                degraded=True,
                retrieval_id=retrieval_id,
                snapshot_id=snapshot_id,
                requested_mode=requested_mode,
                mode="unavailable",
                warnings=[f"OUT_OF_SCOPE: {smuggling_msg}"],
                error={"code": "OUT_OF_SCOPE", "message": smuggling_msg, "retryable": False},
            )

        if raw_error:
            err_msg = (
                raw_error.get("message", str(raw_error))
                if isinstance(raw_error, Mapping)
                else str(raw_error)
            )
            return self._make_response(
                ok=False,
                degraded=True,
                retrieval_id=retrieval_id,
                snapshot_id=snapshot_id,
                requested_mode=requested_mode,
                mode="unavailable",
                warnings=[*warnings, f"rag_degraded:RETRIEVAL_ERROR:{err_msg}"],
                error={
                    "code": "RETRIEVAL_UNAVAILABLE",
                    "message": err_msg,
                    "retryable": True,
                },
            )

        degraded = actual_mode == "dense_fallback" or any(
            "fallback" in w.lower() or "unavailable" in w.lower() for w in warnings
        )

        # Hydrate full chunk metadata from store when available so P7/P9/role checks use full fields.
        store = getattr(client, "store", None)
        filtered_rows: list[Mapping[str, Any]] = []
        for item in raw_results:
            merged_item = dict(item)
            if store is not None and hasattr(store, "chunk") and item.get("chunk_id"):
                try:
                    raw_chunk = store.chunk(item["chunk_id"])
                    if isinstance(raw_chunk, Mapping):
                        for k, v in raw_chunk.items():
                            merged_item.setdefault(k, v)
                except Exception:  # noqa: BLE001
                    pass
            if _chunk_matches_policy(
                merged_item,
                role_key=role_key,
                norm_filters=norm_filters,
                exclude_scene_ids=self._exclude_scene_ids,
            ):
                filtered_rows.append(merged_item)

        refs = [
            _normalize_knowledge_ref(
                row,
                snapshot_id=snapshot_id,
                actual_mode=actual_mode,
                retrieval_id=retrieval_id,
            )
            for row in filtered_rows[:top_k]
        ]
        return self._make_response(
            ok=True,
            degraded=degraded,
            retrieval_id=retrieval_id,
            snapshot_id=snapshot_id,
            requested_mode=requested_mode,
            mode=actual_mode,
            refs=refs,
            warnings=warnings,
        )

    def _invoke_subprocess_v1(
        self,
        *,
        resource_path: Path,
        query: str,
        top_k: int,
        mode: str,
        request_id: str,
    ) -> dict[str, Any]:
        if self._subprocess_runner is not None:
            context = {
                "case_id": self.ctx.case_id if self.ctx else "default_case",
                "run_id": self.ctx.run_id if self.ctx else "default_run",
                "resources": {"knowledge": str(resource_path)},
            }
            request = {
                "protocol_version": "1.0",
                "request_id": request_id,
                "tool": "search_knowledge",
                "tool_version": "1.0.0",
                "context": context,
                "arguments": {"query": query, "top_k": top_k, "mode": mode},
            }
            sig = inspect.signature(self._subprocess_runner)
            if len(sig.parameters) == 1:
                return self._subprocess_runner(request)
            return self._subprocess_runner(
                query=query, top_k=top_k, mode=mode, context=context, request=request
            )

        manifest_file = self.manifest_path.resolve(strict=False)
        if not manifest_file.is_file():
            return {
                "protocol_version": "1.0",
                "request_id": request_id,
                "ok": False,
                "error": {
                    "code": "START_ERROR",
                    "message": f"RAG manifest not found: {manifest_file}",
                    "retryable": False,
                },
            }

        try:
            with _prepend_sys_path(manifest_file.parent):
                langgraph_adapter = importlib.import_module("langgraph_adapter")
                wire = importlib.import_module("wire")
            manifest = wire.decode(manifest_file.read_bytes())
            if manifest.get("protocol_version") != "1.0":
                raise ValueError("Unsupported RAG tool protocol version.")
            if set(manifest.get("resources") or []) != {"knowledge"}:
                raise ValueError("Manifest resources must be exactly {'knowledge'}.")
            output_schema = manifest["output_schema"]
            Draft202012Validator.check_schema(output_schema)
            output_validator = Draft202012Validator(output_schema)
        except Exception as exc:  # noqa: BLE001
            return {
                "protocol_version": "1.0",
                "request_id": request_id,
                "ok": False,
                "error": {
                    "code": "DATA_ERROR",
                    "message": f"Invalid RAG manifest: {exc}",
                    "retryable": False,
                },
            }

        if not resource_path.is_file():
            return {
                "protocol_version": "1.0",
                "request_id": request_id,
                "ok": False,
                "error": {
                    "code": "DATA_ERROR",
                    "message": f"Knowledge resource file not found: {resource_path}",
                    "retryable": False,
                },
            }

        argv = list(manifest["argv"])
        if argv[0] == "{python}":
            argv[0] = sys.executable
        elif "/" in argv[0] or "\\" in argv[0]:
            argv[0] = str((manifest_file.parent / argv[0]).resolve())

        manifest_timeout_ms = int(manifest.get("timeout_ms", 60000))
        if self._manifest_explicit and self.config.timeout_ms == 60000:
            effective_timeout_s = manifest_timeout_ms / 1000.0
        else:
            effective_timeout_s = min(manifest_timeout_ms, self.config.timeout_ms) / 1000.0

        request = {
            "protocol_version": "1.0",
            "request_id": request_id,
            "tool": manifest["name"],
            "tool_version": manifest["tool_version"],
            "context": {
                "case_id": self.ctx.case_id if self.ctx else "default_case",
                "run_id": self.ctx.run_id if self.ctx else "default_run",
                "resources": {"knowledge": str(resource_path.resolve(strict=True))},
            },
            "arguments": {"query": query, "top_k": top_k, "mode": mode},
        }

        try:
            proc = subprocess.run(
                argv,
                cwd=manifest_file.parent,
                shell=False,
                timeout=effective_timeout_s,
                capture_output=True,
                stdin=None,
                input=json.dumps(request, ensure_ascii=False, allow_nan=False).encode("utf-8"),
                check=False,
            )
        except subprocess.TimeoutExpired:
            return langgraph_adapter.failure(
                request_id, "TIMEOUT", "Tool invocation timed out.", retryable=True
            )
        except OSError as exc:
            return langgraph_adapter.failure(
                request_id, "START_ERROR", f"Tool process could not be started: {exc}"
            )

        if proc.returncode != 0:
            return langgraph_adapter.failure(
                request_id, "PROCESS_EXIT", f"Tool exited with status {proc.returncode}."
            )

        return langgraph_adapter.validate_response(
            proc.stdout, request_id, output_validator, frozenset()
        )

    def _search_subprocess(
        self,
        *,
        resource_path: Path,
        query: str,
        top_k: int,
        role_key: str,
        norm_filters: Mapping[str, Any],
        retrieval_id: str,
        requested_mode: str,
        snapshot_override: str | None,
    ) -> dict[str, Any]:
        request_id = retrieval_id.removeprefix("rag:")
        fetch_k = min(20, max(top_k * 4, 20)) if norm_filters or role_key != "lead" else top_k
        reply = self._invoke_subprocess_v1(
            resource_path=resource_path,
            query=query,
            top_k=fetch_k,
            mode=requested_mode,
            request_id=request_id,
        )

        extra_warnings: list[str] = []
        degraded = False
        if (
            not reply.get("ok")
            and isinstance(reply.get("error"), Mapping)
            and reply["error"].get("code") == "MODE_UNAVAILABLE"
            and requested_mode != "bm25"
            and self._allow_mode_fallback
        ):
            extra_warnings.append(
                f"MODE_UNAVAILABLE: {reply['error'].get('message', '')}; degraded to bm25"
            )
            degraded = True
            reply = self._invoke_subprocess_v1(
                resource_path=resource_path,
                query=query,
                top_k=fetch_k,
                mode="bm25",
                request_id=request_id,
            )

        if not isinstance(reply, Mapping):
            return self._make_response(
                ok=False,
                degraded=True,
                retrieval_id=retrieval_id,
                snapshot_id=self._default_snapshot_id(snapshot_override),
                requested_mode=requested_mode,
                mode="unavailable",
                warnings=["rag_degraded:BAD_RESPONSE:non_mapping_reply"],
                error={
                    "code": "RETRIEVAL_UNAVAILABLE",
                    "message": "RAG subprocess returned invalid response.",
                    "retryable": False,
                },
            )

        if not reply.get("ok"):
            err = reply.get("error") if isinstance(reply.get("error"), Mapping) else {}
            raw_code = str(err.get("code") or "RETRIEVAL_ERROR")
            err_msg = str(err.get("message") or "RAG retrieval failed.")
            retryable = bool(err.get("retryable", False))
            if raw_code == "OUT_OF_SCOPE":
                return self._make_response(
                    ok=False,
                    degraded=True,
                    retrieval_id=retrieval_id,
                    snapshot_id=self._default_snapshot_id(snapshot_override),
                    requested_mode=requested_mode,
                    mode="unavailable",
                    warnings=[f"OUT_OF_SCOPE: {err_msg}"],
                    error={"code": "OUT_OF_SCOPE", "message": err_msg, "retryable": False},
                )
            mapped_code = "TIMEOUT" if raw_code == "TIMEOUT" else "RETRIEVAL_UNAVAILABLE"
            return self._make_response(
                ok=False,
                degraded=True,
                retrieval_id=retrieval_id,
                snapshot_id=self._default_snapshot_id(snapshot_override),
                requested_mode=requested_mode,
                mode="unavailable",
                warnings=[*extra_warnings, f"rag_degraded:{raw_code}:{err_msg}"],
                error={"code": mapped_code, "message": err_msg, "retryable": retryable},
            )

        data = reply.get("data") if isinstance(reply.get("data"), Mapping) else {}
        raw_refs = list(data.get("refs") or [])
        smuggling_msg = self._check_evidence_smuggling(reply.get("evidence_ids"), raw_refs)
        if smuggling_msg:
            return self._make_response(
                ok=False,
                degraded=True,
                retrieval_id=retrieval_id,
                snapshot_id=self._default_snapshot_id(snapshot_override),
                requested_mode=requested_mode,
                mode="unavailable",
                warnings=[f"OUT_OF_SCOPE: {smuggling_msg}"],
                error={"code": "OUT_OF_SCOPE", "message": smuggling_msg, "retryable": False},
            )

        snapshot_id = snapshot_override or str(
            data.get("snapshot_id") or self._default_snapshot_id(None)
        )
        actual_mode = str(data.get("mode") or requested_mode)
        warnings = [*extra_warnings, *(str(w) for w in (data.get("warnings") or []))]

        # Enrich with full chunk metadata if querying a local JSONL corpus so role/P7 filters
        # behave identically across subprocess and in-process modes.
        chunk_lookup: dict[str, dict[str, Any]] = {}
        if resource_path.is_file() and resource_path.name.lower().endswith((".jsonl", ".jsonl.gz")):
            try:
                _, corpus_chunks = self._load_jsonl_corpus(resource_path)
                chunk_lookup = {str(c["chunk_id"]): c for c in corpus_chunks if c.get("chunk_id")}
            except Exception:  # noqa: BLE001
                chunk_lookup = {}

        filtered_refs: list[dict[str, Any]] = []
        for item in raw_refs:
            merged = dict(item)
            cid = str(item.get("chunk_id") or "")
            if cid and cid in chunk_lookup:
                for k, v in chunk_lookup[cid].items():
                    merged.setdefault(k, v)
            if _chunk_matches_policy(
                merged,
                role_key=role_key,
                norm_filters=norm_filters,
                exclude_scene_ids=self._exclude_scene_ids,
            ):
                filtered_refs.append(
                    _normalize_knowledge_ref(
                        merged,
                        snapshot_id=snapshot_id,
                        actual_mode=actual_mode,
                        retrieval_id=retrieval_id,
                    )
                )

        return self._make_response(
            ok=True,
            degraded=degraded,
            retrieval_id=retrieval_id,
            snapshot_id=snapshot_id,
            requested_mode=requested_mode,
            mode=actual_mode,
            refs=filtered_refs[:top_k],
            warnings=warnings,
        )

    def search_knowledge(
        self,
        query: str,
        *,
        role: str,
        filters: Mapping[str, Any] | None = None,
        top_k: int | None = None,
        mode: str | None = None,
        snapshot_id: str | None = None,
    ) -> dict[str, Any]:
        """Search the read-only knowledge base with role, P7/P9 isolation, cache, and degradation."""
        started = time.perf_counter()
        request_id = uuid4().hex
        retrieval_id = f"rag:{request_id}"
        requested_mode = str(mode if mode is not None else self.config.mode).strip().lower()
        resolved_snapshot_id = self._default_snapshot_id(snapshot_id)

        try:
            if not isinstance(query, str) or not query.strip():
                raise ValueError("query must be a non-blank string.")
            if len(query) > 2000:
                raise ValueError("query must not exceed 2000 characters.")
            normalized_query = " ".join(query.strip().split())

            effective_top_k = self.config.top_k if top_k is None else top_k
            if (
                isinstance(effective_top_k, bool)
                or not isinstance(effective_top_k, int)
                or not (1 <= effective_top_k <= 20)
            ):
                raise ValueError("top_k must be an integer between 1 and 20.")

            if requested_mode not in _VALID_MODES:
                raise ValueError("mode must be 'bm25', 'dense', or 'hybrid'.")

            role_key = normalize_rag_role(role)
            norm_filters = _normalize_rag_filters(filters)
        except PermissionError as exc:
            return self._make_response(
                ok=False,
                degraded=False,
                retrieval_id=retrieval_id,
                snapshot_id=resolved_snapshot_id,
                requested_mode=requested_mode,
                mode="unavailable",
                error={"code": "PERMISSION_DENIED", "message": str(exc), "retryable": False},
            )
        except ValueError as exc:
            return self._make_response(
                ok=False,
                degraded=False,
                retrieval_id=retrieval_id,
                snapshot_id=resolved_snapshot_id,
                requested_mode=requested_mode,
                mode="unavailable",
                error={"code": "INVALID_ARGUMENT", "message": str(exc), "retryable": False},
            )

        cache_key = (
            role_key,
            _freeze_value(norm_filters),
            resolved_snapshot_id,
            requested_mode,
            normalized_query,
            effective_top_k,
        )
        with self._lock:
            self.stats["calls"] += 1
            cached_entry = self._cache.get(cache_key)
            if cached_entry is not None:
                self.stats["cache_hits"] += 1
                self.stats["total_latency_ms"] += (time.perf_counter() - started) * 1000.0
                hit_copy = copy.deepcopy(cached_entry)
                hit_copy["cached"] = True
                return hit_copy

        try:
            if self.use_subprocess:
                result = self._search_subprocess(
                    resource_path=self._resource_path,
                    query=query.strip(),
                    top_k=effective_top_k,
                    role_key=role_key,
                    norm_filters=norm_filters,
                    retrieval_id=retrieval_id,
                    requested_mode=requested_mode,
                    snapshot_override=snapshot_id,
                )
            elif self._client is not None or self._resource_path.suffix.lower() in {".yaml", ".yml"}:
                result = self._search_yaml_client(
                    path=self._resource_path,
                    query=query.strip(),
                    top_k=effective_top_k,
                    role_key=role_key,
                    norm_filters=norm_filters,
                    retrieval_id=retrieval_id,
                    requested_mode=requested_mode,
                    snapshot_override=snapshot_id,
                )
            else:
                result = self._search_bm25_jsonl(
                    path=self._resource_path,
                    query=query.strip(),
                    top_k=effective_top_k,
                    role_key=role_key,
                    norm_filters=norm_filters,
                    retrieval_id=retrieval_id,
                    requested_mode=requested_mode,
                    snapshot_override=snapshot_id,
                )
        except Exception as exc:  # noqa: BLE001 - never crash investigation on RAG failure
            result = self._make_response(
                ok=False,
                degraded=True,
                retrieval_id=retrieval_id,
                snapshot_id=resolved_snapshot_id,
                requested_mode=requested_mode,
                mode="unavailable",
                warnings=[f"rag_degraded:{type(exc).__name__}:{exc}"],
                error={
                    "code": "RETRIEVAL_UNAVAILABLE",
                    "message": f"Unexpected RAG failure: {exc}",
                    "retryable": True,
                },
            )

        with self._lock:
            self.stats["total_latency_ms"] += (time.perf_counter() - started) * 1000.0
            if result.get("degraded"):
                self.stats["degraded_calls"] += 1
            if (
                isinstance(result.get("error"), Mapping)
                and result["error"].get("code") == "OUT_OF_SCOPE"
            ):
                self.stats["rejected_smuggling"] += 1
            if result.get("ok") and not result.get("degraded"):
                self._cache[cache_key] = copy.deepcopy(result)

        return result


__all__ = [
    "DEFAULT_MANIFEST_PATH",
    "DEFAULT_PUBLIC_KB_PATH",
    "ROLE_KB_POLICY",
    "RagService",
    "normalize_rag_role",
]
