"""Sandboxed base tools, typed forensic query tools, RAG service, and role-scoped registry."""

from __future__ import annotations

from apt_agent.tools.base_tools import (
    DEFAULT_BASH_ALLOWLIST,
    DEFAULT_BASH_MAX_OUTPUT_BYTES,
    DEFAULT_BASH_TIMEOUT_S,
    DEFAULT_READ_LIMIT,
    DEFAULT_READ_MAX_BYTES,
    DEFAULT_WRITE_MAX_BYTES,
    BaseToolset,
    tool_bash,
    tool_edit,
    tool_read,
    tool_write,
)
from apt_agent.tools.investigation import (
    correlate_lineage_and_flows,
    fetch_raw_evidence,
    query_events,
)
from apt_agent.tools.rag_service import (
    DEFAULT_MANIFEST_PATH,
    DEFAULT_PUBLIC_KB_PATH,
    ROLE_KB_POLICY,
    RagService,
    normalize_rag_role,
)
from apt_agent.tools.registry import (
    INVESTIGATION_ROLES,
    MAINTENANCE_ROLES,
    REGISTERED_TOOLS,
    ROLE_PERMISSIONS,
    AuditLogEntry,
    ToolCallResult,
    ToolRegistry,
    normalize_caller_role,
)

__all__ = [
    "AuditLogEntry",
    "BaseToolset",
    "DEFAULT_BASH_ALLOWLIST",
    "DEFAULT_BASH_MAX_OUTPUT_BYTES",
    "DEFAULT_BASH_TIMEOUT_S",
    "DEFAULT_MANIFEST_PATH",
    "DEFAULT_PUBLIC_KB_PATH",
    "DEFAULT_READ_LIMIT",
    "DEFAULT_READ_MAX_BYTES",
    "DEFAULT_WRITE_MAX_BYTES",
    "INVESTIGATION_ROLES",
    "MAINTENANCE_ROLES",
    "REGISTERED_TOOLS",
    "ROLE_KB_POLICY",
    "ROLE_PERMISSIONS",
    "RagService",
    "ToolCallResult",
    "ToolRegistry",
    "correlate_lineage_and_flows",
    "fetch_raw_evidence",
    "normalize_caller_role",
    "normalize_rag_role",
    "query_events",
    "tool_bash",
    "tool_edit",
    "tool_read",
    "tool_write",
]
