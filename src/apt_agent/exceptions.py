"""Typed exceptions and error wire helpers for OPEN_APT_AGENT."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from enum import StrEnum
from typing import Any


class ErrorCode(StrEnum):
    """Canonical error codes shared across tools, engines, blackboard, and graph."""

    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    ENGINE_ERROR = "ENGINE_ERROR"
    RETRIEVAL_UNAVAILABLE = "RETRIEVAL_UNAVAILABLE"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    CONFLICT_ERROR = "CONFLICT_ERROR"
    CONFIG_ERROR = "CONFIG_ERROR"
    TIMEOUT = "TIMEOUT"


class AptAgentError(Exception):
    """Base exception carrying a structured error code, retryable flag, and details."""

    default_code: ErrorCode = ErrorCode.ENGINE_ERROR
    default_retryable: bool = False

    def __init__(
        self,
        message: str,
        *,
        code: ErrorCode | str | None = None,
        retryable: bool | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message: str = message
        if code is None:
            resolved_code: ErrorCode | str = self.default_code
        elif isinstance(code, ErrorCode):
            resolved_code = code
        elif not isinstance(code, str):
            raise ValueError("Error code must be a non-blank string.")
        else:
            stripped = code.strip()
            if not stripped:
                raise ValueError("Error code must not be blank.")
            try:
                resolved_code = ErrorCode(stripped)
            except ValueError:
                resolved_code = stripped
        self.code: ErrorCode | str = resolved_code
        self.retryable: bool = self.default_retryable if retryable is None else bool(retryable)
        self.details: dict[str, Any] = copy.deepcopy(dict(details)) if details else {}

    def to_error_dict(self, *, include_details: bool = True) -> dict[str, Any]:
        """Serialize error payload, optionally including diagnostic details."""
        payload: dict[str, Any] = {
            "code": str(self.code),
            "message": self.message,
            "retryable": self.retryable,
        }
        if include_details:
            payload["details"] = copy.deepcopy(self.details)
        return payload

    def to_wire_error(self) -> dict[str, Any]:
        """Return exact 3-key error object compatible with LangGraph tool protocol v1."""
        return self.to_error_dict(include_details=False)

    def to_envelope(self) -> dict[str, Any]:
        """Return Interface §5 envelope `{"error": {"code", "message", "retryable"}}`."""
        return {"error": self.to_wire_error()}


class OutOfScopeError(AptAgentError):
    default_code = ErrorCode.OUT_OF_SCOPE
    default_retryable = False


class PermissionDeniedError(AptAgentError):
    default_code = ErrorCode.PERMISSION_DENIED
    default_retryable = False


class InvalidArgumentError(AptAgentError):
    default_code = ErrorCode.INVALID_ARGUMENT
    default_retryable = False


class EngineError(AptAgentError):
    default_code = ErrorCode.ENGINE_ERROR
    default_retryable = False


class RetrievalUnavailableError(AptAgentError):
    default_code = ErrorCode.RETRIEVAL_UNAVAILABLE
    default_retryable = True


class BudgetExhaustedError(AptAgentError):
    default_code = ErrorCode.BUDGET_EXHAUSTED
    default_retryable = False


class ConflictError(AptAgentError):
    default_code = ErrorCode.CONFLICT_ERROR
    default_retryable = False


class ConfigError(AptAgentError):
    default_code = ErrorCode.CONFIG_ERROR
    default_retryable = False


class OperationTimeoutError(AptAgentError):
    default_code = ErrorCode.TIMEOUT
    default_retryable = True


_CANONICAL_ERROR_MAP: dict[ErrorCode, type[AptAgentError]] = {
    ErrorCode.OUT_OF_SCOPE: OutOfScopeError,
    ErrorCode.PERMISSION_DENIED: PermissionDeniedError,
    ErrorCode.INVALID_ARGUMENT: InvalidArgumentError,
    ErrorCode.ENGINE_ERROR: EngineError,
    ErrorCode.RETRIEVAL_UNAVAILABLE: RetrievalUnavailableError,
    ErrorCode.BUDGET_EXHAUSTED: BudgetExhaustedError,
    ErrorCode.CONFLICT_ERROR: ConflictError,
    ErrorCode.CONFIG_ERROR: ConfigError,
    ErrorCode.TIMEOUT: OperationTimeoutError,
}

_ENGINE_SUBCODES = frozenset(
    {"START_ERROR", "PROCESS_EXIT", "BAD_RESPONSE", "OUTPUT_LIMIT", "DATA_ERROR"}
)
_RETRIEVAL_SUBCODES = frozenset(
    {"MODE_UNAVAILABLE", "DEPENDENCY_MISSING", "RETRIEVAL_ERROR"}
)


def exception_from_error_code(
    code: str,
    message: str,
    *,
    retryable: bool | None = None,
    details: Mapping[str, Any] | None = None,
) -> AptAgentError:
    """Convert canonical or LangGraph v1 tool subcodes into typed AptAgentError instances."""
    if not isinstance(code, str):
        raise ValueError("Error code must be a non-blank string.")
    normalized = code.strip()
    if not normalized:
        raise ValueError("Error code must not be blank.")

    try:
        canonical = ErrorCode(normalized)
    except ValueError:
        canonical = None

    if canonical is not None:
        exc_cls = _CANONICAL_ERROR_MAP[canonical]
        return exc_cls(message, retryable=retryable, details=details)

    merged_details = copy.deepcopy(dict(details)) if details else {}
    merged_details["raw_code"] = normalized

    if normalized in _ENGINE_SUBCODES:
        return EngineError(message, retryable=retryable, details=merged_details)
    if normalized in _RETRIEVAL_SUBCODES:
        return RetrievalUnavailableError(message, retryable=retryable, details=merged_details)

    return AptAgentError(message, code=normalized, retryable=retryable, details=details)


__all__ = [
    "AptAgentError",
    "BudgetExhaustedError",
    "ConfigError",
    "ConflictError",
    "EngineError",
    "ErrorCode",
    "InvalidArgumentError",
    "OperationTimeoutError",
    "OutOfScopeError",
    "PermissionDeniedError",
    "RetrievalUnavailableError",
    "exception_from_error_code",
]
