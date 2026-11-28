"""Externalized configuration models and layered loader for OPEN_APT_AGENT."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from apt_agent.exceptions import ConfigError

_TRUTHY = frozenset({"1", "true", "yes", "on"})
_FALSY = frozenset({"0", "false", "no", "off"})

_NULLABLE_ENV_FIELDS = frozenset(
    {
        "bin_path",
        "rules_dir",
        "config_path",
        "mapping_path",
        "working_dir",
        "knowledge_path",
        "base_url",
        "api_key",
        "model",
    }
)
_BOOL_ENV_FIELDS = frozenset({"enabled", "offline"})

_FLAT_ENV_ALIASES: dict[str, tuple[str, ...]] = {
    "APT_AGENT_MINIMUM_SEED_LEVEL": ("minimum_seed_level",),
    "APT_AGENT_LLM_ENABLED": ("llm", "enabled"),
    "APT_AGENT_LLM_PROVIDER": ("llm", "provider"),
    "APT_AGENT_LLM_API_KEY": ("llm", "api_key"),
    "APT_AGENT_LLM_BASE_URL": ("llm", "base_url"),
    "APT_AGENT_LLM_MODEL": ("llm", "model"),
    "APT_AGENT_RAG_MODE": ("rag", "mode"),
    "APT_AGENT_RAG_KNOWLEDGE_PATH": ("rag", "knowledge_path"),
    "APT_AGENT_SNAPSHOTS_ROOT_DIR": ("snapshots", "root_dir"),
    "APT_AGENT_SNAPSHOTS_ROOT": ("snapshots", "root_dir"),
}


def _reject_bool_numeric(value: Any) -> Any:
    if isinstance(value, bool):
        raise ValueError("Boolean value is not valid for a numeric field.")
    return value


def _require_non_blank_str(value: Any) -> Any:
    if isinstance(value, str) and not value.strip():
        raise ValueError("String field must not be blank.")
    return value


class EngineConfig(BaseModel):
    """Configuration for a single detection engine binary/ruleset."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    bin_path: Path | None = None
    rules_dir: Path | None = None
    config_path: Path | None = None
    mapping_path: Path | None = None
    working_dir: Path | None = None
    timeout_s: float = Field(default=120.0, gt=0.0, le=3600.0)

    @field_validator("timeout_s", mode="before")
    @classmethod
    def _validate_timeout(cls, value: Any) -> Any:
        return _reject_bool_numeric(value)


class EnginesConfig(BaseModel):
    """Collection of supported detection engine configurations."""

    model_config = ConfigDict(extra="forbid")

    zircolite: EngineConfig = Field(default_factory=EngineConfig)
    hayabusa: EngineConfig = Field(default_factory=EngineConfig)
    takajo: EngineConfig = Field(default_factory=EngineConfig)
    chainsaw: EngineConfig = Field(default_factory=EngineConfig)
    rsigma: EngineConfig = Field(default_factory=EngineConfig)
    pysigma: EngineConfig = Field(default_factory=EngineConfig)


class RagConfig(BaseModel):
    """Configuration for RAG retrieval (LangGraph tool + BM25 fallback)."""

    model_config = ConfigDict(extra="forbid")

    knowledge_path: Path | None = None
    config_path: Path | None = None
    mode: Literal["bm25", "dense", "hybrid"] = "bm25"
    top_k: int = Field(default=5, ge=1, le=20)
    timeout_ms: int = Field(default=60000, ge=100, le=300000)
    offline: bool = True

    @field_validator("top_k", "timeout_ms", mode="before")
    @classmethod
    def _validate_ints(cls, value: Any) -> Any:
        return _reject_bool_numeric(value)


class LLMConfig(BaseModel):
    """Configuration for optional LLM-backed planning and reasoning."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    provider: str = Field(default="openai_compatible", min_length=1)
    base_url: str | None = None
    api_key: str | None = Field(default=None, repr=False)
    model: str | None = None
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    max_tokens: int = Field(default=4096, ge=1)
    timeout_s: float = Field(default=60.0, gt=0.0)

    @field_validator("provider", mode="before")
    @classmethod
    def _validate_provider(cls, value: Any) -> Any:
        return _require_non_blank_str(value)

    @field_validator("base_url", "api_key", "model", mode="before")
    @classmethod
    def _normalize_optional_str(cls, value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, str):
            stripped = value.strip()
            return stripped if stripped else None
        return value

    @field_validator("temperature", "max_tokens", "timeout_s", mode="before")
    @classmethod
    def _validate_numeric(cls, value: Any) -> Any:
        return _reject_bool_numeric(value)

    @property
    def is_configured(self) -> bool:
        return self.enabled and bool(
            self.model
            and self.model.strip()
            and (
                (self.api_key and self.api_key.strip())
                or (self.base_url and self.base_url.strip())
            )
        )


class BudgetConfig(BaseModel):
    """Investigation loop resource and round budgets."""

    model_config = ConfigDict(extra="forbid")

    max_tasks_per_round: int = Field(default=3, ge=1)
    max_rounds: int = Field(default=5, ge=1)
    max_steps_per_task: int = Field(default=8, ge=1)
    max_challenger_rounds: int = Field(default=1, ge=0)
    max_repair_rounds: int = Field(default=1, ge=0)
    wall_clock_s: float = Field(default=300.0, gt=0.0)
    max_tokens: int = Field(default=120000, ge=1)
    reserve_ratio: float = Field(default=0.8, gt=0.0, le=1.0)

    @field_validator(
        "max_tasks_per_round",
        "max_rounds",
        "max_steps_per_task",
        "max_challenger_rounds",
        "max_repair_rounds",
        "wall_clock_s",
        "max_tokens",
        "reserve_ratio",
        mode="before",
    )
    @classmethod
    def _validate_numeric(cls, value: Any) -> Any:
        return _reject_bool_numeric(value)


class SnapshotsConfig(BaseModel):
    """Versioned snapshot root and default bindings."""

    model_config = ConfigDict(extra="forbid")

    root_dir: Path = Path(".apt_agent/snapshots")
    mapping_version: str = Field(default="v1", min_length=1)
    ruleset_version: str = Field(default="v1", min_length=1)
    knowledge_snapshot_id: str = Field(default="public_kb", min_length=1)

    @field_validator("root_dir", mode="before")
    @classmethod
    def _validate_root_dir(cls, value: Any) -> Any:
        if value is None:
            raise ValueError("snapshots.root_dir must not be null.")
        if isinstance(value, str) and not value.strip():
            raise ValueError("snapshots.root_dir must not be blank.")
        return value

    @field_validator("mapping_version", "ruleset_version", "knowledge_snapshot_id", mode="before")
    @classmethod
    def _validate_non_blank(cls, value: Any) -> Any:
        return _require_non_blank_str(value)


class AppConfig(BaseModel):
    """Top-level configuration object injected into RunContext and pipeline entrypoints."""

    model_config = ConfigDict(extra="forbid")

    minimum_seed_level: Literal["informational", "low", "medium", "high", "critical"] = "medium"
    engines: EnginesConfig = Field(default_factory=EnginesConfig)
    rag: RagConfig = Field(default_factory=RagConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    snapshots: SnapshotsConfig = Field(default_factory=SnapshotsConfig)

    def redacted_dump(self) -> dict[str, Any]:
        """Return a JSON-safe dict with secret credentials masked."""
        data = self.model_dump(mode="json")
        if data.get("llm", {}).get("api_key"):
            data["llm"]["api_key"] = "***"
        return data


def _deep_merge(base: Mapping[str, Any], patch: Mapping[str, Any]) -> dict[str, Any]:
    """Recursively merge `patch` onto `base` without mutating either input."""
    merged: dict[str, Any] = {
        k: (_deep_merge({}, v) if isinstance(v, Mapping) else v)
        for k, v in base.items()
    }
    for key, value in patch.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), Mapping):
            merged[key] = _deep_merge(merged[key], value)
        elif isinstance(value, Mapping):
            merged[key] = _deep_merge({}, value)
        else:
            merged[key] = value
    return merged


def _set_nested(target: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    cursor = target
    for segment in path[:-1]:
        existing = cursor.get(segment)
        if not isinstance(existing, dict):
            existing = {}
            cursor[segment] = existing
        cursor = existing
    cursor[path[-1]] = value


def _coerce_env_value(env_key: str, field_name: str, raw_val: str) -> Any:
    stripped = raw_val.strip()
    if field_name in _BOOL_ENV_FIELDS:
        lowered = stripped.lower()
        if lowered in _TRUTHY:
            return True
        if lowered in _FALSY:
            return False
        raise ConfigError(
            f"Invalid boolean value for environment variable {env_key}.",
            details={"env_var": env_key, "value": raw_val},
        )
    if field_name in _NULLABLE_ENV_FIELDS and stripped == "":
        return None
    return stripped


def _load_yaml_dict(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ConfigError(
            f"Configuration file not found: {path}",
            details={"config_path": str(path)},
        )
    try:
        raw_text = path.read_text(encoding="utf-8")
        loaded = yaml.safe_load(raw_text)
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(
            f"Failed to read or parse configuration YAML: {path}",
            details={"config_path": str(path), "reason": str(exc)},
        ) from exc

    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ConfigError(
            f"Configuration YAML root must be a mapping: {path}",
            details={"config_path": str(path), "actual_type": type(loaded).__name__},
        )
    return loaded


def _extract_env_layers(env_map: Mapping[str, str]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    openai_layer: dict[str, Any] = {}
    flat_layer: dict[str, Any] = {}
    nested_layer: dict[str, Any] = {}

    openai_mapping = {
        "OPENAI_API_KEY": ("llm", "api_key"),
        "OPENAI_BASE_URL": ("llm", "base_url"),
        "OPENAI_MODEL": ("llm", "model"),
    }
    for env_key, path in openai_mapping.items():
        if env_key in env_map:
            val = env_map[env_key].strip()
            if val:
                _set_nested(openai_layer, path, val)

    for env_key, raw_val in env_map.items():
        if env_key == "APT_AGENT_CONFIG":
            continue
        if env_key in _FLAT_ENV_ALIASES:
            path = _FLAT_ENV_ALIASES[env_key]
            coerced = _coerce_env_value(env_key, path[-1], raw_val)
            _set_nested(flat_layer, path, coerced)
            continue
        if env_key.startswith("APT_AGENT_") and "__" in env_key:
            suffix = env_key[len("APT_AGENT_") :]
            segments = tuple(part.lower() for part in suffix.split("__"))
            if any(not seg for seg in segments):
                raise ConfigError(
                    f"Malformed nested configuration variable: {env_key}",
                    details={"env_var": env_key},
                )
            coerced = _coerce_env_value(env_key, segments[-1], raw_val)
            _set_nested(nested_layer, segments, coerced)

    return openai_layer, flat_layer, nested_layer


def load_config(
    config_path: Path | str | None = None,
    *,
    overrides: Mapping[str, Any] | None = None,
    env: Mapping[str, str] | None = None,
) -> AppConfig:
    """Load configuration with precedence: overrides > APT_AGENT_* > OPENAI_* > YAML > defaults."""
    env_map: Mapping[str, str] = os.environ if env is None else env

    resolved_path: Path | str | None = config_path
    if resolved_path is None:
        env_cfg = env_map.get("APT_AGENT_CONFIG")
        if env_cfg is not None and env_cfg.strip():
            resolved_path = env_cfg.strip()
    elif isinstance(resolved_path, str) and not resolved_path.strip():
        resolved_path = None

    merged: dict[str, Any] = {}
    if resolved_path is not None:
        merged = _load_yaml_dict(Path(resolved_path))

    openai_layer, flat_layer, nested_layer = _extract_env_layers(env_map)
    for layer in (openai_layer, flat_layer, nested_layer):
        if layer:
            merged = _deep_merge(merged, layer)

    if overrides is not None:
        if not isinstance(overrides, Mapping):
            raise ConfigError(
                "Configuration overrides must be a mapping.",
                details={"actual_type": type(overrides).__name__},
            )
        merged = _deep_merge(merged, overrides)

    try:
        return AppConfig.model_validate(merged)
    except ValidationError as exc:
        raise ConfigError(
            "Invalid configuration.",
            details={"errors": exc.errors()},
        ) from exc


__all__ = [
    "AppConfig",
    "BudgetConfig",
    "EngineConfig",
    "EnginesConfig",
    "LLMConfig",
    "RagConfig",
    "SnapshotsConfig",
    "load_config",
]
