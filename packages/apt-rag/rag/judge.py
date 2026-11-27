"""LLM-as-a-Judge core for silver relevance labels.

Security and validity rules:
- API keys are read only from environment variables and are never logged.
- Candidate passages are untrusted; the system prompt forbids following their
  instructions, and each request uses a random nonce delimiter.
- Failed or invalid judgments are never converted to relevance 0.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]


class JudgeError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        usage: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.usage = dict(usage or {})


@dataclass(frozen=True)
class JudgeConfig:
    provider: str
    prompt_version: str
    prompt_system_path: Path
    prompt_user_path: Path
    max_tokens: int
    temperature: float
    timeout_seconds: int
    max_retries: int
    max_parse_retries: int
    max_candidate_chars: int
    workers: int
    openai_base_url: str
    openai_model: str
    openai_key_env: str
    anthropic_base_url_env: str
    anthropic_token_env: str
    anthropic_model_env: str
    anthropic_fallback_model: str
    anthropic_disable_thinking: bool
    price_input_per_m: float
    price_output_per_m: float
    pricing_note: str


def _resolve(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def load_judge_config(path: str | Path = PROJECT_ROOT / "configs" / "judge.yaml") -> JudgeConfig:
    path = Path(path)
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    openai_data = data.get("openai") or {}
    anthropic_data = data.get("anthropic") or {}
    pricing = data.get("pricing") or {}
    provider = str(data.get("provider", "auto")).lower()
    if provider not in {"auto", "openai", "anthropic"}:
        raise ValueError("judge.provider must be auto, openai, or anthropic")
    return JudgeConfig(
        provider=provider,
        prompt_version=str(data.get("prompt_version", "judge_v1")),
        prompt_system_path=_resolve(str(data.get("prompt_system", "prompts/judge_v1_system.txt"))),
        prompt_user_path=_resolve(str(data.get("prompt_user", "prompts/judge_v1_user.txt"))),
        max_tokens=int(data.get("max_tokens", 400)),
        temperature=float(data.get("temperature", 0.0)),
        timeout_seconds=int(data.get("timeout_seconds", 90)),
        max_retries=max(1, int(data.get("max_retries", 3))),
        max_parse_retries=max(0, int(data.get("max_parse_retries", 2))),
        max_candidate_chars=int(data.get("max_candidate_chars", 12000)),
        workers=max(1, int(data.get("workers", 4))),
        openai_base_url=str(openai_data.get("base_url", "https://api.deepseek.com/v1")),
        openai_model=str(openai_data.get("model", "deepseek-chat")),
        openai_key_env=str(openai_data.get("api_key_env", "DEEPSEEK_API_KEY")),
        anthropic_base_url_env=str(anthropic_data.get("base_url_env", "ANTHROPIC_BASE_URL")),
        anthropic_token_env=str(anthropic_data.get("token_env", "ANTHROPIC_AUTH_TOKEN")),
        anthropic_model_env=str(anthropic_data.get("model_env", "ANTHROPIC_MODEL")),
        anthropic_fallback_model=str(anthropic_data.get("fallback_model", "deepseek-chat")),
        anthropic_disable_thinking=bool(anthropic_data.get("disable_thinking", True)),
        price_input_per_m=float(pricing.get("input_per_million_usd", 0.0)),
        price_output_per_m=float(pricing.get("output_per_million_usd", 0.0)),
        pricing_note=str(pricing.get("note", "")),
    )


def load_templates(config: JudgeConfig) -> tuple[str, str]:
    return (
        config.prompt_system_path.read_text(encoding="utf-8"),
        config.prompt_user_path.read_text(encoding="utf-8"),
    )


def template_sha256(system: str, user_template: str) -> str:
    payload = (system + "\n---USER---\n" + user_template).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def build_messages(
    config: JudgeConfig,
    system: str,
    user_template: str,
    *,
    question: Mapping[str, Any],
    candidate: Mapping[str, Any],
    judge_model: str,
) -> tuple[str, str, bool, str]:
    full_text = str(candidate.get("text") or "")
    truncated = len(full_text) > config.max_candidate_chars
    text = full_text[: config.max_candidate_chars]
    nonce = secrets.token_hex(8)
    user = user_template.format(
        query_id=str(question.get("question_id") or ""),
        question=str(question.get("question") or ""),
        category=str(question.get("category") or "unknown"),
        candidate_id=str(candidate.get("candidate_id") or ""),
        title=str(candidate.get("title") or ""),
        text=text,
        judge_model=judge_model,
        nonce=nonce,
    )
    return system, user, truncated, nonce


def extract_json(text: str) -> dict[str, Any]:
    if not isinstance(text, str) or not text.strip():
        raise JudgeError("invalid_json", "empty model output")
    raw = text.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.S | re.I)
    if fenced:
        raw = fenced.group(1)
    else:
        start = raw.find("{")
        end = raw.rfind("}")
        if start < 0 or end <= start:
            raise JudgeError("invalid_json", "no JSON object found")
        raw = raw[start : end + 1]
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise JudgeError("invalid_json", f"JSON decode failed: {exc}") from exc
    if not isinstance(payload, dict):
        raise JudgeError("invalid_schema", "model output is not a JSON object")
    return payload


def validate_payload(
    payload: Mapping[str, Any],
    *,
    query_id: str,
    candidate_id: str,
    candidate_text: str,
    expected_model: str,
) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise JudgeError("invalid_schema", "payload is not an object")
    required = {"query_id", "candidate_id", "relevance", "reason", "supporting_quote", "judge_model"}
    missing = required - set(payload)
    if missing:
        raise JudgeError("invalid_schema", f"missing fields: {sorted(missing)}")
    if str(payload["query_id"]) != query_id:
        raise JudgeError("id_mismatch", "query_id does not match the requested question")
    if str(payload["candidate_id"]) != candidate_id:
        raise JudgeError("id_mismatch", "candidate_id does not match the requested candidate")
    relevance = payload["relevance"]
    if isinstance(relevance, bool) or not isinstance(relevance, (int, str)):
        raise JudgeError("invalid_schema", "relevance must be an integer 0/1/2")
    try:
        relevance = int(relevance)
    except (TypeError, ValueError) as exc:
        raise JudgeError("invalid_schema", "relevance must be an integer 0/1/2") from exc
    if relevance not in {0, 1, 2}:
        raise JudgeError("invalid_schema", "relevance must be 0, 1, or 2")

    reason = str(payload["reason"] or "").strip()
    if not reason:
        raise JudgeError("invalid_schema", "reason must be non-empty")
    if len(reason) > 1200:
        reason = reason[:1200]
    quote = payload["supporting_quote"]
    if quote is None:
        quote = ""
    if not isinstance(quote, str):
        raise JudgeError("invalid_schema", "supporting_quote must be a string or null")
    quote = quote.strip()
    if relevance in {1, 2} and not quote:
        raise JudgeError("invalid_quote", "relevance 1/2 requires a supporting_quote")
    if relevance == 0 and quote and quote not in candidate_text:
        # A zero label has no evidence requirement. Some judges still emit a
        # title-like phrase in supporting_quote; normalize it to empty rather
        # than failing an otherwise valid relevance-0 decision. Relevance 1/2
        # still requires an exact substring.
        quote = ""
    if quote and quote not in candidate_text:
        raise JudgeError("invalid_quote", "supporting_quote is not an exact substring of the candidate")
    reported_model = str(payload["judge_model"] or "").strip()
    if not reported_model:
        raise JudgeError("invalid_schema", "judge_model must be non-empty")
    return {
        "query_id": query_id,
        "candidate_id": candidate_id,
        "relevance": relevance,
        "reason": reason,
        "supporting_quote": quote,
        "judge_model": expected_model,
        "reported_judge_model": reported_model,
    }


def _sanitize(value: str, secret: str) -> str:
    text = value.replace(secret, "***") if secret else value
    return " ".join(text.split())[:500]


class JudgeClient(Protocol):
    provider: str
    model: str

    def complete(self, system: str, user: str) -> dict[str, Any]: ...


class _HTTPJudgeClient:
    provider = "http"
    model = ""

    def __init__(
        self,
        *,
        model: str,
        max_tokens: int,
        temperature: float,
        timeout_seconds: int,
        max_retries: int,
    ) -> None:
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries

    def _post(self, url: str, headers: Mapping[str, str], body: Mapping[str, Any], secret: str) -> dict[str, Any]:
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        last_error = ""
        for attempt in range(1, self.max_retries + 1):
            started = time.perf_counter()
            try:
                request = urllib.request.Request(
                    url,
                    data=payload,
                    headers=dict(headers),
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                    raw = response.read()
                return {
                    "data": json.loads(raw),
                    "latency_ms": (time.perf_counter() - started) * 1000,
                }
            except urllib.error.HTTPError as exc:
                body_text = _sanitize(exc.read().decode("utf-8", errors="replace"), secret)
                last_error = f"HTTP {exc.code}: {body_text}"
                if exc.code in {408, 409, 429, 500, 502, 503, 504} and attempt < self.max_retries:
                    time.sleep(2 ** (attempt - 1))
                    continue
                break
            except Exception as exc:  # noqa: BLE001 - sanitize all client failures
                last_error = _sanitize(f"{type(exc).__name__}: {exc}", secret)
                if attempt < self.max_retries:
                    time.sleep(2 ** (attempt - 1))
                    continue
                break
        raise JudgeError("api_error", last_error or "API request failed")


class AnthropicCompatibleClient(_HTTPJudgeClient):
    provider = "anthropic-compatible"

    def __init__(
        self,
        *,
        base_url: str,
        token: str,
        model: str,
        disable_thinking: bool = False,
        **kwargs: Any,
    ) -> None:
        super().__init__(model=model, **kwargs)
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._disable_thinking = disable_thinking
        if self._base_url.endswith("/messages"):
            self._endpoint = self._base_url
        elif self._base_url.endswith("/v1"):
            self._endpoint = self._base_url + "/messages"
        else:
            self._endpoint = self._base_url + "/v1/messages"

    def complete(self, system: str, user: str) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        if self._disable_thinking:
            body["thinking"] = {"type": "disabled"}
        result = self._post(
            self._endpoint,
            {
                "content-type": "application/json",
                "anthropic-version": "2023-06-01",
                "x-api-key": self._token,
                "Authorization": f"Bearer {self._token}",
            },
            body,
            self._token,
        )
        data = result["data"]
        blocks = data.get("content") or []
        text = "".join(
            str(block.get("text") or "")
            for block in blocks
            if isinstance(block, Mapping) and block.get("type") == "text"
        )
        if not text.strip():
            block_types = [
                str(block.get("type"))
                for block in blocks
                if isinstance(block, Mapping)
            ]
            usage = data.get("usage") or {}
            raise JudgeError(
                "empty_response",
                "no text block; "
                f"types={block_types}; stop_reason={data.get('stop_reason')}; "
                f"output_tokens={usage.get('output_tokens')}",
                usage={
                    "input_tokens": int(usage.get("input_tokens") or 0),
                    "output_tokens": int(usage.get("output_tokens") or 0),
                },
            )
        usage = data.get("usage") or {}
        return {
            "text": text,
            "model": str(data.get("model") or self.model),
            "provider": self.provider,
            "input_tokens": int(usage.get("input_tokens") or 0),
            "output_tokens": int(usage.get("output_tokens") or 0),
            "latency_ms": result["latency_ms"],
        }


class OpenAICompatibleClient(_HTTPJudgeClient):
    provider = "openai-compatible"

    def __init__(self, *, base_url: str, api_key: str, model: str, **kwargs: Any) -> None:
        super().__init__(model=model, **kwargs)
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._endpoint = self._base_url + "/chat/completions"

    def complete(self, system: str, user: str) -> dict[str, Any]:
        result = self._post(
            self._endpoint,
            {
                "content-type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
            },
            {
                "model": self.model,
                "max_tokens": self.max_tokens,
                "temperature": self.temperature,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
            self._api_key,
        )
        data = result["data"]
        choices = data.get("choices") or []
        if not choices:
            raise JudgeError("empty_response", "OpenAI-compatible response has no choices")
        message = choices[0].get("message") or {}
        text = str(message.get("content") or "")
        if not text.strip():
            raise JudgeError("empty_response", "OpenAI-compatible response has no text content")
        usage = data.get("usage") or {}
        return {
            "text": text,
            "model": str(data.get("model") or self.model),
            "provider": self.provider,
            "input_tokens": int(usage.get("prompt_tokens") or 0),
            "output_tokens": int(usage.get("completion_tokens") or 0),
            "latency_ms": result["latency_ms"],
        }


def create_client(config: JudgeConfig, *, model_override: str | None = None) -> JudgeClient:
    provider = config.provider
    if provider == "auto":
        if os.environ.get(config.openai_key_env):
            provider = "openai"
        elif os.environ.get(config.anthropic_base_url_env) and os.environ.get(config.anthropic_token_env):
            provider = "anthropic"
        else:
            raise JudgeError(
                "no_provider",
                "no judge credentials found; set DEEPSEEK_API_KEY/OPENAI_API_KEY "
                "or the configured Anthropic-compatible environment variables",
            )
    common = {
        "max_tokens": config.max_tokens,
        "temperature": config.temperature,
        "timeout_seconds": config.timeout_seconds,
        "max_retries": config.max_retries,
    }
    if provider == "openai":
        api_key = os.environ.get(config.openai_key_env)
        if not api_key:
            raise JudgeError("no_provider", f"missing environment variable {config.openai_key_env}")
        return OpenAICompatibleClient(
            base_url=config.openai_base_url,
            api_key=api_key,
            model=model_override or config.openai_model,
            **common,
        )
    if provider == "anthropic":
        base_url = os.environ.get(config.anthropic_base_url_env)
        token = os.environ.get(config.anthropic_token_env)
        model = (
            model_override
            or os.environ.get(config.anthropic_model_env)
            or config.anthropic_fallback_model
        )
        if not base_url or not token:
            raise JudgeError(
                "no_provider",
                f"missing {config.anthropic_base_url_env} or {config.anthropic_token_env}",
            )
        return AnthropicCompatibleClient(
            base_url=base_url,
            token=token,
            model=model,
            disable_thinking=config.anthropic_disable_thinking,
            **common,
        )
    raise JudgeError("no_provider", f"unsupported provider: {provider}")


def annotate_one(
    client: JudgeClient,
    config: JudgeConfig,
    system: str,
    user_template: str,
    *,
    question: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> dict[str, Any]:
    query_id = str(question.get("question_id") or "")
    candidate_id = str(candidate.get("candidate_id") or "")
    candidate_text = str(candidate.get("text") or "")
    attempts = 0
    input_tokens = 0
    output_tokens = 0
    latencies: list[float] = []
    last_error: JudgeError | None = None
    last_prompt_hash = ""
    truncated = False

    for parse_attempt in range(config.max_parse_retries + 1):
        system_text, user_text, truncated, _nonce = build_messages(
            config,
            system,
            user_template,
            question=question,
            candidate=candidate,
            judge_model=client.model,
        )
        last_prompt_hash = hashlib.sha256(
            (system_text + "\n---USER---\n" + user_text).encode("utf-8")
        ).hexdigest()
        attempts += 1
        try:
            result = client.complete(system_text, user_text)
        except JudgeError as exc:
            input_tokens += int(exc.usage.get("input_tokens") or 0)
            output_tokens += int(exc.usage.get("output_tokens") or 0)
            last_error = exc
            break
        input_tokens += int(result.get("input_tokens") or 0)
        output_tokens += int(result.get("output_tokens") or 0)
        latencies.append(float(result.get("latency_ms") or 0.0))
        try:
            payload = extract_json(str(result.get("text") or ""))
            validated = validate_payload(
                payload,
                query_id=query_id,
                candidate_id=candidate_id,
                candidate_text=candidate_text[: config.max_candidate_chars],
                expected_model=str(result.get("model") or client.model),
            )
        except JudgeError as exc:
            last_error = exc
            continue
        return {
            "status": "ok",
            **validated,
            "provider": result.get("provider", client.provider),
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "latency_ms": sum(latencies),
            "attempts": attempts,
            "prompt_sha256": last_prompt_hash,
            "text_truncated": truncated,
            "error": None,
        }

    return {
        "status": "failed",
        "query_id": query_id,
        "candidate_id": candidate_id,
        "provider": client.provider,
        "judge_model": client.model,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "latency_ms": sum(latencies),
        "attempts": attempts,
        "prompt_sha256": last_prompt_hash,
        "text_truncated": truncated,
        "error": {
            "code": last_error.code if last_error else "unknown_error",
            "message": last_error.message if last_error else "judgment failed",
        },
    }


def cost_estimate(input_tokens: int, output_tokens: int, config: JudgeConfig) -> float:
    return (
        input_tokens / 1_000_000 * config.price_input_per_m
        + output_tokens / 1_000_000 * config.price_output_per_m
    )
