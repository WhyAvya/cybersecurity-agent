"""Provider-neutral LLM interface and Ollama implementation."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Protocol

import requests
from pydantic import BaseModel

from .config import Settings
from .exceptions import LLMError, SchemaParseError
from .schemas import ModelMetadata
from .utils import parse_model_json


@dataclass(frozen=True)
class HealthStatus:
    ok: bool
    message: str
    metadata: ModelMetadata | None = None


@dataclass(frozen=True)
class LLMResult:
    parsed: BaseModel
    raw_text: str
    metadata: ModelMetadata
    latency_ms: int


class LLMClient(Protocol):
    def healthcheck(self) -> HealthStatus: ...

    def generate_structured(self, prompt: str, schema: type[BaseModel]) -> LLMResult: ...


class OllamaClient:
    def __init__(self, settings: Settings, session: requests.Session | None = None) -> None:
        self.settings = settings
        self.session = session or requests.Session()
        self.base_url = settings.ollama_base_url.rstrip("/")

    def healthcheck(self) -> HealthStatus:
        try:
            response = self.session.get(
                f"{self.base_url}/api/tags",
                timeout=(
                    self.settings.ollama_connect_timeout_seconds,
                    self.settings.ollama_timeout_seconds,
                ),
            )
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            return HealthStatus(False, f"Ollama unreachable: {exc}")
        models = [item.get("name") for item in data.get("models", [])]
        ok = self.settings.ollama_model in models or not models
        message = "Ollama reachable" if ok else f"Model not listed: {self.settings.ollama_model}"
        return HealthStatus(
            ok,
            message,
            ModelMetadata(
                model=self.settings.ollama_model,
                endpoint=self.base_url,
                digest=None,
            ),
        )

    def generate_structured(self, prompt: str, schema: type[BaseModel]) -> LLMResult:
        payload: dict[str, Any] = {
            "model": self.settings.ollama_model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": self.settings.ollama_temperature,
            },
        }
        if self.settings.ollama_seed is not None:
            payload["options"]["seed"] = self.settings.ollama_seed
        if self.settings.ollama_num_ctx is not None:
            payload["options"]["num_ctx"] = self.settings.ollama_num_ctx

        last_error: Exception | None = None
        for attempt in range(self.settings.ollama_max_retries + 1):
            started = time.perf_counter()
            try:
                response = self.session.post(
                    f"{self.base_url}/api/generate",
                    json=payload,
                    timeout=(
                        self.settings.ollama_connect_timeout_seconds,
                        self.settings.ollama_timeout_seconds,
                    ),
                )
                response.raise_for_status()
                body = response.json()
                raw_text = body.get("response", "")
                if not isinstance(raw_text, str) or not raw_text.strip():
                    raise LLMError("Ollama response did not contain text")
                try:
                    parsed = parse_model_json(raw_text, schema)
                except SchemaParseError:
                    raise
                latency_ms = int((time.perf_counter() - started) * 1000)
                metadata = ModelMetadata(
                    model=self.settings.ollama_model,
                    endpoint=self.base_url,
                    digest=body.get("model"),
                    duration_ms=latency_ms,
                )
                return LLMResult(parsed=parsed, raw_text=raw_text, metadata=metadata, latency_ms=latency_ms)
            except SchemaParseError:
                raise
            except (requests.Timeout, requests.ConnectionError, requests.HTTPError, ValueError, LLMError) as exc:
                last_error = exc
                if attempt < self.settings.ollama_max_retries:
                    time.sleep(min(2**attempt, 8))
                    continue
                break
        raise LLMError(f"Ollama generation failed: {last_error}") from last_error


class StaticLLMClient:
    """Small deterministic test/demo client that never reaches the network."""

    def __init__(self, response: BaseModel) -> None:
        self.response = response

    def healthcheck(self) -> HealthStatus:
        return HealthStatus(True, "Static LLM client ready")

    def generate_structured(self, prompt: str, schema: type[BaseModel]) -> LLMResult:
        parsed = schema.model_validate(self.response.model_dump())
        metadata = ModelMetadata(provider="static", model="offline-demo")
        return LLMResult(parsed=parsed, raw_text=parsed.model_dump_json(), metadata=metadata, latency_ms=0)
