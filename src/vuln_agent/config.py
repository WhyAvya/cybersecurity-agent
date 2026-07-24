"""Typed configuration with CLI > environment > file > defaults precedence."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from .exceptions import ConfigurationError


class Settings(BaseModel):
    app_env: str = "local"
    log_level: str = "INFO"
    data_root: Path = Path("data")
    artifact_root: Path = Path("artifacts")
    report_dir: Path = Path("artifacts/reports")
    evaluation_dir: Path = Path("artifacts/evaluation")
    ground_truth_path: Path = Path("evaluation/ground_truth.json")
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen2.5-coder:7b"
    ollama_timeout_seconds: float = Field(default=120, gt=0)
    ollama_connect_timeout_seconds: float = Field(default=10, gt=0)
    ollama_max_retries: int = Field(default=2, ge=0, le=10)
    ollama_temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    ollama_seed: int | None = 42
    ollama_num_ctx: int | None = Field(default=2048, ge=512)
    semgrep_binary: str = "semgrep"
    semgrep_config: str = "semgrep-rules/python"
    semgrep_timeout_seconds: float = Field(default=120, gt=0)
    semgrep_version_timeout_seconds: float = Field(default=10, gt=0)
    semgrep_no_git_ignore: bool = False
    context_lines_before: int = Field(default=10, ge=0, le=200)
    context_lines_after: int = Field(default=10, ge=0, le=200)
    max_file_size_bytes: int = Field(default=1_000_000, ge=1)
    max_files_per_scan: int = Field(default=5000, ge=1)
    allowed_extensions: tuple[str, ...] = (".py",)
    excluded_directories: tuple[str, ...] = (
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        "node_modules",
        "artifacts",
        "results",
        "reports",
    )
    allowed_scan_root: Path = Path(".")
    allow_scan_root_escape: bool = False
    hybrid_accept_confidence: float = Field(default=0.60, ge=0.0, le=1.0)
    hybrid_dedupe_line_threshold: int = Field(default=3, ge=0, le=20)
    high_priority_confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    max_agent_iterations: int = Field(default=3, ge=1, le=10)
    evaluation_seed: int = 42
    llm_baseline_sample_size: int = Field(default=100, ge=1)
    consistency_sample_size: int = Field(default=30, ge=1)
    prompt_sensitivity_sample_size: int = Field(default=30, ge=1)

    @field_validator("allowed_extensions", "excluded_directories", mode="before")
    @classmethod
    def _split_csv(cls, value: Any) -> Any:
        if isinstance(value, str):
            return tuple(part.strip() for part in value.split(",") if part.strip())
        return value

    @field_validator("allowed_extensions")
    @classmethod
    def _normalize_extensions(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(ext if ext.startswith(".") else f".{ext}" for ext in value)

    @model_validator(mode="after")
    def _validate_thresholds(self) -> "Settings":
        if self.high_priority_confidence < self.hybrid_accept_confidence:
            raise ValueError("HIGH_PRIORITY_CONFIDENCE must be >= HYBRID_ACCEPT_CONFIDENCE")
        return self


ENV_MAP = {field.upper(): field for field in Settings.model_fields}


def _read_config_file(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    if not path.exists():
        raise ConfigurationError(f"Configuration file does not exist: {path}")
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return json.loads(text)
    try:
        import yaml  # type: ignore
    except Exception as exc:  # pragma: no cover - depends on optional import
        raise ConfigurationError("YAML config requires PyYAML to be installed") from exc
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise ConfigurationError("Configuration file must contain a mapping")
    return data


def _environment_values() -> dict[str, Any]:
    values: dict[str, Any] = {}
    for env_name, field_name in ENV_MAP.items():
        if env_name in os.environ:
            values[field_name] = os.environ[env_name]
    return values


def load_settings(
    config_path: str | Path | None = None,
    cli_overrides: dict[str, Any] | None = None,
) -> Settings:
    values: dict[str, Any] = {}
    values.update(_read_config_file(Path(config_path) if config_path else None))
    values.update(_environment_values())
    values.update({k: v for k, v in (cli_overrides or {}).items() if v is not None})
    try:
        return Settings(**values)
    except ValidationError as exc:
        raise ConfigurationError(str(exc)) from exc
