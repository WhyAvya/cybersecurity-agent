"""Configuration for the thin web API adapter."""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field, field_validator


class WebSettings(BaseModel):
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8000, ge=1, le=65535)
    api_cors_origins: tuple[str, ...] = ("http://localhost:5173", "http://127.0.0.1:5173")
    api_version: str = "0.1.0"
    scan_temp_root: Path = Path(".scan_runtime")
    scan_workspace_ttl_seconds: int = Field(default=3600, ge=60)
    scan_timeout_seconds: int = Field(default=600, ge=10)
    github_clone_timeout_seconds: int = Field(default=60, ge=5)
    max_repository_bytes: int = Field(default=50_000_000, ge=1)
    max_zip_bytes: int = Field(default=20_000_000, ge=1)
    max_extracted_bytes: int = Field(default=40_000_000, ge=1)
    max_source_file_bytes: int = Field(default=1_000_000, ge=1)
    max_source_files: int = Field(default=200, ge=1)
    allowed_source_extensions: tuple[str, ...] = (".py",)
    ignored_paths: tuple[str, ...] = (
        ".git",
        ".github",
        "venv",
        ".venv",
        "node_modules",
        "__pycache__",
        "dist",
        "build",
        "coverage",
        "vendor",
        "artifacts",
        "reports",
    )

    @field_validator("api_cors_origins", "allowed_source_extensions", "ignored_paths", mode="before")
    @classmethod
    def _split_csv(cls, value):
        if isinstance(value, str):
            return tuple(part.strip() for part in value.split(",") if part.strip())
        return value

    @field_validator("allowed_source_extensions")
    @classmethod
    def _normalize_extensions(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(ext if ext.startswith(".") else f".{ext}" for ext in value)


def load_web_settings() -> WebSettings:
    values = {}
    for field in WebSettings.model_fields:
        env_name = field.upper()
        if env_name in os.environ:
            values[field] = os.environ[env_name]
    return WebSettings(**values)

