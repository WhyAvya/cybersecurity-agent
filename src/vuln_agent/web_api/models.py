"""API response and request models."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


ScanMode = Literal["semgrep", "llm", "semgrep_gated", "hybrid"]


class ApiError(BaseModel):
    code: str
    message: str
    stage: str | None = None
    recoverable: bool = True
    details: dict[str, Any] = Field(default_factory=dict)


class SourceFile(BaseModel):
    path: str
    size: int
    selected: bool = True
    content: str | None = None


class SourceRecord(BaseModel):
    source_id: str
    source_type: Literal["paste", "files", "zip", "github"]
    name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    files: list[SourceFile]
    metadata: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


class PasteSourceRequest(BaseModel):
    filename: str = "pasted.py"
    code: str


class GitHubRevision(BaseModel):
    type: Literal["default", "branch", "tag", "commit"] = "default"
    value: str = ""


class GitHubInspectRequest(BaseModel):
    repository_url: str
    revision: GitHubRevision = Field(default_factory=GitHubRevision)
    subdirectory: str = ""
    include_tests: bool = True


class CreateScanRequest(BaseModel):
    source_id: str
    mode: ScanMode = "hybrid"
    scan_name: str = "Security scan"
    selected_files: list[str] | None = None
    save_raw: bool = True


class JobState(str, Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class ScanProgress(BaseModel):
    stage: str
    current_file: str | None = None
    files_completed: int = 0
    files_total: int = 0
    started_at: datetime | None = None
    ended_at: datetime | None = None
    elapsed_seconds: float = 0


class Artifact(BaseModel):
    name: str
    category: str
    path: str
    size: int


class ScanJob(BaseModel):
    scan_id: str
    source_id: str
    name: str
    mode: ScanMode
    state: JobState
    progress: ScanProgress
    warnings: list[str] = Field(default_factory=list)
    error: ApiError | None = None
    result: dict[str, Any] | None = None
    artifacts: list[Artifact] = Field(default_factory=list)

