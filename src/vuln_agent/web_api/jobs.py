"""In-memory scan job registry."""

from __future__ import annotations

import shutil
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from vuln_agent.config import Settings

from .config import WebSettings
from .models import ApiError, CreateScanRequest, JobState, ScanJob, ScanProgress
from .scanner_adapter import list_artifacts, result_payload, run_existing_scan
from .source_manager import SourceManager


class JobRegistry:
    def __init__(self, scanner_settings: Settings, web_settings: WebSettings, sources: SourceManager) -> None:
        self.scanner_settings = scanner_settings
        self.web_settings = web_settings
        self.sources = sources
        self._jobs: dict[str, ScanJob] = {}
        self._outputs: dict[str, Path] = {}
        self._lock = threading.Lock()
        self._cancelled: set[str] = set()

    def create(self, request: CreateScanRequest) -> ScanJob:
        source, source_root = self.sources.get(request.source_id)
        scan_id = "scan_" + uuid.uuid4().hex
        output_dir = self.web_settings.scan_temp_root.resolve() / scan_id / "reports"
        output_dir.mkdir(parents=True, exist_ok=True)
        job = ScanJob(
            scan_id=scan_id,
            source_id=request.source_id,
            name=request.scan_name,
            mode=request.mode,
            state=JobState.queued,
            progress=ScanProgress(stage="queued", files_total=len(source.files)),
        )
        with self._lock:
            self._jobs[scan_id] = job
            self._outputs[scan_id] = output_dir
        thread = threading.Thread(target=self._run, args=(scan_id, source_root, output_dir, request), daemon=True)
        thread.start()
        return job

    def get(self, scan_id: str) -> ScanJob | None:
        return self._jobs.get(scan_id)

    def cancel(self, scan_id: str) -> ScanJob | None:
        job = self._jobs.get(scan_id)
        if job and job.state in {JobState.queued, JobState.running}:
            self._cancelled.add(scan_id)
            job.state = JobState.cancelled
            job.progress.stage = "cancelled"
            job.progress.ended_at = datetime.now(timezone.utc)
        return job

    def active_count(self) -> int:
        return sum(1 for job in self._jobs.values() if job.state in {JobState.queued, JobState.running})

    def artifact_path(self, scan_id: str, rel: str) -> Path | None:
        base = self._outputs.get(scan_id)
        if not base:
            return None
        path = (base / rel).resolve()
        if base.resolve() not in path.parents and path != base.resolve():
            return None
        return path if path.exists() and path.is_file() else None

    def _run(self, scan_id: str, source_root: Path, output_dir: Path, request: CreateScanRequest) -> None:
        job = self._jobs[scan_id]
        started = datetime.now(timezone.utc)
        job.state = JobState.running
        job.progress = ScanProgress(stage="running scanner", started_at=started, files_total=job.progress.files_total)
        try:
            if scan_id in self._cancelled:
                return
            scan_root = self._selected_source_root(source_root, request.selected_files, scan_id)
            records, out_dir = run_existing_scan(scan_root, output_dir, request.mode, request.save_raw, self.scanner_settings)
            if scan_id in self._cancelled:
                return
            job.artifacts = list_artifacts(out_dir)
            job.result = result_payload(records, out_dir, scan_root)
            job.state = JobState.completed
            job.progress.stage = "completed"
            job.progress.files_completed = job.progress.files_total
        except Exception as exc:
            job.state = JobState.failed
            job.error = ApiError(code="SCAN_FAILED", message="Scan failed.", stage=job.progress.stage, recoverable=True, details={"error": str(exc)[:500]})
            job.progress.stage = "failed"
        finally:
            job.progress.ended_at = datetime.now(timezone.utc)
            job.progress.elapsed_seconds = time.monotonic() - time.monotonic() if not job.progress.started_at else (job.progress.ended_at - job.progress.started_at).total_seconds()
            if job.state == JobState.cancelled:
                shutil.rmtree(output_dir, ignore_errors=True)

    def _selected_source_root(self, source_root: Path, selected_files: list[str] | None, scan_id: str) -> Path:
        if not selected_files:
            return source_root
        staged = self.web_settings.scan_temp_root.resolve() / scan_id / "selected_source"
        root = source_root.resolve()
        for rel in selected_files:
            clean = rel.replace("\\", "/")
            if clean.startswith("/") or ".." in clean.split("/"):
                raise ValueError("Selected source path is invalid.")
            source = (root / clean).resolve()
            if root not in source.parents or not source.is_file() or source.suffix != ".py":
                raise ValueError("Selected source path is outside the source workspace.")
            target = staged / clean
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        return staged
