"""Bounded real health checks."""

from __future__ import annotations

import time
from pathlib import Path

from vuln_agent.config import Settings
from vuln_agent.llm import OllamaClient
from vuln_agent.semgrep import SemgrepAdapter

from .config import WebSettings
from .evaluation_reader import RUN_ID


def timed(name: str, fn):
    started = time.perf_counter()
    try:
        data = fn()
        status = data.pop("status", "ok")
        return {"name": name, "status": status, "response_time_ms": int((time.perf_counter() - started) * 1000), **data}
    except Exception as exc:
        return {"name": name, "status": "unavailable", "response_time_ms": int((time.perf_counter() - started) * 1000), "error": str(exc)[:300]}


def health_payload(scanner: Settings, web: WebSettings, active_scans: int) -> dict:
    semgrep = SemgrepAdapter(scanner)
    ollama = OllamaClient(scanner)
    checks = [
        timed("Backend API", lambda: {"status": "ok", "version": web.api_version}),
        timed("Scanner orchestrator", lambda: {"status": "ok", "version": "vuln-agent"}),
        timed("Semgrep", lambda: {"status": "ok" if semgrep.executable_path() else "unavailable", "version": semgrep.version()}),
        timed("Ollama", lambda: {"status": "ok" if ollama.healthcheck().ok else "unavailable", "message": ollama.healthcheck().message}),
        timed("Report generation", lambda: {"status": "ok" if scanner.report_dir.parent.exists() or scanner.report_dir.parent.mkdir(parents=True, exist_ok=True) is None else "unavailable"}),
        timed("Temporary workspace", lambda: {"status": "ok" if web.scan_temp_root.exists() or web.scan_temp_root.mkdir(parents=True, exist_ok=True) is None else "unavailable"}),
        timed("Evaluation artifacts", lambda: {"status": "ok" if (Path(scanner.evaluation_dir) / RUN_ID).exists() else "unavailable"}),
    ]
    return {
        "api_version": web.api_version,
        "scanner_version": "0.1.0",
        "supported_language": "Python",
        "active_model": scanner.ollama_model,
        "active_scan_count": active_scans,
        "temporary_workspace_policy": f"Temporary workspaces under {web.scan_temp_root.name}, TTL {web.scan_workspace_ttl_seconds}s",
        "checks": checks,
    }

