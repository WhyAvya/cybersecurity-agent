"""FastAPI application for the React frontend."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from vuln_agent.config import load_settings

from .config import load_web_settings
from .evaluation_reader import read_frozen_evaluation
from .github_import import GitHubImporter
from .health import health_payload
from .jobs import JobRegistry
from .models import ApiError, CreateScanRequest, GitHubInspectRequest, PasteSourceRequest
from .source_manager import SourceError, SourceManager

scanner_settings = load_settings()
web_settings = load_web_settings()
sources = SourceManager(web_settings)
jobs = JobRegistry(scanner_settings, web_settings, sources)
github = GitHubImporter(web_settings, sources)

app = FastAPI(title="Vulnerability Discovery API", version=web_settings.api_version)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(web_settings.api_cors_origins),
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)


def api_error(exc: SourceError, stage: str) -> HTTPException:
    return HTTPException(status_code=400, detail=ApiError(code=exc.code, message=str(exc), stage=stage, details=exc.details).model_dump())


@app.get("/api/health")
def get_health():
    return health_payload(scanner_settings, web_settings, jobs.active_count())


@app.get("/api/config")
def get_config():
    return {
        "supported_language": "Python",
        "scan_modes": ["semgrep", "llm", "semgrep_gated", "hybrid"],
        "default_mode": "hybrid",
        "active_model": scanner_settings.ollama_model,
        "limits": {
            "max_source_files": web_settings.max_source_files,
            "max_source_file_bytes": web_settings.max_source_file_bytes,
            "max_zip_bytes": web_settings.max_zip_bytes,
            "ignored_paths": web_settings.ignored_paths,
        },
    }


@app.get("/api/evaluation/frozen")
def get_evaluation():
    return read_frozen_evaluation(Path(scanner_settings.evaluation_dir))


@app.post("/api/sources/paste")
def create_paste(request: PasteSourceRequest):
    try:
        return sources.create_paste(request.filename, request.code)
    except SourceError as exc:
        raise api_error(exc, "creating_paste_source") from exc


@app.post("/api/sources/files")
async def create_files(files: list[UploadFile] = File(...)):
    try:
        payload = [(file.filename or "uploaded.py", await file.read()) for file in files]
        return sources.create_files(payload)
    except SourceError as exc:
        raise api_error(exc, "uploading_files") from exc


@app.post("/api/sources/zip")
async def create_zip(file: UploadFile = File(...)):
    try:
        return sources.create_zip(file.filename or "project.zip", await file.read())
    except SourceError as exc:
        raise api_error(exc, "extracting_zip") from exc


@app.post("/api/sources/github/inspect")
def inspect_github(request: GitHubInspectRequest):
    try:
        return github.inspect(request.repository_url, request.revision.type, request.revision.value, request.subdirectory, request.include_tests)
    except SourceError as exc:
        raise api_error(exc, "importing_github_repository") from exc


@app.get("/api/sources/{source_id}")
def get_source(source_id: str):
    try:
        return sources.get(source_id)[0]
    except SourceError as exc:
        raise api_error(exc, "loading_source") from exc


@app.delete("/api/sources/{source_id}")
def delete_source(source_id: str):
    try:
        sources.delete(source_id)
        return {"deleted": True}
    except SourceError as exc:
        raise api_error(exc, "deleting_source") from exc


@app.post("/api/scans")
def create_scan(request: CreateScanRequest):
    try:
        return jobs.create(request)
    except SourceError as exc:
        raise api_error(exc, "starting_scan") from exc


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    job = jobs.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=ApiError(code="SCAN_NOT_FOUND", message="Scan was not found.", stage="loading_scan").model_dump())
    return job


@app.get("/api/scans/{scan_id}/result")
def get_scan_result(scan_id: str):
    job = jobs.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=ApiError(code="SCAN_NOT_FOUND", message="Scan was not found.", stage="loading_result").model_dump())
    return job.result or {"available": False, "state": job.state}


@app.post("/api/scans/{scan_id}/cancel")
def cancel_scan(scan_id: str):
    job = jobs.cancel(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=ApiError(code="SCAN_NOT_FOUND", message="Scan was not found.", stage="cancelling_scan").model_dump())
    return job


@app.get("/api/scans/{scan_id}/artifacts")
def get_artifacts(scan_id: str):
    job = jobs.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=ApiError(code="SCAN_NOT_FOUND", message="Scan was not found.", stage="loading_artifacts").model_dump())
    return job.artifacts


@app.get("/api/scans/{scan_id}/artifacts/{artifact_path:path}")
def download_artifact(scan_id: str, artifact_path: str):
    path = jobs.artifact_path(scan_id, artifact_path)
    if not path:
        raise HTTPException(status_code=404, detail=ApiError(code="ARTIFACT_NOT_FOUND", message="Artifact was not found.", stage="downloading_artifact").model_dump())
    return FileResponse(path, filename=path.name)


