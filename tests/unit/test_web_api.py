from __future__ import annotations

import io
import json
import time
import zipfile
from pathlib import Path

import pytest

from vuln_agent.config import Settings
from vuln_agent.web_api.config import WebSettings
from vuln_agent.web_api.evaluation_reader import read_frozen_evaluation
from vuln_agent.web_api.github_import import normalize_github_url, validate_revision
from vuln_agent.web_api.jobs import JobRegistry
from vuln_agent.web_api.models import CreateScanRequest, JobState
from vuln_agent.web_api.source_manager import SourceError, SourceManager


def make_settings(tmp_path: Path) -> WebSettings:
    return WebSettings(scan_temp_root=tmp_path, max_source_files=3, max_source_file_bytes=20, max_zip_bytes=10_000)


def test_github_url_validation_accepts_canonical_and_git_suffix() -> None:
    assert normalize_github_url("https://github.com/openai/codex") == (
        "https://github.com/openai/codex",
        "openai",
        "codex",
    )
    assert normalize_github_url("https://github.com/openai/codex.git") == (
        "https://github.com/openai/codex",
        "openai",
        "codex",
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/openai/codex",
        "https://example.com/openai/codex",
        "https://github.com:443/openai/codex",
        "https://user:pass@github.com/openai/codex",
        "https://github.com/openai/codex/issues",
        "git@github.com:openai/codex.git",
        "file:///tmp/repo",
        "https://github.com/127.0.0.1/repo?token=x",
    ],
)
def test_github_url_validation_rejects_unsafe_forms(url: str) -> None:
    with pytest.raises(SourceError):
        normalize_github_url(url)


def test_revision_validation() -> None:
    validate_revision("default", "")
    validate_revision("branch", "main")
    validate_revision("tag", "v1.2.3")
    validate_revision("commit", "0123456789abcdef")
    with pytest.raises(SourceError):
        validate_revision("commit", "main")
    with pytest.raises(SourceError):
        validate_revision("branch", "../main")


def test_paste_and_multiple_files_preserve_relative_paths(tmp_path: Path) -> None:
    manager = SourceManager(make_settings(tmp_path))
    pasted = manager.create_paste("pkg/app.py", "print('ok')\n")
    assert pasted.files[0].path == "pkg/app.py"
    uploaded = manager.create_files([("a.py", b"x = 1\n"), ("pkg/b.py", b"y = 2\n")])
    assert [item.path for item in uploaded.files] == ["a.py", "pkg/b.py"]
    assert not any(str(tmp_path) in item.path for item in uploaded.files)


def test_file_limits_and_extensions(tmp_path: Path) -> None:
    manager = SourceManager(make_settings(tmp_path))
    with pytest.raises(SourceError) as too_large:
        manager.create_files([("big.py", b"x" * 21)])
    assert too_large.value.code == "FILE_TOO_LARGE"
    with pytest.raises(SourceError) as unsupported:
        manager.create_files([("notes.txt", b"x")])
    assert unsupported.value.code == "UNSUPPORTED_EXTENSION"


def test_zip_rejects_traversal_absolute_and_symlink(tmp_path: Path) -> None:
    manager = SourceManager(make_settings(tmp_path))
    for entry in ("../evil.py", "/abs.py", "C:/abs.py"):
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as zf:
            zf.writestr(entry, "x = 1\n")
        with pytest.raises(SourceError):
            manager.create_zip("bad.zip", data.getvalue())

    data = io.BytesIO()
    info = zipfile.ZipInfo("link.py")
    info.external_attr = 0o120777 << 16
    with zipfile.ZipFile(data, "w") as zf:
        zf.writestr(info, "target")
    with pytest.raises(SourceError) as symlink:
        manager.create_zip("bad.zip", data.getvalue())
    assert symlink.value.code == "ZIP_SYMLINK"


def test_zip_file_count_limit(tmp_path: Path) -> None:
    manager = SourceManager(make_settings(tmp_path))
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as zf:
        for index in range(4):
            zf.writestr(f"{index}.py", "x = 1\n")
    with pytest.raises(SourceError) as exc:
        manager.create_zip("too-many.zip", data.getvalue())
    assert exc.value.code == "TOO_MANY_FILES"


def test_evaluation_reader_reports_missing_frozen_artifacts(tmp_path: Path) -> None:
    payload = read_frozen_evaluation(tmp_path)
    assert payload["available"] is False
    assert "Missing frozen artifact files" in payload["error"]


def test_evaluation_reader_loads_nested_canonical_run_by_explicit_path(tmp_path: Path) -> None:
    run = tmp_path / "plan-b-pilot" / "run-a"
    _write_canonical_evaluation_run(run, "run-a")

    payload = read_frozen_evaluation(tmp_path, run)

    assert payload["available"] is True
    assert payload["run_id"] == "run-a"
    assert payload["mode_comparison"][0]["mode"] == "semgrep"
    assert payload["hybrid_agreement"][0]["agreement"] == "agree_vulnerable"


def test_evaluation_reader_reports_missing_canonical_files_for_explicit_path(tmp_path: Path) -> None:
    run = tmp_path / "plan-b-pilot" / "run-missing"
    run.mkdir(parents=True)
    (run / "manifest.json").write_text('{"run_id":"run-missing"}', encoding="utf-8")

    payload = read_frozen_evaluation(tmp_path, run)

    assert payload["available"] is False
    assert "Missing canonical evaluation artifact files" in payload["error"]


def test_evaluation_reader_does_not_select_newest_run_without_explicit_path(tmp_path: Path) -> None:
    _write_canonical_evaluation_run(tmp_path / "newer-run", "newer-run")

    payload = read_frozen_evaluation(tmp_path)

    assert payload["available"] is False
    assert payload["run_id"] != "newer-run"


def _write_canonical_evaluation_run(run: Path, run_id: str) -> None:
    (run / "metrics").mkdir(parents=True)
    (run / "predictions").mkdir()
    (run / "manifest.json").write_text(
        json.dumps({"run_id": run_id, "mode": "all", "sample_size": 1, "selected_ids": ["BenchmarkTest00001"]}),
        encoding="utf-8",
    )
    (run / "metrics" / "summary.csv").write_text(
        "mode,tp,fp,tn,fn,precision,recall,f1,accuracy\nsemgrep,1,0,0,0,1,1,1,1\n",
        encoding="utf-8",
    )
    (run / "metrics" / "per_cwe.csv").write_text(
        "mode,cwe,sample_count,tp,fp,tn,fn\nsemgrep,CWE-078,1,1,0,0,0\n",
        encoding="utf-8",
    )
    for mode in ("semgrep", "llm", "semgrep_gated", "hybrid"):
        row = {
            "test_id": "BenchmarkTest00001",
            "expected_vulnerable": True,
            "predicted_vulnerable": True,
            "detector_agreement": "agree_vulnerable" if mode == "hybrid" else None,
        }
        (run / "predictions" / f"{mode}.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")


def test_job_state_transitions_with_mocked_scanner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import vuln_agent.web_api.jobs as jobs_module

    manager = SourceManager(make_settings(tmp_path / "sources"))
    source = manager.create_paste("app.py", "print('ok')\n")

    def fake_scan(target, output_dir, mode, save_raw, base_settings):
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "manifest.json").write_text("{}", encoding="utf-8")
        (output_dir / "scan_report.jsonl").write_text("", encoding="utf-8")
        return [], output_dir

    monkeypatch.setattr(jobs_module, "run_existing_scan", fake_scan)
    registry = JobRegistry(Settings(), make_settings(tmp_path / "runtime"), manager)
    job = registry.create(CreateScanRequest(source_id=source.source_id, mode="hybrid", selected_files=["app.py"]))
    for _ in range(50):
        current = registry.get(job.scan_id)
        if current and current.state == JobState.completed:
            break
        time.sleep(0.02)
    current = registry.get(job.scan_id)
    assert current is not None
    assert current.state == JobState.completed
    assert current.result is not None
    assert current.result["status_label"] == "No findings detected"
    assert current.artifacts
