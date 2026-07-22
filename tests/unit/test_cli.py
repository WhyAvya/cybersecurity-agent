import argparse
from pathlib import Path

import pytest

from vuln_agent import cli
from vuln_agent.config import Settings


def test_latest_run_returns_newest_manifest_dir(tmp_path: Path):
    older = tmp_path / "20250101T000000Z-old"
    newer = tmp_path / "20250102T000000Z-new"
    older.mkdir()
    newer.mkdir()
    (older / "manifest.json").write_text("{}", encoding="utf-8")
    (newer / "manifest.json").write_text("{}", encoding="utf-8")

    assert cli.latest_run(tmp_path) == newer


def test_doctor_reports_missing_services(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path):
    settings = Settings(artifact_root=tmp_path, report_dir=tmp_path / "reports", evaluation_dir=tmp_path / "eval")
    monkeypatch.setattr(cli, "_settings_from_args", lambda args: settings)
    monkeypatch.setattr(cli.shutil, "which", lambda binary: None)
    monkeypatch.setattr(cli.SemgrepAdapter, "executable_path", lambda self: None)

    class UnhealthyClient:
        def __init__(self, settings: Settings) -> None:
            self.settings = settings

        def healthcheck(self):
            return argparse.Namespace(ok=False, message="Ollama unreachable")

    monkeypatch.setattr(cli, "OllamaClient", UnhealthyClient)

    assert cli.doctor(argparse.Namespace(config=None)) == 2
    output = capsys.readouterr().out
    assert "Config: OK" in output
    assert "Semgrep: missing" in output


def test_main_evaluate_routes_to_runner(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    monkeypatch.setattr(cli, "_settings_from_args", lambda args: Settings(evaluation_dir=tmp_path))
    monkeypatch.setattr(cli, "run_evaluation", lambda *args, **kwargs: tmp_path / "run")

    assert cli.main(["evaluate", "all", "--offline"]) == 0
    assert "Evaluation output:" in capsys.readouterr().out


def test_scan_mode_default_and_save_raw_route(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    calls = {}

    class Orchestrator:
        def __init__(self, settings):
            pass

        def scan(self, path, output_dir, offline=False, mode="hybrid", save_raw=False):
            calls.update({"path": path, "mode": mode, "save_raw": save_raw})
            out = tmp_path / "out"
            out.mkdir()
            (out / "raw_findings.jsonl").write_text("", encoding="utf-8")
            return [], out

    monkeypatch.setattr(cli, "_settings_from_args", lambda args: Settings(report_dir=tmp_path))
    monkeypatch.setattr(cli, "VulnerabilityOrchestrator", Orchestrator)
    assert cli.main(["scan", "examples/vulnerable_app", "--save-raw"]) == 0
    assert calls["mode"] == "hybrid"
    assert calls["save_raw"] is True
    assert "Grouped findings:" in capsys.readouterr().out


def test_report_requires_existing_evaluation_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    monkeypatch.setattr(cli, "_settings_from_args", lambda args: Settings(evaluation_dir=tmp_path))

    assert cli.main(["report", "week4"]) == 1
    assert "No evaluation runs found" in capsys.readouterr().err
