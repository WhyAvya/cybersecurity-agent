import json
import subprocess

import pytest

from vuln_agent.config import Settings
from vuln_agent.exceptions import ToolError
from vuln_agent.semgrep import SemgrepAdapter


def test_semgrep_parses_and_deduplicates(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: "semgrep")

    payload = {
        "results": [
            {
                "path": "app.py",
                "check_id": "python.flask.security.injection",
                "start": {"line": 3, "col": 5},
                "end": {"line": 3, "col": 20},
                "extra": {
                    "severity": "WARNING",
                    "lines": "cursor.execute(query)",
                    "metadata": {"cwe": ["CWE-89", "CWE-564"]},
                },
            },
            {
                "path": "app.py",
                "check_id": "python.flask.security.injection",
                "start": {"line": 3, "col": 5},
                "end": {"line": 3, "col": 20},
                "extra": {
                    "severity": "WARNING",
                    "lines": "cursor.execute(query)",
                    "metadata": {"cwe": ["CWE-89"]},
                },
            },
        ]
    }

    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(payload), stderr="")

    findings, metadata = SemgrepAdapter(Settings(), runner=runner).scan("app.py")
    assert len(findings) == 1
    assert findings[0].normalized_cwe == "CWE-089"
    assert metadata.name == "semgrep"
    assert len(calls) == 1
    command, kwargs = calls[0]
    assert command[:6] == [
        "semgrep",
        "--json",
        "--metrics",
        "off",
        "--disable-version-check",
        "--config",
    ]
    assert command[6].endswith("semgrep-rules\\python") or command[6].endswith("semgrep-rules/python")
    assert command[7] == "app.py"
    assert kwargs["env"]["SEMGREP_SEND_METRICS"] == "off"
    assert kwargs["timeout"] == Settings().semgrep_timeout_seconds


def test_semgrep_can_use_target_as_project_root_with_experimental_flag(monkeypatch, tmp_path):
    monkeypatch.setattr("shutil.which", lambda _: "semgrep")
    target = tmp_path / "target"
    target.mkdir()
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps({"results": []}), stderr="")

    SemgrepAdapter(
        Settings(semgrep_no_git_ignore=True),
        runner=runner,
        use_target_as_project_root=True,
    ).scan(target)

    command = calls[0]
    assert command[1:4] == ["--experimental", "--project-root", str(target.resolve())]
    assert "--no-git-ignore" in command
    assert command[-1] == str(target)


def test_semgrep_accepts_valid_json_with_return_code_one(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: "semgrep")

    def runner(command, **kwargs):
        return subprocess.CompletedProcess(command, 1, stdout=json.dumps({"results": []}), stderr="no findings")

    findings, metadata = SemgrepAdapter(Settings(), runner=runner).scan("app.py")
    assert findings == []
    assert metadata.error is None
    assert metadata.warnings == ["no findings"]
    assert metadata.stderr_excerpt == "no findings"


def test_semgrep_missing_binary(monkeypatch, tmp_path):
    monkeypatch.setattr("shutil.which", lambda _: None)
    monkeypatch.setattr("vuln_agent.semgrep.sys.executable", str(tmp_path / "python.exe"))
    with pytest.raises(ToolError):
        SemgrepAdapter(Settings()).scan("app.py")


def test_semgrep_malformed_json(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: "semgrep")

    def runner(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout="{", stderr="")

    with pytest.raises(ToolError):
        SemgrepAdapter(Settings(), runner=runner).scan("app.py")


@pytest.mark.parametrize("returncode", [0, 1])
def test_semgrep_empty_stdout_raises(monkeypatch, returncode):
    monkeypatch.setattr("shutil.which", lambda _: "semgrep")

    def runner(command, **kwargs):
        return subprocess.CompletedProcess(command, returncode, stdout="", stderr="diagnostic")

    with pytest.raises(ToolError, match=f"exited with {returncode} and no JSON output"):
        SemgrepAdapter(Settings(), runner=runner).scan("app.py")


def test_semgrep_unaccepted_return_code_with_json_raises(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: "semgrep")

    def runner(command, **kwargs):
        return subprocess.CompletedProcess(command, 2, stdout=json.dumps({"results": []}), stderr="x" * 3000)

    with pytest.raises(ToolError) as exc_info:
        SemgrepAdapter(Settings(), runner=runner).scan("app.py")
    message = str(exc_info.value)
    assert "Semgrep exited with 2" in message
    assert len(message) < 2100


def test_semgrep_timeout_raises_tool_error(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: "semgrep")

    def runner(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    with pytest.raises(ToolError, match="Semgrep timed out"):
        SemgrepAdapter(Settings(semgrep_timeout_seconds=3), runner=runner).scan("app.py")


def test_semgrep_version_timeout_returns_unavailable_status(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: "semgrep")

    def runner(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    status = SemgrepAdapter(Settings(semgrep_version_timeout_seconds=2), runner=runner).version_status()

    assert status["status"] == "timeout"
    assert status["version"] is None
    assert "timed out after 2" in str(status["error"])
