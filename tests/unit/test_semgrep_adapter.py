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

    def runner(command, **kwargs):
        if command[-1] == "--version":
            return subprocess.CompletedProcess(command, 0, stdout="1.2.3\n", stderr="")
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(payload), stderr="")

    findings, metadata = SemgrepAdapter(Settings(), runner=runner).scan("app.py")
    assert len(findings) == 1
    assert findings[0].normalized_cwe == "CWE-089"
    assert metadata.name == "semgrep"


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
