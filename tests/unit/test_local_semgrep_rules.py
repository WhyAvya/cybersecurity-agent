import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

from vuln_agent.config import Settings
from vuln_agent.semgrep import SemgrepAdapter


def test_local_cwe_078_rule_detects_input_to_os_system_line_4(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text(
        textwrap.dedent(
            """\
            import os

            cmd = input("cmd: ")
            os.system(cmd)
            """
        ),
        encoding="utf-8",
    )

    def runner(command, **kwargs):
        assert "--config" in command
        config = command[command.index("--config") + 1]
        assert config.endswith("semgrep-rules\\python") or config.endswith("semgrep-rules/python")
        payload = {
            "results": [
                {
                    "path": str(source),
                    "check_id": "vuln-agent.python.command-injection.input-to-os-system",
                    "start": {"line": 4, "col": 1},
                    "end": {"line": 4, "col": 15},
                    "extra": {
                        "severity": "ERROR",
                        "lines": "os.system(cmd)",
                        "metadata": {"cwe": ["CWE-078"], "category": "security", "confidence": "HIGH"},
                    },
                }
            ]
        }
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(payload), stderr="")

    findings, metadata = SemgrepAdapter(Settings(allowed_scan_root=tmp_path), runner=runner).scan(source)

    assert metadata.config.endswith("semgrep-rules\\python") or metadata.config.endswith("semgrep-rules/python")
    assert len(findings) == 1
    assert findings[0].rule_id == "vuln-agent.python.command-injection.input-to-os-system"
    assert findings[0].normalized_cwe == "CWE-078"
    assert findings[0].line_start == 4


def test_local_cwe_078_rule_ignores_allowlisted_subprocess_shell_false(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text(
        textwrap.dedent(
            """\
            import subprocess

            allowed_commands = {
                "status": ["git", "status"],
                "version": ["python", "--version"],
            }
            choice = input("Choose command: ")
            if choice in allowed_commands:
                subprocess.run(allowed_commands[choice], check=True, shell=False)
            """
        ),
        encoding="utf-8",
    )

    def runner(command, **kwargs):
        assert command[-1] == str(source)
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps({"results": []}), stderr="")

    findings, _metadata = SemgrepAdapter(Settings(allowed_scan_root=tmp_path), runner=runner).scan(source)

    assert findings == []


def _run_real_semgrep(source: Path):
    if shutil.which("semgrep") is None:
        pytest.skip("semgrep is not installed")
    return SemgrepAdapter(Settings(allowed_scan_root=source.parent)).scan(source)[0]


def test_local_cwe_078_rule_detects_flask_request_to_shell_array(tmp_path: Path):
    source = tmp_path / "cmdi.py"
    source.write_text(
        textwrap.dedent(
            """\
            from flask import request
            import subprocess

            values = request.form.getlist("case")
            param = values[0]
            bar = param
            argList = []
            argList.append("sh")
            argList.append("-c")
            argList.append(f"echo {bar}")
            subprocess.run(argList, capture_output=True)
            """
        ),
        encoding="utf-8",
    )

    findings = _run_real_semgrep(source)

    assert len(findings) == 1
    assert findings[0].rule_id.endswith("vuln-agent.python.command-injection.flask-to-subprocess-run-shell-array")
    assert findings[0].normalized_cwe == "CWE-078"
    assert findings[0].line_start == 11


def test_local_cwe_078_rule_ignores_constant_overwrite_before_shell(tmp_path: Path):
    source = tmp_path / "cmdi_safe.py"
    source.write_text(
        textwrap.dedent(
            """\
            from flask import request
            import subprocess

            param = request.form.get("case")
            commands = {"safe": "status", "user": param}
            bar = commands["user"]
            bar = commands["safe"]
            subprocess.run(f"echo {bar}", shell=True)
            """
        ),
        encoding="utf-8",
    )

    findings = _run_real_semgrep(source)

    assert findings == []


def test_local_cwe_089_rule_detects_flask_request_to_string_built_execute(tmp_path: Path):
    source = tmp_path / "sqli.py"
    source.write_text(
        textwrap.dedent(
            """\
            from flask import request

            param = request.form.get("case")
            bar = param
            sql = f"SELECT username FROM users WHERE password = '{bar}'"
            cur.execute(sql)
            """
        ),
        encoding="utf-8",
    )

    findings = _run_real_semgrep(source)

    assert len(findings) == 1
    assert findings[0].rule_id.endswith("vuln-agent.python.sql-injection.flask-to-execute-string")
    assert findings[0].normalized_cwe == "CWE-089"
    assert findings[0].line_start == 6


def test_local_cwe_089_rule_ignores_parameterized_execute(tmp_path: Path):
    source = tmp_path / "sqli_safe.py"
    source.write_text(
        textwrap.dedent(
            """\
            from flask import request

            param = request.args.get("case")
            sql = "SELECT username FROM users WHERE password = ?"
            cur.execute(sql, (param,))
            """
        ),
        encoding="utf-8",
    )

    findings = _run_real_semgrep(source)

    assert findings == []
