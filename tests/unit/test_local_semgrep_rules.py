import json
import subprocess
import textwrap
from pathlib import Path

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
