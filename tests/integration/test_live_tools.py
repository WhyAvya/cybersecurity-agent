import shutil
import sys

import pytest

from vuln_agent.config import Settings
from vuln_agent.llm import OllamaClient
from vuln_agent.semgrep import SemgrepAdapter


pytestmark = pytest.mark.integration


def test_semgrep_binary_reports_version():
    settings = Settings()
    adapter = SemgrepAdapter(settings)
    if adapter.executable_path() is None:
        pytest.skip("Semgrep binary is not installed")
    if sys.platform == "win32" and shutil.which(settings.semgrep_binary) is None:
        pytest.skip("Semgrep is only available through a Windows venv shim; Docker covers live Semgrep verification")
    assert adapter.version()


def test_ollama_healthcheck_is_reachable():
    if shutil.which("ollama") is None:
        pytest.skip("Ollama CLI is not installed")
    health = OllamaClient(Settings()).healthcheck()
    if not health.ok:
        pytest.skip(f"Ollama is not reachable: {health.message}")
    assert health.ok
