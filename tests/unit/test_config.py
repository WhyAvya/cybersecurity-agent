import pytest

from vuln_agent.config import ConfigurationError, load_settings


def test_cli_overrides_environment(monkeypatch):
    monkeypatch.setenv("OLLAMA_MODEL", "from-env")
    settings = load_settings(cli_overrides={"ollama_model": "from-cli"})
    assert settings.ollama_model == "from-cli"


def test_threshold_validation():
    with pytest.raises(ConfigurationError):
        load_settings(
            cli_overrides={
                "hybrid_accept_confidence": 0.9,
                "high_priority_confidence": 0.8,
            }
        )


def test_csv_environment_values(monkeypatch):
    monkeypatch.setenv("ALLOWED_EXTENSIONS", "py,js")
    settings = load_settings()
    assert settings.allowed_extensions == (".py", ".js")
