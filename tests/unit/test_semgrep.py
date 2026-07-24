from vuln_agent.config import Settings


def test_semgrep_default_config_uses_local_python_ruleset():
    assert Settings().semgrep_config == "semgrep-rules/python"
