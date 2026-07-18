from vuln_agent.failure_taxonomy import FailureCategory, automated_failure_category


def test_automated_failure_category_priorities():
    assert automated_failure_category(None, duplicate=True) == FailureCategory.duplicate_finding
    assert automated_failure_category(None, cwe_mismatch=True) == FailureCategory.cwe_mismatch
    assert automated_failure_category("invalid JSON schema") == FailureCategory.schema_failure
    assert automated_failure_category("Ollama connection failed") == FailureCategory.model_failure
    assert automated_failure_category("Semgrep timed out") == FailureCategory.tool_failure
