from vuln_agent.prompts import ANALYZER_PROMPT_VERSION, build_analyzer_prompt
from vuln_agent.schemas import SemgrepFinding, Severity


def test_analyzer_prompt_contains_injection_boundary_and_checksum():
    finding = SemgrepFinding(
        finding_id="finding-1",
        relative_file="app.py",
        line_start=3,
        line_end=3,
        rule_id="python.lang.security",
        raw_semgrep_cwes=["CWE-089"],
        normalized_cwe="CWE-089",
        severity=Severity.high,
        snippet="execute(query)",
    )

    prompt = build_analyzer_prompt(finding, "3: execute(query)")

    assert prompt.name == "analyzer"
    assert prompt.version == ANALYZER_PROMPT_VERSION
    assert "SOURCE_CODE_BEGIN" in prompt.text
    assert "SOURCE_CODE_END" in prompt.text
    assert len(prompt.checksum) == 64
