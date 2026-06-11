from schemas.verdict import (
    SemgrepFinding,
    AgentVerdict
)

finding = SemgrepFinding(
    finding_id="F001",
    file="test.py",
    line=10,
    rule_id="python.test.rule",
    cwe_tag="CWE-78",
    severity="HIGH",
    snippet="os.system(user_input)"
)

verdict = AgentVerdict(
    finding_id="F001",
    verdict="TP",
    confidence=0.95,
    cwe_id="CWE-78",
    cwe_mismatch=False,
    priority="HIGH",
    reasoning="Command injection detected",
    iterations=1,
    agent_role="analyzer",
    schema_valid=True,
    tool_call_evaded=False
)

print(finding.model_dump())
print(verdict.model_dump())