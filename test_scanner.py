# test_scanner.py
from schemas.verdict import SemgrepFinding
from agents.scanner_agent import run_scanner

finding = SemgrepFinding(
    finding_id="F001",
    file="data/BenchmarkPython/testcode/BenchmarkTest00001.py",
    line=47,
    rule_id="test-rule",
    cwe_tag="CWE-022",
    severity="HIGH",
    snippet="codecs.open(...)"
)

result = run_scanner(finding)

print(result)