# test_reporter.py

from schemas.verdict import SemgrepFinding
from agents.scanner_agent import run_scanner
from agents.analyzer_agent import run_analyzer
from agents.reporter_agent import run_reporter


finding = SemgrepFinding(
    finding_id="F001",
    file="data/BenchmarkPython/testcode/BenchmarkTest00001.py",
    line=47,
    rule_id="test-rule",
    cwe_tag="CWE-022",
    severity="HIGH",
    snippet="codecs.open(...)"
)

context = run_scanner(finding)

analysis = run_analyzer(
    finding,
    context
)

report = run_reporter(
    finding,
    analysis
)

print(report)