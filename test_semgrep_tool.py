from tools.semgrep_tool import run_semgrep

findings = run_semgrep(
    "data/BenchmarkPython/testcode",
    "auto"
)

print("Findings:", len(findings))
print(findings[0])