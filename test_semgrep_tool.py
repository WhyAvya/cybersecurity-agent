from tools.semgrep_tool import run_semgrep

findings = run_semgrep("data/BenchmarkPython")

print("Findings:", len(findings))

if findings:
    print(findings[0])