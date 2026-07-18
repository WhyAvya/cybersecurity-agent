from tools.context_fetcher import fetch_context
from tools.cwe_lookup import lookup_cwe


print("=== CWE TEST ===")
print(lookup_cwe("CWE-022"))

print("\n=== CONTEXT TEST ===")

print(
    fetch_context(
        "data/BenchmarkPython/testcode/BenchmarkTest00001.py",
        40
    )
)