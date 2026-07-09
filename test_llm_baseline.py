from agents.llm_baseline_agent import run_llm_baseline


with open(
    "data/BenchmarkPython/testcode/BenchmarkTest00001.py",
    "r",
    encoding="utf-8"
) as file:

    code = file.read()


result = run_llm_baseline(code)

print(result)