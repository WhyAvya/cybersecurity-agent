# Plan B v2 Usage

Plan B v2 runs from the local CLI against a local repository path. It does not accept GitHub URLs and does not clone remote repositories.

## Prerequisites

- Python virtual environment with the project test/runtime dependencies installed.
- Semgrep available through the existing project environment.
- Ollama running locally for live model execution.
- A local model configured through the existing project settings, typically `qwen2.5-coder:7b`.

Install or confirm the model on the host where Ollama runs:

```powershell
ollama pull qwen2.5-coder:7b
```

## CLI

Run from the repository root:

```powershell
python scripts/run_agentic_v2.py `
  --repository <local_path> `
  --cwes CWE-078 CWE-089
```

The `--repository` value must be an existing local directory. The `--cwes` values are limited to `CWE-078` and `CWE-089`.

## Plan Approval

By default, the CLI prints the inventory-derived scan plan and asks:

```text
Approve scan plan? [y/n]
```

Use `--auto-approve` for noninteractive demo runs:

```powershell
python scripts/run_agentic_v2.py `
  --repository tests/fixtures/agentic_v2/cwe078_vulnerable `
  --cwes CWE-078 CWE-089 `
  --auto-approve
```

## Human Review Policy

Unresolved findings are sent to human checkpoint 2. Interactive review supports:

- `A`: accept
- `R`: reject
- `U`: keep human review
- `S`: stop

For reproducible noninteractive runs, use:

```powershell
python scripts/run_agentic_v2.py `
  --repository tests/fixtures/agentic_v2/cwe078_missing_helper `
  --cwes CWE-078 CWE-089 `
  --auto-approve `
  --auto-review-policy keep
```

The implemented CLI currently supports `keep` as the automatic review policy.

## Artifacts

Runs write to the configured agentic artifact root, under a timestamped run directory. The expected files are:

- `run_manifest.json`: run id, repository, requested CWEs, review policy, start time.
- `scan_plan.json`: inventory, active/skipped routes, candidate budget, safety policy.
- `events.jsonl`: append-only event trace.
- `findings.json`: normalized candidate list.
- `state.json`: run state, budget usage, human-review counters.
- `final_report.json`: terminal decisions and human-review decisions.

## Fixture Demo Paths

The repository includes six local fixture repositories:

- `tests/fixtures/agentic_v2/cwe078_vulnerable`
- `tests/fixtures/agentic_v2/cwe078_safe_overwrite`
- `tests/fixtures/agentic_v2/cwe078_missing_helper`
- `tests/fixtures/agentic_v2/cwe089_vulnerable`
- `tests/fixtures/agentic_v2/cwe089_parameterized`
- `tests/fixtures/agentic_v2/no_relevant_apis`

Use the same CLI form for each fixture. `no_relevant_apis` should be skipped during routing because it has no shell or SQL indicators.

## Common Failures

- Missing Semgrep: install project dependencies or use the project runtime that already includes Semgrep.
- Ollama unavailable: start Ollama and confirm the configured base URL.
- Missing model: pull the configured local model.
- Rejected repository path: pass an existing local directory without path traversal.
- Empty active route: the inventory found no indicators for the requested CWEs.
- `TOOL_ERROR`: model JSON remained invalid after one repair attempt, or a configured budget was exhausted.
