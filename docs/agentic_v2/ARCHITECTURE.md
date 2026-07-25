# Plan B v2 Architecture

Plan B v2 is a bounded agentic MVP layered on top of the frozen Plan B v1 workflow. Its goal is to make repository analysis adaptive and reproducible while preserving deterministic control over tools, validation, safety, memory, and stopping conditions.

One open-source local LLM is used sequentially in isolated reasoner and
reviewer roles. A deterministic orchestrator controls planning, routing,
tools, validation, safety, memory, and stopping conditions.

## Inventory

The inventory module performs static filesystem inspection only. It collects Python files, framework indicators, database imports, SQL execution APIs, shell-related imports and calls, request/input sources, scanned file count, and excluded directory count.

Ignored directories include `.git`, `.venv`, `venv`, `node_modules`, `dist`, `build`, `__pycache__`, and `artifacts`. Inventory never imports target modules, executes target code, installs dependencies, runs target tests, or starts applications.

## Deterministic Planner And Router

The router activates `CWE-078` when shell indicators exist and activates `CWE-089` when SQL or database indicators exist. If indicators are absent, the CWE is skipped with an explicit reason. Requested CWEs constrain the active set, so an implemented route can still be skipped when it was not requested.

The scan plan records repository path, Python file count, framework indicators, active CWEs, skipped CWEs, candidate budget, safety policy, and planning steps.

## Human Checkpoint 1

After inventory and routing, the CLI displays the scan plan and prompts:

```text
Approve scan plan? [y/n]
```

`--auto-approve` bypasses the prompt. The approval decision is recorded in `events.jsonl`. A rejected plan stops before Semgrep and writes state.

## Semgrep And Candidates

Plan B v2 reuses the existing Semgrep wrapper and existing rules. Findings are normalized into candidate objects with candidate id, file, line, rule id, candidate CWE, sink expression, and raw result reference. The orchestrator enforces a maximum of 20 candidates and records a truncation event when the budget is exceeded.

## Context Extraction

For each candidate, the orchestrator uses Python AST parsing to find the containing function. It extracts the complete function plus relevant imports. If function extraction fails, it uses a bounded source window. Follow-up evidence can request a larger same-file context or an AST assignment summary.

Benchmark labels, expected answers, and ground-truth target lines are not part of the model payloads.

## Reasoner

The reasoner receives `REASONER_SYSTEM_PROMPT`, candidate metadata, extracted context, Semgrep evidence, active CWE scope, and pass number. Each candidate and pass uses a fresh model context. The reasoner must return the structured Phase 1 schema. One automatic JSON repair attempt is allowed; a second malformed response becomes `TOOL_ERROR`.

## Validator

The validator path reuses existing Plan B v1 deterministic validation through imports and adapters. It checks source, sink, line validity, CWE/sink compatibility, plausible flow, constant overwrite, SQL parameterization, and safe shell usage. An LLM decision cannot override a failed deterministic check.

## Reviewer

The reviewer receives `REVIEWER_SYSTEM_PROMPT`, a reviewer-specific payload, the current reasoner output, validator result, collected evidence, and pass number. It receives no hidden reasoner history and no evaluation ground truth. Allowed decisions are `accept`, `reject`, `needs_more_evidence`, and `human_review`. Allowed follow-up actions are `more_context`, `assignment_history`, and `none`.

## Optional Second Pass

The bounded loop is:

```text
context -> reasoner -> validator -> reviewer
```

A second pass runs only when the reviewer requests `more_context` or `assignment_history`. The second pass uses fresh reasoner, validator, and reviewer executions. A third pass is not allowed. LLM-call and step budgets stop execution with `TOOL_ERROR` if exhausted.

## Human Checkpoint 2

Findings that remain `HUMAN_REVIEW_REQUIRED` enter CLI review. The CLI displays finding, CWE, known evidence, and missing evidence. Actions are `A=accept`, `R=reject`, `U=keep human review`, and `S=stop`. `--auto-review-policy keep` records unresolved findings as kept human-review findings without prompting.

## Artifacts

Every run writes:

- `run_manifest.json`
- `scan_plan.json`
- `events.jsonl`
- `findings.json`
- `state.json`
- `final_report.json`

Events record inventory, approval, Semgrep completion, budget truncation, reasoner starts, validator results, reviewer starts, evidence requests, terminal decisions, and human-review decisions.

## Safety

Plan B v2 accepts local paths only. Resolved repository and source paths must remain inside the supplied repository. The repository is treated as read-only. The orchestrator does not import or execute target code, install dependencies, run target tests, start applications, use cloud models, or clone GitHub URLs.

## Budgets And Terminal States

Implemented budgets include candidate count, maximum passes per candidate, reviewer cycles, LLM calls, and total steps. Terminal states are `CONFIRMED`, `REJECTED`, `HUMAN_REVIEW_REQUIRED`, `TOOL_ERROR`, and `OUT_OF_SCOPE`.
