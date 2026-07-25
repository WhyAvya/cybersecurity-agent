# Plan B v2 Word Report Draft

## 1. Plan A Baseline

Plan A established a conventional static-analysis baseline for vulnerability discovery. It provided deterministic tool output and reproducible artifacts, but it did not attempt adaptive investigation or model-assisted review.

## 2. Plan B v1 Hybrid Workflow

Plan B v1 added a hybrid workflow that combined Semgrep evidence with local-model source-code reasoning. It preserved structured outputs, validation, and benchmark artifacts. Plan B v1 remains the frozen quantitative benchmark baseline.

## 3. Why V1 Remained Workflow-Oriented

Plan B v1 was intentionally workflow-oriented. It compared fixed scanner modes and protected evaluation reproducibility, but it did not dynamically adapt investigation depth, request follow-up evidence, or separate model reasoning from skeptical review.

## 4. Plan B v2 Objectives

Plan B v2 extends the frozen Plan B v1 workflow with a bounded agentic
control layer that adapts analysis to repository capabilities, uses isolated
local-model reasoning and review, requests one additional evidence-gathering
action when necessary, escalates unresolved findings to humans, and saves a
reproducible decision trace.

The objective is presentability, reproducibility, and defensibility using implemented behavior, not a claim of statistical improvement over v1.

## 5. Agentic Control Layer

The control layer inventories the repository, routes supported CWEs, manages Semgrep execution, extracts source context, invokes the local model in bounded roles, applies deterministic validation, records events, and stops according to configured budgets.

One open-source local LLM is used sequentially in isolated reasoner and
reviewer roles. A deterministic orchestrator controls planning, routing,
tools, validation, safety, memory, and stopping conditions.

## 6. Bounded ReAct-Style Loop

The implemented loop is context, reasoner, validator, and reviewer. A second pass is allowed only when the reviewer requests `more_context` or `assignment_history`. A third pass is not allowed.

## 7. Role Isolation

The reasoner and reviewer use different prompts and payload schemas. Each call uses a fresh context. The reviewer receives the current reasoner output, validator result, and collected evidence, but not hidden reasoner history or evaluation ground truth.

## 8. Tool Orchestration

Plan B v2 reuses existing Semgrep interfaces and validator behavior. It normalizes findings into bounded candidates and records tool events. It does not add GitHub URL cloning, databases, cloud models, or automatic remediation.

## 9. Human Checkpoints

Human checkpoint 1 approves or rejects the scan plan after inventory. Human checkpoint 2 reviews unresolved findings with actions to accept, reject, keep human review, or stop. The noninteractive policy `--auto-review-policy keep` preserves unresolved findings as human-review items.

## 10. Safety And Trustworthiness

The repository under analysis is treated as read-only. Plan B v2 performs static filesystem inspection, resolves paths inside the supplied repository, avoids target-code execution, avoids dependency installation, avoids target tests, and records a reproducible artifact trail.

## 11. Demonstration And Test Evidence

Verified evidence includes focused tests for Phase 1 through Phase 5, the latest full unit suite result of `199 passed, 2 skipped`, six local fixtures, clean Git checkpoints, and confirmation that frozen Plan B v1 files remained unchanged.

The six fixtures cover command injection, constant overwrite, missing helper evidence, string SQL, parameterized SQL, and no relevant APIs.

## 12. Limitations

Plan B v2 is Python-only, supports only `CWE-078` and `CWE-089`, accepts local repository paths only, exposes a CLI only, uses same-file AST/context support, lacks a full interprocedural call graph, permits one additional evidence pass, and uses the same local model for isolated reasoner and reviewer roles.

It does not automatically remediate findings, does not provide robust resume support, does not clone GitHub URLs, and has not completed a large external v2 benchmark.

## 13. Future Work

Future work includes external benchmark execution, broader language and CWE coverage, stronger interprocedural evidence, calibrated reporting, improved resume support, richer review ergonomics, and measured comparison against the frozen v1 baseline.

## 14. Conclusion

Plan B v2 demonstrates a bounded agentic control layer around the existing Plan B workflow. It improves auditability and adaptability through deterministic routing, isolated model roles, validator enforcement, human checkpoints, budgets, and reproducible artifacts while leaving the frozen Plan B v1 benchmark baseline intact.
