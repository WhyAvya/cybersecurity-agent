# Plan B v2 Limitations

Plan B v2 is a bounded agentic MVP, not a complete autonomous security reviewer.

- Python only.
- `CWE-078` and `CWE-089` only.
- Local repository paths only.
- CLI only.
- Same-file AST/context support.
- No full interprocedural call graph.
- One additional evidence pass.
- Same local model used for two isolated roles.
- No automatic remediation.
- No robust resume engine.
- No GitHub URL cloning.
- No large external v2 benchmark yet.

The system is designed for defensive analysis and reproducible research workflows. Human judgment remains required for high-impact findings, unresolved evidence, and any production security decision.
