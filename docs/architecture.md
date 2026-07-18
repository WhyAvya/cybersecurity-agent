# Architecture

```mermaid
flowchart TD
    A[CLI] --> B[Settings]
    A --> C[Semgrep Adapter]
    C --> D[Canonical SemgrepFinding]
    D --> E[Safe Context Fetcher]
    E --> F[Analyzer Prompt]
    F --> G[LLM Client]
    G --> H[AgentAnalysis]
    H --> I[Reporter Policy]
    I --> J[FinalFinding JSONL and Markdown]
```

The current implementation is a bounded Semgrep -> context -> analyzer -> reporter workflow. It is intentionally conservative and records failures as errors or review items rather than silently treating them as safe code.
