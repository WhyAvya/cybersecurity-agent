# Demo Script

This two-minute demo shows a Dockerized vulnerability-discovery workflow that combines Semgrep with local LLM analysis.

First, the project scans a deliberately vulnerable Python example. Semgrep runs inside the application container, while the LLM call goes to Windows-host Ollama using `qwen2.5-coder:7b`. The output is a structured finding with CWE, confidence, evidence, and remediation.

Second, the demo scans a safe example. This shows that the same workflow can complete without inventing findings.

The important research result is not that the model is perfect. Week 4 showed the LLM had high recall but too many false positives. The original hybrid gave a more balanced trade-off. Week 5 and the post-Week-5 experiment showed that a conservative prompt could remove false positives, but it also collapsed recall and introduced reliability costs.

The conclusion is that local LLMs can help triage and explain static-analysis findings, but they need strict schemas, raw-output preservation, and human review for high-impact decisions.
