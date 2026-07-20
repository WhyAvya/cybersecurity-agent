# Evaluation Protocol

The CLI supports offline harness evaluation and live benchmark evaluation. Main comparisons must use the same immutable test ID sample for Semgrep-only, LLM-only, and hybrid runs.

Future runs should write a manifest, predictions, summary metrics, calibration data, and generated Week 4/Week 5 reports under `artifacts/evaluation/<run_id>/`.

The authoritative live LLM is configured through `OLLAMA_MODEL`. Use a pinned model tag so evaluation manifests, Docker runs, and local CLI runs remain reproducible.

Current live LLM tests and evaluation should point to the Windows Ollama service:

```text
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=qwen2.5-coder:7b
OLLAMA_NUM_CTX=2048
```

Docker Compose Ollama is preserved for later reproducibility testing through the optional `docker-ollama` profile.
