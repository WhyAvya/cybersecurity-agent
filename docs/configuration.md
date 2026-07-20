# Configuration

Configuration precedence is CLI arguments, environment variables, selected YAML/JSON config, then safe defaults.

Important variables are documented in `.env.example`, including Ollama endpoint/model, Semgrep binary/config, context limits, scan limits, allowed extensions, excluded directories, and hybrid confidence thresholds.

The authoritative local LLM is configured through `OLLAMA_MODEL`. Do not hardcode model names in commands or Python modules; override `OLLAMA_MODEL` when a different model is part of a documented experiment.

Current local development and live evaluation should use the Windows Ollama service:

```text
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=qwen2.5-coder:7b
OLLAMA_NUM_CTX=2048
```

Docker Compose Ollama remains available for reproducibility testing through the `docker-ollama` profile:

```text
OLLAMA_BASE_URL=http://ollama:11434
```

Do not enable both Ollama modes at the same time.
