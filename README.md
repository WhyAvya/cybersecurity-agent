# Vulnerability Agent

This repository contains a reproducible Python workflow for comparing static-analysis findings with local LLM-assisted vulnerability analysis.

The current implementation is a conservative Semgrep plus Ollama pipeline with typed configuration, strict Pydantic schemas, stable finding IDs, safe source-context reads, mockable adapters, an offline demo mode, and isolated unit tests. Legacy research scripts remain in `agents/`, `tools/`, `evaluation/`, `pipeline.py`, and `scan.py` for continuity while the supported package is migrated under `src/vuln_agent`.

## Problem And Research Question

Can an open-source local LLM improve the trustworthiness of SAST results by triaging Semgrep findings, explaining evidence, identifying CWE mismatches, and routing uncertain cases to human review?

## What The System Does

- Runs Semgrep through a dependency-injected adapter.
- Converts raw tool output into canonical schemas.
- Fetches bounded source context without executing target code.
- Sends delimited, prompt-injection-aware prompts to Ollama.
- Validates model output with strict schemas.
- Writes JSONL, Markdown, and manifest artifacts.
- Keeps parser, network, and tool errors separate from safe verdicts.

## Quick Start

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
vuln-agent demo
pytest
```

The demo uses `--offline` behavior internally, so it does not require Semgrep or Ollama.

## Real Scan

Start the local Windows Ollama app first. Current development and evaluation use:

```text
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=qwen2.5-coder:7b
OLLAMA_NUM_CTX=2048
```

Install the configured model in Windows Ollama before running live LLM checks:

```bash
ollama pull qwen2.5-coder:7b
vuln-agent doctor
vuln-agent scan examples/vulnerable_app
```

Reports are written under `artifacts/reports/<run_id>/`.

In PowerShell, do not type `<run_id>` literally. Use the folder printed by the
command, or inspect the latest scan with:

```powershell
$latestScan = Get-ChildItem artifacts\reports -Directory |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1
Get-Content (Join-Path $latestScan.FullName "scan_report.md")
```

## Configuration

Configuration precedence is:

1. CLI arguments
2. Environment variables
3. YAML/JSON config
4. Defaults

See `.env.example` and `configs/evaluation.yaml`.

## Docker

Docker support is preserved for later reproducibility testing. The normal local
development workflow currently uses the Windows Ollama service, not the Docker
Ollama service.

```bash
docker compose build
docker compose run --rm app doctor
```

To test the Docker Ollama service explicitly, enable the optional profile:

```bash
docker compose --profile docker-ollama up -d ollama
docker compose --profile docker-ollama run --rm ollama ollama pull qwen2.5-coder:7b
```

Use only one Ollama mode at a time:

- Windows Ollama: `OLLAMA_BASE_URL=http://127.0.0.1:11434`
- Docker Compose Ollama: `OLLAMA_BASE_URL=http://ollama:11434`

## Evaluation Status

The legacy `evaluation/` scripts contain useful Week 4/Week 5 work. The supported CLI writes reproducible evaluation artifacts and can run offline harness checks or live Semgrep/LLM/hybrid benchmark checks against the configured local benchmark dataset:

```bash
vuln-agent evaluate all --config configs/evaluation.yaml --sample-size 30 --offline
vuln-agent evaluate all --config configs/evaluation.yaml --sample-size 30
vuln-agent trustworthiness --latest-run
vuln-agent report week4 --latest-run
vuln-agent report week5 --latest-run
```

Each run writes a manifest, prediction JSONL, summary CSV, calibration CSV, and generated Week 4/Week 5 reports under `artifacts/evaluation/<run_id>/`.

To inspect the latest evaluation run in PowerShell:

```powershell
$latestEval = Get-ChildItem artifacts\evaluation -Directory |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1
Get-ChildItem $latestEval.FullName -Recurse
Get-Content (Join-Path $latestEval.FullName "week4_report.md")
Get-Content (Join-Path $latestEval.FullName "week5_report.md")
```

Scientific Semgrep-only, LLM-only, and hybrid comparisons must use the same immutable evaluation IDs for all modes.

## Testing

Default tests are isolated unit tests and do not require live Semgrep or Ollama:

```bash
pytest
ruff check src tests
mypy src
```

Markers are configured for `unit`, `integration`, `e2e`, and `slow`.

## Documentation

- `docs/architecture.md`
- `docs/configuration.md`
- `docs/security.md`
- `docs/evaluation_protocol.md`
- `docs/trustworthiness.md`
- `docs/demo.md`

## Security And Privacy

Scanned files are read as untrusted input and never executed. Source context is sent to the configured LLM endpoint, so use a trusted local Ollama endpoint for private code.

## Known Limitations

- Full benchmark bootstrap from a remote source still needs checksum-pinned dataset release metadata.
- Final Week 4/Week 5 reports should be regenerated after the full live benchmark run.
- Docker build was added but may require internet access to install Semgrep during image build.
- Legacy scripts remain for historical continuity and should be migrated or archived incrementally.
