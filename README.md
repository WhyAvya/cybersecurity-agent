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

Start Ollama and pull the configured model first:

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

```bash
docker compose build
docker compose up -d ollama
docker compose run --rm ollama ollama pull qwen2.5-coder:7b
docker compose run --rm app doctor
```

Docker config uses `OLLAMA_BASE_URL=http://ollama:11434`, not `localhost`.

## Evaluation Status

The legacy `evaluation/` scripts contain useful Week 4/Week 5 work, but full benchmark execution migration is not complete. The new CLI writes reproducible evaluation artifacts for offline harness checks:

```bash
vuln-agent evaluate all --config configs/evaluation.yaml --sample-size 30 --offline
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

Scientific Semgrep-only, LLM-only, and hybrid comparisons still need live benchmark migration. Those final comparisons must use the same immutable evaluation IDs for all modes.

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

- Full benchmark bootstrap and fair evaluation migration are not complete.
- Week 4/Week 5 reports still need complete generation from canonical artifacts.
- Docker build was added but may require internet access to install Semgrep during image build.
- Legacy scripts remain for historical continuity and should be migrated or archived incrementally.
