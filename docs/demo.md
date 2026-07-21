# Week 6 Demo

## Preparation

Start Windows Ollama and install the required model:

```powershell
ollama pull qwen2.5-coder:7b
```

Build the Docker app image:

```powershell
docker compose build app
```

## Command

```powershell
.\scripts\week6_demo.ps1 -ArtifactRoot artifacts\final\week6-demo-local
```

Shell equivalent:

```sh
sh scripts/week6_demo.sh artifacts/final/week6-demo-local
```

## Expected Stages

1. Docker availability check.
2. Ollama reachability check.
3. Model availability check.
4. Application image build.
5. Original hybrid scan of `examples/vulnerable_app`.
6. Original hybrid scan of `examples/safe_app`.
7. Output manifest written under the artifact root.

## Output Fields

The scan report includes status, analyzer verdict, confidence, CWE, concise evidence, remediation, and metadata. Raw and structured outputs are stored in the selected artifact directory.

## Common Failures

- Docker is not running.
- Windows Ollama is not running.
- `qwen2.5-coder:7b` has not been pulled.
- Local hardware makes LLM inference slow.

## Cleanup

Demo artifacts can be removed from `artifacts/final/week6-demo-local` after inspection. Frozen Week 4, Week 5, and post-Week-5 artifacts should not be modified.
