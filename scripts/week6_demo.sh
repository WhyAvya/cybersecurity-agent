#!/usr/bin/env sh
set -eu

ARTIFACT_ROOT="${1:-artifacts/final/week6-demo-local}"
IMAGE_NAME="${IMAGE_NAME:-cybersecurity-agent-app:latest}"

cd "$(dirname "$0")/.."

docker version >/dev/null
docker run --rm --entrypoint python "$IMAGE_NAME" -c "import requests; r=requests.get('http://host.docker.internal:11434/api/tags', timeout=10); r.raise_for_status(); assert 'qwen2.5-coder:7b' in r.text"
docker compose build app

mkdir -p "$ARTIFACT_ROOT"
docker run --rm -v "$PWD:/work" -w /work --user root -e OLLAMA_BASE_URL=http://host.docker.internal:11434 -e OLLAMA_MODEL=qwen2.5-coder:7b "$IMAGE_NAME" scan examples/vulnerable_app --mode hybrid --save-raw --output-dir "$ARTIFACT_ROOT/demo_vulnerable"
docker run --rm -v "$PWD:/work" -w /work --user root -e OLLAMA_BASE_URL=http://host.docker.internal:11434 -e OLLAMA_MODEL=qwen2.5-coder:7b "$IMAGE_NAME" scan examples/safe_app --mode hybrid --save-raw --output-dir "$ARTIFACT_ROOT/demo_safe"

cat > "$ARTIFACT_ROOT/demo_manifest.json" <<EOF
{"artifact_root":"$ARTIFACT_ROOT","vulnerable_output":"$ARTIFACT_ROOT/demo_vulnerable","safe_output":"$ARTIFACT_ROOT/demo_safe","mode":"original hybrid scan workflow","ollama_base_url":"http://host.docker.internal:11434","model":"qwen2.5-coder:7b"}
EOF
echo "Week 6 demo complete: $ARTIFACT_ROOT"
