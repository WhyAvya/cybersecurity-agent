param(
    [string]$ArtifactRoot = "artifacts/final/week6-demo-local",
    [string]$ImageName = "cybersecurity-agent-app:latest"
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $repo

function Fail($message) {
    Write-Error $message
    exit 1
}

docker version *> $null
if ($LASTEXITCODE -ne 0) { Fail "Docker is not available." }

$tags = docker run --rm --entrypoint python $ImageName -c "import requests; r=requests.get('http://host.docker.internal:11434/api/tags', timeout=10); r.raise_for_status(); print(r.text)"
if ($LASTEXITCODE -ne 0) { Fail "Ollama is not reachable at http://host.docker.internal:11434." }
if ($tags -notmatch "qwen2.5-coder:7b") { Fail "Required Ollama model qwen2.5-coder:7b is not installed." }

docker compose build app
if ($LASTEXITCODE -ne 0) { Fail "Docker build failed." }

New-Item -ItemType Directory -Force -Path $ArtifactRoot | Out-Null

$vulnOut = Join-Path $ArtifactRoot "demo_vulnerable"
$safeOut = Join-Path $ArtifactRoot "demo_safe"
$containerVulnOut = ($vulnOut -replace "\\", "/")
$containerSafeOut = ($safeOut -replace "\\", "/")

docker run --rm -v "${PWD}:/work" -w /work --user root -e OLLAMA_BASE_URL=http://host.docker.internal:11434 -e OLLAMA_MODEL=qwen2.5-coder:7b $ImageName scan examples/vulnerable_app --output-dir $containerVulnOut
if ($LASTEXITCODE -ne 0) { Fail "Vulnerable demo scan failed." }

docker run --rm -v "${PWD}:/work" -w /work --user root -e OLLAMA_BASE_URL=http://host.docker.internal:11434 -e OLLAMA_MODEL=qwen2.5-coder:7b $ImageName scan examples/safe_app --output-dir $containerSafeOut
if ($LASTEXITCODE -ne 0) { Fail "Safe demo scan failed." }

$manifest = @{
    artifact_root = $ArtifactRoot
    vulnerable_output = $vulnOut
    safe_output = $safeOut
    mode = "original hybrid scan workflow"
    ollama_base_url = "http://host.docker.internal:11434"
    model = "qwen2.5-coder:7b"
    completed_at = (Get-Date).ToUniversalTime().ToString("o")
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $ArtifactRoot "demo_manifest.json")

Write-Host "Week 6 demo complete"
Write-Host "Vulnerable output: $vulnOut"
Write-Host "Safe output: $safeOut"
