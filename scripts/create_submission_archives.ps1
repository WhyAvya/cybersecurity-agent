param(
    [string]$Ref = "week6-final-complete",
    [string]$OutputDir = "submission_archives",
    [string]$EvidenceArtifact,
    [switch]$AllowDirty
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $repo

if (-not $AllowDirty) {
    $dirty = git status --porcelain
    if ($dirty) {
        throw "Working tree is not clean. Commit/stash changes or use -AllowDirty intentionally."
    }
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$sourceZip = Join-Path $OutputDir "cybersecurity-agent-source-$($Ref -replace '[^A-Za-z0-9_.-]','-').zip"
git archive --format zip --output $sourceZip $Ref

Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::OpenRead((Resolve-Path $sourceZip)).Dispose()
Write-Host "Source archive: $sourceZip $((Get-Item $sourceZip).Length) bytes"

if ($EvidenceArtifact) {
    $evidenceZip = Join-Path $OutputDir "cybersecurity-agent-evidence.zip"
    if (Test-Path $evidenceZip) { Remove-Item $evidenceZip -Force }
    Compress-Archive -Path (Join-Path $EvidenceArtifact "*") -DestinationPath $evidenceZip
    [IO.Compression.ZipFile]::OpenRead((Resolve-Path $evidenceZip)).Dispose()
    Write-Host "Evidence archive: $evidenceZip $((Get-Item $evidenceZip).Length) bytes"
}
