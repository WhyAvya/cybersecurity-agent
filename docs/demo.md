# Demo

Run an offline demo without Semgrep or Ollama:

```bash
vuln-agent demo
```

Run a real scan after installing Semgrep and starting Ollama:

```bash
vuln-agent scan examples/vulnerable_app
```

PowerShell helper to inspect the latest scan report without manually replacing
`<run_id>`:

```powershell
$latestScan = Get-ChildItem artifacts\reports -Directory |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1
Get-ChildItem $latestScan.FullName
Get-Content (Join-Path $latestScan.FullName "scan_report.md")
```

PowerShell helper to inspect the latest evaluation report:

```powershell
$latestEval = Get-ChildItem artifacts\evaluation -Directory |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1
Get-ChildItem $latestEval.FullName -Recurse
Get-Content (Join-Path $latestEval.FullName "week4_report.md")
Get-Content (Join-Path $latestEval.FullName "week5_report.md")
```
