import subprocess
import json


def run_semgrep(target_path: str, config: str = "p/python"):

    command = [
        "semgrep",
        "--json",
        "--config",
        config,
        target_path
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore"
    )

    raw = json.loads(result.stdout)

    findings = []

    for i, r in enumerate(raw.get("results", [])):
        findings.append({
            "finding_id": f"finding-{i:04d}",
            "file": r["path"],
            "line": r["start"]["line"],
            "rule_id": r["check_id"],
            "cwe_tag": r.get("extra", {}).get("metadata", {}).get("cwe", "UNKNOWN"),
            "severity": r.get("extra", {}).get("severity", "MEDIUM"),
            "snippet": r.get("extra", {}).get("lines", "")
        })

    return findings