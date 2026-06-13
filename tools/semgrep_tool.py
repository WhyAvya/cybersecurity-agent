import subprocess
import json


def run_semgrep(target_path: str, config: str = "p/python"):

    command = [
        "semgrep",
        "--json",
        "--no-git-ignore",
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

    if not result.stdout:
        return []

    raw = json.loads(result.stdout)

    findings = []

    for i, r in enumerate(raw.get("results", [])):

        cwe = (
            r.get("extra", {})
             .get("metadata", {})
             .get("cwe", "UNKNOWN")
        )

        # Semgrep sometimes returns a list of CWEs
        if isinstance(cwe, list):
            cwe = cwe[0]

        findings.append({
            "finding_id": f"finding-{i:04d}",
            "file": r["path"],
            "line": r["start"]["line"],
            "rule_id": r["check_id"],
            "cwe_tag": cwe,
            "severity": r.get("extra", {}).get("severity", "MEDIUM"),
            "snippet": r.get("extra", {}).get("lines", "")
        })

    return findings