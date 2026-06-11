from tools.context_fetcher import fetch_context


def run_scanner(finding):
    context = fetch_context(
        finding.file,
        finding.line
    )

    summary = {
        "finding_id": finding.finding_id,
        "flagged_variable": "UNKNOWN",
        "context_lines": context,
        "semgrep_cwe": finding.cwe_tag
    }

    return summary