import json
from datetime import datetime

from schemas.verdict import (
    SemgrepFinding,
    AgentVerdict
)


def log_verdict(
    finding: SemgrepFinding,
    verdict: AgentVerdict,
    output_path: str = "results/results.jsonl"
):
    record = {
        "timestamp": datetime.utcnow().isoformat(),
        **finding.model_dump(),
        **verdict.model_dump()
    }

    with open(output_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def log_failure(
    finding_id: str,
    error: str,
    agent_role: str,
    output_path: str = "results/results.jsonl"
):
    record = {
        "timestamp": datetime.utcnow().isoformat(),
        "finding_id": finding_id,
        "agent_role": agent_role,
        "schema_valid": False,
        "error": error,
        "verdict": "SCHEMA_FAILURE"
    }

    with open(output_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")