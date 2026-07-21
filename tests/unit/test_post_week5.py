from pathlib import Path

import pytest

from vuln_agent.exceptions import SchemaParseError
from vuln_agent.post_week5 import (
    as_bool,
    completed_keys,
    deterministic_balanced_ids,
    evidence_first_prompt,
    evidence_unsupported,
    parse_analysis,
    repair_prompt,
    resolve_critic_decision,
    sha256_text,
)
from vuln_agent.schemas import AgentAnalysis, Verdict


def test_deterministic_sampling_balances_and_excludes():
    ground_truth = {
        f"v{i}": {"vulnerable": True, "cwe": "CWE-089" if i % 2 else "CWE-079"} for i in range(8)
    } | {f"s{i}": {"vulnerable": False, "cwe": "CWE-089" if i % 2 else "CWE-079"} for i in range(8)}
    first = deterministic_balanced_ids(ground_truth, 6, 3, seed=7, exclude={"v0", "s0"})
    second = deterministic_balanced_ids(ground_truth, 6, 3, seed=7, exclude={"v0", "s0"})
    assert first == second
    assert "v0" not in first
    assert "s0" not in first
    assert sum(1 for item in first if ground_truth[item]["vulnerable"]) == 3


def test_evidence_first_prompt_requires_strict_schema():
    prompt = evidence_first_prompt("BenchmarkTest00001", "print('x')")
    assert "Confidence must be a JSON number" in prompt
    assert "Return exactly one JSON object" in prompt
    assert "attacker-controlled source" in prompt


def test_numeric_confidence_enforced():
    with pytest.raises(SchemaParseError):
        parse_analysis('{"verdict":"TP","confidence":"HIGH","normalized_cwe":"CWE-089","reasoning_summary":"x"}')


def test_repair_prompt_preserves_semantics_instruction():
    prompt = repair_prompt('{"verdict":"TP","confidence":"HIGH"}')
    assert "same semantic answer" in prompt
    assert "confidence: number from 0 to 1" in prompt


def test_evidence_unsupported_for_tp_missing_flow():
    analysis = AgentAnalysis(
        verdict=Verdict.tp,
        confidence=0.8,
        normalized_cwe="CWE-089",
        reasoning_summary="x",
        source_evidence="request arg",
        sink_evidence="execute",
        data_flow_evidence="",
    )
    assert evidence_unsupported(analysis)


def test_critic_resolution_can_reject_candidate_tp():
    candidate = AgentAnalysis(verdict=Verdict.tp, confidence=0.8, normalized_cwe="CWE-089", reasoning_summary="x")
    critic = AgentAnalysis(verdict=Verdict.fp, confidence=0.7, normalized_cwe="NONE", reasoning_summary="unsupported")
    assert resolve_critic_decision(candidate, critic).verdict == Verdict.fp


def test_checkpoint_resume_accounts_error_rows(tmp_path: Path):
    path = tmp_path / "runs.jsonl"
    path.write_text(
        '{"configuration":"a","case_id":"1","error":"timeout"}\n'
        '{"configuration":"a","case_id":"2","raw_response_path":"raw.txt"}\n',
        encoding="utf-8",
    )
    assert completed_keys(path, ("configuration", "case_id")) == {("a", "1"), ("a", "2")}


def test_prompt_hash_stable_and_bool_parser():
    assert sha256_text("abc") == sha256_text("abc")
    assert as_bool(True)
    assert as_bool("True")
    assert not as_bool("False")
