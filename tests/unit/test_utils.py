import pytest
from pydantic import BaseModel

from vuln_agent.exceptions import SchemaParseError
from vuln_agent.utils import extract_json_object, infer_cwe_from_rule, normalize_cwe, normalize_cwe_list, parse_model_json, stable_finding_id
from vuln_agent.schemas import FileAnalysis


class TinyModel(BaseModel):
    verdict: str


def test_normalize_cwe_variants():
    assert normalize_cwe("CWE-79: XSS") == "CWE-079"
    assert normalize_cwe("cwe_22") == "CWE-022"
    assert normalize_cwe(None) == "NONE"
    assert normalize_cwe_list(["CWE-79", "CWE-079", "noise"]) == ["CWE-079"]


def test_extract_json_from_fenced_response():
    assert extract_json_object('```json\n{"verdict": "TP"}\n```') == {"verdict": "TP"}


def test_extract_json_allows_harmless_surrounding_text():
    assert extract_json_object('Here is JSON:\n{"verdict": "TP"}\nDone.') == {"verdict": "TP"}


def test_file_analysis_allows_null_evidence_strings_only():
    parsed = parse_model_json(
        '{"findings":[{"line_start":1,"line_end":1,"verdict":"TP","confidence":0.8,'
        '"normalized_cwe":"CWE-078","reasoning_summary":"x","sanitization_evidence":null}]}',
        FileAnalysis,
    )
    assert parsed.findings[0].sanitization_evidence == ""


def test_parse_model_json_rejects_malformed_text():
    with pytest.raises(SchemaParseError):
        parse_model_json("no json here", TinyModel)


def test_stable_finding_id_is_deterministic():
    first = stable_finding_id("a.py", 10, 2, "rule", "x = 1")
    second = stable_finding_id("a.py", 10, 2, "rule", "x = 1")
    assert first == second
    assert first.startswith("finding-")


def test_conservative_cwe_rule_inference():
    assert infer_cwe_from_rule("python.sql.injection", "CWE-704") == ("CWE-089", "rule_inference")
    assert infer_cwe_from_rule("python.subprocess.shell", "NONE") == ("CWE-078", "rule_inference")
    assert infer_cwe_from_rule("python.path-traversal.open", "NONE") == ("CWE-022", "rule_inference")
    assert infer_cwe_from_rule("python.flask.debug-enabled", "NONE") == ("CWE-489", "rule_inference")
    assert infer_cwe_from_rule("unknown.rule", "CWE-079") == ("CWE-079", "provided")
