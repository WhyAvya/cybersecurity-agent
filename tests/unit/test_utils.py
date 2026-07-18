import pytest
from pydantic import BaseModel

from vuln_agent.exceptions import SchemaParseError
from vuln_agent.utils import extract_json_object, normalize_cwe, normalize_cwe_list, parse_model_json, stable_finding_id


class TinyModel(BaseModel):
    verdict: str


def test_normalize_cwe_variants():
    assert normalize_cwe("CWE-79: XSS") == "CWE-079"
    assert normalize_cwe("cwe_22") == "CWE-022"
    assert normalize_cwe(None) == "NONE"
    assert normalize_cwe_list(["CWE-79", "CWE-079", "noise"]) == ["CWE-079"]


def test_extract_json_from_fenced_response():
    assert extract_json_object('```json\n{"verdict": "TP"}\n```') == {"verdict": "TP"}


def test_parse_model_json_rejects_malformed_text():
    with pytest.raises(SchemaParseError):
        parse_model_json("no json here", TinyModel)


def test_stable_finding_id_is_deterministic():
    first = stable_finding_id("a.py", 10, 2, "rule", "x = 1")
    second = stable_finding_id("a.py", 10, 2, "rule", "x = 1")
    assert first == second
    assert first.startswith("finding-")
