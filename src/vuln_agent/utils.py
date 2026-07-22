"""Shared parsing, CWE normalization, and identity helpers."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from pydantic import BaseModel, ValidationError

from .exceptions import SchemaParseError


def normalize_cwe(cwe_text: Any) -> str:
    if not cwe_text:
        return "NONE"
    if isinstance(cwe_text, list):
        for item in cwe_text:
            normalized = normalize_cwe(item)
            if normalized != "NONE":
                return normalized
        return "NONE"
    match = re.search(r"CWE[-_ ]?(\d+)", str(cwe_text), re.IGNORECASE)
    if not match:
        return "NONE"
    return f"CWE-{int(match.group(1)):03d}"


def normalize_cwe_list(cwes: Any) -> list[str]:
    if cwes is None:
        return []
    values = cwes if isinstance(cwes, list) else [cwes]
    normalized = []
    for value in values:
        cwe = normalize_cwe(value)
        if cwe != "NONE" and cwe not in normalized:
            normalized.append(cwe)
    return normalized


def extract_json_object(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?", "", cleaned, flags=re.IGNORECASE).strip()
    cleaned = re.sub(r"```$", "", cleaned).strip()
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start < 0 or end <= start:
            raise SchemaParseError("No JSON object found in response")
        try:
            data = json.loads(cleaned[start : end + 1])
        except json.JSONDecodeError as exc:
            raise SchemaParseError(f"Invalid JSON response: {exc}") from exc
    if not isinstance(data, dict):
        raise SchemaParseError("Expected a JSON object")
    return data


def parse_model_json(text: str, schema: type[BaseModel]) -> BaseModel:
    try:
        return schema.model_validate(extract_json_object(text))
    except ValidationError as exc:
        raise SchemaParseError(str(exc)) from exc


def stable_finding_id(
    relative_file: str,
    line: int,
    column: int | None,
    rule_id: str,
    snippet: str,
) -> str:
    canonical = "|".join(
        [
            relative_file.replace("\\", "/"),
            str(line),
            str(column or 0),
            rule_id,
            " ".join(snippet.split()),
        ]
    )
    return "finding-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def infer_cwe_from_rule(rule_id: str, existing_cwe: str = "NONE") -> tuple[str, str]:
    normalized = normalize_cwe(existing_cwe)
    rule = rule_id.lower()
    generic = normalized in {"NONE", "CWE-704"}
    if not generic:
        return normalized, "provided"
    if any(token in rule for token in ("sql", "sqli")):
        return "CWE-089", "rule_inference"
    if any(token in rule for token in ("command", "subprocess", "shell", "os-system", "exec")):
        return "CWE-078", "rule_inference"
    if any(token in rule for token in ("path-traversal", "path_traversal", "directory-traversal")):
        return "CWE-022", "rule_inference"
    if "debug" in rule:
        return "CWE-489", "rule_inference"
    return normalized, "provided" if normalized != "NONE" else "unknown"
