# agents/llm_baseline_agent.py

import json
import re

from llm.ollama_client import call_qwen


ALLOWED_CWES = [
    "CWE-022",
    "CWE-078",
    "CWE-079",
    "CWE-089",
    "CWE-090",
    "CWE-094",
    "CWE-328",
    "CWE-330",
    "CWE-501",
    "CWE-502",
    "CWE-601",
    "CWE-611",
    "CWE-614",
    "CWE-643",
]


def normalize_cwe(cwe_text):
    if not cwe_text:
        return "NONE"

    match = re.search(r"CWE[-_]?(\d+)", str(cwe_text), re.IGNORECASE)

    if not match:
        return "NONE"

    return f"CWE-{int(match.group(1)):03d}"


def extract_json(response):
    response = response.replace("```json", "")
    response = response.replace("```", "")
    response = response.strip()

    match = re.search(r"\{.*\}", response, re.DOTALL)

    if not match:
        raise ValueError("No JSON found in LLM response")

    return json.loads(match.group(0))


def run_llm_baseline(code):
    allowed_cwes = "\n".join(f"- {cwe}" for cwe in ALLOWED_CWES)

    prompt = f"""
You are a cybersecurity expert.

Analyze the following Python source code.

Your task is to determine whether the code contains one of the security
vulnerabilities present in the benchmark.

The benchmark ONLY contains the following CWE IDs:

{allowed_cwes}

Instructions:

1. Decide whether the code is vulnerable.
2. If vulnerable, choose ONLY ONE CWE from the allowed list.
3. Do NOT invent a new CWE.
4. If none of the listed CWEs apply, return SAFE.
5. Return ONLY valid JSON.

Valid vulnerable output:

{{
    "verdict": "VULNERABLE",
    "cwe": "CWE-022",
    "confidence": 0.92,
    "reasoning": "..."
}}

Valid safe output:

{{
    "verdict": "SAFE",
    "cwe": "NONE",
    "confidence": 0.80,
    "reasoning": "..."
}}

Python Code:

{code[:6000]}
"""

    response = call_qwen(prompt)

    try:
        result = extract_json(response)

        verdict = str(result.get("verdict", "SAFE")).upper()

        if verdict not in ["VULNERABLE", "SAFE"]:
            verdict = "SAFE"

        cwe = normalize_cwe(result.get("cwe", "NONE"))

        if verdict == "SAFE":
            cwe = "NONE"

        if verdict == "VULNERABLE" and cwe not in ALLOWED_CWES:
            cwe = "NONE"

        return {
            "verdict": verdict,
            "cwe": cwe,
            "confidence": float(result.get("confidence", 0.0)),
            "reasoning": result.get("reasoning", ""),
            "schema_valid": True
        }

    except Exception as e:
        return {
            "verdict": "SAFE",
            "cwe": "NONE",
            "confidence": 0.0,
            "reasoning": f"Failed to parse model response: {str(e)}",
            "schema_valid": False
        }
