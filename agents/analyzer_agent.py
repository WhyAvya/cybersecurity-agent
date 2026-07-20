import json

from llm.ollama_client import call_qwen


def run_analyzer(finding, context):

    prompt = f"""
You are a cybersecurity vulnerability analyst.

Your task is to determine whether the Semgrep finding is:

TP = True Positive
FP = False Positive
UNCERTAIN = Insufficient evidence

Allowed verdict values:
TP
FP
UNCERTAIN

Do NOT output FN.
Do NOT output TN.
Do NOT output any other label.

Analyze:

File:
{finding.file}

Rule:
{finding.rule_id}

CWE:
{finding.cwe_tag}

Code Context:
{context["context_lines"]}

Reason about:

1. Source:
Is user-controlled input present?

2. Data Flow:
Can the input reach the vulnerable operation?

3. Sink:
Is there a dangerous function or operation?

4. Sanitization:
Is there validation, escaping, filtering, or protection?

5. CWE Match:
Does the code actually match the CWE?

Return ONLY valid JSON:

{{
    "verdict": "TP",
    "confidence": 0.90,
    "reasoning": "...",
    "iterations": 1,
    "tool_call_evaded": false
}}
"""

    response = call_qwen(prompt)

    response = response.replace("```json", "")
    response = response.replace("```", "")
    response = response.strip()

    try:

        result = json.loads(response)

        verdict = result["verdict"].upper()

        if verdict not in ["TP", "FP", "UNCERTAIN"]:
            verdict = "UNCERTAIN"

        return {
            "verdict": verdict,
            "confidence": float(result["confidence"]),
            "reasoning": result["reasoning"],
            "iterations": result.get("iterations", 1),
            "tool_call_evaded": result.get(
                "tool_call_evaded",
                False
            )
        }

    except Exception:

        return {
            "verdict": "UNCERTAIN",
            "confidence": 0.0,
            "reasoning": "Failed to parse model response.",
            "iterations": 1,
            "tool_call_evaded": True
        }
