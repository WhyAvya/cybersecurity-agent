# agents/reporter_agent.py

def run_reporter(finding, analysis):

    confidence = analysis["confidence"]

    if finding.severity == "HIGH" and confidence > 0.85:
        priority = "CRITICAL"
    elif finding.severity == "HIGH" and confidence > 0.6:
        priority = "HIGH"
    elif confidence >= 0.4:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    return {
        "cwe_id": finding.cwe_tag,
        "cwe_mismatch": False,
        "priority": priority,
        "reasoning": analysis["reasoning"]
    }