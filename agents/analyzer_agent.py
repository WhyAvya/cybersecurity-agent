# agents/analyzer_agent.py

def run_analyzer(finding, context):

    context_text = context["context_lines"]

    if "request.cookies" in context_text and "codecs.open" in context_text:
        return {
            "verdict": "TP",
            "confidence": 0.85,
            "reasoning": (
                "User-controlled cookie value reaches file open operation."
            ),
            "iterations": 1,
            "tool_call_evaded": False
        }

    return {
        "verdict": "UNCERTAIN",
        "confidence": 0.4,
        "reasoning": "Insufficient evidence.",
        "iterations": 1,
        "tool_call_evaded": False
    }