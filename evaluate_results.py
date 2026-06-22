import json

tp = 0
fp = 0
uncertain = 0

schema_failures = 0
tool_evasion = 0

confidences = []

with open(
    "results/results.jsonl",
    "r",
    encoding="utf-8"
) as f:

    for line in f:

        row = json.loads(line)

        verdict = row.get("verdict")

        if verdict == "TP":
            tp += 1

        elif verdict == "FP":
            fp += 1

        elif verdict == "UNCERTAIN":
            uncertain += 1

        elif verdict == "SCHEMA_FAILURE":
            schema_failures += 1

        if row.get("tool_call_evaded"):
            tool_evasion += 1

        if "confidence" in row:
            confidences.append(
                row["confidence"]
            )

avg_confidence = (
    sum(confidences) / len(confidences)
    if confidences
    else 0
)

print("\n=== EVALUATION RESULTS ===")
print("TP:", tp)
print("FP:", fp)
print("UNCERTAIN:", uncertain)
print("Schema Failures:", schema_failures)
print("Tool Evasion:", tool_evasion)
print(
    "Average Confidence:",
    round(avg_confidence, 3)
)