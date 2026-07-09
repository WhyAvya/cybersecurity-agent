import csv
import json


def load_ground_truth(csv_path):

    ground_truth = {}

    with open(csv_path, "r", encoding="utf-8") as file:

        reader = csv.reader(file)

        for row in reader:

            # Skip empty rows and comment line
            if not row or row[0].startswith("#"):
                continue

            test_id = row[0]
            category = row[1]
            vulnerable = row[2].lower() == "true"

            # Normalize CWE IDs (22 -> CWE-022)
            cwe_number = int(row[3])
            cwe = f"CWE-{cwe_number:03d}"

            ground_truth[test_id] = {
                "category": category,
                "vulnerable": vulnerable,
                "cwe": cwe
            }

    return ground_truth


if __name__ == "__main__":

    ground_truth = load_ground_truth(
        "data/BenchmarkPython/expectedresults-0.1.csv"
    )

    print(f"Loaded {len(ground_truth)} benchmark entries")
    benchmark_cwes = sorted(
    {entry["cwe"] for entry in ground_truth.values()}
)

    print("\nBenchmark CWEs:")
    print(benchmark_cwes)

    

    print("\nExample entry:")
    print(ground_truth["BenchmarkTest00001"])

    with open(
        "evaluation/ground_truth.json",
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            ground_truth,
            file,
            indent=4
        )

    print("\nSaved evaluation/ground_truth.json")