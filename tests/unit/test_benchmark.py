from pathlib import Path

import pytest

from vuln_agent.benchmark import bootstrap_benchmark, ground_truth_from_csv, verify_checksum


def test_ground_truth_from_csv_validates_and_normalizes(tmp_path: Path):
    csv_path = tmp_path / "truth.csv"
    csv_path.write_text("test_id,vulnerable,cwe\nA,true,CWE-89\nB,false,\n", encoding="utf-8")
    rows = ground_truth_from_csv(csv_path)
    assert rows["A"] == {"vulnerable": True, "cwe": "CWE-089"}
    assert rows["B"] == {"vulnerable": False, "cwe": "NONE"}


def test_ground_truth_from_csv_rejects_duplicates(tmp_path: Path):
    csv_path = tmp_path / "truth.csv"
    csv_path.write_text("test_id,vulnerable,cwe\nA,true,CWE-89\nA,false,\n", encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        ground_truth_from_csv(csv_path)


def test_verify_checksum_rejects_mismatch(tmp_path: Path):
    artifact = tmp_path / "benchmark.zip"
    artifact.write_text("payload", encoding="utf-8")
    actual = verify_checksum(artifact, None)
    assert len(actual) == 64
    with pytest.raises(ValueError, match="checksum mismatch"):
        verify_checksum(artifact, "0" * 64)


def test_bootstrap_benchmark_copies_local_source(tmp_path: Path):
    source = tmp_path / "source.zip"
    output = tmp_path / "downloads" / "benchmark.zip"
    source.write_text("benchmark", encoding="utf-8")
    checksum = verify_checksum(source, None)
    assert bootstrap_benchmark(str(source), output, checksum) == checksum
    assert output.read_text(encoding="utf-8") == "benchmark"
