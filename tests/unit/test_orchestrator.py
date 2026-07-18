from pathlib import Path

from vuln_agent.config import Settings
from vuln_agent.orchestrator import VulnerabilityOrchestrator
from vuln_agent.schemas import FindingStatus, Verdict


def test_offline_scan_writes_reports(tmp_path: Path):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "app.py").write_text(
        "import os\n\n\ndef run(name):\n    os.system('echo ' + name)\n",
        encoding="utf-8",
    )
    settings = Settings(
        report_dir=tmp_path / "reports",
        artifact_root=tmp_path / "artifacts",
        allowed_scan_root=tmp_path,
    )

    records, output_dir = VulnerabilityOrchestrator(settings).scan(app_dir, offline=True)

    assert len(records) == 1
    assert records[0].status == FindingStatus.accepted
    assert records[0].analyzer_verdict == Verdict.tp
    assert (output_dir / "manifest.json").exists()
    assert (output_dir / "scan_report.jsonl").exists()
    assert (output_dir / "scan_report.md").exists()
