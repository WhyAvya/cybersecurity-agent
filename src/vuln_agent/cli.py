"""Command line interface for vuln-agent."""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from .config import ConfigurationError, load_settings
from .exceptions import SecurityPolicyError, ToolError
from .evaluation import run_evaluation
from .llm import OllamaClient
from .orchestrator import VulnerabilityOrchestrator
from .semgrep import SemgrepAdapter


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vuln-agent")
    parser.add_argument("--config", help="Path to YAML or JSON configuration.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor_parser = subparsers.add_parser("doctor", help="Check local configuration and optional services.")
    doctor_parser.add_argument("--config", help=argparse.SUPPRESS)

    scan = subparsers.add_parser("scan", help="Scan a file or directory.")
    scan.add_argument("--config", help=argparse.SUPPRESS)
    scan.add_argument("path")
    scan.add_argument("--output-dir")
    scan.add_argument("--semgrep-config")
    scan.add_argument("--model")
    scan.add_argument("--max-files", type=int)
    scan.add_argument("--mode", choices=["semgrep", "llm", "semgrep_gated", "hybrid"], default="hybrid")
    scan.add_argument("--offline", action="store_true")
    scan.add_argument("--save-raw", action="store_true")

    demo = subparsers.add_parser("demo", help="Run a local offline demo scan.")
    demo.add_argument("--config", help=argparse.SUPPRESS)
    demo.add_argument("--output-dir")

    evaluate = subparsers.add_parser("evaluate", help="Create an evaluation run scaffold.")
    evaluate.add_argument("--config", help=argparse.SUPPRESS)
    evaluate.add_argument("mode", choices=["semgrep", "llm", "semgrep_gated", "hybrid", "all"])
    evaluate.add_argument("--sample-size", type=int)
    evaluate.add_argument("--seed", type=int)
    evaluate.add_argument("--offline", action="store_true")
    evaluate.add_argument("--resume", action="store_true")

    trust = subparsers.add_parser("trustworthiness", help="Locate or generate trustworthiness report artifacts.")
    trust.add_argument("--config", help=argparse.SUPPRESS)
    trust.add_argument("--latest-run", action="store_true")

    report = subparsers.add_parser("report", help="Generate report scaffold.")
    report.add_argument("--config", help=argparse.SUPPRESS)
    report.add_argument("name", choices=["week4", "week5"])
    report.add_argument("--latest-run", action="store_true")
    return parser


def _settings_from_args(args: argparse.Namespace):
    overrides = {
        "semgrep_config": getattr(args, "semgrep_config", None),
        "ollama_model": getattr(args, "model", None),
        "max_files_per_scan": getattr(args, "max_files", None),
    }
    return load_settings(args.config, overrides)


def doctor(args: argparse.Namespace) -> int:
    settings = _settings_from_args(args)
    print("Python:", sys.version.split()[0])
    print("Config: OK")
    semgrep_path = shutil.which(settings.semgrep_binary) or SemgrepAdapter(settings).executable_path()
    if semgrep_path:
        print(f"Semgrep: {semgrep_path}")
    else:
        print(f"Semgrep: missing ({settings.semgrep_binary})")
    health = OllamaClient(settings).healthcheck()
    print(f"Ollama: {health.message}")
    for path in (settings.artifact_root, settings.report_dir, settings.evaluation_dir):
        path.mkdir(parents=True, exist_ok=True)
        print(f"Writable: {path}")
    return 0 if semgrep_path and health.ok else 2


def scan(args: argparse.Namespace) -> int:
    settings = _settings_from_args(args)
    orchestrator = VulnerabilityOrchestrator(settings)
    records, output_dir = orchestrator.scan(
        args.path,
        Path(args.output_dir) if args.output_dir else None,
        offline=args.offline,
        mode=args.mode,
        save_raw=args.save_raw,
    )
    underlying = 0
    report_path = output_dir / "raw_findings.jsonl"
    if report_path.exists():
        underlying = sum(1 for line in report_path.read_text(encoding="utf-8").splitlines() if line.strip())
    print(f"Mode: {args.mode}")
    print(f"Grouped findings: {len(records)}")
    print(f"Underlying matches: {underlying or len(records)}")
    print(f"Output: {output_dir}")
    return 0


def demo(args: argparse.Namespace) -> int:
    settings = _settings_from_args(args)
    demo_path = Path("examples/vulnerable_app")
    if not demo_path.exists():
        demo_path = PROJECT_ROOT / "examples/vulnerable_app"
    if not demo_path.exists():
        demo_path = PROJECT_ROOT / "test_projects/vulnerable_app"
    orchestrator = VulnerabilityOrchestrator(settings)
    records, output_dir = orchestrator.scan(
        demo_path,
        Path(args.output_dir) if args.output_dir else None,
        offline=True,
    )
    print(f"Demo findings: {len(records)}")
    print(f"Output: {output_dir}")
    return 0


def latest_run(evaluation_dir: Path) -> Path | None:
    if not evaluation_dir.exists():
        return None
    runs = [path for path in evaluation_dir.iterdir() if path.is_dir() and (path / "manifest.json").exists()]
    return sorted(runs)[-1] if runs else None


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            return doctor(args)
        if args.command == "scan":
            return scan(args)
        if args.command == "demo":
            return demo(args)
        settings = _settings_from_args(args)
        if args.command == "evaluate":
            output_dir = run_evaluation(
                settings,
                args.mode,
                sample_size=args.sample_size,
                seed=args.seed,
                offline=args.offline,
                project_root=PROJECT_ROOT,
            )
            print(f"Evaluation output: {output_dir}")
            return 0
        if args.command == "trustworthiness":
            run_dir = latest_run(settings.evaluation_dir) if args.latest_run else None
            if run_dir is None:
                output_dir = run_evaluation(settings, "all", offline=True, project_root=PROJECT_ROOT)
                print(f"Trustworthiness output: {output_dir / 'week5_report.md'}")
                return 0
            print(f"Trustworthiness output: {run_dir / 'week5_report.md'}")
            return 0
        if args.command == "report":
            run_dir = latest_run(settings.evaluation_dir)
            if run_dir is None:
                print("No evaluation runs found. Run `vuln-agent evaluate all --offline` first.", file=sys.stderr)
                return 1
            report_name = "week4_report.md" if args.name == "week4" else "week5_report.md"
            print(f"Report output: {run_dir / report_name}")
            return 0
    except (ConfigurationError, SecurityPolicyError, ToolError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
