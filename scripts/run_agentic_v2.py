from __future__ import annotations

import argparse
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from vuln_agent.agentic_v2.orchestrator import run_from_args


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the bounded Plan B v2 agentic MVP on a local repository.")
    parser.add_argument("--repository", required=True, help="Local repository path to inspect and scan.")
    parser.add_argument("--cwes", nargs="+", choices=["CWE-078", "CWE-089"], required=True)
    parser.add_argument("--auto-approve", action="store_true")
    parser.add_argument("--auto-review-policy", default="keep", choices=["keep"])
    return parser


def main() -> int:
    return run_from_args(build_parser().parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
