from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .models import PlanStep, RepositoryInventory, ScanGoal, ScanPlan


IGNORED_DIRECTORIES = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__", "artifacts"}
DEFAULT_CONFIG_PATH = Path("config") / "agentic_v2.yaml"


@dataclass(frozen=True)
class RouteDecision:
    inventory: RepositoryInventory
    active_cwes: list[str]
    skipped_cwes: dict[str, str]
    reason: str
    planning_steps: list[PlanStep]
    framework_indicators: list[str]
    database_imports: list[str]
    sql_execution_apis: list[str]
    shell_indicators: list[str]
    request_input_sources: list[str]
    excluded_directory_count: int
    scanned_file_count: int

    def scan_plan(self) -> ScanPlan:
        return ScanPlan(
            goal=ScanGoal(target_path=self.inventory.root_path, supported_cwes=self.active_cwes),
            steps=self.planning_steps,
        )


def inspect_repository(repository_root: str | Path, config_path: str | Path | None = None) -> RouteDecision:
    root = _safe_root(repository_root)
    config = _load_policy(Path(config_path) if config_path else DEFAULT_CONFIG_PATH)
    shell_patterns = tuple(config["routing"]["shell_indicators"])
    sql_patterns = tuple(config["routing"]["sql_indicators"])

    python_files: list[str] = []
    skipped_files: list[str] = []
    excluded_directory_count = 0
    text_by_file: dict[str, str] = {}

    for current, dirs, files in _walk_sorted(root):
        kept_dirs = []
        for dirname in dirs:
            if dirname in IGNORED_DIRECTORIES:
                excluded_directory_count += 1
                continue
            candidate = _resolve_inside(root, current / dirname)
            if candidate.is_symlink() and not candidate.resolve().is_relative_to(root):
                excluded_directory_count += 1
                continue
            kept_dirs.append(dirname)
        dirs[:] = kept_dirs

        for filename in files:
            path = _resolve_inside(root, current / filename)
            relative = path.relative_to(root).as_posix()
            if path.suffix != ".py":
                skipped_files.append(relative)
                continue
            python_files.append(relative)
            try:
                text_by_file[relative] = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                skipped_files.append(relative)

    framework_indicators = _collect_indicators(text_by_file, ("flask", "django", "fastapi", "aiohttp", "tornado"))
    database_imports = _collect_indicators(text_by_file, ("sqlite3", "sqlalchemy", "psycopg2", "pymysql", "mysql", "postgres"))
    sql_execution_apis = _collect_indicators(text_by_file, sql_patterns)
    shell_indicators = _collect_indicators(text_by_file, shell_patterns)
    request_input_sources = _collect_indicators(
        text_by_file,
        ("request.", "request(", "input(", "sys.argv", "os.environ", "argparse"),
    )

    active_cwes: list[str] = []
    skipped_cwes: dict[str, str] = {}
    planning_steps: list[PlanStep] = []

    if shell_indicators:
        active_cwes.append("CWE-078")
        planning_steps.append(
            PlanStep(step_id="route-cwe-078", role="router", action="activate", target="CWE-078", status="planned")
        )
    else:
        skipped_cwes["CWE-078"] = "no shell indicators found"

    if database_imports or sql_execution_apis:
        active_cwes.append("CWE-089")
        planning_steps.append(
            PlanStep(step_id="route-cwe-089", role="router", action="activate", target="CWE-089", status="planned")
        )
    else:
        skipped_cwes["CWE-089"] = "no SQL or database indicators found"

    reason = "static indicators found" if active_cwes else "no supported CWE indicators found"
    inventory = RepositoryInventory(
        root_path=str(root),
        files_considered=len(python_files) + len(skipped_files),
        python_files=sorted(python_files),
        skipped_files=sorted(skipped_files),
    )
    return RouteDecision(
        inventory=inventory,
        active_cwes=active_cwes,
        skipped_cwes=skipped_cwes,
        reason=reason,
        planning_steps=planning_steps,
        framework_indicators=framework_indicators,
        database_imports=database_imports,
        sql_execution_apis=sql_execution_apis,
        shell_indicators=shell_indicators,
        request_input_sources=request_input_sources,
        excluded_directory_count=excluded_directory_count,
        scanned_file_count=len(python_files),
    )


def _load_policy(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _safe_root(repository_root: str | Path) -> Path:
    raw = Path(repository_root)
    if any(part == ".." for part in raw.parts):
        raise ValueError("repository path traversal is not allowed")
    root = raw.resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError("repository root must be an existing directory")
    return root


def _resolve_inside(root: Path, path: Path) -> Path:
    resolved = path.resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError("resolved path escapes repository root")
    return resolved


def _walk_sorted(root: Path):
    import os

    for current, dirs, files in os.walk(root):
        dirs.sort()
        files.sort()
        yield Path(current), dirs, files


def _collect_indicators(text_by_file: dict[str, str], patterns: tuple[str, ...]) -> list[str]:
    found = set()
    for text in text_by_file.values():
        lowered = text.lower()
        for pattern in patterns:
            if pattern.lower() in lowered:
                found.add(pattern)
    return sorted(found)
