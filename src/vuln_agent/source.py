"""Safe source path resolution and bounded context fetching."""

from __future__ import annotations

from pathlib import Path

from .config import Settings
from .exceptions import SecurityPolicyError


def resolve_scan_path(path: str | Path, settings: Settings) -> Path:
    target = Path(path).resolve()
    if not target.exists():
        raise SecurityPolicyError(f"Target path does not exist: {target}")
    if target.is_symlink():
        raise SecurityPolicyError(f"Refusing symlink scan target: {target}")
    root = settings.allowed_scan_root.resolve()
    if not settings.allow_scan_root_escape and target != root and root not in target.parents:
        raise SecurityPolicyError(f"Target path is outside allowed scan root: {target}")
    return target


def iter_source_files(target: Path, settings: Settings) -> list[Path]:
    paths = [target] if target.is_file() else [p for p in target.rglob("*") if p.is_file()]
    accepted: list[Path] = []
    for path in paths:
        if len(accepted) >= settings.max_files_per_scan:
            raise SecurityPolicyError("Maximum files per scan exceeded")
        if path.is_symlink():
            continue
        if any(part in settings.excluded_directories for part in path.parts):
            continue
        if path.suffix not in settings.allowed_extensions:
            continue
        if path.stat().st_size > settings.max_file_size_bytes:
            raise SecurityPolicyError(f"File exceeds size limit: {path}")
        accepted.append(path)
    return accepted


def fetch_context(file_path: str | Path, line: int, settings: Settings) -> str:
    path = Path(file_path).resolve()
    root = settings.allowed_scan_root.resolve()
    if not settings.allow_scan_root_escape and root not in path.parents and path != root:
        raise SecurityPolicyError(f"Context file is outside allowed scan root: {path}")
    if path.is_symlink():
        raise SecurityPolicyError(f"Refusing symlink context file: {path}")
    if path.stat().st_size > settings.max_file_size_bytes:
        raise SecurityPolicyError(f"File exceeds size limit: {path}")
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(0, line - settings.context_lines_before - 1)
    end = min(len(lines), line + settings.context_lines_after)
    return "\n".join(f"{number}: {lines[number - 1]}" for number in range(start + 1, end + 1))
