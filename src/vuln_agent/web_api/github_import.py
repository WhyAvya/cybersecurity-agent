"""Public GitHub repository inspection with conservative validation."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import uuid
from pathlib import Path
from urllib.parse import urlparse

from .config import WebSettings
from .source_manager import SourceError, SourceManager

OWNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")
REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
REF_RE = re.compile(r"^[A-Za-z0-9._/\-]{1,200}$")
COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")


def normalize_github_url(url: str) -> tuple[str, str, str]:
    if "\x00" in url or any(ord(ch) < 32 for ch in url):
        raise SourceError("INVALID_GITHUB_URL", "Repository URL contains control characters.")
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "github.com" or parsed.port:
        raise SourceError("INVALID_GITHUB_URL", "Use a public https://github.com/owner/repository URL.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise SourceError("INVALID_GITHUB_URL", "Credentials, query strings and fragments are not accepted.")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 2:
        raise SourceError("INVALID_GITHUB_URL", "Repository URL must contain exactly owner and repository.")
    owner, repo = parts
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not OWNER_RE.fullmatch(owner) or not REPO_RE.fullmatch(repo):
        raise SourceError("INVALID_GITHUB_URL", "Owner or repository name is invalid.")
    return f"https://github.com/{owner}/{repo}", owner, repo


def validate_revision(kind: str, value: str) -> None:
    if kind == "default":
        return
    if kind == "commit":
        if not COMMIT_RE.fullmatch(value):
            raise SourceError("INVALID_REVISION", "Commit revisions must be hexadecimal commit IDs.")
        return
    if kind in {"branch", "tag"} and REF_RE.fullmatch(value) and ".." not in value and not value.startswith(("-", "/")):
        return
    raise SourceError("INVALID_REVISION", "Revision value is not accepted.")


class GitHubImporter:
    def __init__(self, settings: WebSettings, sources: SourceManager) -> None:
        self.settings = settings
        self.sources = sources

    def inspect(self, url: str, revision_type: str, revision_value: str, subdirectory: str, include_tests: bool):
        normalized, owner, repo = normalize_github_url(url)
        validate_revision(revision_type, revision_value)
        source_id = "src_" + uuid.uuid4().hex
        workspace = self.settings.scan_temp_root.resolve() / source_id
        clone_dir = workspace / "repo"
        hooks = workspace / "empty-hooks"
        hooks.mkdir(parents=True, exist_ok=True)
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}
        clone_cmd = ["git", "-c", f"core.hooksPath={hooks}", "clone", "--no-tags", "--depth", "1"]
        if revision_type == "branch":
            clone_cmd += ["--branch", revision_value]
        if revision_type == "tag":
            clone_cmd += ["--branch", revision_value]
        clone_cmd += [normalized, str(clone_dir)]
        try:
            subprocess.run(clone_cmd, shell=False, env=env, capture_output=True, text=True, timeout=self.settings.github_clone_timeout_seconds, check=True)
            if revision_type == "commit":
                subprocess.run(["git", "-c", f"core.hooksPath={hooks}", "fetch", "--depth", "1", "origin", revision_value], cwd=clone_dir, shell=False, env=env, capture_output=True, text=True, timeout=self.settings.github_clone_timeout_seconds, check=True)
                subprocess.run(["git", "-c", f"core.hooksPath={hooks}", "checkout", "--detach", revision_value], cwd=clone_dir, shell=False, env=env, capture_output=True, text=True, timeout=self.settings.github_clone_timeout_seconds, check=True)
            commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=clone_dir, capture_output=True, text=True, timeout=5, check=True).stdout.strip()
            date = subprocess.run(["git", "show", "-s", "--format=%cI", "HEAD"], cwd=clone_dir, capture_output=True, text=True, timeout=5, check=True).stdout.strip()
        except subprocess.TimeoutExpired as exc:
            shutil.rmtree(workspace, ignore_errors=True)
            raise SourceError("CLONE_TIMEOUT", "Repository clone timed out.") from exc
        except subprocess.CalledProcessError as exc:
            shutil.rmtree(workspace, ignore_errors=True)
            raise SourceError("CLONE_FAILED", "Public repository could not be cloned.", {"stderr": (exc.stderr or "")[:500]}) from exc
        scan_root = clone_dir
        if subdirectory:
            rel = self.sources._safe_relative(subdirectory)
            scan_root = (clone_dir / rel).resolve()
            if clone_dir.resolve() not in scan_root.parents and scan_root != clone_dir.resolve():
                raise SourceError("INVALID_SUBDIRECTORY", "Subdirectory escapes repository root.")
            if not scan_root.exists() or not scan_root.is_dir():
                raise SourceError("INVALID_SUBDIRECTORY", "Subdirectory was not found in the repository.")
        total_bytes = sum(path.stat().st_size for path in scan_root.rglob("*") if path.is_file() and not path.is_symlink())
        if total_bytes > self.settings.max_repository_bytes:
            raise SourceError("REPOSITORY_TOO_LARGE", "Repository exceeds the configured size limit.")
        record = self.sources._register(
            source_id,
            scan_root,
            "github",
            f"{owner}/{repo}",
            {
                "owner": owner,
                "repository": repo,
                "repository_url": normalized,
                "requested_revision": revision_type if revision_type == "default" else f"{revision_type}:{revision_value}",
                "resolved_commit": commit,
                "commit_date": date,
                "subdirectory": subdirectory or None,
                "include_tests": include_tests,
                "repository_size": total_bytes,
            },
        )
        return record

