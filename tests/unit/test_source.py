from pathlib import Path

import pytest

from vuln_agent.config import Settings
from vuln_agent.exceptions import SecurityPolicyError
from vuln_agent.source import fetch_context, iter_source_files, resolve_scan_path


def test_context_boundaries(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("a\nb\nc\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, context_lines_before=1, context_lines_after=1)
    assert fetch_context(source, 1, settings) == "1: a\n2: b"


def test_rejects_scan_root_escape(tmp_path: Path):
    settings = Settings(allowed_scan_root=tmp_path / "allowed")
    outside = tmp_path / "outside.py"
    outside.write_text("", encoding="utf-8")
    with pytest.raises(SecurityPolicyError):
        resolve_scan_path(outside, settings)


def test_iter_source_files_filters_extensions_and_excludes(tmp_path: Path):
    (tmp_path / "app.py").write_text("", encoding="utf-8")
    (tmp_path / "app.txt").write_text("", encoding="utf-8")
    cache = tmp_path / "__pycache__"
    cache.mkdir()
    (cache / "bad.py").write_text("", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path)
    assert iter_source_files(tmp_path, settings) == [tmp_path / "app.py"]
