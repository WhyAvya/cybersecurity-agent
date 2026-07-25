from pathlib import Path

import pytest

from vuln_agent.agentic_v2.inventory import inspect_repository


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_shell_only_routes_cwe_078(tmp_path: Path):
    _write(tmp_path / "app.py", "import os\ncmd = input('cmd: ')\nos.system(cmd)\n")

    decision = inspect_repository(tmp_path)

    assert decision.active_cwes == ["CWE-078"]
    assert decision.skipped_cwes == {"CWE-089": "no SQL or database indicators found"}
    assert decision.shell_indicators == ["os.system"]
    assert decision.request_input_sources == ["input("]


def test_sql_only_routes_cwe_089(tmp_path: Path):
    _write(tmp_path / "app.py", "import sqlite3\ncursor.execute('select * from users')\n")

    decision = inspect_repository(tmp_path)

    assert decision.active_cwes == ["CWE-089"]
    assert decision.skipped_cwes == {"CWE-078": "no shell indicators found"}
    assert "sqlite3" in decision.database_imports
    assert "cursor.execute" in decision.sql_execution_apis


def test_mixed_indicators_route_both_cwes_deterministically(tmp_path: Path):
    _write(tmp_path / "b.py", "cursor.execute('select 1')\n")
    _write(tmp_path / "a.py", "import subprocess\nsubprocess.run(['id'])\n")

    first = inspect_repository(tmp_path)
    second = inspect_repository(tmp_path)

    assert first.active_cwes == ["CWE-078", "CWE-089"]
    assert [step.step_id for step in first.planning_steps] == ["route-cwe-078", "route-cwe-089"]
    assert first.inventory.python_files == ["a.py", "b.py"]
    assert first == second


def test_no_indicators_skips_supported_cwes_with_reasons(tmp_path: Path):
    _write(tmp_path / "app.py", "def ok():\n    return 'hello'\n")

    decision = inspect_repository(tmp_path)

    assert decision.active_cwes == []
    assert decision.skipped_cwes == {
        "CWE-078": "no shell indicators found",
        "CWE-089": "no SQL or database indicators found",
    }
    assert decision.reason == "no supported CWE indicators found"


def test_ignored_directories_are_excluded(tmp_path: Path):
    _write(tmp_path / "app.py", "print('ok')\n")
    _write(tmp_path / ".git" / "hidden.py", "import os\nos.system('bad')\n")
    _write(tmp_path / "__pycache__" / "cached.py", "cursor.execute('select 1')\n")
    _write(tmp_path / "node_modules" / "pkg.py", "import subprocess\nsubprocess.run(['id'])\n")

    decision = inspect_repository(tmp_path)

    assert decision.active_cwes == []
    assert decision.inventory.python_files == ["app.py"]
    assert decision.excluded_directory_count == 3


def test_path_traversal_attempt_is_rejected(tmp_path: Path):
    with pytest.raises(ValueError):
        inspect_repository(tmp_path / ".." / tmp_path.name)


def test_symlink_escape_is_rejected(tmp_path: Path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    _write(outside / "escape.py", "import os\nos.system('id')\n")
    link = tmp_path / "escape.py"
    try:
        link.symlink_to(outside / "escape.py")
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(ValueError):
        inspect_repository(tmp_path)


def test_inventory_does_not_mutate_repository(tmp_path: Path):
    _write(tmp_path / "app.py", "import os\nos.popen('id')\n")
    before = sorted(path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*"))

    inspect_repository(tmp_path)

    after = sorted(path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*"))
    assert after == before


def test_scan_plan_contains_only_routing_steps(tmp_path: Path):
    _write(tmp_path / "app.py", "from sqlalchemy import text\nexecute('select 1')\n")

    plan = inspect_repository(tmp_path).scan_plan()

    assert plan.goal.supported_cwes == ["CWE-089"]
    assert [(step.role, step.action, step.target) for step in plan.steps] == [("router", "activate", "CWE-089")]
