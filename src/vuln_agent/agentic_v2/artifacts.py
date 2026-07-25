from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel


REQUIRED_ARTIFACTS = (
    "run_manifest.json",
    "scan_plan.json",
    "events.jsonl",
    "findings.json",
    "state.json",
    "final_report.json",
)


class AgenticArtifactManager:
    def __init__(self, artifact_root: str | Path = Path("artifacts") / "agentic-runs") -> None:
        self.artifact_root = Path(artifact_root)

    def create_run(self, run_id: str) -> Path:
        run_dir = self._run_dir(run_id)
        run_dir.mkdir(parents=True, exist_ok=False)
        for name in REQUIRED_ARTIFACTS:
            path = run_dir / name
            if name.endswith(".jsonl"):
                path.write_text("", encoding="utf-8")
            else:
                self.write_json(run_id, name, {})
        return run_dir

    def write_json(self, run_id: str, name: str, payload: Any) -> Path:
        if name not in REQUIRED_ARTIFACTS or not name.endswith(".json"):
            raise ValueError("unsupported JSON artifact")
        path = self._artifact_path(run_id, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = _json_ready(payload)
        temporary = path.with_name(f".{path.name}.tmp")
        temporary.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temporary, path)
        return path

    def append_event(self, run_id: str, event: Any) -> Path:
        path = self._artifact_path(run_id, "events.jsonl")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(_json_ready(event), sort_keys=True) + "\n")
        return path

    def _artifact_path(self, run_id: str, name: str) -> Path:
        if name not in REQUIRED_ARTIFACTS:
            raise ValueError("unsupported artifact name")
        return self._ensure_inside(self._run_dir(run_id) / name)

    def _run_dir(self, run_id: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", run_id):
            raise ValueError("unsafe run_id")
        return self._ensure_inside(self.artifact_root / run_id)

    def _ensure_inside(self, path: Path) -> Path:
        root = self.artifact_root.resolve()
        resolved = path.resolve()
        if resolved != root and root not in resolved.parents:
            raise ValueError("artifact path escapes root")
        return resolved


def _json_ready(payload: Any) -> Any:
    if isinstance(payload, BaseModel):
        return payload.model_dump(mode="json")
    return payload
