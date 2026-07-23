"""Temporary source workspace management."""

from __future__ import annotations

import shutil
import uuid
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath

from .config import WebSettings
from .models import SourceFile, SourceRecord


class SourceError(ValueError):
    def __init__(self, code: str, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or {}


class SourceManager:
    def __init__(self, settings: WebSettings) -> None:
        self.settings = settings
        self.root = settings.scan_temp_root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._sources: dict[str, tuple[SourceRecord, Path]] = {}

    def create_paste(self, filename: str, code: str) -> SourceRecord:
        if not code.strip():
            raise SourceError("EMPTY_SOURCE", "Paste input is empty.")
        clean = self._safe_relative(filename or "pasted.py")
        if Path(clean).suffix not in self.settings.allowed_source_extensions:
            raise SourceError("UNSUPPORTED_EXTENSION", "Only Python files are supported.", {"filename": clean})
        source_id, workspace = self._new_workspace()
        path = workspace / clean
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(code, encoding="utf-8")
        return self._register(source_id, workspace, "paste", "Pasted code")

    def create_files(self, files: list[tuple[str, bytes]]) -> SourceRecord:
        if not files:
            raise SourceError("EMPTY_SOURCE", "No files were uploaded.")
        source_id, workspace = self._new_workspace()
        for name, data in files:
            self._write_bytes(workspace, name, data)
        return self._register(source_id, workspace, "files", "Uploaded files")

    def create_zip(self, filename: str, data: bytes) -> SourceRecord:
        if len(data) > self.settings.max_zip_bytes:
            raise SourceError("ZIP_TOO_LARGE", "The ZIP file exceeds the configured size limit.")
        source_id, workspace = self._new_workspace()
        archive = workspace / "_upload.zip"
        archive.write_bytes(data)
        extracted = workspace / "project"
        extracted.mkdir()
        total = 0
        count = 0
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                if self._is_zip_symlink(info):
                    raise SourceError("ZIP_SYMLINK", "ZIP symbolic-link entries are not allowed.", {"entry": info.filename})
                rel = self._safe_relative(info.filename)
                if Path(rel).suffix not in self.settings.allowed_source_extensions:
                    continue
                count += 1
                if count > self.settings.max_source_files:
                    raise SourceError("TOO_MANY_FILES", "The project contains more Python files than allowed.")
                total += info.file_size
                if total > self.settings.max_extracted_bytes:
                    raise SourceError("EXTRACTED_TOO_LARGE", "The ZIP expands beyond the configured size limit.")
                target = (extracted / rel).resolve()
                if extracted.resolve() not in target.parents:
                    raise SourceError("ZIP_TRAVERSAL", "ZIP entry escapes the extraction root.", {"entry": info.filename})
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src:
                    target.write_bytes(src.read())
        archive.unlink(missing_ok=True)
        return self._register(source_id, extracted, "zip", filename or "Uploaded project")

    def get(self, source_id: str) -> tuple[SourceRecord, Path]:
        if source_id not in self._sources:
            raise SourceError("SOURCE_NOT_FOUND", "Source was not found.", {"source_id": source_id})
        return self._sources[source_id]

    def delete(self, source_id: str) -> None:
        record, path = self.get(source_id)
        shutil.rmtree(path, ignore_errors=True)
        self._sources.pop(record.source_id, None)

    def _new_workspace(self) -> tuple[str, Path]:
        source_id = "src_" + uuid.uuid4().hex
        workspace = self.root / source_id
        workspace.mkdir(parents=True, exist_ok=False)
        return source_id, workspace

    def _register(self, source_id: str, workspace: Path, source_type: str, name: str, metadata: dict | None = None) -> SourceRecord:
        files = self._discover(workspace)
        record = SourceRecord(source_id=source_id, source_type=source_type, name=name, files=files, metadata=metadata or {})
        self._sources[source_id] = (record, workspace)
        return record

    def _discover(self, root: Path) -> list[SourceFile]:
        files: list[SourceFile] = []
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            if any(part in self.settings.ignored_paths for part in path.relative_to(root).parts):
                continue
            if path.suffix not in self.settings.allowed_source_extensions:
                continue
            size = path.stat().st_size
            if size > self.settings.max_source_file_bytes:
                raise SourceError("FILE_TOO_LARGE", "A source file exceeds the configured size limit.", {"path": path.name})
            rel = path.relative_to(root).as_posix()
            files.append(SourceFile(path=rel, size=size, content=path.read_text(encoding="utf-8", errors="replace")))
            if len(files) > self.settings.max_source_files:
                raise SourceError("TOO_MANY_FILES", "The source contains more Python files than allowed.")
        if not files:
            raise SourceError("EMPTY_SOURCE", "No supported Python files were found.")
        return files

    def _write_bytes(self, root: Path, name: str, data: bytes) -> None:
        rel = self._safe_relative(name)
        if Path(rel).suffix not in self.settings.allowed_source_extensions:
            raise SourceError("UNSUPPORTED_EXTENSION", "Only .py files are supported.", {"filename": rel})
        if not data:
            raise SourceError("EMPTY_FILE", "Uploaded Python files cannot be empty.", {"filename": rel})
        if len(data) > self.settings.max_source_file_bytes:
            raise SourceError("FILE_TOO_LARGE", "A source file exceeds the configured size limit.", {"filename": rel})
        target = (root / rel).resolve()
        if root.resolve() not in target.parents:
            raise SourceError("PATH_TRAVERSAL", "Uploaded file path escapes the workspace.", {"filename": rel})
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def _safe_relative(self, raw: str) -> str:
        if "\x00" in raw or any(ord(ch) < 32 for ch in raw):
            raise SourceError("INVALID_PATH", "File paths cannot contain control characters.")
        if raw.startswith("/") or raw.startswith("\\"):
            raise SourceError("ABSOLUTE_PATH", "Absolute paths are not allowed.", {"path": raw})
        text = raw.replace("\\", "/")
        if PureWindowsPath(raw).drive or raw.startswith("\\\\"):
            raise SourceError("ABSOLUTE_PATH", "Absolute paths are not allowed.", {"path": raw})
        posix = PurePosixPath(text)
        if posix.is_absolute() or any(part in ("", ".", "..") for part in posix.parts):
            raise SourceError("PATH_TRAVERSAL", "Relative paths must stay inside the workspace.", {"path": raw})
        if any(part in self.settings.ignored_paths for part in posix.parts):
            raise SourceError("IGNORED_PATH", "This path is ignored by policy.", {"path": raw})
        return posix.as_posix()

    def _is_zip_symlink(self, info: zipfile.ZipInfo) -> bool:
        return ((info.external_attr >> 16) & 0o170000) == 0o120000
