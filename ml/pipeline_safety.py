"""Filesystem safety, staging, and atomic publishing utilities for ML pipelines."""

from __future__ import annotations

import os
import shutil
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Generator


class WorkflowError(ValueError):
    """Raised when batch workflow destination checks, preflights, or executions fail."""


def atomic_replace_file(src: Path, dst: Path) -> None:
    """Atomically replace dst with src on the same filesystem."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    src.replace(dst)


def atomic_write_text(path: Path, content: str, encoding: str = "utf-8") -> None:
    """Write text atomically via temporary file replacement in the same directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f".tmp_{uuid.uuid4().hex[:8]}_{path.name}")
    try:
        temp_path.write_text(content, encoding=encoding)
        temp_path.replace(path)
    except Exception:
        if temp_path.exists():
            temp_path.unlink()
        raise


def safe_replace_dir(src: Path, dst: Path) -> None:
    """Safely replace dst with src within the same filesystem.

    If dst does not exist, moves src to dst.
    If dst exists, renames dst to a backup, moves src to dst, and upon success
    removes the backup. If moving src to dst fails, restores dst from backup.
    """
    if not dst.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        src.rename(dst)
        return

    backup_name = f".backup_{uuid.uuid4().hex[:8]}_{dst.name}"
    backup = dst.parent / backup_name
    dst.rename(backup)
    try:
        src.rename(dst)
    except Exception:
        if backup.exists() and not dst.exists():
            try:
                backup.rename(dst)
            except Exception:
                pass
        raise
    else:
        shutil.rmtree(backup, ignore_errors=True)


@contextmanager
def staging_directory(parent: Path, prefix: str = ".staging_") -> Generator[Path, None, None]:
    """Create a temporary staging directory and guarantee cleanup on completion or failure."""
    parent.mkdir(parents=True, exist_ok=True)
    staging_path = parent / f"{prefix}{uuid.uuid4().hex[:8]}"
    staging_path.mkdir(parents=True, exist_ok=True)
    try:
        yield staging_path
    finally:
        if staging_path.exists():
            shutil.rmtree(staging_path, ignore_errors=True)
