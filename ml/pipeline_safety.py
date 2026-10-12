"""Filesystem safety, staging, and atomic publishing utilities for ML pipelines."""

from __future__ import annotations

import os
import shutil
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator


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


def _restore_untracked_files(backup_dir: Path, target_dir: Path) -> None:
    """Restore any file or directory from backup_dir that does not exist in target_dir."""
    if not backup_dir.exists():
        return
    for item in backup_dir.rglob("*"):
        rel_path = item.relative_to(backup_dir)
        target_item = target_dir / rel_path
        if item.is_file() and not target_item.exists():
            target_item.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target_item)
        elif item.is_dir() and not target_item.exists():
            target_item.mkdir(parents=True, exist_ok=True)


def safe_replace_dir(src: Path, dst: Path, preserve_untracked: bool = True) -> None:
    """Safely replace dst with src within the same filesystem.

    If dst does not exist, moves src to dst.
    If dst exists:
      1. Renames dst to a temporary backup.
      2. Moves src to dst.
      3. If preserve_untracked is True, restores any files/directories from backup
         that do not collide with src (e.g. researcher notes, custom nested files).
      4. If any error occurs, rolls back dst by removing dst and restoring backup.
      5. Upon success, removes the backup directory.
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
        if preserve_untracked:
            _restore_untracked_files(backup, dst)
    except Exception:
        if dst.exists():
            shutil.rmtree(dst, ignore_errors=True)
        if backup.exists() and not dst.exists():
            try:
                backup.rename(dst)
            except Exception:
                pass
        raise
    else:
        shutil.rmtree(backup, ignore_errors=True)


class PublicationTransaction:
    """Recoverable multi-artifact publication protocol with automatic rollback on failure."""

    def __init__(self, target_base: Path, run_id: str | None = None) -> None:
        self.target_base = target_base
        self.run_id = run_id or uuid.uuid4().hex[:8]
        self.backup_dir = target_base / f".backup_tx_{self.run_id}_{uuid.uuid4().hex[:6]}"
        self.backed_up_items: dict[str, Path] = {}
        self.published_items: list[Path] = []
        self.is_committed = False

    def backup_existing(self, rel_paths: list[str]) -> None:
        """Back up any of the specified paths that currently exist in target_base."""
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        for rel in rel_paths:
            target_path = self.target_base / rel
            if target_path.exists():
                backup_path = self.backup_dir / rel
                backup_path.parent.mkdir(parents=True, exist_ok=True)
                target_path.rename(backup_path)
                self.backed_up_items[rel] = backup_path

    def publish_dir(self, staged_dir: Path, target_dir: Path, preserve_untracked: bool = True) -> None:
        """Publish a staged directory into target_dir with untracked file preservation."""
        target_dir.parent.mkdir(parents=True, exist_ok=True)
        staged_dir.rename(target_dir)
        self.published_items.append(target_dir)

        rel = str(target_dir.relative_to(self.target_base))
        if rel in self.backed_up_items and preserve_untracked:
            backup_path = self.backed_up_items[rel]
            _restore_untracked_files(backup_path, target_dir)

    def publish_file(self, staged_file: Path, target_file: Path) -> None:
        """Publish a staged file into target_file."""
        target_file.parent.mkdir(parents=True, exist_ok=True)
        staged_file.replace(target_file)
        self.published_items.append(target_file)

    def rollback(self) -> None:
        """Roll back all published changes, restoring original artifacts from backup."""
        # 1. Remove all newly published items
        for item in reversed(self.published_items):
            if item.exists():
                if item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)
                else:
                    try:
                        item.unlink()
                    except Exception:
                        pass
        self.published_items.clear()

        # 2. Restore all original backed-up items to target_base
        for rel, backup_path in self.backed_up_items.items():
            orig_target = self.target_base / rel
            if backup_path.exists() and not orig_target.exists():
                orig_target.parent.mkdir(parents=True, exist_ok=True)
                backup_path.rename(orig_target)

        # 3. Clean up the transaction backup directory
        if self.backup_dir.exists():
            shutil.rmtree(self.backup_dir, ignore_errors=True)

    def commit(self) -> None:
        """Commit the publication transaction, cleaning up the backup directory."""
        self.is_committed = True
        if self.backup_dir.exists():
            shutil.rmtree(self.backup_dir, ignore_errors=True)

    def __enter__(self) -> PublicationTransaction:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if exc_type is not None or not self.is_committed:
            self.rollback()
        else:
            self.commit()


@contextmanager
def staging_directory(parent: Path, prefix: str = ".staging_") -> Generator[Path, None, None]:
    """Create a temporary staging directory and guarantee cleanup on completion or failure.

    Cleanup is strictly scoped to the yielded staging directory and never deletes
    sibling files or another run's staging directory.
    """
    parent.mkdir(parents=True, exist_ok=True)
    staging_path = parent / f"{prefix}{uuid.uuid4().hex[:8]}"
    staging_path.mkdir(parents=True, exist_ok=True)
    try:
        yield staging_path
    finally:
        if staging_path.exists():
            shutil.rmtree(staging_path, ignore_errors=True)
