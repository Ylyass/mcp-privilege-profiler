"""Durable one-object-per-line JSONL audit sink."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import anyio
from anyio.to_thread import run_sync as run_sync_in_worker_thread

from mcp_privprof.contracts.event import AuditEventV1


class JsonlAuditSink:
    """Append and fsync every event before reporting success."""

    def __init__(self, path: Path) -> None:
        if not path.name:
            raise ValueError("audit path must name a file")
        self._path = path
        self._file_identity: tuple[int, int] | None = None
        self._lock = anyio.Lock()

    @property
    def path(self) -> Path:
        """Return the configured audit destination."""
        return self._path

    async def initialize(self) -> None:
        """Create and fsync a regular non-symlink audit file."""
        self._file_identity = await run_sync_in_worker_thread(self._initialize_sync)

    async def append(self, event: AuditEventV1) -> None:
        """Append one complete JSON object and force it to durable storage."""
        document = event.model_dump(mode="json")
        record = (
            json.dumps(document, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
        ).encode()
        async with self._lock:
            if self._file_identity is None:
                raise RuntimeError("audit sink is not initialized")
            await run_sync_in_worker_thread(
                self._append_sync,
                record,
                self._file_identity,
            )

    def _initialize_sync(self) -> tuple[int, int]:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if self._path.is_symlink():
            raise ValueError("audit path must not be a symbolic link")
        if self._path.exists() and not self._path.is_file():
            raise ValueError("audit path must be a regular file")
        descriptor = os.open(
            self._path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            status = os.fstat(descriptor)
            if not stat.S_ISREG(status.st_mode):
                raise ValueError("audit path must be a regular file")
            os.fsync(descriptor)
            return (status.st_dev, status.st_ino)
        finally:
            os.close(descriptor)

    def _append_sync(
        self,
        record: bytes,
        expected_identity: tuple[int, int],
    ) -> None:
        descriptor = os.open(
            self._path,
            os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            status = os.fstat(descriptor)
            if (
                not stat.S_ISREG(status.st_mode)
                or (status.st_dev, status.st_ino) != expected_identity
            ):
                raise OSError("audit file identity changed")
            view = memoryview(record)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("audit append made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
