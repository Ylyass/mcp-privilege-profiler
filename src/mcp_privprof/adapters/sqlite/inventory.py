"""Append-only SQLite inventory history with explicit schema migrations."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import aiosqlite
import anyio

from mcp_privprof.domain.inventory import StoredToolsetSnapshot, ToolsetSnapshot, ToolSnapshot

SCHEMA_VERSION = 1

_CREATE_MIGRATIONS = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
)
"""

_CREATE_SNAPSHOTS = """
CREATE TABLE inventory_snapshots (
    snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id TEXT NOT NULL CHECK (length(server_id) > 0),
    fingerprint TEXT NOT NULL CHECK (
        length(fingerprint) = 71
        AND substr(fingerprint, 1, 7) = 'sha256:'
        AND substr(fingerprint, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    captured_at TEXT NOT NULL,
    tool_count INTEGER NOT NULL CHECK (tool_count >= 0)
)
"""

_CREATE_TOOLS = """
CREATE TABLE inventory_tools (
    snapshot_id INTEGER NOT NULL REFERENCES inventory_snapshots(snapshot_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    name TEXT NOT NULL CHECK (length(name) > 0),
    fingerprint TEXT NOT NULL CHECK (
        length(fingerprint) = 71
        AND substr(fingerprint, 1, 7) = 'sha256:'
        AND substr(fingerprint, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    canonical_json BLOB NOT NULL,
    PRIMARY KEY (snapshot_id, name),
    UNIQUE (snapshot_id, ordinal)
)
"""


class SqliteInventoryRepository:
    """Persist every complete observation without mutating prior snapshots."""

    def __init__(self, database_path: Path) -> None:
        if not database_path.name:
            raise ValueError("database_path must name a database file")
        self._database_path = database_path

    async def initialize(self) -> None:
        """Apply known migrations atomically and reject newer databases."""
        async with aiosqlite.connect(self._database_path) as database:
            await _configure(database)
            await database.execute("BEGIN IMMEDIATE")
            try:
                await database.execute(_CREATE_MIGRATIONS)
                cursor = await database.execute(
                    "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
                )
                row = await cursor.fetchone()
                await cursor.close()
                current_version = int(row[0]) if row is not None else 0
                if current_version > SCHEMA_VERSION:
                    raise RuntimeError(
                        f"inventory database schema {current_version} is newer than supported "
                        f"schema {SCHEMA_VERSION}"
                    )
                if current_version < 1:
                    await database.execute(_CREATE_SNAPSHOTS)
                    await database.execute(_CREATE_TOOLS)
                    await database.execute(
                        "CREATE INDEX inventory_snapshots_server_latest "
                        "ON inventory_snapshots(server_id, snapshot_id DESC)"
                    )
                    await database.execute(
                        "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                        (1, _format_timestamp(datetime.now(UTC))),
                    )
                await database.commit()
            except BaseException:
                with anyio.CancelScope(shield=True):
                    await database.rollback()
                raise

    async def save(
        self,
        snapshot: ToolsetSnapshot,
        captured_at: datetime,
    ) -> StoredToolsetSnapshot:
        """Append a snapshot and all canonical Tool objects in one transaction."""
        timestamp = _format_timestamp(captured_at)
        async with aiosqlite.connect(self._database_path) as database:
            await _configure(database)
            await database.execute("BEGIN IMMEDIATE")
            try:
                cursor = await database.execute(
                    """
                    INSERT INTO inventory_snapshots(server_id, fingerprint, captured_at, tool_count)
                    VALUES (?, ?, ?, ?)
                    """,
                    (snapshot.server_id, snapshot.fingerprint, timestamp, len(snapshot.tools)),
                )
                snapshot_id = cursor.lastrowid
                await cursor.close()
                if snapshot_id is None:
                    raise RuntimeError("SQLite did not return an inventory snapshot ID")
                await database.executemany(
                    """
                    INSERT INTO inventory_tools(
                        snapshot_id, ordinal, name, fingerprint, canonical_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            snapshot_id,
                            ordinal,
                            tool.name,
                            tool.fingerprint,
                            tool.canonical_json,
                        )
                        for ordinal, tool in enumerate(snapshot.tools)
                    ],
                )
                await database.commit()
            except BaseException:
                with anyio.CancelScope(shield=True):
                    await database.rollback()
                raise

        return StoredToolsetSnapshot(
            snapshot_id=snapshot_id,
            captured_at=_parse_timestamp(timestamp),
            snapshot=snapshot,
        )

    async def latest(self, server_id: str) -> StoredToolsetSnapshot | None:
        """Return the latest complete snapshot for one exact server identity."""
        if not server_id:
            raise ValueError("server_id must not be empty")
        records = await self.history(server_id, limit=1)
        return records[0] if records else None

    async def history(
        self,
        server_id: str,
        *,
        limit: int = 100,
    ) -> tuple[StoredToolsetSnapshot, ...]:
        """Load a bounded newest-first history and verify row completeness."""
        if not server_id:
            raise ValueError("server_id must not be empty")
        if limit <= 0:
            raise ValueError("history limit must be positive")

        async with aiosqlite.connect(self._database_path) as database:
            await _configure(database)
            cursor = await database.execute(
                """
                SELECT snapshot_id, server_id, fingerprint, captured_at, tool_count
                FROM inventory_snapshots
                WHERE server_id = ?
                ORDER BY snapshot_id DESC
                LIMIT ?
                """,
                (server_id, limit),
            )
            raw_rows = await cursor.fetchall()
            await cursor.close()
            rows = [cast(tuple[object, ...], row) for row in raw_rows]
            return tuple([await _load_snapshot(database, row) for row in rows])


async def _configure(database: aiosqlite.Connection) -> None:
    await database.execute("PRAGMA foreign_keys = ON")
    await database.execute("PRAGMA busy_timeout = 5000")


async def _load_snapshot(
    database: aiosqlite.Connection,
    row: tuple[object, ...],
) -> StoredToolsetSnapshot:
    snapshot_id = int(cast(int, row[0]))
    server_id = str(row[1])
    fingerprint = str(row[2])
    captured_at = _parse_timestamp(str(row[3]))
    expected_tool_count = int(cast(int, row[4]))

    cursor = await database.execute(
        """
        SELECT name, fingerprint, canonical_json
        FROM inventory_tools
        WHERE snapshot_id = ?
        ORDER BY ordinal
        """,
        (snapshot_id,),
    )
    raw_tool_rows = list(await cursor.fetchall())
    await cursor.close()
    if len(raw_tool_rows) != expected_tool_count:
        raise RuntimeError("inventory snapshot tool count does not match stored rows")

    tools: list[ToolSnapshot] = []
    for raw_tool_row in raw_tool_rows:
        tool_row = cast(tuple[object, ...], raw_tool_row)
        canonical_value = tool_row[2]
        if not isinstance(canonical_value, bytes):
            raise RuntimeError("inventory canonical JSON must be stored as bytes")
        tools.append(
            ToolSnapshot(
                name=str(tool_row[0]),
                fingerprint=str(tool_row[1]),
                canonical_json=canonical_value,
            )
        )

    return StoredToolsetSnapshot(
        snapshot_id=snapshot_id,
        captured_at=captured_at,
        snapshot=ToolsetSnapshot(
            server_id=server_id,
            fingerprint=fingerprint,
            tools=tuple(tools),
        ),
    )


def _format_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("captured_at must include a timezone")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise RuntimeError("stored captured_at timestamp must include a timezone")
    return parsed.astimezone(UTC)
