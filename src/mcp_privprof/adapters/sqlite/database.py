"""Shared atomic SQLite schema migrations for all local repositories."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import aiosqlite
import anyio

SCHEMA_VERSION = 2

_CREATE_MIGRATIONS = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
)
"""

_MIGRATION_1 = (
    """
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
    """,
    """
    CREATE TABLE inventory_tools (
        snapshot_id INTEGER NOT NULL
            REFERENCES inventory_snapshots(snapshot_id) ON DELETE CASCADE,
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
    """,
    """
    CREATE INDEX inventory_snapshots_server_latest
    ON inventory_snapshots(server_id, snapshot_id DESC)
    """,
)

_MIGRATION_2 = (
    """
    CREATE TABLE profile_sessions (
        profile_id TEXT PRIMARY KEY CHECK (length(profile_id) > 0),
        task_type TEXT NOT NULL CHECK (length(task_type) > 0),
        agent_id TEXT NOT NULL CHECK (length(agent_id) > 0),
        server_id TEXT NOT NULL CHECK (length(server_id) > 0),
        inventory_snapshot_id INTEGER NOT NULL
            REFERENCES inventory_snapshots(snapshot_id),
        toolset_fingerprint TEXT NOT NULL CHECK (
            length(toolset_fingerprint) = 71
            AND substr(toolset_fingerprint, 1, 7) = 'sha256:'
            AND substr(toolset_fingerprint, 8) NOT GLOB '*[^0-9a-f]*'
        ),
        status TEXT NOT NULL CHECK (status IN ('OPEN', 'SEALED')),
        created_at TEXT NOT NULL,
        sealed_at TEXT,
        CHECK (
            (status = 'OPEN' AND sealed_at IS NULL)
            OR (status = 'SEALED' AND sealed_at IS NOT NULL)
        )
    )
    """,
    """
    CREATE TABLE profile_scenarios (
        profile_id TEXT NOT NULL
            REFERENCES profile_sessions(profile_id) ON DELETE CASCADE,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        scenario_id TEXT NOT NULL CHECK (length(scenario_id) > 0),
        PRIMARY KEY (profile_id, scenario_id),
        UNIQUE (profile_id, ordinal)
    )
    """,
    """
    CREATE TABLE profile_runs (
        run_id TEXT PRIMARY KEY CHECK (length(run_id) > 0),
        profile_id TEXT NOT NULL,
        scenario_id TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('OPEN', 'COMPLETED', 'ABORTED')),
        started_at TEXT NOT NULL,
        completed_at TEXT,
        FOREIGN KEY (profile_id, scenario_id)
            REFERENCES profile_scenarios(profile_id, scenario_id),
        CHECK (
            (status = 'OPEN' AND completed_at IS NULL)
            OR (status IN ('COMPLETED', 'ABORTED') AND completed_at IS NOT NULL)
        )
    )
    """,
    """
    CREATE INDEX profile_runs_profile_started
    ON profile_runs(profile_id, started_at, run_id)
    """,
    """
    CREATE TABLE profile_calls (
        call_id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT NOT NULL REFERENCES profile_runs(run_id) ON DELETE CASCADE,
        tool_name TEXT NOT NULL CHECK (length(tool_name) > 0),
        attempted_at TEXT NOT NULL,
        outcome TEXT CHECK (
            outcome IS NULL
            OR outcome IN ('SUCCESS', 'TOOL_ERROR', 'INFRASTRUCTURE_ERROR')
        ),
        completed_at TEXT,
        CHECK (
            (outcome IS NULL AND completed_at IS NULL)
            OR (outcome IS NOT NULL AND completed_at IS NOT NULL)
        )
    )
    """,
    """
    CREATE INDEX profile_calls_run_attempted
    ON profile_calls(run_id, attempted_at, call_id)
    """,
    """
    CREATE TABLE profile_reviews (
        review_id TEXT PRIMARY KEY CHECK (length(review_id) > 0),
        profile_id TEXT NOT NULL UNIQUE
            REFERENCES profile_sessions(profile_id),
        status TEXT NOT NULL CHECK (status = 'COMPLETED'),
        reviewer TEXT NOT NULL CHECK (length(reviewer) > 0),
        reviewed_at TEXT NOT NULL,
        evidence_fingerprint TEXT NOT NULL CHECK (
            length(evidence_fingerprint) = 71
            AND substr(evidence_fingerprint, 1, 7) = 'sha256:'
            AND substr(evidence_fingerprint, 8) NOT GLOB '*[^0-9a-f]*'
        ),
        toolset_fingerprint TEXT NOT NULL CHECK (
            length(toolset_fingerprint) = 71
            AND substr(toolset_fingerprint, 1, 7) = 'sha256:'
            AND substr(toolset_fingerprint, 8) NOT GLOB '*[^0-9a-f]*'
        )
    )
    """,
    """
    CREATE TABLE profile_review_decisions (
        review_id TEXT NOT NULL
            REFERENCES profile_reviews(review_id) ON DELETE CASCADE,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        tool_name TEXT NOT NULL CHECK (length(tool_name) > 0),
        effect TEXT NOT NULL CHECK (effect IN ('ALLOW', 'REQUIRE_APPROVAL', 'DENY')),
        PRIMARY KEY (review_id, tool_name),
        UNIQUE (review_id, ordinal)
    )
    """,
)

_MIGRATIONS: dict[int, tuple[str, ...]] = {
    1: _MIGRATION_1,
    2: _MIGRATION_2,
}


async def initialize_database(database_path: Path) -> None:
    """Apply every supported migration atomically and in order."""
    async with aiosqlite.connect(database_path) as database:
        await configure_database(database)
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
                    f"database schema {current_version} is newer than supported "
                    f"schema {SCHEMA_VERSION}"
                )
            for version in range(current_version + 1, SCHEMA_VERSION + 1):
                for statement in _MIGRATIONS[version]:
                    await database.execute(statement)
                await database.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                    (version, _format_timestamp(datetime.now(UTC))),
                )
            await database.commit()
        except BaseException:
            with anyio.CancelScope(shield=True):
                await database.rollback()
            raise


async def configure_database(database: aiosqlite.Connection) -> None:
    """Enable the per-connection SQLite safety settings."""
    await database.execute("PRAGMA foreign_keys = ON")
    await database.execute("PRAGMA busy_timeout = 5000")


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
