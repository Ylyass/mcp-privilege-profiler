"""SQLite single-use permit metadata storage."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import aiosqlite
import anyio

from mcp_privprof.adapters.sqlite.database import configure_database, initialize_database
from mcp_privprof.domain.permits import ApprovalPermit


class SqlitePermitRepository:
    """Store no pending arguments and atomically prevent permit replay."""

    def __init__(self, database_path: Path) -> None:
        if not database_path.name:
            raise ValueError("database_path must name a database file")
        self._database_path = database_path

    async def initialize(self) -> None:
        await initialize_database(self._database_path)

    async def save_permit(self, permit: ApprovalPermit) -> None:
        async with aiosqlite.connect(self._database_path) as database:
            await configure_database(database)
            await database.execute(
                """
                INSERT INTO approval_permits(
                    permit_id, request_id, task_id, policy_id, server_id, tool_name,
                    argument_digest, issued_at, expires_at, nonce, permit_mac,
                    decision, use_count, consumed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'approved', 0, NULL)
                """,
                (
                    permit.permit_id,
                    permit.request_id,
                    permit.task_id,
                    permit.policy_id,
                    permit.server_id,
                    permit.tool_name,
                    permit.argument_digest,
                    _timestamp(permit.issued_at),
                    _timestamp(permit.expires_at),
                    permit.nonce,
                    permit.permit_mac,
                ),
            )
            await database.commit()

    async def consume_permit(self, permit_id: str, *, consumed_at: datetime) -> bool:
        async with aiosqlite.connect(self._database_path) as database:
            await configure_database(database)
            await database.execute("BEGIN IMMEDIATE")
            try:
                cursor = await database.execute(
                    """
                    UPDATE approval_permits
                    SET use_count = 1, consumed_at = ?
                    WHERE permit_id = ? AND use_count = 0
                    """,
                    (_timestamp(consumed_at), permit_id),
                )
                consumed = cursor.rowcount == 1
                await cursor.close()
                await database.commit()
                return consumed
            except BaseException:
                with anyio.CancelScope(shield=True):
                    await database.rollback()
                raise


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("permit timestamp must include a timezone")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
