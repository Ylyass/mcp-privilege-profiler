"""SQLite restart-resistant enforcement counters."""

from __future__ import annotations

from pathlib import Path

import aiosqlite
import anyio

from mcp_privprof.adapters.sqlite.database import configure_database, initialize_database
from mcp_privprof.domain.limits import LimitType, ToolLimits


class SqliteEnforcementRepository:
    """Atomically reserve per-task and fixed-window per-tool usage."""

    def __init__(self, database_path: Path) -> None:
        if not database_path.name:
            raise ValueError("database_path must name a database file")
        self._database_path = database_path

    async def initialize(self) -> None:
        await initialize_database(self._database_path)

    async def reserve_usage(
        self,
        *,
        task_id: str,
        policy_id: str,
        tool_name: str,
        window_start: int,
        limits: ToolLimits,
    ) -> LimitType:
        """Reserve one future forwarded call or return its exact denial limit."""
        async with aiosqlite.connect(self._database_path) as database:
            await configure_database(database)
            await database.execute("BEGIN IMMEDIATE")
            try:
                task_count = await _usage_count(
                    database,
                    """
                    SELECT call_count FROM enforcement_task_usage
                    WHERE task_id = ? AND policy_id = ? AND tool_name = ?
                    """,
                    (task_id, policy_id, tool_name),
                )
                if task_count >= limits.max_calls_per_task:
                    await database.rollback()
                    return LimitType.CALLS_PER_TASK

                rate_count = await _usage_count(
                    database,
                    """
                    SELECT call_count FROM enforcement_rate_usage
                    WHERE task_id = ? AND policy_id = ? AND tool_name = ?
                      AND window_start = ?
                    """,
                    (task_id, policy_id, tool_name, window_start),
                )
                if rate_count >= limits.max_calls_per_minute:
                    await database.rollback()
                    return LimitType.CALLS_PER_MINUTE

                await database.execute(
                    """
                    INSERT INTO enforcement_task_usage(
                        task_id, policy_id, tool_name, call_count
                    ) VALUES (?, ?, ?, 1)
                    ON CONFLICT(task_id, policy_id, tool_name)
                    DO UPDATE SET call_count = call_count + 1
                    """,
                    (task_id, policy_id, tool_name),
                )
                await database.execute(
                    """
                    INSERT INTO enforcement_rate_usage(
                        task_id, policy_id, tool_name, window_start, call_count
                    ) VALUES (?, ?, ?, ?, 1)
                    ON CONFLICT(task_id, policy_id, tool_name, window_start)
                    DO UPDATE SET call_count = call_count + 1
                    """,
                    (task_id, policy_id, tool_name, window_start),
                )
                await database.execute(
                    """
                    DELETE FROM enforcement_rate_usage
                    WHERE task_id = ? AND policy_id = ? AND tool_name = ?
                      AND window_start < ?
                    """,
                    (task_id, policy_id, tool_name, max(0, window_start - 1440)),
                )
                await database.commit()
                return LimitType.NONE
            except BaseException:
                with anyio.CancelScope(shield=True):
                    await database.rollback()
                raise

    async def rollback_usage(
        self,
        *,
        task_id: str,
        policy_id: str,
        tool_name: str,
        window_start: int,
    ) -> None:
        """Undo a reservation when mandatory pre-forward audit did not succeed."""
        async with aiosqlite.connect(self._database_path) as database:
            await configure_database(database)
            await database.execute("BEGIN IMMEDIATE")
            try:
                await _decrement(
                    database,
                    "enforcement_task_usage",
                    "task_id = ? AND policy_id = ? AND tool_name = ?",
                    (task_id, policy_id, tool_name),
                )
                await _decrement(
                    database,
                    "enforcement_rate_usage",
                    """
                    task_id = ? AND policy_id = ? AND tool_name = ?
                    AND window_start = ?
                    """,
                    (task_id, policy_id, tool_name, window_start),
                )
                await database.commit()
            except BaseException:
                with anyio.CancelScope(shield=True):
                    await database.rollback()
                raise


async def _usage_count(
    database: aiosqlite.Connection,
    query: str,
    parameters: tuple[object, ...],
) -> int:
    cursor = await database.execute(query, parameters)
    row = await cursor.fetchone()
    await cursor.close()
    return int(row[0]) if row is not None else 0


async def _decrement(
    database: aiosqlite.Connection,
    table: str,
    predicate: str,
    parameters: tuple[object, ...],
) -> None:
    # Table and predicate are internal constants, never external input.
    await database.execute(
        f"UPDATE {table} SET call_count = call_count - 1 WHERE {predicate} AND call_count > 0",
        parameters,
    )
    await database.execute(
        f"DELETE FROM {table} WHERE {predicate} AND call_count = 0",
        parameters,
    )
