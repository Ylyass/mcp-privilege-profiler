"""SQLite inventory history and application-service tests."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import mcp.types as types
import pytest

from mcp_privprof.adapters.mcp.inventory import snapshot_toolset
from mcp_privprof.adapters.sqlite import SqliteInventoryRepository
from mcp_privprof.application import InventoryService
from mcp_privprof.domain import DriftSeverity, ToolsetSnapshot


@pytest.fixture
def anyio_backend() -> str:
    """Use the supported asyncio backend."""
    return "asyncio"


class MutableToolsetSource:
    """Deterministic source used to exercise refresh orchestration."""

    def __init__(self, snapshot: ToolsetSnapshot) -> None:
        self.current = snapshot
        self.server_id = snapshot.server_id

    async def collect(self) -> ToolsetSnapshot:
        """Return the currently configured complete snapshot."""
        return self.current


def _snapshot(server_id: str = "lab", *, include_added_tool: bool = False) -> ToolsetSnapshot:
    tools = [_tool("read_fixture")]
    if include_added_tool:
        tools.append(_tool("new_capability"))
    return snapshot_toolset(server_id, tools)


def _tool(name: str) -> types.Tool:
    return types.Tool(
        name=name,
        description=f"Fixture {name}",
        inputSchema={"type": "object", "properties": {}, "additionalProperties": False},
    )


@pytest.mark.anyio
async def test_repository_migrates_and_preserves_append_only_history(tmp_path: Path) -> None:
    """Repeated equal observations remain distinct historical facts."""
    repository = SqliteInventoryRepository(tmp_path / "inventory.sqlite3")
    await repository.initialize()
    await repository.initialize()
    snapshot = _snapshot()
    first_time = datetime(2026, 7, 15, 1, 2, 3, tzinfo=UTC)
    second_time = first_time + timedelta(minutes=1)

    first = await repository.save(snapshot, first_time)
    second = await repository.save(snapshot, second_time)
    history = await repository.history("lab")

    assert first.snapshot_id == 1
    assert second.snapshot_id == 2
    assert [record.snapshot_id for record in history] == [2, 1]
    assert history[0].captured_at == second_time
    assert history[0].snapshot == snapshot
    assert await repository.latest("missing") is None


@pytest.mark.anyio
async def test_repository_keeps_server_histories_separate(tmp_path: Path) -> None:
    """An exact server identity cannot read another server's latest snapshot."""
    repository = SqliteInventoryRepository(tmp_path / "inventory.sqlite3")
    await repository.initialize()
    captured_at = datetime(2026, 7, 15, tzinfo=UTC)
    await repository.save(_snapshot("server-a"), captured_at)
    await repository.save(_snapshot("server-b"), captured_at)

    latest_a = await repository.latest("server-a")
    latest_b = await repository.latest("server-b")

    assert latest_a is not None and latest_a.snapshot.server_id == "server-a"
    assert latest_b is not None and latest_b.snapshot.server_id == "server-b"


@pytest.mark.anyio
async def test_repository_preserves_an_empty_catalog(tmp_path: Path) -> None:
    """A server with zero tools is a valid complete inventory observation."""
    repository = SqliteInventoryRepository(tmp_path / "inventory.sqlite3")
    await repository.initialize()
    empty = snapshot_toolset("empty-server", [])

    stored = await repository.save(empty, datetime(2026, 7, 15, tzinfo=UTC))
    loaded = await repository.latest("empty-server")

    assert stored.snapshot.tools == ()
    assert loaded == stored


@pytest.mark.anyio
async def test_repository_rejects_database_from_newer_software(tmp_path: Path) -> None:
    """Older code must not guess how to read a future storage schema."""
    database_path = tmp_path / "future.sqlite3"
    with sqlite3.connect(database_path) as database:
        database.execute(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        database.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (3, '2026-07-15T00:00:00Z')"
        )

    repository = SqliteInventoryRepository(database_path)
    with pytest.raises(RuntimeError, match="newer than supported"):
        await repository.initialize()


@pytest.mark.anyio
async def test_repository_detects_changed_canonical_tool_bytes(tmp_path: Path) -> None:
    """Stored tool bytes cannot silently disagree with their SHA-256 identity."""
    database_path = tmp_path / "inventory.sqlite3"
    repository = SqliteInventoryRepository(database_path)
    await repository.initialize()
    await repository.save(_snapshot(), datetime(2026, 7, 15, tzinfo=UTC))
    with sqlite3.connect(database_path) as database:
        database.execute(
            "UPDATE inventory_tools SET canonical_json = ?",
            (b'{"name":"tampered"}',),
        )

    with pytest.raises(ValueError, match="fingerprint does not match"):
        await repository.latest("lab")


@pytest.mark.anyio
async def test_inventory_service_persists_and_classifies_each_refresh(tmp_path: Path) -> None:
    """The service compares each durable observation with its predecessor."""
    source = MutableToolsetSource(_snapshot())
    repository = SqliteInventoryRepository(tmp_path / "inventory.sqlite3")
    service = InventoryService(source, repository)
    await service.initialize()

    initial = await service.refresh(captured_at=datetime(2026, 7, 15, tzinfo=UTC))
    source.current = _snapshot(include_added_tool=True)
    changed = await service.refresh(captured_at=datetime(2026, 7, 15, 0, 1, tzinfo=UTC))

    assert initial.previous is None
    assert initial.drift is None
    assert changed.previous == initial.current
    assert changed.drift is not None
    assert changed.drift.maximum_severity is DriftSeverity.SECURITY_WIDENING


@pytest.mark.anyio
async def test_inventory_service_rejects_naive_capture_time(tmp_path: Path) -> None:
    """Persisted evidence always carries an unambiguous timezone."""
    service = InventoryService(
        MutableToolsetSource(_snapshot()),
        SqliteInventoryRepository(tmp_path / "inventory.sqlite3"),
    )
    await service.initialize()

    with pytest.raises(ValueError, match="timezone"):
        await service.refresh(captured_at=datetime(2026, 7, 15))
