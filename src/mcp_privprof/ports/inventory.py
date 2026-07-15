"""Ports required by inventory application services."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from mcp_privprof.domain.inventory import StoredToolsetSnapshot, ToolsetSnapshot


class ToolsetSource(Protocol):
    """A source capable of collecting one server's complete current catalog."""

    @property
    def server_id(self) -> str:
        """Return the trusted launch-bound server identity."""
        ...

    async def collect(self) -> ToolsetSnapshot:
        """Collect a complete current catalog snapshot."""
        ...


class InventoryRepository(Protocol):
    """Durable history for complete catalog observations."""

    async def initialize(self) -> None:
        """Apply supported storage migrations idempotently."""
        ...

    async def save(
        self,
        snapshot: ToolsetSnapshot,
        captured_at: datetime,
    ) -> StoredToolsetSnapshot:
        """Append one observation without overwriting earlier history."""
        ...

    async def latest(self, server_id: str) -> StoredToolsetSnapshot | None:
        """Return the newest observation for a server, if one exists."""
        ...

    async def history(
        self,
        server_id: str,
        *,
        limit: int = 100,
    ) -> tuple[StoredToolsetSnapshot, ...]:
        """Return newest-first observations for one server."""
        ...
