"""Inventory collection, persistence, and drift orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

import anyio

from mcp_privprof.domain.inventory import DriftReport, StoredToolsetSnapshot, compare_toolsets
from mcp_privprof.ports.inventory import InventoryRepository, ToolsetSource


@dataclass(frozen=True, slots=True)
class InventoryRefresh:
    """The durable result of one complete catalog refresh."""

    current: StoredToolsetSnapshot
    previous: StoredToolsetSnapshot | None
    drift: DriftReport | None

    def __post_init__(self) -> None:
        if (self.previous is None) != (self.drift is None):
            raise ValueError("previous snapshot and drift report must be present together")
        if self.previous is not None and self.drift is not None:
            if self.previous.snapshot.server_id != self.current.snapshot.server_id:
                raise ValueError("previous and current snapshots must use the same server_id")
            if self.previous.snapshot.fingerprint != self.drift.previous_fingerprint:
                raise ValueError("drift previous fingerprint does not match previous snapshot")
            if self.current.snapshot.fingerprint != self.drift.current_fingerprint:
                raise ValueError("drift current fingerprint does not match current snapshot")


class InventoryService:
    """Serialize refreshes and compare each observation with its predecessor."""

    def __init__(self, source: ToolsetSource, repository: InventoryRepository) -> None:
        if not source.server_id:
            raise ValueError("source server_id must not be empty")
        self._source = source
        self._repository = repository
        self._refresh_lock = anyio.Lock()

    async def initialize(self) -> None:
        """Prepare durable storage before the first refresh."""
        await self._repository.initialize()

    async def refresh(self, *, captured_at: datetime) -> InventoryRefresh:
        """Collect, persist, and conservatively compare one complete catalog."""
        if captured_at.tzinfo is None or captured_at.utcoffset() is None:
            raise ValueError("captured_at must include a timezone")

        async with self._refresh_lock:
            current_snapshot = await self._source.collect()
            if current_snapshot.server_id != self._source.server_id:
                raise ValueError("source returned a snapshot for a different server")

            previous = await self._repository.latest(self._source.server_id)
            current = await self._repository.save(current_snapshot, captured_at)
            drift = (
                compare_toolsets(previous.snapshot, current.snapshot)
                if previous is not None
                else None
            )
            return InventoryRefresh(current=current, previous=previous, drift=drift)
