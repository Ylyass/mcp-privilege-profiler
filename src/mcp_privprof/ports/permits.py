"""Single-use permit persistence port."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from mcp_privprof.domain.permits import ApprovalPermit


class PermitRepository(Protocol):
    """Persist only permit metadata and atomically consume it once."""

    async def initialize(self) -> None: ...

    async def save_permit(self, permit: ApprovalPermit) -> None: ...

    async def consume_permit(self, permit_id: str, *, consumed_at: datetime) -> bool: ...
