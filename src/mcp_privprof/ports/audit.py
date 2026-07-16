"""Mandatory audit sink port."""

from __future__ import annotations

from typing import Protocol

from mcp_privprof.contracts.event import AuditEventV1


class AuditSink(Protocol):
    """Durably append privacy-minimized events."""

    async def initialize(self) -> None: ...

    async def append(self, event: AuditEventV1) -> None: ...
