"""Durable enforcement-state ports."""

from __future__ import annotations

from typing import Protocol

from mcp_privprof.domain.limits import LimitType, ToolLimits


class EnforcementStateRepository(Protocol):
    """Persist restart-resistant rate and task-budget counters."""

    async def initialize(self) -> None: ...

    async def reserve_usage(
        self,
        *,
        task_id: str,
        policy_id: str,
        tool_name: str,
        window_start: int,
        limits: ToolLimits,
    ) -> LimitType: ...

    async def rollback_usage(
        self,
        *,
        task_id: str,
        policy_id: str,
        tool_name: str,
        window_start: int,
    ) -> None: ...
