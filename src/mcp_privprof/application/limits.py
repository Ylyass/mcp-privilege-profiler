"""Atomic runtime coordination of reviewed call limits."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

import anyio

from mcp_privprof.domain.limits import LimitType, ToolLimits
from mcp_privprof.ports.enforcement import EnforcementStateRepository


@dataclass(frozen=True, slots=True)
class LimitLease:
    """One reserved future downstream call."""

    task_id: str
    policy_id: str
    tool_name: str
    window_start: int


@dataclass(frozen=True, slots=True)
class LimitCheck:
    """A lease or an exact reviewed limit denial."""

    lease: LimitLease | None
    limit_type: LimitType

    @property
    def allowed(self) -> bool:
        """Return whether a reservation was acquired."""
        return self.lease is not None


class LimitCoordinator:
    """Combine persistent rate/task counters with in-process concurrency."""

    def __init__(self, repository: EnforcementStateRepository) -> None:
        self._repository = repository
        self._concurrent: dict[tuple[str, str, str], int] = {}
        self._lock = anyio.Lock()

    async def initialize(self) -> None:
        await self._repository.initialize()

    async def reserve(
        self,
        *,
        task_id: str,
        policy_id: str,
        tool_name: str,
        limits: ToolLimits,
        now: datetime,
    ) -> LimitCheck:
        """Atomically reserve capacity before mandatory audit and forwarding."""
        window_start = int(now.timestamp()) // 60
        key = (task_id, policy_id, tool_name)
        async with self._lock:
            if self._concurrent.get(key, 0) >= limits.max_concurrent_calls:
                return LimitCheck(lease=None, limit_type=LimitType.CONCURRENT_CALLS)
            limit_type = await self._repository.reserve_usage(
                task_id=task_id,
                policy_id=policy_id,
                tool_name=tool_name,
                window_start=window_start,
                limits=limits,
            )
            if limit_type is not LimitType.NONE:
                return LimitCheck(lease=None, limit_type=limit_type)
            self._concurrent[key] = self._concurrent.get(key, 0) + 1
            return LimitCheck(
                lease=LimitLease(
                    task_id=task_id,
                    policy_id=policy_id,
                    tool_name=tool_name,
                    window_start=window_start,
                ),
                limit_type=LimitType.NONE,
            )

    async def finish(self, lease: LimitLease, *, forwarded: bool) -> None:
        """Release concurrency and optionally undo a non-forwarded reservation."""
        key = (lease.task_id, lease.policy_id, lease.tool_name)
        async with self._lock:
            active = self._concurrent.get(key, 0)
            if active <= 0:
                raise RuntimeError("limit lease is not active")
            if active == 1:
                self._concurrent.pop(key)
            else:
                self._concurrent[key] = active - 1
            if not forwarded:
                await self._repository.rollback_usage(
                    task_id=lease.task_id,
                    policy_id=lease.policy_id,
                    tool_name=lease.tool_name,
                    window_start=lease.window_start,
                )
