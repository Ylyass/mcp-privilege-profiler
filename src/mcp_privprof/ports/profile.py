"""Persistence port for profile evidence and completed reviews."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from mcp_privprof.domain.profile import (
    AvailableTool,
    CallFact,
    CallOutcome,
    CompletedReview,
    ProfileSession,
    ScenarioRun,
)


class ProfileRepository(Protocol):
    """Durable profile lifecycle and privacy-safe call facts."""

    async def initialize(self) -> None: ...

    async def create_profile(
        self,
        profile: ProfileSession,
        *,
        inventory_snapshot_id: int,
    ) -> None: ...

    async def get_profile(self, profile_id: str) -> ProfileSession | None: ...

    async def available_tools(self, profile_id: str) -> tuple[AvailableTool, ...]: ...

    async def create_run(self, run: ScenarioRun) -> None: ...

    async def get_run(self, run_id: str) -> ScenarioRun | None: ...

    async def list_runs(self, profile_id: str) -> tuple[ScenarioRun, ...]: ...

    async def finish_run(self, run: ScenarioRun) -> None: ...

    async def begin_call(
        self,
        run_id: str,
        tool_name: str,
        attempted_at: datetime,
    ) -> CallFact: ...

    async def finish_call(
        self,
        call_id: int,
        outcome: CallOutcome,
        completed_at: datetime,
    ) -> CallFact: ...

    async def list_calls(self, profile_id: str) -> tuple[CallFact, ...]: ...

    async def seal_profile(self, profile: ProfileSession) -> None: ...

    async def save_review(self, review: CompletedReview) -> None: ...

    async def get_review(self, review_id: str) -> CompletedReview | None: ...
