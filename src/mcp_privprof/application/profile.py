"""Profile lifecycle and completed-review orchestration."""

from __future__ import annotations

from datetime import datetime

from mcp_privprof.application.profile_reports import build_profile_evidence_report
from mcp_privprof.contracts.profile import ProfileEvidenceReportV1
from mcp_privprof.domain.inventory import StoredToolsetSnapshot
from mcp_privprof.domain.policy import Policy, PolicyEffect
from mcp_privprof.domain.profile import (
    AvailableTool,
    CallFact,
    CallOutcome,
    CompletedReview,
    ProfileSession,
    ReviewDecision,
    RunStatus,
    ScenarioRun,
    complete_review,
    generate_reviewed_policy,
)
from mcp_privprof.ports.profile import ProfileRepository


class ProfileService:
    """Coordinate trusted profile state without observing argument values."""

    def __init__(self, repository: ProfileRepository) -> None:
        self._repository = repository

    async def initialize(self) -> None:
        await self._repository.initialize()

    async def create(
        self,
        profile: ProfileSession,
        inventory: StoredToolsetSnapshot,
    ) -> None:
        if profile.server_id != inventory.snapshot.server_id:
            raise ValueError("profile server_id does not match inventory")
        if profile.toolset_fingerprint != inventory.snapshot.fingerprint:
            raise ValueError("profile toolset fingerprint does not match inventory")
        await self._repository.create_profile(
            profile,
            inventory_snapshot_id=inventory.snapshot_id,
        )

    async def profile(self, profile_id: str) -> ProfileSession:
        profile = await self._repository.get_profile(profile_id)
        if profile is None:
            raise ValueError("profile does not exist")
        return profile

    async def available_tools(self, profile_id: str) -> tuple[AvailableTool, ...]:
        await self.profile(profile_id)
        return await self._repository.available_tools(profile_id)

    async def start_run(
        self,
        profile_id: str,
        *,
        run_id: str,
        scenario_id: str,
        started_at: datetime,
    ) -> ScenarioRun:
        profile = await self.profile(profile_id)
        run = profile.start_run(run_id, scenario_id, started_at)
        await self._repository.create_run(run)
        return run

    async def finish_run(
        self,
        run_id: str,
        *,
        status: RunStatus,
        completed_at: datetime,
    ) -> ScenarioRun:
        run = await self._repository.get_run(run_id)
        if run is None:
            raise ValueError("run does not exist")
        finished = run.finish(status, completed_at)
        await self._repository.finish_run(finished)
        return finished

    async def begin_call(
        self,
        run_id: str,
        tool_name: str,
        attempted_at: datetime,
    ) -> CallFact:
        return await self._repository.begin_call(run_id, tool_name, attempted_at)

    async def finish_call(
        self,
        call_id: int,
        outcome: CallOutcome,
        completed_at: datetime,
    ) -> CallFact:
        return await self._repository.finish_call(call_id, outcome, completed_at)

    async def seal(self, profile_id: str, *, sealed_at: datetime) -> ProfileSession:
        profile = await self.profile(profile_id)
        runs = await self._repository.list_runs(profile_id)
        sealed = profile.seal(runs, sealed_at)
        await self._repository.seal_profile(sealed)
        return sealed

    async def calls(self, profile_id: str) -> tuple[CallFact, ...]:
        await self.profile(profile_id)
        return await self._repository.list_calls(profile_id)

    async def runs(self, profile_id: str) -> tuple[ScenarioRun, ...]:
        await self.profile(profile_id)
        return await self._repository.list_runs(profile_id)

    async def complete_review(
        self,
        profile_id: str,
        *,
        review_id: str,
        reviewer: str,
        reviewed_at: datetime,
        evidence_fingerprint: str,
        decisions: tuple[tuple[str, PolicyEffect], ...],
    ) -> CompletedReview:
        profile = await self.profile(profile_id)
        tools = await self._repository.available_tools(profile_id)
        evidence = await self.evidence_report(profile_id, generated_at=reviewed_at)
        if evidence.evidence_fingerprint != evidence_fingerprint:
            raise ValueError("review evidence fingerprint does not match sealed profile evidence")
        review = complete_review(
            profile,
            tools,
            review_id=review_id,
            reviewer=reviewer,
            reviewed_at=reviewed_at,
            evidence_fingerprint=evidence_fingerprint,
            decisions=tuple(
                ReviewDecision(tool_name=tool_name, effect=effect)
                for tool_name, effect in decisions
            ),
        )
        await self._repository.save_review(review)
        return review

    async def evidence_report(
        self,
        profile_id: str,
        *,
        generated_at: datetime,
    ) -> ProfileEvidenceReportV1:
        profile = await self.profile(profile_id)
        tools = await self._repository.available_tools(profile_id)
        runs = await self._repository.list_runs(profile_id)
        calls = await self._repository.list_calls(profile_id)
        return build_profile_evidence_report(
            profile,
            tools,
            runs,
            calls,
            generated_at=generated_at,
        )

    async def policy_from_review(self, review_id: str, policy_id: str) -> Policy:
        review = await self._repository.get_review(review_id)
        if review is None:
            raise ValueError("completed review does not exist")
        profile = await self.profile(review.profile_id)
        tools = await self._repository.available_tools(profile.profile_id)
        evidence = await self.evidence_report(
            profile.profile_id,
            generated_at=review.reviewed_at,
        )
        if evidence.evidence_fingerprint != review.evidence_fingerprint:
            raise ValueError("completed review evidence no longer matches sealed profile")
        return generate_reviewed_policy(profile, tools, review, policy_id=policy_id)
