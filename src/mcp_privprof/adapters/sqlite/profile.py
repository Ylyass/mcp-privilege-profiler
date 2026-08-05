"""SQLite profile lifecycle, privacy-safe call facts, and review storage."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import aiosqlite
import anyio

from mcp_privprof.adapters.sqlite.constraints import decode_constraints, encode_constraints
from mcp_privprof.adapters.sqlite.database import configure_database, initialize_database
from mcp_privprof.adapters.sqlite.policy_metadata import (
    decode_capability_tags,
    decode_limits,
    encode_capability_tags,
    encode_limits,
)
from mcp_privprof.domain.policy import PolicyEffect
from mcp_privprof.domain.profile import (
    AvailableTool,
    CallFact,
    CallOutcome,
    CompletedReview,
    ProfileSession,
    ProfileStatus,
    ReviewDecision,
    RunStatus,
    ScenarioRun,
)


class SqliteProfileRepository:
    """Persist profile evidence without raw arguments or result bodies."""

    def __init__(self, database_path: Path) -> None:
        if not database_path.name:
            raise ValueError("database_path must name a database file")
        self._database_path = database_path

    async def initialize(self) -> None:
        await initialize_database(self._database_path)

    async def create_profile(
        self,
        profile: ProfileSession,
        *,
        inventory_snapshot_id: int,
    ) -> None:
        if profile.status is not ProfileStatus.OPEN:
            raise ValueError("a new profile must be open")
        async with aiosqlite.connect(self._database_path) as database:
            await configure_database(database)
            await database.execute("BEGIN IMMEDIATE")
            try:
                cursor = await database.execute(
                    """
                    SELECT server_id, fingerprint
                    FROM inventory_snapshots
                    WHERE snapshot_id = ?
                    """,
                    (inventory_snapshot_id,),
                )
                snapshot_row = await cursor.fetchone()
                await cursor.close()
                if snapshot_row is None:
                    raise ValueError("inventory snapshot does not exist")
                if (
                    str(snapshot_row[0]) != profile.server_id
                    or str(snapshot_row[1]) != profile.toolset_fingerprint
                ):
                    raise ValueError("profile context does not match inventory snapshot")
                await database.execute(
                    """
                    INSERT INTO profile_sessions(
                        profile_id, task_type, agent_id, server_id,
                        inventory_snapshot_id, toolset_fingerprint,
                        status, created_at, sealed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
                    """,
                    (
                        profile.profile_id,
                        profile.task_type,
                        profile.agent_id,
                        profile.server_id,
                        inventory_snapshot_id,
                        profile.toolset_fingerprint,
                        profile.status.value,
                        _format_timestamp(profile.created_at),
                    ),
                )
                await database.executemany(
                    """
                    INSERT INTO profile_scenarios(profile_id, ordinal, scenario_id)
                    VALUES (?, ?, ?)
                    """,
                    [
                        (profile.profile_id, ordinal, scenario_id)
                        for ordinal, scenario_id in enumerate(profile.planned_scenarios)
                    ],
                )
                await database.commit()
            except BaseException:
                with anyio.CancelScope(shield=True):
                    await database.rollback()
                raise

    async def get_profile(self, profile_id: str) -> ProfileSession | None:
        if not profile_id:
            raise ValueError("profile_id must not be empty")
        async with aiosqlite.connect(self._database_path) as database:
            await configure_database(database)
            cursor = await database.execute(
                """
                SELECT profile_id, task_type, agent_id, server_id,
                       toolset_fingerprint, status, created_at, sealed_at
                FROM profile_sessions
                WHERE profile_id = ?
                """,
                (profile_id,),
            )
            raw_row = await cursor.fetchone()
            await cursor.close()
            if raw_row is None:
                return None
            return await _load_profile(database, cast(tuple[object, ...], raw_row))

    async def available_tools(self, profile_id: str) -> tuple[AvailableTool, ...]:
        async with aiosqlite.connect(self._database_path) as database:
            await configure_database(database)
            cursor = await database.execute(
                """
                SELECT tools.name, tools.fingerprint
                FROM profile_sessions AS profiles
                JOIN inventory_tools AS tools
                  ON tools.snapshot_id = profiles.inventory_snapshot_id
                WHERE profiles.profile_id = ?
                ORDER BY tools.ordinal
                """,
                (profile_id,),
            )
            rows = await cursor.fetchall()
            await cursor.close()
            return tuple(AvailableTool(name=str(row[0]), fingerprint=str(row[1])) for row in rows)

    async def create_run(self, run: ScenarioRun) -> None:
        if run.status is not RunStatus.OPEN:
            raise ValueError("a new run must be open")
        async with aiosqlite.connect(self._database_path) as database:
            await configure_database(database)
            cursor = await database.execute(
                """
                INSERT INTO profile_runs(
                    run_id, profile_id, scenario_id, status, started_at, completed_at
                )
                SELECT ?, profile_id, ?, ?, ?, NULL
                FROM profile_sessions
                WHERE profile_id = ? AND status = 'OPEN'
                """,
                (
                    run.run_id,
                    run.scenario_id,
                    run.status.value,
                    _format_timestamp(run.started_at),
                    run.profile_id,
                ),
            )
            if cursor.rowcount != 1:
                await cursor.close()
                raise ValueError("profile does not exist or is not open")
            await cursor.close()
            await database.commit()

    async def get_run(self, run_id: str) -> ScenarioRun | None:
        async with aiosqlite.connect(self._database_path) as database:
            await configure_database(database)
            cursor = await database.execute(
                """
                SELECT run_id, profile_id, scenario_id, status, started_at, completed_at
                FROM profile_runs
                WHERE run_id = ?
                """,
                (run_id,),
            )
            row = await cursor.fetchone()
            await cursor.close()
            return _run_from_row(cast(tuple[object, ...], row)) if row is not None else None

    async def list_runs(self, profile_id: str) -> tuple[ScenarioRun, ...]:
        async with aiosqlite.connect(self._database_path) as database:
            await configure_database(database)
            cursor = await database.execute(
                """
                SELECT run_id, profile_id, scenario_id, status, started_at, completed_at
                FROM profile_runs
                WHERE profile_id = ?
                ORDER BY started_at, run_id
                """,
                (profile_id,),
            )
            rows = await cursor.fetchall()
            await cursor.close()
            return tuple(_run_from_row(cast(tuple[object, ...], row)) for row in rows)

    async def finish_run(self, run: ScenarioRun) -> None:
        if run.status is RunStatus.OPEN or run.completed_at is None:
            raise ValueError("finished run must be completed or aborted")
        async with aiosqlite.connect(self._database_path) as database:
            await configure_database(database)
            if run.status is RunStatus.COMPLETED:
                cursor = await database.execute(
                    """
                    UPDATE profile_runs
                    SET status = ?, completed_at = ?
                    WHERE run_id = ?
                      AND status = 'OPEN'
                      AND NOT EXISTS (
                          SELECT 1
                          FROM profile_calls
                          WHERE profile_calls.run_id = profile_runs.run_id
                            AND profile_calls.outcome IS NULL
                      )
                    """,
                    (run.status.value, _format_timestamp(run.completed_at), run.run_id),
                )
            else:
                cursor = await database.execute(
                    """
                    UPDATE profile_runs
                    SET status = ?, completed_at = ?
                    WHERE run_id = ? AND status = 'OPEN'
                    """,
                    (run.status.value, _format_timestamp(run.completed_at), run.run_id),
                )
            if cursor.rowcount != 1:
                await cursor.close()
                if run.status is RunStatus.COMPLETED:
                    raise ValueError(
                        "run does not exist, is already finished, or has unfinished calls"
                    )
                raise ValueError("run does not exist or is already finished")
            await cursor.close()
            await database.commit()

    async def begin_call(
        self,
        run_id: str,
        tool_name: str,
        attempted_at: datetime,
    ) -> CallFact:
        if not tool_name:
            raise ValueError("tool_name must not be empty")
        timestamp = _format_timestamp(attempted_at)
        async with aiosqlite.connect(self._database_path) as database:
            await configure_database(database)
            cursor = await database.execute(
                """
                INSERT INTO profile_calls(run_id, tool_name, attempted_at, outcome, completed_at)
                SELECT run_id, ?, ?, NULL, NULL
                FROM profile_runs
                WHERE run_id = ? AND status = 'OPEN'
                """,
                (tool_name, timestamp, run_id),
            )
            if cursor.rowcount != 1 or cursor.lastrowid is None:
                await cursor.close()
                raise ValueError("run does not exist or is not open")
            call_id = cursor.lastrowid
            await cursor.close()
            await database.commit()
        return CallFact(
            call_id=call_id,
            run_id=run_id,
            tool_name=tool_name,
            attempted_at=_parse_timestamp(timestamp),
        )

    async def finish_call(
        self,
        call_id: int,
        outcome: CallOutcome,
        completed_at: datetime,
    ) -> CallFact:
        timestamp = _format_timestamp(completed_at)
        async with aiosqlite.connect(self._database_path) as database:
            await configure_database(database)
            cursor = await database.execute(
                """
                UPDATE profile_calls
                SET outcome = ?, completed_at = ?
                WHERE call_id = ? AND outcome IS NULL
                """,
                (outcome.value, timestamp, call_id),
            )
            if cursor.rowcount != 1:
                await cursor.close()
                raise ValueError("call does not exist or is already finished")
            await cursor.close()
            await database.commit()
            fact = await _get_call(database, call_id)
        if fact is None:
            raise RuntimeError("finished profile call could not be reloaded")
        return fact

    async def list_calls(self, profile_id: str) -> tuple[CallFact, ...]:
        async with aiosqlite.connect(self._database_path) as database:
            await configure_database(database)
            cursor = await database.execute(
                """
                SELECT calls.call_id, calls.run_id, calls.tool_name,
                       calls.attempted_at, calls.outcome, calls.completed_at
                FROM profile_calls AS calls
                JOIN profile_runs AS runs ON runs.run_id = calls.run_id
                WHERE runs.profile_id = ?
                ORDER BY calls.call_id
                """,
                (profile_id,),
            )
            rows = await cursor.fetchall()
            await cursor.close()
            return tuple(_call_from_row(cast(tuple[object, ...], row)) for row in rows)

    async def seal_profile(self, profile: ProfileSession) -> None:
        if profile.status is not ProfileStatus.SEALED or profile.sealed_at is None:
            raise ValueError("profile must be sealed")
        async with aiosqlite.connect(self._database_path) as database:
            await configure_database(database)
            cursor = await database.execute(
                """
                UPDATE profile_sessions
                SET status = 'SEALED', sealed_at = ?
                WHERE profile_id = ? AND status = 'OPEN'
                """,
                (_format_timestamp(profile.sealed_at), profile.profile_id),
            )
            if cursor.rowcount != 1:
                await cursor.close()
                raise ValueError("profile does not exist or is already sealed")
            await cursor.close()
            await database.commit()

    async def save_review(self, review: CompletedReview) -> None:
        async with aiosqlite.connect(self._database_path) as database:
            await configure_database(database)
            await database.execute("BEGIN IMMEDIATE")
            try:
                cursor = await database.execute(
                    """
                    SELECT status, toolset_fingerprint
                    FROM profile_sessions
                    WHERE profile_id = ?
                    """,
                    (review.profile_id,),
                )
                profile_row = await cursor.fetchone()
                await cursor.close()
                if profile_row is None or str(profile_row[0]) != ProfileStatus.SEALED.value:
                    raise ValueError("review profile does not exist or is not sealed")
                if str(profile_row[1]) != review.toolset_fingerprint:
                    raise ValueError("review toolset does not match stored profile")
                await database.execute(
                    """
                    INSERT INTO profile_reviews(
                        review_id, profile_id, status, reviewer, reviewed_at,
                        evidence_fingerprint, toolset_fingerprint
                    ) VALUES (?, ?, 'COMPLETED', ?, ?, ?, ?)
                    """,
                    (
                        review.review_id,
                        review.profile_id,
                        review.reviewer,
                        _format_timestamp(review.reviewed_at),
                        review.evidence_fingerprint,
                        review.toolset_fingerprint,
                    ),
                )
                await database.executemany(
                    """
                    INSERT INTO profile_review_decisions(
                        review_id, ordinal, tool_name, effect, constraints_json,
                        limits_json, primary_risk_category, capability_tags_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            review.review_id,
                            ordinal,
                            decision.tool_name,
                            decision.effect.value,
                            encode_constraints(decision.constraints),
                            encode_limits(decision.limits),
                            decision.primary_risk_category,
                            encode_capability_tags(decision.capability_tags),
                        )
                        for ordinal, decision in enumerate(review.decisions)
                    ],
                )
                await database.commit()
            except BaseException:
                with anyio.CancelScope(shield=True):
                    await database.rollback()
                raise

    async def get_review(self, review_id: str) -> CompletedReview | None:
        async with aiosqlite.connect(self._database_path) as database:
            await configure_database(database)
            cursor = await database.execute(
                """
                SELECT review_id, profile_id, reviewer, reviewed_at,
                       evidence_fingerprint, toolset_fingerprint
                FROM profile_reviews
                WHERE review_id = ? AND status = 'COMPLETED'
                """,
                (review_id,),
            )
            raw_row = await cursor.fetchone()
            await cursor.close()
            if raw_row is None:
                return None
            row = cast(tuple[object, ...], raw_row)
            cursor = await database.execute(
                """
                SELECT tool_name, effect, constraints_json, limits_json,
                       primary_risk_category, capability_tags_json
                FROM profile_review_decisions
                WHERE review_id = ?
                ORDER BY ordinal
                """,
                (review_id,),
            )
            decision_rows = await cursor.fetchall()
            await cursor.close()
            return CompletedReview(
                review_id=str(row[0]),
                profile_id=str(row[1]),
                reviewer=str(row[2]),
                reviewed_at=_parse_timestamp(str(row[3])),
                evidence_fingerprint=str(row[4]),
                toolset_fingerprint=str(row[5]),
                decisions=tuple(
                    ReviewDecision(
                        tool_name=str(decision_row[0]),
                        effect=PolicyEffect(str(decision_row[1])),
                        constraints=decode_constraints(decision_row[2]),
                        limits=decode_limits(decision_row[3]),
                        primary_risk_category=str(decision_row[4]),
                        capability_tags=decode_capability_tags(decision_row[5]),
                    )
                    for decision_row in decision_rows
                ),
            )


async def _load_profile(
    database: aiosqlite.Connection,
    row: tuple[object, ...],
) -> ProfileSession:
    profile_id = str(row[0])
    cursor = await database.execute(
        """
        SELECT scenario_id
        FROM profile_scenarios
        WHERE profile_id = ?
        ORDER BY ordinal
        """,
        (profile_id,),
    )
    scenario_rows = await cursor.fetchall()
    await cursor.close()
    return ProfileSession(
        profile_id=profile_id,
        task_type=str(row[1]),
        agent_id=str(row[2]),
        server_id=str(row[3]),
        toolset_fingerprint=str(row[4]),
        status=ProfileStatus(str(row[5])),
        created_at=_parse_timestamp(str(row[6])),
        sealed_at=_parse_timestamp(str(row[7])) if row[7] is not None else None,
        planned_scenarios=tuple(str(scenario_row[0]) for scenario_row in scenario_rows),
    )


def _run_from_row(row: tuple[object, ...]) -> ScenarioRun:
    return ScenarioRun(
        run_id=str(row[0]),
        profile_id=str(row[1]),
        scenario_id=str(row[2]),
        status=RunStatus(str(row[3])),
        started_at=_parse_timestamp(str(row[4])),
        completed_at=_parse_timestamp(str(row[5])) if row[5] is not None else None,
    )


async def _get_call(database: aiosqlite.Connection, call_id: int) -> CallFact | None:
    cursor = await database.execute(
        """
        SELECT call_id, run_id, tool_name, attempted_at, outcome, completed_at
        FROM profile_calls
        WHERE call_id = ?
        """,
        (call_id,),
    )
    row = await cursor.fetchone()
    await cursor.close()
    return _call_from_row(cast(tuple[object, ...], row)) if row is not None else None


def _call_from_row(row: tuple[object, ...]) -> CallFact:
    return CallFact(
        call_id=int(cast(int, row[0])),
        run_id=str(row[1]),
        tool_name=str(row[2]),
        attempted_at=_parse_timestamp(str(row[3])),
        outcome=CallOutcome(str(row[4])) if row[4] is not None else None,
        completed_at=_parse_timestamp(str(row[5])) if row[5] is not None else None,
    )


def _format_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise RuntimeError("stored timestamp must include a timezone")
    return parsed.astimezone(UTC)
