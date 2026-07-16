"""Exact, expiring, tamper-evident, single-use approval permit tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from mcp_privprof.adapters.sqlite import SqlitePermitRepository
from mcp_privprof.application.permits import PermitService
from mcp_privprof.domain import ApprovalPermit

NOW = datetime(2026, 7, 16, 12, 0, tzinfo=UTC)
SECRET = bytes.fromhex("11" * 32)


@pytest.fixture
def anyio_backend() -> str:
    """Use the project's supported asyncio backend."""
    return "asyncio"


async def _service(path: Path, *, ttl: timedelta = timedelta(minutes=5)) -> PermitService:
    service = PermitService(SqlitePermitRepository(path), secret=SECRET, ttl=ttl)
    await service.initialize()
    return service


async def _approved(
    service: PermitService,
    arguments: dict[str, object],
) -> tuple[ApprovalPermit, str]:
    requested = await service.authorize_or_request(
        task_id="task-1",
        policy_id="policy-1",
        server_id="lab",
        tool_name="simulated_command_run",
        arguments=arguments,
        now=NOW,
    )
    assert requested.pending is not None
    permit = await service.approve(requested.pending.request_id, now=NOW + timedelta(seconds=1))
    return permit, requested.pending.argument_digest


@pytest.mark.anyio
async def test_exact_permit_consumes_once_and_database_contains_no_raw_arguments(
    tmp_path: Path,
) -> None:
    """Approval authorizes one exact call while SQLite stores metadata only."""
    database = tmp_path / "state.sqlite3"
    service = await _service(database)
    canary = "PRIVATE_COMMAND_79C231"
    arguments: dict[str, object] = {"command": canary}
    permit, digest = await _approved(service, arguments)

    consumed = await service.consume_exact(
        permit,
        argument_digest=digest,
        now=NOW + timedelta(seconds=2),
    )
    replayed = await service.consume_exact(
        permit,
        argument_digest=digest,
        now=NOW + timedelta(seconds=3),
    )

    assert consumed.allowed
    assert consumed.reason_code == "MCP_PRIVPROF_PERMIT_CONSUMED"
    assert not replayed.allowed
    assert replayed.reason_code == "MCP_PRIVPROF_PERMIT_REPLAY"
    assert canary.encode() not in database.read_bytes()


@pytest.mark.anyio
async def test_permit_rejects_changed_arguments_expiry_clock_skew_and_tampering(
    tmp_path: Path,
) -> None:
    """Each security-relevant permit field and time boundary fails closed."""
    service = await _service(tmp_path / "state.sqlite3")
    permit, digest = await _approved(service, {"command": "fixture command"})

    changed = await service.consume_exact(
        permit,
        argument_digest=f"sha256:{'f' * 64}",
        now=NOW + timedelta(seconds=2),
    )
    expired = await service.consume_exact(
        permit,
        argument_digest=digest,
        now=permit.expires_at + timedelta(microseconds=1),
    )
    skewed = await service.consume_exact(
        permit,
        argument_digest=digest,
        now=permit.issued_at - timedelta(seconds=31),
    )
    tampered = await service.consume_exact(
        replace(permit, tool_name="different_tool"),
        argument_digest=digest,
        now=NOW + timedelta(seconds=2),
    )

    assert changed.reason_code == "MCP_PRIVPROF_PERMIT_ARGUMENT_MISMATCH"
    assert expired.reason_code == "MCP_PRIVPROF_PERMIT_EXPIRED"
    assert skewed.reason_code == "MCP_PRIVPROF_PERMIT_CLOCK_SKEW"
    assert tampered.reason_code == "MCP_PRIVPROF_PERMIT_INVALID"


@pytest.mark.anyio
async def test_failed_approval_audit_prevents_permit_persistence(tmp_path: Path) -> None:
    """A mandatory permit-decision audit failure leaves no usable permit."""
    database = tmp_path / "state.sqlite3"
    service = await _service(database)
    requested = await service.authorize_or_request(
        task_id="task-1",
        policy_id="policy-1",
        server_id="lab",
        tool_name="simulated_command_run",
        arguments={"command": "fixture command"},
        now=NOW,
    )
    assert requested.pending is not None

    async def fail_audit(_: ApprovalPermit) -> None:
        raise OSError("simulated mandatory audit failure")

    with pytest.raises(OSError, match="mandatory audit"):
        await service.approve(
            requested.pending.request_id,
            now=NOW + timedelta(seconds=1),
            before_persist=fail_audit,
        )

    assert b"permit-" not in database.read_bytes()
