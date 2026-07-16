"""Authenticated local approval-control integration tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import anyio
import pytest

from mcp_privprof.adapters.approval_control import (
    ApprovalControlServer,
    approve_request,
    inspect_approval,
)
from mcp_privprof.adapters.sqlite import SqlitePermitRepository
from mcp_privprof.application.permits import PermitService
from mcp_privprof.domain import ApprovalPermit

NOW = datetime(2026, 7, 16, 12, 0, tzinfo=UTC)
PERMIT_SECRET = bytes.fromhex("22" * 32)
CONTROL_SECRET = bytes.fromhex("33" * 32)


@pytest.fixture
def anyio_backend() -> str:
    """Use the project's supported asyncio backend."""
    return "asyncio"


@pytest.mark.anyio
async def test_control_requires_capability_secret_and_approves_exact_pending_call(
    tmp_path: Path,
) -> None:
    """Only the ephemeral authenticated endpoint reveals and approves arguments."""
    permits = PermitService(
        SqlitePermitRepository(tmp_path / "state.sqlite3"),
        secret=PERMIT_SECRET,
    )
    await permits.initialize()
    requested = await permits.authorize_or_request(
        task_id="task-1",
        policy_id="policy-1",
        server_id="lab",
        tool_name="simulated_command_run",
        arguments={"command": "operator-visible fixture"},
        now=datetime.now(UTC),
    )
    assert requested.pending is not None
    audited: list[str] = []

    async def on_approved(permit: ApprovalPermit) -> None:
        audited.append(permit.permit_id)

    control_path = tmp_path / "approval-control.json"
    server = ApprovalControlServer(
        control_path=control_path,
        secret=CONTROL_SECRET,
        permits=permits,
        on_approved=on_approved,
    )
    await server.initialize()
    bad_control = tmp_path / "bad-control.json"
    document = json.loads(control_path.read_text(encoding="utf-8"))
    document["secret"] = "00" * 32
    bad_control.write_text(json.dumps(document), encoding="utf-8")

    async with anyio.create_task_group() as tasks:
        tasks.start_soon(server.serve)
        inspected = await inspect_approval(control_path, requested.pending.request_id)
        inspected_request = inspected["request"]
        assert isinstance(inspected_request, dict)
        assert inspected_request["arguments"] == {"command": "operator-visible fixture"}
        with pytest.raises(RuntimeError, match="CONTROL_AUTHENTICATION_FAILED"):
            await inspect_approval(bad_control, requested.pending.request_id)

        approved = await approve_request(control_path, requested.pending.request_id)
        approved_permit = approved["permit"]
        assert isinstance(approved_permit, dict)
        permit_id = approved_permit["permit_id"]
        assert isinstance(permit_id, str)
        assert audited == [permit_id]
        await server.aclose()
        tasks.cancel_scope.cancel()

    assert not control_path.exists()


@pytest.mark.anyio
async def test_control_publication_failure_removes_partial_capability_and_listener(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed secret-file write leaves no endpoint or partial capability behind."""
    permits = PermitService(
        SqlitePermitRepository(tmp_path / "state.sqlite3"),
        secret=PERMIT_SECRET,
    )
    await permits.initialize()

    async def on_approved(_: ApprovalPermit) -> None:
        return None

    control_path = tmp_path / "approval-control.json"
    server = ApprovalControlServer(
        control_path=control_path,
        secret=CONTROL_SECRET,
        permits=permits,
        on_approved=on_approved,
    )

    def fail_write(_: int, __: object) -> int:
        raise OSError("simulated capability write failure")

    monkeypatch.setattr("mcp_privprof.adapters.approval_control.os.write", fail_write)

    with pytest.raises(OSError, match="capability write failure"):
        await server.initialize()

    assert not control_path.exists()
    await server.aclose()
