"""Real public CLI profile, review, and policy workflow integration test."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import anyio
import pytest
from anyio.to_thread import run_sync as run_sync_in_worker_thread
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import McpError
from mcp.types import TextContent
from typer.testing import CliRunner

from mcp_privprof.adapters.sqlite import SqliteProfileRepository
from mcp_privprof.application import ProfileService
from mcp_privprof.cli import app
from mcp_privprof.contracts.policy import PolicyV1
from mcp_privprof.domain.profile import CallOutcome, RunStatus

PROJECT_ROOT = Path(__file__).parents[2]
CLI_EXE = PROJECT_ROOT / ".venv" / "Scripts" / "mcp-privprof.exe"


@pytest.fixture
def anyio_backend() -> str:
    """Use the project's supported asyncio backend."""
    return "asyncio"


async def _create_profile(
    runner: CliRunner,
    database: Path,
    *,
    profile_id: str,
    scenario_id: str,
    server_module: str,
) -> None:
    created = await run_sync_in_worker_thread(
        runner.invoke,
        app,
        [
            "profile",
            "create",
            "--profile-id",
            profile_id,
            "--task-type",
            "dependency-review",
            "--agent-id",
            "agent-real-1",
            "--server-id",
            "lab",
            "--scenario",
            scenario_id,
            "--database",
            str(database),
            "--cwd",
            str(PROJECT_ROOT),
            "--",
            sys.executable,
            "-m",
            server_module,
        ],
    )
    assert created.exit_code == 0, created.output
    assert f"Created open profile {profile_id}" in created.stdout


@pytest.mark.anyio
async def test_public_profile_workflow_records_reviews_and_generates_policy(
    tmp_path: Path,
) -> None:
    """A real MCP call can become policy only after sealed exact human review."""
    database = tmp_path / "state" / "state.sqlite3"
    evidence_json = tmp_path / "reports" / "profile-evidence.json"
    evidence_markdown = tmp_path / "reports" / "profile-evidence.md"
    decisions_file = tmp_path / "reports" / "review-decisions.json"
    policy_file = tmp_path / "reports" / "policy.json"
    runner = CliRunner()

    await _create_profile(
        runner,
        database,
        profile_id="profile-real-1",
        scenario_id="read-project-readme",
        server_module="lab.server",
    )

    parameters = StdioServerParameters(
        command=str(CLI_EXE),
        args=[
            "profile",
            "run",
            "--profile-id",
            "profile-real-1",
            "--run-id",
            "run-real-1",
            "--scenario-id",
            "read-project-readme",
            "--database",
            str(database),
            "--cwd",
            str(PROJECT_ROOT),
            "--",
            sys.executable,
            "-m",
            "lab.server",
        ],
        cwd=PROJECT_ROOT,
    )
    with anyio.fail_after(30):
        async with (
            stdio_client(parameters) as streams,
            ClientSession(*streams) as session,
        ):
            await session.initialize()
            tools = await session.list_tools()
            assert "read_fixture" in {tool.name for tool in tools.tools}
            result = await session.call_tool(
                "read_fixture",
                {"relative_path": "project/README.md"},
            )
            assert result.isError is not True
            assert isinstance(result.content[0], TextContent)
            assert "Fixture project" in result.content[0].text

    service = ProfileService(SqliteProfileRepository(database))
    await service.initialize()
    runs = await service.runs("profile-real-1")
    calls = await service.calls("profile-real-1")
    assert len(runs) == 1
    assert runs[0].status is RunStatus.COMPLETED
    assert len(calls) == 1
    assert calls[0].tool_name == "read_fixture"
    assert calls[0].outcome is CallOutcome.SUCCESS
    assert b"project/README.md" not in database.read_bytes()

    sealed = await run_sync_in_worker_thread(
        runner.invoke,
        app,
        [
            "profile",
            "seal",
            "--profile-id",
            "profile-real-1",
            "--database",
            str(database),
            "--json-report",
            str(evidence_json),
            "--markdown-report",
            str(evidence_markdown),
            "--review-template",
            str(decisions_file),
        ],
    )
    assert sealed.exit_code == 0, sealed.output
    evidence = json.loads(evidence_json.read_text(encoding="utf-8"))
    assert evidence["completed_run_count"] == 1
    assert evidence["profile_status"] == "SEALED"
    assert "do not authorize" in evidence_markdown.read_text(encoding="utf-8")

    before_review = await run_sync_in_worker_thread(
        runner.invoke,
        app,
        [
            "policy",
            "generate",
            "--review-id",
            "review-real-1",
            "--policy-id",
            "policy-real-1",
            "--database",
            str(database),
            "--output",
            str(policy_file),
        ],
    )
    assert before_review.exit_code == 1
    assert not policy_file.exists()

    decisions = json.loads(decisions_file.read_text(encoding="utf-8"))
    assert {decision["effect"] for decision in decisions["decisions"]} == {"DENY"}
    for decision in decisions["decisions"]:
        if decision["tool_name"] == "read_fixture":
            decision["effect"] = "ALLOW"
    decisions_file.write_text(json.dumps(decisions), encoding="utf-8")

    reviewed = await run_sync_in_worker_thread(
        runner.invoke,
        app,
        [
            "review",
            "complete",
            "--review-id",
            "review-real-1",
            "--reviewer",
            "operator@example.test",
            "--decisions",
            str(decisions_file),
            "--database",
            str(database),
        ],
    )
    assert reviewed.exit_code == 0, reviewed.output

    generated = await run_sync_in_worker_thread(
        runner.invoke,
        app,
        [
            "policy",
            "generate",
            "--review-id",
            "review-real-1",
            "--policy-id",
            "policy-real-1",
            "--database",
            str(database),
            "--output",
            str(policy_file),
        ],
    )
    assert generated.exit_code == 0, generated.output
    policy = PolicyV1.model_validate_json(policy_file.read_bytes())
    effects = {rule.tool_name: rule.effect.value for rule in policy.tools}
    assert policy.reviewed_profile_id == "profile-real-1"
    assert effects["read_fixture"] == "ALLOW"
    assert set(effects.values()) == {"ALLOW", "DENY"}


@pytest.mark.anyio
async def test_profile_proxy_invalidates_changed_catalog_before_next_call(tmp_path: Path) -> None:
    """A tools/list_changed signal closes the exact-catalog gate immediately."""
    database = tmp_path / "drift.sqlite3"
    runner = CliRunner()
    await _create_profile(
        runner,
        database,
        profile_id="profile-drift-1",
        scenario_id="catalog-change",
        server_module="lab.changing_catalog_server",
    )
    parameters = StdioServerParameters(
        command=str(CLI_EXE),
        args=[
            "profile",
            "run",
            "--profile-id",
            "profile-drift-1",
            "--run-id",
            "run-drift-1",
            "--scenario-id",
            "catalog-change",
            "--database",
            str(database),
            "--cwd",
            str(PROJECT_ROOT),
            "--",
            sys.executable,
            "-m",
            "lab.changing_catalog_server",
        ],
        cwd=PROJECT_ROOT,
    )
    with anyio.fail_after(30):
        async with (
            stdio_client(parameters) as streams,
            ClientSession(*streams) as session,
        ):
            await session.initialize()
            with pytest.raises(McpError, match="MCP_PRIVPROF_PROFILE_TOOLSET_DRIFT"):
                await session.call_tool("change_catalog", {})
            await anyio.sleep(0.1)
            denied = await session.call_tool("before_change", {})
            assert denied.isError is True
            assert isinstance(denied.content[0], TextContent)
            assert denied.content[0].text == "MCP_PRIVPROF_PROFILE_TOOLSET_DRIFT"

    service = ProfileService(SqliteProfileRepository(database))
    await service.initialize()
    calls = await service.calls("profile-drift-1")
    assert [(call.tool_name, call.outcome) for call in calls] == [
        ("change_catalog", CallOutcome.SUCCESS),
        ("before_change", CallOutcome.INFRASTRUCTURE_ERROR),
    ]


@pytest.mark.anyio
async def test_cancelled_profile_call_remains_an_incomplete_attempt(tmp_path: Path) -> None:
    """Cancellation is not converted into a fabricated success or failure fact."""
    database = tmp_path / "cancel.sqlite3"
    runner = CliRunner()
    await _create_profile(
        runner,
        database,
        profile_id="profile-cancel-1",
        scenario_id="cancel-and-recover",
        server_module="lab.fault_server",
    )
    parameters = StdioServerParameters(
        command=str(CLI_EXE),
        args=[
            "profile",
            "run",
            "--profile-id",
            "profile-cancel-1",
            "--run-id",
            "run-cancel-1",
            "--scenario-id",
            "cancel-and-recover",
            "--database",
            str(database),
            "--cwd",
            str(PROJECT_ROOT),
            "--",
            sys.executable,
            "-m",
            "lab.fault_server",
        ],
        cwd=PROJECT_ROOT,
    )
    with anyio.fail_after(30):
        async with (
            stdio_client(parameters) as streams,
            ClientSession(*streams) as session,
        ):
            await session.initialize()
            with anyio.move_on_after(0.05) as cancellation:
                await session.call_tool(
                    "delayed_echo",
                    {"text": "private-value", "delay_seconds": 1.0},
                )
            assert cancellation.cancel_called
            recovered = await session.call_tool("immediate_echo", {"text": "still-alive"})
            assert recovered.isError is not True

    service = ProfileService(SqliteProfileRepository(database))
    await service.initialize()
    calls = await service.calls("profile-cancel-1")
    assert [(call.tool_name, call.outcome) for call in calls] == [
        ("delayed_echo", None),
        ("immediate_echo", CallOutcome.SUCCESS),
    ]
    assert b"private-value" not in database.read_bytes()
