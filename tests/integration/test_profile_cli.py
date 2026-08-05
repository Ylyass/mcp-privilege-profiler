"""Real public CLI profile, review, and policy workflow integration test."""

from __future__ import annotations

import json
import sys
from functools import partial
from pathlib import Path
from shutil import which

import anyio
import mcp.types as types
import pytest
from anyio.to_thread import run_sync as run_sync_in_worker_thread
from click import unstyle
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import MCPError
from mcp.types import TextContent
from typer.testing import CliRunner

from mcp_privprof.adapters.sqlite import SqliteProfileRepository
from mcp_privprof.application import ProfileService
from mcp_privprof.cli import app
from mcp_privprof.contracts.policy import PolicyV1
from mcp_privprof.domain.profile import CallOutcome, RunStatus

PROJECT_ROOT = Path(__file__).parents[2]
CLI_EXE = which("mcp-privprof")
if CLI_EXE is None:
    raise RuntimeError("mcp-privprof console script is not available on PATH")


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
            assert result.is_error is not True
            assert isinstance(result.content[0], TextContent)
            assert "Fixture project" in result.content[0].text

    service = ProfileService(SqliteProfileRepository(database))
    await service.initialize()
    unconfirmed = await run_sync_in_worker_thread(
        runner.invoke,
        app,
        [
            "profile",
            "complete-run",
            "--run-id",
            "run-real-1",
            "--database",
            str(database),
        ],
    )
    assert unconfirmed.exit_code == 2
    unconfirmed_output = unstyle(unconfirmed.output)
    for word in ("explicit", "success", "confirmation", "required"):
        assert word in unconfirmed_output

    completed = await run_sync_in_worker_thread(
        runner.invoke,
        app,
        [
            "profile",
            "complete-run",
            "--run-id",
            "run-real-1",
            "--confirm-success",
            "--database",
            str(database),
        ],
    )
    assert completed.exit_code == 0, completed.output
    assert "explicit operator confirmation" in completed.output

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
            decision["limits"] = {
                "max_calls_per_minute": 60,
                "max_calls_per_task": 100,
                "max_concurrent_calls": 2,
            }
            decision["primary_risk_category"] = "file_read"
            decision["capability_tags"] = ["filesystem"]
            decision["constraints"] = [
                {
                    "kind": "path",
                    "argument": "relative_path",
                    "path_roots": ["PROJECT_ROOT"],
                }
            ]
        if decision["tool_name"] == "simulated_command_run":
            decision["effect"] = "REQUIRE_APPROVAL"
            decision["limits"] = {
                "max_calls_per_minute": 10,
                "max_calls_per_task": 20,
                "max_concurrent_calls": 1,
            }
            decision["primary_risk_category"] = "command_execution"
            decision["capability_tags"] = ["process"]
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
    assert policy.default_effect == "DENY"
    assert effects["read_fixture"] == "ALLOW"
    assert effects["simulated_command_run"] == "REQUIRE_APPROVAL"
    assert set(effects.values()) == {"ALLOW", "REQUIRE_APPROVAL", "DENY"}
    read_rule = next(rule for rule in policy.tools if rule.tool_name == "read_fixture")
    assert read_rule.constraints[0].kind == "path"
    assert read_rule.limits is not None
    assert read_rule.limits.max_calls_per_task == 100

    audit_log = tmp_path / "state" / "enforcement-events.jsonl"
    enforcement_state = tmp_path / "state" / "enforcement.sqlite3"
    approval_control = tmp_path / "state" / "approval-control.json"
    enforce_parameters = StdioServerParameters(
        command=str(CLI_EXE),
        args=[
            "enforce",
            "--policy",
            str(policy_file),
            "--task-id",
            "task-real-1",
            "--agent-id",
            "agent-real-1",
            "--audit-log",
            str(audit_log),
            "--state-database",
            str(enforcement_state),
            "--approval-control",
            str(approval_control),
            "--path-root",
            f"PROJECT_ROOT={PROJECT_ROOT / 'lab' / 'fixtures'}",
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
            stdio_client(enforce_parameters) as streams,
            ClientSession(*streams) as session,
        ):
            await session.initialize()
            visible = await session.list_tools()
            assert {tool.name for tool in visible.tools} == {
                "read_fixture",
                "simulated_command_run",
            }

            allowed = await session.call_tool(
                "read_fixture",
                {"relative_path": "project/README.md"},
            )
            assert allowed.is_error is not True
            assert isinstance(allowed.content[0], TextContent)
            assert "Fixture project" in allowed.content[0].text

            traversal = await session.call_tool(
                "read_fixture",
                {"relative_path": "../outside.txt"},
            )
            assert traversal.is_error is True
            assert traversal.structured_content == {
                "argument_name": "relative_path",
                "constraint_kind": "path",
                "reason_code": "MCP_PRIVPROF_CONSTRAINT_PATH_OUTSIDE_ROOT",
            }

            approval = await session.call_tool(
                "simulated_command_run",
                {"command": "harmless fixture"},
            )
            assert approval.is_error is True
            assert approval.structured_content is not None
            assert approval.structured_content["reason_code"] == "MCP_PRIVPROF_APPROVAL_REQUIRED"
            request_id = approval.structured_content["request_id"]
            assert isinstance(request_id, str)

            permit = await run_sync_in_worker_thread(
                partial(
                    runner.invoke,
                    app,
                    [
                        "permit",
                        "create",
                        "--request",
                        request_id,
                        "--control",
                        str(approval_control),
                    ],
                    input="y\n",
                )
            )
            assert permit.exit_code == 0, permit.output
            assert "Created single-use permit" in permit.stdout

            changed_arguments = await session.call_tool(
                "simulated_command_run",
                {"command": "different harmless fixture"},
            )
            assert changed_arguments.is_error is True
            assert changed_arguments.structured_content is not None
            assert (
                changed_arguments.structured_content["reason_code"]
                == "MCP_PRIVPROF_APPROVAL_REQUIRED"
            )

            approved = await session.call_tool(
                "simulated_command_run",
                {"command": "harmless fixture"},
            )
            assert approved.is_error is not True
            assert isinstance(approved.content[0], TextContent)
            assert "SIMULATED_ONLY" in approved.content[0].text

            used = await session.call_tool(
                "simulated_command_run",
                {"command": "harmless fixture"},
            )
            assert used.is_error is True
            assert used.structured_content is not None
            assert used.structured_content["reason_code"] == "MCP_PRIVPROF_APPROVAL_REQUIRED"
            assert used.structured_content["request_id"] != request_id

            denied = await session.call_tool("simulated_credential_read", {})
            assert denied.is_error is True
            assert denied.structured_content == {"reason_code": "MCP_PRIVPROF_POLICY_DENY"}

            unknown = await session.call_tool("not_in_catalog", {})
            assert unknown.is_error is True
            assert unknown.structured_content == {"reason_code": "MCP_PRIVPROF_UNKNOWN_TOOL"}

    audit_records = [
        json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()
    ]
    assert {"policy_decision", "permit_decision", "tool_completion"} <= {
        record["event_type"] for record in audit_records
    }
    serialized_audit = audit_log.read_text(encoding="utf-8")
    assert "project/README.md" not in serialized_audit
    assert "harmless fixture" not in serialized_audit
    assert "different harmless fixture" not in serialized_audit
    assert b"harmless fixture" not in enforcement_state.read_bytes()
    assert b"different harmless fixture" not in enforcement_state.read_bytes()


@pytest.mark.anyio
async def test_profile_proxy_invalidates_changed_catalog_before_next_call(tmp_path: Path) -> None:
    """Pre-request revalidation closes the exact-catalog gate after a change."""
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
            with pytest.raises(MCPError, match="MCP_PRIVPROF_PROFILE_TOOLSET_DRIFT"):
                await session.call_tool("change_catalog", {})
            await anyio.sleep(0.1)
            denied = await session.call_tool("before_change", {})
            assert denied.is_error is True
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
async def test_profile_proxy_returns_the_exact_revalidated_catalog(tmp_path: Path) -> None:
    """Profile tools/list returns one exact full snapshot, not a second fetch."""
    database = tmp_path / "profile-list.sqlite3"
    runner = CliRunner()
    await _create_profile(
        runner,
        database,
        profile_id="profile-exact-list",
        scenario_id="list-catalog",
        server_module="lab.paginated_server",
    )
    parameters = StdioServerParameters(
        command=str(CLI_EXE),
        args=[
            "profile",
            "run",
            "--profile-id",
            "profile-exact-list",
            "--run-id",
            "run-exact-list",
            "--scenario-id",
            "list-catalog",
            "--database",
            str(database),
            "--cwd",
            str(PROJECT_ROOT),
            "--",
            sys.executable,
            "-m",
            "lab.paginated_server",
        ],
        cwd=PROJECT_ROOT,
    )

    async with (
        stdio_client(parameters) as streams,
        ClientSession(*streams) as session,
    ):
        await session.initialize()
        catalog = await session.list_tools()
        with pytest.raises(MCPError, match="MCP_PRIVPROF_INVALID_CATALOG_CURSOR"):
            await session.list_tools(
                params=types.PaginatedRequestParams(cursor="unexpected-cursor")
            )

    assert [tool.name for tool in catalog.tools] == ["page_one_tool", "page_two_tool"]
    assert catalog.next_cursor is None


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
            assert recovered.is_error is not True

    service = ProfileService(SqliteProfileRepository(database))
    await service.initialize()
    calls = await service.calls("profile-cancel-1")
    assert [(call.tool_name, call.outcome) for call in calls] == [
        ("delayed_echo", None),
        ("immediate_echo", CallOutcome.SUCCESS),
    ]
    assert b"private-value" not in database.read_bytes()
