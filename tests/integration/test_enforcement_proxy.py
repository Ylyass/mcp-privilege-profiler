"""Real MCP enforcement drift integration test."""

from __future__ import annotations

import sys
from pathlib import Path

import anyio
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import McpError

from mcp_privprof.adapters.mcp.inventory import collect_toolset
from mcp_privprof.application.policies import policy_contract, render_policy_json
from mcp_privprof.domain.policy import Policy, PolicyEffect, PolicyRule, ToolIdentity

PROJECT_ROOT = Path(__file__).parents[2]
CLI_EXE = PROJECT_ROOT / ".venv" / "Scripts" / "mcp-privprof.exe"


@pytest.fixture
def anyio_backend() -> str:
    """Use the supported asyncio backend."""
    return "asyncio"


async def _changing_catalog_policy(
    path: Path,
    *,
    change_effect: PolicyEffect = PolicyEffect.ALLOW,
) -> None:
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "lab.changing_catalog_server"],
        cwd=PROJECT_ROOT,
    )
    async with (
        stdio_client(parameters) as streams,
        ClientSession(*streams) as session,
    ):
        await session.initialize()
        snapshot = await collect_toolset(session, "changing-lab")
    policy = Policy(
        policy_id="changing-policy",
        task_type="catalog-change-test",
        server_id="changing-lab",
        approved_toolset_fingerprint=snapshot.fingerprint,
        reviewed_profile_id="changing-profile",
        rules=tuple(
            PolicyRule(
                ToolIdentity("changing-lab", tool.name),
                change_effect if tool.name == "change_catalog" else PolicyEffect.ALLOW,
            )
            for tool in snapshot.tools
        ),
    )
    path.write_bytes(render_policy_json(policy_contract(policy)))


@pytest.mark.anyio
async def test_enforcement_invalidates_catalog_change_before_next_call(tmp_path: Path) -> None:
    """A list-changed signal closes the reviewed policy gate until exact revalidation."""
    policy_file = tmp_path / "changing-policy.json"
    await _changing_catalog_policy(policy_file)
    parameters = StdioServerParameters(
        command=str(CLI_EXE),
        args=[
            "enforce",
            "--policy",
            str(policy_file),
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
            initial = await session.list_tools()
            assert {tool.name for tool in initial.tools} == {
                "before_change",
                "change_catalog",
            }

            invalid_schema = await session.call_tool(
                "before_change",
                {"unexpected": True},
            )
            assert invalid_schema.isError is True
            assert invalid_schema.structuredContent == {
                "reason_code": "MCP_PRIVPROF_INPUT_SCHEMA_INVALID"
            }

            changed = await session.call_tool("change_catalog", {})
            assert changed.isError is not True
            await anyio.sleep(0.1)

            denied = await session.call_tool("before_change", {})
            assert denied.isError is True
            assert denied.structuredContent == {"reason_code": "MCP_PRIVPROF_POLICY_TOOLSET_DRIFT"}
            with pytest.raises(McpError, match="MCP_PRIVPROF_POLICY_TOOLSET_DRIFT"):
                await session.list_tools()


@pytest.mark.parametrize(
    ("effect", "expected_tools", "reason_code"),
    [
        (PolicyEffect.DENY, {"before_change"}, "MCP_PRIVPROF_POLICY_DENY"),
        (
            PolicyEffect.REQUIRE_APPROVAL,
            {"before_change", "change_catalog"},
            "MCP_PRIVPROF_APPROVAL_REQUIRED",
        ),
    ],
)
@pytest.mark.anyio
async def test_denied_and_unapproved_calls_never_reach_downstream(
    tmp_path: Path,
    effect: PolicyEffect,
    expected_tools: set[str],
    reason_code: str,
) -> None:
    """Blocking change_catalog proves the downstream state remains untouched."""
    policy_file = tmp_path / f"blocked-{effect.value}.json"
    await _changing_catalog_policy(policy_file, change_effect=effect)
    parameters = StdioServerParameters(
        command=str(CLI_EXE),
        args=[
            "enforce",
            "--policy",
            str(policy_file),
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
            initial = await session.list_tools()
            assert {tool.name for tool in initial.tools} == expected_tools

            blocked = await session.call_tool("change_catalog", {})
            assert blocked.isError is True
            assert blocked.structuredContent == {"reason_code": reason_code}
            await anyio.sleep(0.1)

            unchanged = await session.list_tools()
            assert {tool.name for tool in unchanged.tools} == expected_tools
