"""One-command, source-checkout demonstration of the enforced security boundary.

The example policy is deterministic fixture data. It is not a substitute for
the real profiling and explicit human-review workflow.
"""

from __future__ import annotations

import json
import logging
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from functools import partial
from io import StringIO
from pathlib import Path
from uuid import uuid4

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import CallToolResult, TextContent

from mcp_privprof.adapters.mcp.inventory import collect_toolset
from mcp_privprof.application.policies import policy_contract, render_policy_json
from mcp_privprof.contracts.event import AuditEventV1
from mcp_privprof.domain import EnumConstraint, PathConstraint, ToolLimits
from mcp_privprof.domain.inventory import ToolsetSnapshot
from mcp_privprof.domain.policy import Policy, PolicyEffect, PolicyRule, ToolIdentity

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SERVER_ID = "safe-demo-lab"
EXPECTED_TOOLS = {
    "fetch_fixture_advisory",
    "list_fixture_directory",
    "read_fixture",
    "simulated_command_run",
    "simulated_credential_read",
    "simulated_external_post",
    "write_sandbox_patch",
}
VISIBLE_TOOLS = {
    "fetch_fixture_advisory",
    "list_fixture_directory",
    "read_fixture",
}
CLI_BOOTSTRAP = (
    "import logging; logging.disable(logging.CRITICAL); from mcp_privprof.cli import app; app()"
)
QUIET_LAB_BOOTSTRAP = (
    "import logging; logging.disable(logging.CRITICAL); "
    "from lab.server import mcp; "
    "mcp.settings.log_level = 'ERROR'; "
    "mcp.run(transport='stdio')"
)


@dataclass(frozen=True, slots=True)
class DemoResult:
    """Small, stable summary suitable for tests and beginner-facing output."""

    visible_tools: tuple[str, ...]
    denied_tool: str
    denial_reason: str
    audit_event_count: int


async def run_demo(workspace: Path) -> DemoResult:
    """Run allowed calls and a direct hidden-tool bypass probe through the proxy."""
    workspace.mkdir(parents=True, exist_ok=True)
    snapshot = await _collect_lab_toolset()
    observed_names = {tool.name for tool in snapshot.tools}
    if observed_names != EXPECTED_TOOLS:
        raise RuntimeError(
            "safe-lab catalog differs from the reviewed demo fixture; refusing to continue"
        )

    policy_file = workspace / "demo-policy.json"
    audit_log = workspace / "demo-events.jsonl"
    state_database = workspace / "demo-state.sqlite3"
    policy_file.write_bytes(render_policy_json(policy_contract(_demo_policy(snapshot))))

    blocked_name = f"blocked-{uuid4().hex}.txt"
    blocked_path = PROJECT_ROOT / "runtime" / "lab-sandbox" / blocked_name
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[
            "-c",
            CLI_BOOTSTRAP,
            "enforce",
            "--policy",
            str(policy_file),
            "--task-id",
            "safe-demo-task",
            "--agent-id",
            "safe-demo-agent",
            "--audit-log",
            str(audit_log),
            "--state-database",
            str(state_database),
            "--path-root",
            f"LAB_FIXTURES={PROJECT_ROOT / 'lab' / 'fixtures'}",
            "--cwd",
            str(PROJECT_ROOT),
            "--",
            sys.executable,
            "-c",
            QUIET_LAB_BOOTSTRAP,
        ],
        cwd=PROJECT_ROOT,
    )

    with anyio.fail_after(30):
        async with (
            stdio_client(parameters) as streams,
            ClientSession(*streams) as session,
        ):
            await session.initialize()
            listed = await session.list_tools()
            visible = {tool.name for tool in listed.tools}
            if visible != VISIBLE_TOOLS:
                raise RuntimeError("enforced catalog does not match the reviewed demo policy")

            directory = await session.call_tool("list_fixture_directory", {})
            _require_success_text(directory, "project/requirements.txt")

            requirements = await session.call_tool(
                "read_fixture",
                {"relative_path": "project/requirements.txt"},
            )
            _require_success_text(requirements, "demo-client==4.5.6")

            advisory = await session.call_tool(
                "fetch_fixture_advisory",
                {"advisory_id": "LAB-2026-0002"},
            )
            _require_success_text(advisory, "demo-client")

            denied = await session.call_tool(
                "write_sandbox_patch",
                {"relative_path": blocked_name, "content": "must never be written"},
            )
            if denied.is_error is not True or denied.structured_content != {
                "reason_code": "MCP_PRIVPROF_POLICY_DENY"
            }:
                raise RuntimeError("direct hidden-tool bypass was not denied as expected")

    if blocked_path.exists():
        raise RuntimeError("denied hidden tool unexpectedly reached the downstream server")

    records = [
        AuditEventV1.model_validate(json.loads(line))
        for line in audit_log.read_text(encoding="utf-8").splitlines()
    ]
    if not any(
        record.tool_name == "write_sandbox_patch"
        and record.decision == "denied"
        and record.reason_code == "MCP_PRIVPROF_POLICY_DENY"
        for record in records
    ):
        raise RuntimeError("audit evidence does not contain the hidden-tool denial")

    serialized_audit = audit_log.read_text(encoding="utf-8")
    forbidden_raw_values = (
        "project/requirements.txt",
        "project/README.md",
        "LAB-2026-0002",
        "demo-parser==1.2.3",
        "demo-client==4.5.6",
        "demo-client",
        "medium",
        "Second deterministic fixture advisory.",
        blocked_name,
        "must never be written",
    )
    if any(value in serialized_audit for value in forbidden_raw_values):
        raise RuntimeError("privacy-minimized audit unexpectedly contains raw demo values")
    serialized_state = state_database.read_bytes()
    if any(value.encode("utf-8") in serialized_state for value in forbidden_raw_values):
        raise RuntimeError("privacy-minimized state unexpectedly contains raw demo values")

    return DemoResult(
        visible_tools=tuple(sorted(visible)),
        denied_tool="write_sandbox_patch",
        denial_reason="MCP_PRIVPROF_POLICY_DENY",
        audit_event_count=len(records),
    )


async def _collect_lab_toolset() -> ToolsetSnapshot:
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-c", QUIET_LAB_BOOTSTRAP],
        cwd=PROJECT_ROOT,
    )
    async with (
        stdio_client(parameters) as streams,
        ClientSession(*streams) as session,
    ):
        await session.initialize()
        return await collect_toolset(session, SERVER_ID)


def _demo_policy(snapshot: ToolsetSnapshot) -> Policy:
    limits = ToolLimits(
        max_calls_per_minute=5,
        max_calls_per_task=1,
        max_concurrent_calls=1,
    )
    rules: list[PolicyRule] = []
    for tool in snapshot.tools:
        constraints = ()
        effect = PolicyEffect.ALLOW if tool.name in VISIBLE_TOOLS else PolicyEffect.DENY
        if tool.name == "read_fixture":
            constraints = (
                EnumConstraint("relative_path", ("project/requirements.txt",)),
                PathConstraint("relative_path", ("LAB_FIXTURES",)),
            )
        elif tool.name == "fetch_fixture_advisory":
            constraints = (EnumConstraint("advisory_id", ("LAB-2026-0002",)),)
        rules.append(
            PolicyRule(
                identity=ToolIdentity(SERVER_ID, tool.name),
                effect=effect,
                constraints=constraints,
                limits=limits if effect is PolicyEffect.ALLOW else None,
                primary_risk_category=(
                    "read_only_fixture" if effect is PolicyEffect.ALLOW else "unneeded_capability"
                ),
                capability_tags=("safe_demo",),
            )
        )
    return Policy(
        policy_id="safe-demo-policy-v1",
        task_type="dependency-review-demo",
        server_id=SERVER_ID,
        approved_toolset_fingerprint=snapshot.fingerprint,
        reviewed_profile_id="bundled-demo-fixture-v1",
        rules=tuple(rules),
    )


def _require_success_text(result: CallToolResult, expected: str) -> None:
    if result.is_error is True:
        raise RuntimeError(f"allowed safe fixture call failed while expecting {expected!r}")
    text = "\n".join(item.text for item in result.content if isinstance(item, TextContent))
    if expected not in text:
        raise RuntimeError(f"expected safe fixture value {expected!r} was not returned")


def main() -> None:
    """Run the disposable demo and print only its security-relevant result."""
    logging.disable(logging.CRITICAL)
    with (
        tempfile.TemporaryDirectory(prefix="mcp-privprof-demo-") as temporary,
        redirect_stderr(StringIO()),
        redirect_stdout(StringIO()),
    ):
        result = anyio.run(partial(run_demo, Path(temporary)))
    print("MCP Privilege Profiler safe demo passed.")
    print(
        f"Visible policy-approved tools ({len(result.visible_tools)}): "
        f"{', '.join(result.visible_tools)}"
    )
    print(f"Direct hidden-tool bypass: {result.denied_tool} -> {result.denial_reason}")
    print(f"Privacy-minimized audit events validated: {result.audit_event_count}")
    print(
        "All demo databases, policy files, and audit events were removed from OS temporary storage."
    )


if __name__ == "__main__":
    main()
