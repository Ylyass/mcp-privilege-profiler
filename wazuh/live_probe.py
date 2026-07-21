"""Prove the live proxy-to-Wazuh denial path with harmless local fixtures."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from time import monotonic
from typing import cast
from uuid import uuid4

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcp_privprof.adapters.mcp.inventory import collect_toolset
from mcp_privprof.application.policies import policy_contract, render_policy_json
from mcp_privprof.contracts.event import AuditEventV1
from mcp_privprof.domain.inventory import ToolsetSnapshot
from mcp_privprof.domain.policy import Policy, PolicyEffect, PolicyRule, ToolIdentity
from wazuh import lab

SERVER_ID = "wazuh-live-probe-lab"
EXPECTED_RULE_ID = "100103"
EXPECTED_LEVEL = 10
MANAGER_SERVICE = "wazuh.manager"
ALERT_PATH = "/var/ossec/logs/alerts/alerts.json"

type JsonScalar = bool | int | float | str | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]


@dataclass(frozen=True, slots=True)
class LiveProbeResult:
    """Minimal, non-sensitive evidence from one successful live probe."""

    task_id: str
    trace_id: str
    rule_id: str
    rule_level: int
    agent_id: str
    agent_name: str


@dataclass(frozen=True, slots=True)
class ObservedAlert:
    """Typed fields extracted from one Wazuh alert document."""

    trace_id: str
    rule_id: str
    rule_level: int
    agent_id: str
    agent_name: str


def build_probe_policy(snapshot: ToolsetSnapshot) -> Policy:
    """Build a complete, all-deny policy used only to isolate the Wazuh bridge."""
    if snapshot.server_id != SERVER_ID:
        raise ValueError("live-probe snapshot has an unexpected server identity")
    return Policy(
        policy_id="wazuh-live-probe-policy",
        task_type="wazuh-live-denial-test",
        server_id=SERVER_ID,
        approved_toolset_fingerprint=snapshot.fingerprint,
        reviewed_profile_id="wazuh-live-probe-synthetic-profile",
        rules=tuple(
            PolicyRule(
                identity=ToolIdentity(SERVER_ID, tool.name),
                effect=PolicyEffect.DENY,
                primary_risk_category=(
                    "credential_access"
                    if tool.name == "simulated_credential_read"
                    else "test_fixture"
                ),
                capability_tags=("test_fixture",),
            )
            for tool in snapshot.tools
        ),
    )


async def run_live_probe(*, timeout_seconds: float = 30.0) -> LiveProbeResult:
    """Emit one real proxy denial and wait for its exact Wazuh manager alert."""
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    docker = _require_executable("docker")
    cli = _require_cli()
    manager = _running_manager(docker)
    _require_active_lab_agent(docker, manager)
    lab.prepare_runtime_files()

    task_id = f"wazuh-live-{uuid4()}"
    with tempfile.TemporaryDirectory(prefix="mcp-privprof-wazuh-probe-") as temporary:
        temporary_root = Path(temporary)
        policy_path = temporary_root / "policy.json"
        state_path = temporary_root / "enforcement.sqlite3"
        snapshot = await _collect_lab_snapshot()
        policy_path.write_bytes(render_policy_json(policy_contract(build_probe_policy(snapshot))))
        event = await _emit_denial(
            cli=cli,
            policy_path=policy_path,
            state_path=state_path,
            task_id=task_id,
        )

    alert = await _wait_for_alert(
        docker=docker,
        manager=manager,
        trace_id=event.trace_id,
        timeout_seconds=timeout_seconds,
    )
    return LiveProbeResult(
        task_id=task_id,
        trace_id=event.trace_id,
        rule_id=alert.rule_id,
        rule_level=alert.rule_level,
        agent_id=alert.agent_id,
        agent_name=alert.agent_name,
    )


async def _collect_lab_snapshot() -> ToolsetSnapshot:
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "lab.server"],
        cwd=lab.REPOSITORY_ROOT,
    )
    with anyio.fail_after(30):
        async with (
            stdio_client(parameters) as streams,
            ClientSession(*streams) as session,
        ):
            await session.initialize()
            return await collect_toolset(session, SERVER_ID)


async def _emit_denial(
    *,
    cli: str,
    policy_path: Path,
    state_path: Path,
    task_id: str,
) -> AuditEventV1:
    before_size = lab.EVENTS_PATH.stat().st_size
    parameters = StdioServerParameters(
        command=cli,
        args=[
            "enforce",
            "--policy",
            str(policy_path),
            "--task-id",
            task_id,
            "--agent-id",
            "wazuh-live-probe",
            "--audit-log",
            str(lab.EVENTS_PATH),
            "--state-database",
            str(state_path),
            "--cwd",
            str(lab.REPOSITORY_ROOT),
            "--",
            sys.executable,
            "-m",
            "lab.server",
        ],
        cwd=lab.REPOSITORY_ROOT,
    )
    with anyio.fail_after(30):
        async with (
            stdio_client(parameters) as streams,
            ClientSession(*streams) as session,
        ):
            await session.initialize()
            visible = await session.list_tools()
            if visible.tools:
                raise RuntimeError("all-deny live-probe policy exposed a tool")
            denied = await session.call_tool("simulated_credential_read", {})
            if denied.isError is not True or denied.structuredContent != {
                "reason_code": "MCP_PRIVPROF_POLICY_DENY"
            }:
                raise RuntimeError("live-probe credential request was not denied exactly")

    with lab.EVENTS_PATH.open("rb") as audit_file:
        audit_file.seek(before_size)
        new_lines = audit_file.read().splitlines()
    events = tuple(AuditEventV1.model_validate_json(line) for line in new_lines if line)
    matches = tuple(
        event
        for event in events
        if event.task_id == task_id
        and event.event_type == "policy_decision"
        and event.tool_name == "simulated_credential_read"
    )
    if len(matches) != 1:
        raise RuntimeError(f"expected one new live-probe audit event, found {len(matches)}")
    event = matches[0]
    if (
        event.decision != "denied"
        or event.reason_code != "MCP_PRIVPROF_POLICY_DENY"
        or event.primary_risk_category != "credential_access"
    ):
        raise RuntimeError("live-probe audit event did not contain the expected safe facts")
    return event


async def _wait_for_alert(
    *,
    docker: str,
    manager: str,
    trace_id: str,
    timeout_seconds: float,
) -> ObservedAlert:
    deadline = monotonic() + timeout_seconds
    while monotonic() < deadline:
        for alert in _recent_alerts(docker, manager):
            if (
                alert.trace_id == trace_id
                and alert.rule_id == EXPECTED_RULE_ID
                and alert.rule_level == EXPECTED_LEVEL
                and alert.agent_id == "001"
                and alert.agent_name == "mcp-privprof-lab"
            ):
                return alert
        await anyio.sleep(1)
    raise RuntimeError(
        f"Wazuh did not produce rule {EXPECTED_RULE_ID} for trace {trace_id} "
        f"within {timeout_seconds:g} seconds"
    )


def _recent_alerts(docker: str, manager: str) -> tuple[ObservedAlert, ...]:
    completed = subprocess.run(
        (docker, "exec", manager, "tail", "-n", "500", ALERT_PATH),
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise RuntimeError(f"could not read Wazuh manager alerts: {detail}")
    alerts: list[ObservedAlert] = []
    for line in completed.stdout.splitlines():
        try:
            value = cast(JsonValue, json.loads(line))
        except json.JSONDecodeError:
            continue
        if not isinstance(value, dict):
            continue
        data = value.get("data")
        rule = value.get("rule")
        agent = value.get("agent")
        if not isinstance(data, dict) or not isinstance(rule, dict) or not isinstance(agent, dict):
            continue
        trace_id = data.get("trace_id")
        rule_id = rule.get("id")
        rule_level = rule.get("level")
        agent_id = agent.get("id")
        agent_name = agent.get("name")
        if (
            not isinstance(trace_id, str)
            or not isinstance(rule_id, str)
            or type(rule_level) is not int
            or not isinstance(agent_id, str)
            or not isinstance(agent_name, str)
        ):
            continue
        alerts.append(
            ObservedAlert(
                trace_id=trace_id,
                rule_id=rule_id,
                rule_level=rule_level,
                agent_id=agent_id,
                agent_name=agent_name,
            )
        )
    return tuple(alerts)


def _running_manager(docker: str) -> str:
    completed = subprocess.run(
        (
            docker,
            "ps",
            "--filter",
            f"label=com.docker.compose.project={lab.PROJECT_NAME}",
            "--filter",
            f"label=com.docker.compose.service={MANAGER_SERVICE}",
            "--format",
            "{{.ID}}",
        ),
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    manager_ids = tuple(line for line in completed.stdout.splitlines() if line)
    if completed.returncode != 0 or len(manager_ids) != 1:
        raise RuntimeError("the pinned Wazuh manager is not running exactly once")
    return manager_ids[0]


def _require_active_lab_agent(docker: str, manager: str) -> None:
    completed = subprocess.run(
        (docker, "exec", manager, "/var/ossec/bin/agent_control", "-lc"),
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    if completed.returncode != 0 or "001, Name: mcp-privprof-lab, IP: any, Active" not in (
        completed.stdout
    ):
        raise RuntimeError("the isolated mcp-privprof-lab Wazuh agent is not active")


def _require_executable(name: str) -> str:
    executable = shutil.which(name)
    if executable is None:
        raise RuntimeError(f"required executable is not installed: {name}")
    return executable


def _require_cli() -> str:
    executable = shutil.which("mcp-privprof")
    if executable is not None:
        return executable
    suffix = "Scripts/mcp-privprof.exe" if sys.platform == "win32" else "bin/mcp-privprof"
    candidate = lab.REPOSITORY_ROOT / ".venv" / suffix
    if not candidate.is_file():
        raise RuntimeError(
            "mcp-privprof console command is not installed in the project environment"
        )
    return str(candidate)


def main() -> int:
    """Run the bounded live probe and print only non-sensitive evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="seconds to wait for the exact Wazuh alert (default: 30)",
    )
    args = parser.parse_args()
    try:
        result = anyio.run(partial(run_live_probe, timeout_seconds=args.timeout))
    except Exception as exc:
        print(f"Wazuh live probe failed: {exc}", file=sys.stderr)
        return 1
    print("Wazuh live proxy-to-alert probe passed.")
    print(f"Task: {result.task_id}")
    print(f"Trace: {result.trace_id}")
    print(f"Alert: rule {result.rule_id}, level {result.rule_level}")
    print(f"Source agent: {result.agent_id} ({result.agent_name})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
