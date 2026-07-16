"""Privacy and durability tests for mandatory enforcement audit events."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, cast

import pytest
from jsonschema import Draft202012Validator

from mcp_privprof.adapters.audit import JsonlAuditSink
from mcp_privprof.application.audit import (
    EnforcementIdentity,
    argument_facts,
    build_audit_event,
)
from mcp_privprof.contracts.event import AuditEventV1
from mcp_privprof.domain import (
    PolicyEffect,
    PolicyRule,
    ToolIdentity,
    ToolLimits,
    UrlConstraint,
)

NOW = datetime(2026, 7, 16, 12, 0, tzinfo=UTC)
EVENT_SCHEMA = Path(__file__).parents[2] / "schemas" / "event-v1.schema.json"


class _Validator(Protocol):
    def validate(self, instance: object) -> None: ...


@pytest.fixture
def anyio_backend() -> str:
    """Use the project's supported asyncio backend."""
    return "asyncio"


def _event() -> tuple[AuditEventV1, tuple[str, ...]]:
    raw_values = (
        "PRIVATE_TOKEN_91B764",
        "PRIVATE_QUERY_4F2C",
        "PRIVATE_BODY_8E1A",
    )
    rule = PolicyRule(
        identity=ToolIdentity("lab", "fetch_advisory"),
        effect=PolicyEffect.ALLOW,
        constraints=(UrlConstraint("url", ("https",), ("osv.dev",)),),
        limits=ToolLimits(60, 100, 2),
        primary_risk_category="network_read",
        capability_tags=("network", "vulnerability_data"),
    )
    arguments: dict[str, object] = {
        "url": f"https://osv.dev/query?token={raw_values[1]}",
        "api_token": raw_values[0],
        "payload": {"body": raw_values[2]},
    }
    facts = argument_facts(arguments, rule.constraints)
    event = build_audit_event(
        event_type="policy_decision",
        timestamp=NOW,
        trace_id="trace-audit-1",
        identity=EnforcementIdentity("task-1", "agent-1"),
        task_type="dependency-review",
        server_id="lab",
        tool_name="fetch_advisory",
        tool_fingerprint=f"sha256:{'a' * 64}",
        policy_id="policy-1",
        rule=rule,
        effect=PolicyEffect.ALLOW,
        decision="allowed",
        reason_code="MCP_PRIVPROF_POLICY_ALLOW",
        facts=facts,
    )
    return event, raw_values


def test_event_is_schema_valid_and_contains_only_allowlisted_argument_facts() -> None:
    """Safe metadata remains useful without persisting any raw argument value."""
    event, raw_values = _event()
    document = cast(object, event.model_dump(mode="json"))
    validator = cast(
        _Validator,
        Draft202012Validator(json.loads(EVENT_SCHEMA.read_text(encoding="utf-8"))),
    )

    validator.validate(document)
    serialized = json.dumps(document, sort_keys=True)
    assert event.argument_key_names == ("api_token", "payload", "url")
    assert event.url_scheme == "https"
    assert event.url_host == "osv.dev"
    assert event.capability_tags == ("network", "vulnerability_data")
    assert all(raw not in serialized for raw in raw_values)
    assert "raw_arguments" not in serialized
    assert "result" not in serialized


def test_unapproved_url_destination_is_absent_from_audit_metadata() -> None:
    """Rejected attacker-controlled hosts are values, not safe audit metadata."""
    secret_host = "PRIVATE-SUBDOMAIN-91B764.attacker.test"
    constraint = UrlConstraint("url", ("https",), ("osv.dev",))

    facts = argument_facts({"url": f"https://{secret_host}/query"}, (constraint,))

    assert facts.url_scheme is None
    assert facts.url_host is None
    assert secret_host not in repr(facts)


@pytest.mark.anyio
async def test_jsonl_sink_appends_one_complete_event_without_raw_values(tmp_path: Path) -> None:
    """A successful append produces one parseable, privacy-minimized JSON line."""
    path = tmp_path / "audit" / "events.jsonl"
    sink = JsonlAuditSink(path)
    event, raw_values = _event()

    await sink.initialize()
    await sink.append(event)

    records = path.read_text(encoding="utf-8").splitlines()
    assert len(records) == 1
    persisted = json.loads(records[0])
    assert persisted["trace_id"] == "trace-audit-1"
    assert all(raw not in records[0] for raw in raw_values)


@pytest.mark.anyio
async def test_jsonl_sink_rejects_a_directory_destination(tmp_path: Path) -> None:
    """Mandatory audit never treats a directory as a writable event file."""
    destination = tmp_path / "events.jsonl"
    destination.mkdir()

    with pytest.raises(ValueError, match="regular file"):
        await JsonlAuditSink(destination).initialize()


@pytest.mark.anyio
async def test_jsonl_sink_rejects_file_replacement_after_initialization(
    tmp_path: Path,
) -> None:
    """Every append remains bound to the exact regular file opened at startup."""
    path = tmp_path / "events.jsonl"
    displaced = tmp_path / "displaced.jsonl"
    sink = JsonlAuditSink(path)
    event, _ = _event()
    await sink.initialize()
    path.rename(displaced)
    path.touch()

    with pytest.raises(OSError, match="identity changed"):
        await sink.append(event)

    assert path.read_bytes() == b""
