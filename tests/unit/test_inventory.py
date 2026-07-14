"""Deterministic fingerprint and conservative drift tests."""

from __future__ import annotations

import json

import mcp.types as types
import pytest

from mcp_privprof.adapters.mcp.inventory import (
    fingerprint_json,
    snapshot_tool,
    snapshot_toolset,
)
from mcp_privprof.domain import DriftKind, DriftSeverity, compare_toolsets


def tool(
    name: str,
    *,
    description: str = "fixture",
    input_schema: dict[str, object] | None = None,
) -> types.Tool:
    """Create a minimal tool fixture."""
    return types.Tool(
        name=name,
        description=description,
        inputSchema=input_schema
        or {"type": "object", "properties": {}, "additionalProperties": False},
    )


def test_rfc8785_fingerprint_ignores_object_key_order() -> None:
    """The same parsed JSON value has one canonical digest."""
    _, first = fingerprint_json({"b": 2, "a": {"y": 1, "x": True}})
    _, second = fingerprint_json({"a": {"x": True, "y": 1}, "b": 2})

    assert first == second


def test_toolset_fingerprint_ignores_catalog_order() -> None:
    """Server listing order cannot create false drift."""
    first = snapshot_toolset("lab", [tool("b"), tool("a")])
    second = snapshot_toolset("lab", [tool("a"), tool("b")])

    assert first.fingerprint == second.fingerprint
    assert [item.name for item in first.tools] == ["a", "b"]


def test_complete_tool_snapshot_round_trips_known_fields() -> None:
    """The canonical snapshot retains the complete serialized Tool object."""
    original = types.Tool(
        name="read_fixture",
        title="Read fixture",
        description="Read safe fixture data.",
        inputSchema={"type": "object", "properties": {"path": {"type": "string"}}},
        annotations=types.ToolAnnotations(readOnlyHint=True),
    )

    snapshot = snapshot_tool(original)
    document = json.loads(snapshot.canonical_json)

    assert document["name"] == "read_fixture"
    assert document["title"] == "Read fixture"
    assert document["annotations"]["readOnlyHint"] is True
    assert document["inputSchema"]["properties"]["path"]["type"] == "string"


def test_duplicate_tool_names_are_rejected() -> None:
    """A name collision cannot enter an unambiguous policy inventory."""
    with pytest.raises(ValueError, match="duplicate"):
        snapshot_toolset("lab", [tool("same"), tool("same")])


def test_description_only_drift_is_informational() -> None:
    """Presentation-only change does not become schema widening."""
    previous = snapshot_toolset("lab", [tool("read", description="old")])
    current = snapshot_toolset("lab", [tool("read", description="new")])

    report = compare_toolsets(previous, current)

    assert report.maximum_severity is DriftSeverity.INFORMATIONAL
    assert report.changes[0].changed_fields == ("description",)


def test_input_schema_change_is_security_widening() -> None:
    """v0.1 conservatively re-reviews every input contract change."""
    previous = snapshot_toolset("lab", [tool("read")])
    current = snapshot_toolset(
        "lab",
        [
            tool(
                "read",
                input_schema={
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "additionalProperties": False,
                },
            )
        ],
    )

    report = compare_toolsets(previous, current)

    assert report.maximum_severity is DriftSeverity.SECURITY_WIDENING
    assert report.changes[0].changed_fields == ("inputSchema",)


def test_added_and_removed_tools_have_conservative_severity() -> None:
    """Additions widen capability; removals break an approved policy."""
    previous = snapshot_toolset("lab", [tool("old")])
    current = snapshot_toolset("lab", [tool("new")])

    report = compare_toolsets(previous, current)

    assert [(change.kind, change.severity) for change in report.changes] == [
        (DriftKind.REMOVED, DriftSeverity.BREAKING),
        (DriftKind.ADDED, DriftSeverity.SECURITY_WIDENING),
    ]

