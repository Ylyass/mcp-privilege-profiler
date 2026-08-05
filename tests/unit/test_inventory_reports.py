"""Versioned JSON and human-readable inventory report tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, cast

import mcp.types as types
import pytest
from jsonschema import Draft202012Validator, FormatChecker
from pydantic import ValidationError

from mcp_privprof.adapters.mcp.inventory import snapshot_toolset
from mcp_privprof.application import InventoryRefresh
from mcp_privprof.application.reports import (
    build_inventory_report,
    render_inventory_json,
    render_inventory_markdown,
)
from mcp_privprof.contracts.inventory import InventoryDriftChangeV1, InventoryDriftV1
from mcp_privprof.domain import StoredToolsetSnapshot, compare_toolsets

SCHEMA_PATH = Path(__file__).parents[2] / "schemas" / "inventory-report-v1.schema.json"


class _Validator(Protocol):
    def validate(self, instance: object) -> None:
        """Validate one JSON-compatible instance."""
        ...


def _tool(name: str, *, description: str = "Fixture") -> types.Tool:
    return types.Tool(
        name=name,
        description=description,
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
    )


def _stored(snapshot_id: int, tools: list[types.Tool]) -> StoredToolsetSnapshot:
    return StoredToolsetSnapshot(
        snapshot_id=snapshot_id,
        captured_at=datetime(2026, 7, 15, snapshot_id, tzinfo=UTC),
        snapshot=snapshot_toolset("lab", tools),
    )


def test_first_inventory_report_validates_and_is_deterministic() -> None:
    """The public JSON artifact conforms to its committed schema."""
    current = _stored(1, [_tool("read_fixture")])
    refresh = InventoryRefresh(current=current, previous=None, drift=None)
    generated_at = datetime(2026, 7, 15, 2, tzinfo=UTC)

    report = build_inventory_report(refresh, generated_at=generated_at)
    first = render_inventory_json(report)
    second = render_inventory_json(report)
    document = json.loads(first)
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = cast(
        _Validator,
        Draft202012Validator(schema, format_checker=FormatChecker()),
    )
    validator.validate(document)

    assert first == second
    assert document["drift"] is None
    assert document["tools"][0]["definition"]["name"] == "read_fixture"
    assert first.endswith(b"\n")


def test_drift_report_contains_machine_and_human_explanations() -> None:
    """A changed catalog exposes its conservative reasoning in both formats."""
    previous = _stored(1, [_tool("read_fixture", description="Old")])
    current = _stored(
        2,
        [_tool("read_fixture", description="New"), _tool("new_capability")],
    )
    drift = compare_toolsets(previous.snapshot, current.snapshot)
    report = build_inventory_report(
        InventoryRefresh(current=current, previous=previous, drift=drift),
        generated_at=datetime(2026, 7, 15, 3, tzinfo=UTC),
    )
    markdown = render_inventory_markdown(report)

    assert report.drift is not None
    assert report.drift.maximum_severity == "security_widening"
    assert [change.tool_name for change in report.drift.changes] == [
        "new_capability",
        "read_fixture",
    ]
    assert "Security Widening" in markdown
    assert "new_capability" in markdown
    assert "Complete known MCP Tool definitions" in markdown


def test_markdown_escapes_untrusted_display_text() -> None:
    """Downstream or configured text cannot inject HTML, tables, or headings."""
    current = StoredToolsetSnapshot(
        snapshot_id=1,
        captured_at=datetime(2026, 7, 15, tzinfo=UTC),
        snapshot=snapshot_toolset("<script>|server\n# heading", [_tool("read_fixture")]),
    )
    report = build_inventory_report(
        InventoryRefresh(current=current, previous=None, drift=None),
        generated_at=datetime(2026, 7, 15, tzinfo=UTC),
    )

    markdown = render_inventory_markdown(report)

    assert "<script>" not in markdown
    assert "&lt;script&gt;&#124;server # heading" in markdown


def test_drift_contract_rejects_an_understated_maximum_severity() -> None:
    """A report summary cannot hide a stronger detailed classification."""
    fingerprint = f"sha256:{'a' * 64}"

    with pytest.raises(ValidationError, match="strongest drift change"):
        InventoryDriftV1(
            previous_snapshot_id=1,
            previous_fingerprint=fingerprint,
            current_fingerprint=fingerprint,
            changed=True,
            maximum_severity="informational",
            changes=(
                InventoryDriftChangeV1(
                    tool_name="new_capability",
                    kind="added",
                    severity="security_widening",
                ),
            ),
        )


def test_refresh_fact_rejects_a_previous_snapshot_without_comparison() -> None:
    """Application facts cannot silently omit comparison with their baseline."""
    previous = _stored(1, [_tool("read_fixture")])
    current = _stored(2, [_tool("read_fixture")])

    with pytest.raises(ValueError, match="present together"):
        InventoryRefresh(current=current, previous=previous, drift=None)
