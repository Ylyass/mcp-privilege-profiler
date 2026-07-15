"""Deterministic machine and human inventory report generation."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from html import escape
from typing import cast

from pydantic import JsonValue

from mcp_privprof.application.inventory import InventoryRefresh
from mcp_privprof.contracts.inventory import (
    DriftSeverityName,
    InventoryDriftChangeV1,
    InventoryDriftV1,
    InventoryReportV1,
    InventoryToolV1,
)
from mcp_privprof.domain.inventory import DriftSeverity


def build_inventory_report(
    refresh: InventoryRefresh,
    *,
    generated_at: datetime,
) -> InventoryReportV1:
    """Build a validated report from one durable refresh result."""
    if generated_at.tzinfo is None or generated_at.utcoffset() is None:
        raise ValueError("generated_at must include a timezone")
    current = refresh.current
    tools: list[InventoryToolV1] = []
    for snapshot in current.snapshot.tools:
        document = cast(JsonValue, json.loads(snapshot.canonical_json))
        if not isinstance(document, dict):
            raise ValueError("tool canonical JSON must contain an object")
        tools.append(
            InventoryToolV1(
                name=snapshot.name,
                fingerprint=snapshot.fingerprint,
                definition=document,
            )
        )

    drift: InventoryDriftV1 | None = None
    if refresh.previous is not None and refresh.drift is not None:
        drift = InventoryDriftV1(
            previous_snapshot_id=refresh.previous.snapshot_id,
            previous_fingerprint=refresh.drift.previous_fingerprint,
            current_fingerprint=refresh.drift.current_fingerprint,
            changed=refresh.drift.changed,
            maximum_severity=(
                _severity_name(refresh.drift.maximum_severity)
                if refresh.drift.maximum_severity is not None
                else None
            ),
            changes=tuple(
                InventoryDriftChangeV1(
                    tool_name=change.tool_name,
                    kind=change.kind.value,
                    severity=_severity_name(change.severity),
                    changed_fields=change.changed_fields,
                )
                for change in refresh.drift.changes
            ),
        )

    return InventoryReportV1(
        generated_at=generated_at.astimezone(UTC),
        snapshot_id=current.snapshot_id,
        captured_at=current.captured_at,
        server_id=current.snapshot.server_id,
        toolset_fingerprint=current.snapshot.fingerprint,
        tool_count=len(tools),
        tools=tuple(tools),
        drift=drift,
    )


def render_inventory_json(report: InventoryReportV1) -> bytes:
    """Render stable UTF-8 JSON suitable for validation and automation."""
    document = report.model_dump(mode="json")
    return (
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True, separators=(",", ": "))
        + "\n"
    ).encode()


def render_inventory_markdown(report: InventoryReportV1) -> str:
    """Render a concise Markdown summary without trusting downstream text."""
    lines = [
        "# MCP Tool Inventory",
        "",
        f"- Report schema: `{report.report_schema_version}`",
        f"- Server: {_markdown_text(report.server_id)}",
        f"- Snapshot ID: `{report.snapshot_id}`",
        f"- Captured at: `{_timestamp(report.captured_at)}`",
        f"- Toolset fingerprint: `{report.toolset_fingerprint}`",
        f"- Tool count: `{report.tool_count}`",
        "",
        "## Drift from previous observation",
        "",
    ]

    if report.drift is None:
        lines.append("This is the first stored observation, so there is no earlier baseline.")
    elif not report.drift.changed:
        lines.append("No catalog changes were detected.")
    else:
        lines.extend(
            [
                f"Strongest classification: **{_label(report.drift.maximum_severity)}**",
                "",
                "| Tool | Change | Severity | Changed fields |",
                "|---|---|---|---|",
            ]
        )
        lines.extend(
            "| "
            + " | ".join(
                (
                    _markdown_text(change.tool_name),
                    _label(change.kind),
                    _label(change.severity),
                    _markdown_text(", ".join(change.changed_fields) or "—"),
                )
            )
            + " |"
            for change in report.drift.changes
        )

    lines.extend(
        [
            "",
            "## Current tools",
            "",
            "| Tool | Fingerprint |",
            "|---|---|",
        ]
    )
    if report.tools:
        lines.extend(
            f"| {_markdown_text(tool.name)} | `{tool.fingerprint}` |" for tool in report.tools
        )
    else:
        lines.append("| _No tools reported_ | — |")
    lines.extend(
        [
            "",
            "Complete known MCP Tool definitions are available in the accompanying JSON report.",
            "",
        ]
    )
    return "\n".join(lines)


def _severity_name(severity: DriftSeverity) -> DriftSeverityName:
    return cast(DriftSeverityName, severity.name.lower())


def _markdown_text(value: str) -> str:
    return escape(value, quote=True).replace("|", "&#124;").replace("\r", " ").replace("\n", " ")


def _label(value: str | None) -> str:
    return "None" if value is None else value.replace("_", " ").title()


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
