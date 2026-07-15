"""Versioned public contract for inventory and drift reports."""

from __future__ import annotations

from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, JsonValue, model_validator

type DriftSeverityName = Literal[
    "informational",
    "review_required",
    "security_widening",
    "breaking",
]

_SEVERITY_ORDER: dict[str, int] = {
    "informational": 1,
    "review_required": 2,
    "security_widening": 3,
    "breaking": 4,
}


class InventoryToolV1(BaseModel):
    """One complete known MCP Tool definition and its stable identity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    fingerprint: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    definition: dict[str, JsonValue]

    @model_validator(mode="after")
    def definition_name_matches_identity(self) -> InventoryToolV1:
        """Prevent a report label from disagreeing with its complete definition."""
        if self.definition.get("name") != self.name:
            raise ValueError("definition name must match inventory tool name")
        return self


class InventoryDriftChangeV1(BaseModel):
    """One human-readable, conservatively classified catalog change."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_name: str = Field(min_length=1)
    kind: Literal["added", "removed", "modified"]
    severity: DriftSeverityName
    changed_fields: tuple[str, ...] = ()


class InventoryDriftV1(BaseModel):
    """Comparison with the immediately preceding stored observation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    previous_snapshot_id: int = Field(ge=1)
    previous_fingerprint: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    current_fingerprint: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    changed: bool
    maximum_severity: DriftSeverityName | None
    changes: tuple[InventoryDriftChangeV1, ...] = ()

    @model_validator(mode="after")
    def change_summary_is_consistent(self) -> InventoryDriftV1:
        """Keep summary booleans and severity aligned with detailed changes."""
        if self.changed != bool(self.changes):
            raise ValueError("changed must match whether drift changes are present")
        if self.changed != (self.maximum_severity is not None):
            raise ValueError("maximum_severity must be present exactly when drift changed")
        if self.changes:
            expected = max(
                (change.severity for change in self.changes),
                key=_SEVERITY_ORDER.__getitem__,
            )
            if self.maximum_severity != expected:
                raise ValueError("maximum_severity must match the strongest drift change")
        return self


class InventoryReportV1(BaseModel):
    """A complete machine-readable inventory observation report."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    report_schema_version: Literal["1.0"] = "1.0"
    generated_at: AwareDatetime
    snapshot_id: int = Field(ge=1)
    captured_at: AwareDatetime
    server_id: str = Field(min_length=1)
    toolset_fingerprint: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    tool_count: int = Field(ge=0)
    tools: tuple[InventoryToolV1, ...] = ()
    drift: InventoryDriftV1 | None

    @model_validator(mode="after")
    def tool_summary_is_consistent(self) -> InventoryReportV1:
        """Require sorted, unique tools and an exact count."""
        names = [tool.name for tool in self.tools]
        if self.tool_count != len(self.tools):
            raise ValueError("tool_count must match tools")
        if names != sorted(names):
            raise ValueError("inventory report tools must be sorted by name")
        if len(names) != len(set(names)):
            raise ValueError("inventory report tools must not contain duplicate names")
        return self
