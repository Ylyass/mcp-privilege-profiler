"""Immutable inventory and drift facts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from hashlib import sha256
from re import fullmatch
from typing import cast

type JsonScalar = bool | int | float | str | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]


@dataclass(frozen=True, slots=True)
class ToolSnapshot:
    """One complete Tool definition in canonical JSON form."""

    name: str
    fingerprint: str
    canonical_json: bytes

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("tool name must not be empty")
        _validate_fingerprint(self.fingerprint, "tool fingerprint")
        expected = f"sha256:{sha256(self.canonical_json).hexdigest()}"
        if self.fingerprint != expected:
            raise ValueError("tool fingerprint does not match canonical JSON")
        try:
            document = cast(JsonValue, json.loads(self.canonical_json))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("tool canonical JSON must be valid UTF-8 JSON") from exc
        if not isinstance(document, dict) or document.get("name") != self.name:
            raise ValueError("tool canonical JSON name does not match snapshot name")


@dataclass(frozen=True, slots=True)
class ToolsetSnapshot:
    """A deterministic complete catalog snapshot for one server."""

    server_id: str
    fingerprint: str
    tools: tuple[ToolSnapshot, ...]

    def __post_init__(self) -> None:
        if not self.server_id:
            raise ValueError("server_id must not be empty")
        _validate_fingerprint(self.fingerprint, "toolset fingerprint")
        names = [tool.name for tool in self.tools]
        if names != sorted(names):
            raise ValueError("tool snapshots must be sorted by name")
        if len(names) != len(set(names)):
            raise ValueError("tool snapshot contains duplicate names")


@dataclass(frozen=True, slots=True)
class StoredToolsetSnapshot:
    """A catalog snapshot together with its durable observation identity."""

    snapshot_id: int
    captured_at: datetime
    snapshot: ToolsetSnapshot

    def __post_init__(self) -> None:
        if self.snapshot_id <= 0:
            raise ValueError("snapshot_id must be positive")
        if self.captured_at.tzinfo is None or self.captured_at.utcoffset() is None:
            raise ValueError("captured_at must include a timezone")
        object.__setattr__(self, "captured_at", self.captured_at.astimezone(UTC))


class DriftSeverity(IntEnum):
    """Ordered severity for catalog changes."""

    INFORMATIONAL = 1
    REVIEW_REQUIRED = 2
    SECURITY_WIDENING = 3
    BREAKING = 4


class DriftKind(StrEnum):
    """Stable drift categories used by reports and later audit events."""

    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"


@dataclass(frozen=True, slots=True)
class DriftChange:
    """One changed tool and its conservative classification."""

    tool_name: str
    kind: DriftKind
    severity: DriftSeverity
    changed_fields: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DriftReport:
    """Difference between a previous and current toolset."""

    previous_fingerprint: str
    current_fingerprint: str
    changes: tuple[DriftChange, ...]

    @property
    def changed(self) -> bool:
        """Return whether any catalog change exists."""
        return bool(self.changes)

    @property
    def maximum_severity(self) -> DriftSeverity | None:
        """Return the strongest observed classification."""
        if not self.changes:
            return None
        return max(change.severity for change in self.changes)


def compare_toolsets(
    previous: ToolsetSnapshot,
    current: ToolsetSnapshot,
) -> DriftReport:
    """Compare two snapshots using conservative top-level field rules."""
    if previous.server_id != current.server_id:
        raise ValueError("cannot compare snapshots from different servers")

    previous_by_name = {tool.name: tool for tool in previous.tools}
    current_by_name = {tool.name: tool for tool in current.tools}
    changes: list[DriftChange] = []

    for name in sorted(previous_by_name.keys() - current_by_name.keys()):
        changes.append(
            DriftChange(
                tool_name=name,
                kind=DriftKind.REMOVED,
                severity=DriftSeverity.BREAKING,
            )
        )

    for name in sorted(current_by_name.keys() - previous_by_name.keys()):
        changes.append(
            DriftChange(
                tool_name=name,
                kind=DriftKind.ADDED,
                severity=DriftSeverity.SECURITY_WIDENING,
            )
        )

    for name in sorted(previous_by_name.keys() & current_by_name.keys()):
        old = previous_by_name[name]
        new = current_by_name[name]
        if old.fingerprint == new.fingerprint:
            continue
        changed_fields = _changed_top_level_fields(old, new)
        changes.append(
            DriftChange(
                tool_name=name,
                kind=DriftKind.MODIFIED,
                severity=_classify_fields(changed_fields),
                changed_fields=changed_fields,
            )
        )

    return DriftReport(
        previous_fingerprint=previous.fingerprint,
        current_fingerprint=current.fingerprint,
        changes=tuple(changes),
    )


def _changed_top_level_fields(
    previous: ToolSnapshot,
    current: ToolSnapshot,
) -> tuple[str, ...]:
    old_document = cast(JsonValue, json.loads(previous.canonical_json))
    new_document = cast(JsonValue, json.loads(current.canonical_json))
    if not isinstance(old_document, dict) or not isinstance(new_document, dict):
        raise ValueError("tool canonical JSON must contain an object")
    fields = old_document.keys() | new_document.keys()
    return tuple(
        sorted(field for field in fields if old_document.get(field) != new_document.get(field))
    )


def _classify_fields(changed_fields: tuple[str, ...]) -> DriftSeverity:
    fields = set(changed_fields)
    if fields and fields <= {"title", "description", "icons"}:
        return DriftSeverity.INFORMATIONAL
    if "inputSchema" in fields:
        # Semantic widening is difficult to prove safely. Any input contract
        # change therefore requires the strongest re-review in v0.1.
        return DriftSeverity.SECURITY_WIDENING
    return DriftSeverity.REVIEW_REQUIRED


def _validate_fingerprint(value: str, label: str) -> None:
    if fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 fingerprint")
