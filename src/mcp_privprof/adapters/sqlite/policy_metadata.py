"""Strict SQLite codecs for reviewed limit and risk metadata."""

from __future__ import annotations

import json
from typing import cast

from mcp_privprof.domain.limits import ToolLimits

type JsonScalar = bool | int | float | str | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]


def encode_limits(limits: ToolLimits | None) -> bytes:
    """Encode exact reviewed limits, preserving a distinct absent value."""
    document = (
        None
        if limits is None
        else {
            "max_calls_per_minute": limits.max_calls_per_minute,
            "max_calls_per_task": limits.max_calls_per_task,
            "max_concurrent_calls": limits.max_concurrent_calls,
        }
    )
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode()


def decode_limits(payload: object) -> ToolLimits | None:
    """Decode stored limits and reapply domain invariants."""
    document = _json_payload(payload, "stored limits")
    if document is None:
        return None
    if not isinstance(document, dict) or set(document) != {
        "max_calls_per_minute",
        "max_calls_per_task",
        "max_concurrent_calls",
    }:
        raise RuntimeError("stored limits contain missing or unknown fields")
    values = tuple(document[key] for key in sorted(document))
    if any(type(value) is not int for value in values):
        raise RuntimeError("stored limits must be integers")
    return ToolLimits(
        max_calls_per_minute=cast(int, document["max_calls_per_minute"]),
        max_calls_per_task=cast(int, document["max_calls_per_task"]),
        max_concurrent_calls=cast(int, document["max_concurrent_calls"]),
    )


def encode_capability_tags(tags: tuple[str, ...]) -> bytes:
    """Encode validated scalar tags deterministically."""
    return json.dumps(list(tags), separators=(",", ":")).encode()


def decode_capability_tags(payload: object) -> tuple[str, ...]:
    """Decode stored scalar tags without accepting coercion."""
    document = _json_payload(payload, "stored capability tags")
    if not isinstance(document, list) or any(not isinstance(item, str) for item in document):
        raise RuntimeError("stored capability tags must be a string array")
    return tuple(cast(str, item) for item in document)


def _json_payload(payload: object, label: str) -> JsonValue:
    if not isinstance(payload, bytes):
        raise RuntimeError(f"{label} JSON must be bytes")
    try:
        return cast(JsonValue, json.loads(payload))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{label} JSON is invalid") from exc
