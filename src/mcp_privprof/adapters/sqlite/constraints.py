"""Deterministic internal SQLite codec for reviewed policy constraints."""

from __future__ import annotations

import json
from typing import cast

from mcp_privprof.domain.constraints import (
    EnumConstraint,
    MaxUtf8BytesConstraint,
    PathConstraint,
    PolicyConstraint,
    UrlConstraint,
)

type JsonScalar = bool | int | float | str | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]


def encode_constraints(constraints: tuple[PolicyConstraint, ...]) -> bytes:
    """Serialize already-validated constraints with stable key ordering."""
    document = [_constraint_document(constraint) for constraint in constraints]
    return json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def decode_constraints(payload: object) -> tuple[PolicyConstraint, ...]:
    """Reload stored constraints and reapply every domain invariant."""
    if not isinstance(payload, bytes):
        raise RuntimeError("stored constraint JSON must be bytes")
    try:
        document = cast(JsonValue, json.loads(payload))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("stored constraint JSON is invalid") from exc
    if not isinstance(document, list):
        raise RuntimeError("stored constraints must be a JSON array")
    return tuple(_constraint_domain(item) for item in document)


def _constraint_document(constraint: PolicyConstraint) -> dict[str, JsonValue]:
    if isinstance(constraint, PathConstraint):
        return {
            "kind": "path",
            "argument": constraint.argument,
            "path_roots": list(constraint.path_roots),
        }
    if isinstance(constraint, UrlConstraint):
        return {
            "kind": "url",
            "argument": constraint.argument,
            "schemes": list(constraint.schemes),
            "hosts": list(constraint.hosts),
        }
    if isinstance(constraint, EnumConstraint):
        return {
            "kind": "enum",
            "argument": constraint.argument,
            "values": list(constraint.values),
        }
    return {
        "kind": "max_utf8_bytes",
        "argument": constraint.argument,
        "maximum": constraint.maximum,
    }


def _constraint_domain(value: JsonValue) -> PolicyConstraint:
    if not isinstance(value, dict):
        raise RuntimeError("stored constraint entry must be an object")
    kind = value.get("kind")
    argument = value.get("argument")
    if not isinstance(kind, str) or not isinstance(argument, str):
        raise RuntimeError("stored constraint kind and argument must be strings")
    if kind == "path":
        _require_keys(value, {"kind", "argument", "path_roots"})
        return PathConstraint(argument=argument, path_roots=_string_tuple(value["path_roots"]))
    if kind == "url":
        _require_keys(value, {"kind", "argument", "schemes", "hosts"})
        return UrlConstraint(
            argument=argument,
            schemes=_string_tuple(value["schemes"]),
            hosts=_string_tuple(value["hosts"]),
        )
    if kind == "enum":
        _require_keys(value, {"kind", "argument", "values"})
        raw_values = value["values"]
        if not isinstance(raw_values, list) or any(
            type(item) not in (int, str) for item in raw_values
        ):
            raise RuntimeError("stored enum values must be integers or strings")
        return EnumConstraint(
            argument=argument, values=tuple(cast(int | str, item) for item in raw_values)
        )
    if kind == "max_utf8_bytes":
        _require_keys(value, {"kind", "argument", "maximum"})
        maximum = value["maximum"]
        if type(maximum) is not int:
            raise RuntimeError("stored maximum must be an integer")
        return MaxUtf8BytesConstraint(argument=argument, maximum=maximum)
    raise RuntimeError("stored constraint kind is unsupported")


def _string_tuple(value: JsonValue) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise RuntimeError("stored constraint allowlist must contain strings")
    return tuple(cast(str, item) for item in value)


def _require_keys(value: dict[str, JsonValue], expected: set[str]) -> None:
    if set(value) != expected:
        raise RuntimeError("stored constraint contains missing or unknown fields")
