"""Exact, non-programmable policy constraint facts."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from re import fullmatch

type EnumValue = int | str


@dataclass(frozen=True, slots=True)
class PathConstraint:
    """Require one string path argument to remain within symbolic roots."""

    argument: str
    path_roots: tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_argument(self.argument)
        if not self.path_roots:
            raise ValueError("path constraint requires at least one path root")
        if len(self.path_roots) != len(set(self.path_roots)):
            raise ValueError("path constraint roots must not contain duplicates")
        if any(fullmatch(r"[A-Z][A-Z0-9_]{0,63}", root) is None for root in self.path_roots):
            raise ValueError(
                "path root aliases must use uppercase letters, digits, and underscores"
            )
        object.__setattr__(self, "path_roots", tuple(sorted(self.path_roots)))


@dataclass(frozen=True, slots=True)
class UrlConstraint:
    """Require one URL argument to use exact normalized schemes and hosts."""

    argument: str
    schemes: tuple[str, ...]
    hosts: tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_argument(self.argument)
        if not self.schemes or not self.hosts:
            raise ValueError("URL constraint requires schemes and hosts")
        normalized_schemes = tuple(normalize_scheme(item) for item in self.schemes)
        normalized_hosts = tuple(normalize_host(item) for item in self.hosts)
        if len(normalized_schemes) != len(set(normalized_schemes)):
            raise ValueError("URL constraint schemes must not contain duplicates")
        if len(normalized_hosts) != len(set(normalized_hosts)):
            raise ValueError("URL constraint hosts must not contain duplicates")
        object.__setattr__(self, "schemes", tuple(sorted(normalized_schemes)))
        object.__setattr__(self, "hosts", tuple(sorted(normalized_hosts)))


@dataclass(frozen=True, slots=True)
class EnumConstraint:
    """Require one argument to equal an explicitly reviewed integer or string."""

    argument: str
    values: tuple[EnumValue, ...]

    def __post_init__(self) -> None:
        _validate_argument(self.argument)
        if not self.values:
            raise ValueError("enum constraint requires at least one value")
        if any(type(value) not in (int, str) for value in self.values):
            raise ValueError("enum constraint values must be exact integers or strings")
        typed_values = [(type(value), value) for value in self.values]
        if len(typed_values) != len(set(typed_values)):
            raise ValueError("enum constraint values must not contain duplicates")


@dataclass(frozen=True, slots=True)
class MaxUtf8BytesConstraint:
    """Bound the UTF-8 byte length of one string argument."""

    argument: str
    maximum: int

    def __post_init__(self) -> None:
        _validate_argument(self.argument)
        if type(self.maximum) is not int or self.maximum < 0:
            raise ValueError("maximum UTF-8 bytes must be a non-negative integer")


type PolicyConstraint = PathConstraint | UrlConstraint | EnumConstraint | MaxUtf8BytesConstraint


def normalize_constraints(
    constraints: tuple[PolicyConstraint, ...],
) -> tuple[PolicyConstraint, ...]:
    """Reject duplicate argument/kind entries and return deterministic order."""
    keys = [(constraint_kind(item), item.argument) for item in constraints]
    if len(keys) != len(set(keys)):
        raise ValueError("constraints must not duplicate an argument and kind")
    return tuple(sorted(constraints, key=lambda item: (item.argument, constraint_kind(item))))


def constraint_kind(constraint: PolicyConstraint) -> str:
    """Return the stable public kind label for one constraint."""
    if isinstance(constraint, PathConstraint):
        return "path"
    if isinstance(constraint, UrlConstraint):
        return "url"
    if isinstance(constraint, EnumConstraint):
        return "enum"
    return "max_utf8_bytes"


def normalize_scheme(value: str) -> str:
    """Return one lowercase RFC 3986 scheme or reject it."""
    normalized = value.lower()
    if value != value.strip() or fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*", value) is None:
        raise ValueError("URL schemes must use RFC 3986 scheme syntax")
    return normalized


def normalize_host(value: str) -> str:
    """Normalize an IP literal or IDNA DNS host for exact comparison."""
    if not value or value != value.strip():
        raise ValueError("URL hosts must not be empty or padded")
    if any(ord(character) < 32 or character in "/\\@%" for character in value):
        raise ValueError("URL hosts contain a forbidden character")
    raw = value[:-1] if value.endswith(".") else value
    if not raw:
        raise ValueError("URL host must not be the DNS root")
    try:
        return ipaddress.ip_address(raw).compressed.lower()
    except ValueError:
        if ":" in raw:
            raise ValueError("invalid IP address host") from None
    if fullmatch(r"[0-9.]+", raw) is not None or raw.lower().startswith("0x"):
        raise ValueError("ambiguous numeric host is not allowed")
    try:
        normalized = raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("URL host is not valid IDNA") from exc
    if len(normalized) > 253:
        raise ValueError("URL host exceeds the DNS length limit")
    labels = normalized.split(".")
    if any(
        not label or len(label) > 63 or fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None
        for label in labels
    ):
        raise ValueError("URL host contains an invalid DNS label")
    return normalized


def _validate_argument(value: str) -> None:
    if not value or value != value.strip() or any(ord(character) < 32 for character in value):
        raise ValueError("constraint argument name must be nonblank and contain no controls")
