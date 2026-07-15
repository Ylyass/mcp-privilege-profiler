"""Constraint conversion, launch binding, and exact in-memory evaluation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from re import fullmatch
from urllib.parse import urlsplit

from mcp_privprof.contracts.constraints import (
    ConstraintV1,
    EnumConstraintV1,
    MaxUtf8BytesConstraintV1,
    PathConstraintV1,
    UrlConstraintV1,
)
from mcp_privprof.domain.constraints import (
    EnumConstraint,
    MaxUtf8BytesConstraint,
    PathConstraint,
    PolicyConstraint,
    UrlConstraint,
    constraint_kind,
    normalize_host,
    normalize_scheme,
)

_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}


@dataclass(frozen=True, slots=True)
class ConstraintCheck:
    """One stable allow or denial result without the rejected value."""

    allowed: bool
    reason_code: str
    constraint_kind: str | None = None
    argument_name: str | None = None


def constraint_contract(constraint: PolicyConstraint) -> ConstraintV1:
    """Convert one domain constraint to its public versioned contract."""
    if isinstance(constraint, PathConstraint):
        return PathConstraintV1(
            kind="path",
            argument=constraint.argument,
            path_roots=constraint.path_roots,
        )
    if isinstance(constraint, UrlConstraint):
        return UrlConstraintV1(
            kind="url",
            argument=constraint.argument,
            schemes=constraint.schemes,
            hosts=constraint.hosts,
        )
    if isinstance(constraint, EnumConstraint):
        return EnumConstraintV1(
            kind="enum",
            argument=constraint.argument,
            values=constraint.values,
        )
    return MaxUtf8BytesConstraintV1(
        kind="max_utf8_bytes",
        argument=constraint.argument,
        maximum=constraint.maximum,
    )


def constraint_domain(constraint: ConstraintV1) -> PolicyConstraint:
    """Convert one validated public contract to a domain constraint."""
    if isinstance(constraint, PathConstraintV1):
        return PathConstraint(
            argument=constraint.argument,
            path_roots=constraint.path_roots,
        )
    if isinstance(constraint, UrlConstraintV1):
        return UrlConstraint(
            argument=constraint.argument,
            schemes=constraint.schemes,
            hosts=constraint.hosts,
        )
    if isinstance(constraint, EnumConstraintV1):
        return EnumConstraint(
            argument=constraint.argument,
            values=constraint.values,
        )
    return MaxUtf8BytesConstraint(
        argument=constraint.argument,
        maximum=constraint.maximum,
    )


def prepare_path_roots(bindings: tuple[tuple[str, Path], ...]) -> dict[str, Path]:
    """Resolve trusted symbolic root bindings once at enforce-mode startup."""
    aliases = [alias for alias, _ in bindings]
    if len(aliases) != len(set(aliases)):
        raise ValueError("path root aliases must not be duplicated")
    roots: dict[str, Path] = {}
    for alias, raw_path in bindings:
        if fullmatch(r"[A-Z][A-Z0-9_]{0,63}", alias) is None:
            raise ValueError(
                "path root aliases must use uppercase letters, digits, and underscores"
            )
        resolved = raw_path.resolve(strict=True)
        if not resolved.is_dir():
            raise ValueError(f"path root {alias} must identify an existing directory")
        roots[alias] = resolved
    return roots


def validate_path_root_coverage(
    constraints: tuple[PolicyConstraint, ...],
    path_roots: Mapping[str, Path],
) -> None:
    """Fail startup when a reviewed symbolic root has no trusted binding."""
    referenced = {
        alias
        for constraint in constraints
        if isinstance(constraint, PathConstraint)
        for alias in constraint.path_roots
    }
    missing = sorted(referenced - path_roots.keys())
    if missing:
        raise ValueError(f"unconfigured policy path roots: {', '.join(missing)}")


def evaluate_constraints(
    constraints: tuple[PolicyConstraint, ...],
    arguments: Mapping[str, object],
    path_roots: Mapping[str, Path],
) -> ConstraintCheck:
    """Evaluate every exact reviewed constraint without retaining argument values."""
    for constraint in constraints:
        if constraint.argument not in arguments:
            return _denied(constraint, "MCP_PRIVPROF_CONSTRAINT_ARGUMENT_MISSING")
        value = arguments[constraint.argument]
        if isinstance(constraint, PathConstraint):
            reason = _check_path(constraint, value, path_roots)
        elif isinstance(constraint, UrlConstraint):
            reason = _check_url(constraint, value)
        elif isinstance(constraint, EnumConstraint):
            reason = _check_enum(constraint, value)
        else:
            reason = _check_max_utf8_bytes(constraint, value)
        if reason is not None:
            return _denied(constraint, reason)
    return ConstraintCheck(allowed=True, reason_code="CONSTRAINTS_SATISFIED")


def _check_path(
    constraint: PathConstraint,
    value: object,
    roots: Mapping[str, Path],
) -> str | None:
    if not isinstance(value, str) or not value or _contains_control(value):
        return "MCP_PRIVPROF_CONSTRAINT_TYPE_MISMATCH"
    windows_path = PureWindowsPath(value)
    if windows_path.drive and not windows_path.is_absolute():
        return "MCP_PRIVPROF_CONSTRAINT_PATH_OUTSIDE_ROOT"
    parts = tuple(part for part in windows_path.parts if part not in (windows_path.anchor, "\\"))
    if any(
        part.endswith((" ", ".")) or _is_windows_reserved(part) or ":" in part for part in parts
    ):
        return "MCP_PRIVPROF_CONSTRAINT_PATH_OUTSIDE_ROOT"

    supplied = Path(value)
    candidate_roots = (
        (None,)
        if supplied.is_absolute()
        else tuple(roots[alias] for alias in constraint.path_roots)
    )
    for root in candidate_roots:
        try:
            candidate = (
                supplied.resolve(strict=False)
                if root is None
                else (root / supplied).resolve(strict=False)
            )
        except (OSError, RuntimeError):
            continue
        allowed_roots = tuple(roots[alias] for alias in constraint.path_roots)
        if any(_is_within(candidate, allowed_root) for allowed_root in allowed_roots):
            return None
    return "MCP_PRIVPROF_CONSTRAINT_PATH_OUTSIDE_ROOT"


def _check_url(constraint: UrlConstraint, value: object) -> str | None:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or _contains_control(value)
    ):
        return "MCP_PRIVPROF_CONSTRAINT_TYPE_MISMATCH"
    if "\\" in value:
        return "MCP_PRIVPROF_CONSTRAINT_URL_NOT_ALLOWED"
    try:
        parsed = urlsplit(value)
        port = parsed.port
        if not parsed.netloc or parsed.hostname is None or "@" in parsed.netloc:
            return "MCP_PRIVPROF_CONSTRAINT_URL_NOT_ALLOWED"
        scheme = normalize_scheme(parsed.scheme)
        host = normalize_host(parsed.hostname)
    except ValueError:
        return "MCP_PRIVPROF_CONSTRAINT_URL_NOT_ALLOWED"
    if scheme not in constraint.schemes or host not in constraint.hosts:
        return "MCP_PRIVPROF_CONSTRAINT_URL_NOT_ALLOWED"
    default_ports = {"http": 80, "https": 443}
    if port is not None and default_ports.get(scheme) != port:
        return "MCP_PRIVPROF_CONSTRAINT_URL_NOT_ALLOWED"
    return None


def _check_enum(constraint: EnumConstraint, value: object) -> str | None:
    if type(value) not in (int, str):
        return "MCP_PRIVPROF_CONSTRAINT_TYPE_MISMATCH"
    if not any(type(value) is type(allowed) and value == allowed for allowed in constraint.values):
        return "MCP_PRIVPROF_CONSTRAINT_ENUM_NOT_ALLOWED"
    return None


def _check_max_utf8_bytes(
    constraint: MaxUtf8BytesConstraint,
    value: object,
) -> str | None:
    if not isinstance(value, str):
        return "MCP_PRIVPROF_CONSTRAINT_TYPE_MISMATCH"
    try:
        length = len(value.encode("utf-8", errors="strict"))
    except UnicodeEncodeError:
        return "MCP_PRIVPROF_CONSTRAINT_TYPE_MISMATCH"
    if length > constraint.maximum:
        return "MCP_PRIVPROF_CONSTRAINT_MAX_UTF8_BYTES_EXCEEDED"
    return None


def _is_within(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


def _contains_control(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _is_windows_reserved(component: str) -> bool:
    stem = component.rstrip(" .").split(".", maxsplit=1)[0].upper()
    return stem in _WINDOWS_RESERVED_NAMES


def _denied(constraint: PolicyConstraint, reason_code: str) -> ConstraintCheck:
    return ConstraintCheck(
        allowed=False,
        reason_code=reason_code,
        constraint_kind=constraint_kind(constraint),
        argument_name=constraint.argument,
    )
