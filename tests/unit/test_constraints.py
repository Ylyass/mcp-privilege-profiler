"""Exact constraint contract, storage, and evaluator tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol, cast

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from mcp_privprof.adapters.sqlite.constraints import decode_constraints, encode_constraints
from mcp_privprof.application.constraints import (
    evaluate_constraints,
    prepare_path_roots,
    validate_path_root_coverage,
)
from mcp_privprof.contracts.policy import PolicyRuleV1
from mcp_privprof.contracts.profile import ReviewDecisionsV1, ReviewDecisionV1
from mcp_privprof.domain.constraints import (
    EnumConstraint,
    MaxUtf8BytesConstraint,
    PathConstraint,
    UrlConstraint,
)
from mcp_privprof.domain.policy import PolicyEffect


class _Validator(Protocol):
    def validate(self, instance: object) -> None: ...


def test_path_constraint_allows_unicode_inside_bound_root(tmp_path: Path) -> None:
    """A normal Unicode relative path remains usable within its trusted root."""
    roots = prepare_path_roots((("PROJECT_ROOT", tmp_path),))
    constraint = PathConstraint(argument="relative_path", path_roots=("PROJECT_ROOT",))

    check = evaluate_constraints(
        (constraint,),
        {"relative_path": "données/安全.txt"},
        roots,
    )

    assert check.allowed


@pytest.mark.parametrize(
    "value",
    [
        "../outside.txt",
        "C:drive-relative.txt",
        "CON.txt",
        "folder/trailing. ",
        "folder/name:stream",
    ],
)
def test_path_constraint_denies_portability_and_traversal_edges(
    tmp_path: Path,
    value: str,
) -> None:
    """Traversal and Windows path ambiguities fail closed on every host OS."""
    roots = prepare_path_roots((("PROJECT_ROOT", tmp_path),))
    constraint = PathConstraint(argument="relative_path", path_roots=("PROJECT_ROOT",))

    check = evaluate_constraints((constraint,), {"relative_path": value}, roots)

    assert not check.allowed
    assert check.reason_code == "MCP_PRIVPROF_CONSTRAINT_PATH_OUTSIDE_ROOT"


def test_path_constraint_resolves_symlinks_before_containment(tmp_path: Path) -> None:
    """A link that escapes its reviewed root is denied when the OS supports links."""
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    link = root / "escape"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are not available to this user")
    roots = prepare_path_roots((("PROJECT_ROOT", root),))
    constraint = PathConstraint(argument="relative_path", path_roots=("PROJECT_ROOT",))

    check = evaluate_constraints((constraint,), {"relative_path": "escape/secret.txt"}, roots)

    assert not check.allowed
    assert check.reason_code == "MCP_PRIVPROF_CONSTRAINT_PATH_OUTSIDE_ROOT"


@pytest.mark.parametrize(
    ("url", "allowed"),
    [
        ("https://OSV.DEV/v1/query", True),
        ("https://osv.dev.:443/v1/query", True),
        ("http://osv.dev/v1/query", False),
        ("https://osv.dev.evil.example/v1/query", False),
        ("https://user@osv.dev/v1/query", False),
        ("https://@osv.dev/v1/query", False),
        ("https://osv.dev:444/v1/query", False),
        ("https://127.1/v1/query", False),
        ("https://osv.dev\\@evil.example/v1/query", False),
    ],
)
def test_url_constraint_uses_normalized_exact_scheme_host_and_default_port(
    url: str,
    allowed: bool,
) -> None:
    """URL parsing cannot turn suffix, user-info, port, or slash tricks into access."""
    constraint = UrlConstraint(argument="url", schemes=("https",), hosts=("osv.dev",))

    check = evaluate_constraints((constraint,), {"url": url}, {})

    assert check.allowed is allowed
    if not allowed:
        assert check.reason_code == "MCP_PRIVPROF_CONSTRAINT_URL_NOT_ALLOWED"


def test_url_constraint_normalizes_internationalized_host() -> None:
    """Unicode and ASCII IDNA spellings compare as one host identity."""
    constraint = UrlConstraint(argument="url", schemes=("https",), hosts=("bücher.example",))

    check = evaluate_constraints(
        (constraint,),
        {"url": "https://xn--bcher-kva.example/catalog"},
        {},
    )

    assert check.allowed


def test_enum_constraint_keeps_integer_and_boolean_types_distinct() -> None:
    """Python's bool-is-int relationship cannot bypass an exact enum."""
    constraint = EnumConstraint(argument="mode", values=(1, "safe"))

    integer = evaluate_constraints((constraint,), {"mode": 1}, {})
    boolean = evaluate_constraints((constraint,), {"mode": True}, {})

    assert integer.allowed
    assert not boolean.allowed
    assert boolean.reason_code == "MCP_PRIVPROF_CONSTRAINT_TYPE_MISMATCH"


def test_max_utf8_bytes_counts_encoded_bytes_not_characters() -> None:
    """A multibyte Unicode string is bounded by wire-relevant UTF-8 size."""
    constraint = MaxUtf8BytesConstraint(argument="content", maximum=4)

    exact = evaluate_constraints((constraint,), {"content": "éé"}, {})
    oversized = evaluate_constraints((constraint,), {"content": "ééé"}, {})

    assert exact.allowed
    assert not oversized.allowed
    assert oversized.reason_code == "MCP_PRIVPROF_CONSTRAINT_MAX_UTF8_BYTES_EXCEEDED"


def test_missing_argument_error_contains_identity_but_not_value() -> None:
    """Machine-readable denials identify the rule without retaining input data."""
    constraint = EnumConstraint(argument="mode", values=("safe",))

    check = evaluate_constraints((constraint,), {}, {})

    assert check.reason_code == "MCP_PRIVPROF_CONSTRAINT_ARGUMENT_MISSING"
    assert check.constraint_kind == "enum"
    assert check.argument_name == "mode"


def test_startup_requires_every_symbolic_path_root(tmp_path: Path) -> None:
    """An unbound reviewed alias is a startup error, never an implicit directory."""
    constraint = PathConstraint(argument="path", path_roots=("PROJECT_ROOT",))

    with pytest.raises(ValueError, match="PROJECT_ROOT"):
        validate_path_root_coverage((constraint,), {})

    validate_path_root_coverage(
        (constraint,),
        prepare_path_roots((("PROJECT_ROOT", tmp_path),)),
    )


def test_constraint_storage_codec_is_deterministic_and_round_trips() -> None:
    """SQLite stores only the reviewed constraint document, in stable order."""
    constraints = (
        UrlConstraint(argument="url", schemes=("https",), hosts=("osv.dev",)),
        MaxUtf8BytesConstraint(argument="content", maximum=4096),
    )

    encoded = encode_constraints(constraints)

    assert encode_constraints(decode_constraints(encoded)) == encoded
    assert b"osv.dev" in encoded


def test_contract_rejects_constraints_on_deny_and_strict_boolean_values() -> None:
    """Untrusted JSON cannot widen DENY or coerce booleans into integer limits."""
    path = {"kind": "path", "argument": "path", "path_roots": ["PROJECT_ROOT"]}
    with pytest.raises(ValidationError):
        PolicyRuleV1.model_validate(
            {"tool_name": "read", "effect": PolicyEffect.DENY, "constraints": [path]}
        )
    with pytest.raises(ValidationError):
        PolicyRuleV1.model_validate(
            {
                "tool_name": "write",
                "effect": "ALLOW",
                "constraints": [
                    {
                        "kind": "max_utf8_bytes",
                        "argument": "content",
                        "maximum": True,
                    }
                ],
            }
        )


def test_review_constraint_document_validates_public_json_schema() -> None:
    """The executable review contract and published schema accept the same shape."""
    review = ReviewDecisionsV1.model_validate(
        {
            "review_schema_version": "1.0",
            "profile_id": "profile-1",
            "evidence_fingerprint": "sha256:" + "f" * 64,
            "decisions": [
                {
                    "tool_name": "read_fixture",
                    "effect": "ALLOW",
                    "constraints": [
                        {
                            "kind": "path",
                            "argument": "relative_path",
                            "path_roots": ["PROJECT_ROOT"],
                        }
                    ],
                }
            ],
        }
    )
    schema_path = Path(__file__).parents[2] / "schemas" / "review-decisions-v1.schema.json"
    validator = cast(
        _Validator,
        Draft202012Validator(json.loads(schema_path.read_text(encoding="utf-8"))),
    )

    validator.validate(review.model_dump(mode="json"))
    assert isinstance(review.decisions[0], ReviewDecisionV1)
