"""Adversarial property invariants for constraint normalization."""

from __future__ import annotations

from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from mcp_privprof.application.constraints import evaluate_constraints, prepare_path_roots
from mcp_privprof.domain.constraints import MaxUtf8BytesConstraint, PathConstraint, UrlConstraint

SAFE_COMPONENT = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cc", "Cs"),
        blacklist_characters="/\\:",
    ),
    min_size=1,
    max_size=20,
).filter(lambda value: value not in (".", "..") and value == value.strip(" ."))
DNS_SUFFIX = st.text(
    alphabet=st.characters(min_codepoint=ord("a"), max_codepoint=ord("z")),
    min_size=1,
    max_size=20,
)


@given(SAFE_COMPONENT, st.integers(min_value=1, max_value=8))
def test_any_parent_traversal_prefix_is_outside_root(
    component: str,
    depth: int,
) -> None:
    """Adding arbitrary parent traversal segments never regains permission."""
    roots = prepare_path_roots((("ROOT", Path.cwd()),))
    constraint = PathConstraint(argument="path", path_roots=("ROOT",))
    value = "/".join([".."] * depth + [component])

    check = evaluate_constraints((constraint,), {"path": value}, roots)

    assert not check.allowed


@given(DNS_SUFFIX)
def test_host_suffix_never_matches_exact_allowed_host(suffix: str) -> None:
    """An attacker-controlled DNS suffix cannot satisfy an exact host rule."""
    constraint = UrlConstraint(argument="url", schemes=("https",), hosts=("osv.dev",))
    url = f"https://osv.dev.{suffix}/query"

    check = evaluate_constraints((constraint,), {"url": url}, {})

    assert not check.allowed


@given(st.text(max_size=100), st.integers(min_value=0, max_value=100))
def test_utf8_limit_matches_strict_encoded_length(value: str, maximum: int) -> None:
    """The byte constraint is equivalent to strict UTF-8 length for valid strings."""
    constraint = MaxUtf8BytesConstraint(argument="content", maximum=maximum)

    check = evaluate_constraints((constraint,), {"content": value}, {})

    try:
        expected = len(value.encode("utf-8", errors="strict")) <= maximum
    except UnicodeEncodeError:
        expected = False
    assert check.allowed is expected
