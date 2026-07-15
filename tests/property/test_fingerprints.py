"""Property invariants for RFC 8785 tool-definition fingerprints."""

from __future__ import annotations

from typing import cast

from hypothesis import given
from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy

from mcp_privprof.application.fingerprints import JsonValue, fingerprint_json

JSON_VALUES = cast(
    SearchStrategy[JsonValue],
    st.recursive(
        st.one_of(
            st.none(),
            st.booleans(),
            st.integers(min_value=-(2**53) + 1, max_value=2**53 - 1),
            st.text(),
        ),
        lambda children: st.one_of(
            st.lists(children, max_size=5),
            st.dictionaries(st.text(min_size=1, max_size=8), children, max_size=5),
        ),
        max_leaves=20,
    ),
)


def reverse_object_keys(value: JsonValue) -> JsonValue:
    """Recursively rebuild every object in reverse insertion order."""
    if isinstance(value, dict):
        return {key: reverse_object_keys(value[key]) for key in reversed(tuple(value.keys()))}
    if isinstance(value, list):
        return [reverse_object_keys(item) for item in value]
    return value


@given(JSON_VALUES)
def test_fingerprint_is_invariant_to_recursive_object_key_order(
    document: JsonValue,
) -> None:
    """Object insertion order never creates a different canonical digest."""
    canonical, fingerprint = fingerprint_json(document)
    reordered_canonical, reordered_fingerprint = fingerprint_json(reverse_object_keys(document))

    assert canonical == reordered_canonical
    assert fingerprint == reordered_fingerprint
