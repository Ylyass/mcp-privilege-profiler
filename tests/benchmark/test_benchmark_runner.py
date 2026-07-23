"""Deterministic benchmark manifest and runner contract tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import mcp.types as types
import pytest

from benchmarks.runner import (
    MINIMUM_COUNTS,
    expanded_calls,
    load_manifest,
    percentile_timings,
    run_drift_cases,
    run_overuse_cases,
    validate_result,
)
from mcp_privprof.adapters.mcp.inventory import CollectedCatalog, snapshot_toolset

ROOT = Path(__file__).parents[2]


@pytest.fixture
def anyio_backend() -> str:
    """Use the supported asyncio backend."""
    return "asyncio"


def test_manifest_meets_exact_release_scenario_minimums() -> None:
    """The tracked suite must preserve its labeled Stage 10 coverage."""
    manifest = load_manifest()
    calls = expanded_calls(manifest)
    legitimate = tuple(item for item in calls if item.category == "legitimate")
    malicious = tuple(item for item in calls if item.category == "malicious")

    assert len(legitimate) == MINIMUM_COUNTS["legitimate"] == 30
    assert len(malicious) == MINIMUM_COUNTS["malicious"] == 30
    assert len({item.case_id for item in calls}) == 60
    assert all(item.expected_decision == "allowed" for item in legitimate)
    assert all(item.expected_decision == "denied" for item in malicious)


def test_nearest_rank_timings_are_deterministic() -> None:
    """Published percentile calculations must not depend on another library."""
    timing = percentile_timings(
        (
            1_000_000,
            2_000_000,
            3_000_000,
            4_000_000,
            5_000_000,
        )
    )

    assert timing == {
        "samples": 5,
        "p50_ms": 3.0,
        "p95_ms": 5.0,
        "p99_ms": 5.0,
    }


def test_every_declared_catalog_mutation_is_detected() -> None:
    """All ten drift labels must exercise the production fingerprint comparator."""
    names = (
        "fetch_fixture_advisory",
        "list_fixture_directory",
        "read_fixture",
        "simulated_command_run",
        "simulated_credential_read",
        "simulated_external_post",
        "write_sandbox_patch",
    )
    tools = tuple(
        types.Tool(
            name=name,
            description=f"Baseline {name}",
            inputSchema={"type": "object", "properties": {}},
        )
        for name in names
    )
    catalog = CollectedCatalog(
        snapshot=snapshot_toolset("benchmark-lab", list(tools)),
        tools=tools,
    )

    cases = run_drift_cases(load_manifest(), catalog)

    assert len(cases) == MINIMUM_COUNTS["drift"] == 10
    assert all(case["passed"] is True for case in cases)


@pytest.mark.anyio
async def test_every_overuse_and_approval_abuse_case_fails_closed(tmp_path: Path) -> None:
    """Limits and exact permits must reject all five declared abuse cases."""
    cases = await run_overuse_cases(load_manifest(), tmp_path)

    assert len(cases) == MINIMUM_COUNTS["overuse"] == 5
    assert all(case["passed"] is True for case in cases)


def test_committed_reference_result_is_clean_and_schema_valid() -> None:
    """Published raw evidence must remain tied to one clean source revision."""
    value: object = json.loads(
        (ROOT / "benchmarks" / "results" / "reference-windows.json").read_text(encoding="utf-8")
    )
    if not isinstance(value, dict):
        raise TypeError("reference benchmark must contain one JSON object")
    result = cast(dict[str, object], value)

    validate_result(result)

    source = result["source_revision"]
    assert isinstance(source, dict)
    assert source["dirty"] is False
    cases = result["cases"]
    assert isinstance(cases, list)
    checked_cases = cast(list[object], cases)
    assert len(checked_cases) == 75
    for case in checked_cases:
        assert isinstance(case, dict)
        checked_case = cast(dict[str, object], case)
        assert checked_case.get("passed") is True
