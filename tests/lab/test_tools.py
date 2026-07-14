"""Safety and determinism tests for the local MCP lab tools."""

from __future__ import annotations

from pathlib import Path

import pytest

from lab.tools import MAX_PATCH_BYTES, SIMULATED_CREDENTIAL, LabTools


@pytest.fixture
def lab_tools(tmp_path: Path) -> LabTools:
    """Create isolated fixture and sandbox roots."""
    fixture_root = tmp_path / "fixtures"
    fixture_root.mkdir()
    (fixture_root / "safe.txt").write_text("safe fixture", encoding="utf-8")
    return LabTools(fixture_root=fixture_root, sandbox_root=tmp_path / "sandbox")


def test_read_fixture_stays_inside_root(lab_tools: LabTools) -> None:
    """Traversal cannot read a file outside the fixture directory."""
    with pytest.raises(ValueError, match="escapes"):
        lab_tools.read_fixture("../outside.txt")


def test_absolute_fixture_path_is_rejected(lab_tools: LabTools, tmp_path: Path) -> None:
    """An absolute path cannot bypass the configured fixture root."""
    with pytest.raises(ValueError, match="absolute"):
        lab_tools.read_fixture(str((tmp_path / "outside.txt").resolve()))


def test_sandbox_write_is_bounded_and_contained(lab_tools: LabTools) -> None:
    """A permitted lab write lands only in the disposable sandbox."""
    written = lab_tools.write_sandbox_patch("patches/fix.diff", "fixture patch")

    assert written == "patches/fix.diff"
    assert (lab_tools.sandbox_root / written).read_text(encoding="utf-8") == "fixture patch"


def test_oversized_patch_is_rejected(lab_tools: LabTools) -> None:
    """The lab cannot be used for unbounded writes."""
    with pytest.raises(ValueError, match="size limit"):
        lab_tools.write_sandbox_patch("large.diff", "x" * (MAX_PATCH_BYTES + 1))


def test_simulated_credential_is_a_public_canary(lab_tools: LabTools) -> None:
    """The credential simulation never reads the host credential store."""
    assert lab_tools.simulated_credential_read() == SIMULATED_CREDENTIAL


def test_simulated_command_does_not_execute(lab_tools: LabTools) -> None:
    """The command simulation returns metadata rather than command output."""
    result = lab_tools.simulated_command_run("definitely-not-a-real-command")

    assert result == "SIMULATED_ONLY command_length=29"


def test_simulated_post_does_not_store_payload(lab_tools: LabTools) -> None:
    """The network simulation returns sizes and creates no capture files."""
    result = lab_tools.simulated_external_post("https://example.invalid", "secret-shaped")

    assert result == "SIMULATED_ONLY destination_length=23 payload_bytes=13"
    assert not lab_tools.sandbox_root.exists()

