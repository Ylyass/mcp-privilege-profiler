"""Smoke tests for the public command surface."""

from typer.testing import CliRunner

from mcp_privprof import __version__
from mcp_privprof.cli import app


def test_version_command_reports_package_version() -> None:
    """The installed command must identify the package version."""
    result = CliRunner().invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == __version__


def test_profile_create_rejects_non_finite_timeout_before_launch() -> None:
    """NaN cannot bypass the profile process timeout invariant."""
    result = CliRunner().invoke(
        app,
        [
            "profile",
            "create",
            "--profile-id",
            "profile-1",
            "--task-type",
            "task",
            "--agent-id",
            "agent",
            "--server-id",
            "server",
            "--scenario",
            "scenario",
            "--catalog-timeout",
            "nan",
            "--",
            "unused-command",
        ],
    )

    assert result.exit_code == 2
    assert "positive" in result.output
    assert "finite" in result.output
