"""Smoke tests for the public command surface."""

from typer.testing import CliRunner

from mcp_privprof import __version__
from mcp_privprof.cli import app


def test_version_command_reports_package_version() -> None:
    """The installed command must identify the package version."""
    result = CliRunner().invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == __version__
