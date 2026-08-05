"""Public inventory command integration tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from click import unstyle
from typer.testing import CliRunner

from mcp_privprof.cli import app

PROJECT_ROOT = Path(__file__).parents[2]


def test_inventory_command_writes_history_and_both_reports(tmp_path: Path) -> None:
    """The public command composes a real MCP scan into durable artifacts."""
    database = tmp_path / "state" / "inventory.sqlite3"
    json_report = tmp_path / "reports" / "inventory.json"
    markdown_report = tmp_path / "reports" / "inventory.md"

    result = CliRunner().invoke(
        app,
        [
            "inventory",
            "--server-id",
            "pagination-lab",
            "--database",
            str(database),
            "--json-report",
            str(json_report),
            "--markdown-report",
            str(markdown_report),
            "--cwd",
            str(PROJECT_ROOT),
            "--",
            sys.executable,
            "-m",
            "lab.paginated_server",
        ],
    )

    assert result.exit_code == 0, result.output
    assert database.is_file()
    document = json.loads(json_report.read_text(encoding="utf-8"))
    assert document["server_id"] == "pagination-lab"
    assert document["tool_count"] == 2
    assert [tool["name"] for tool in document["tools"]] == [
        "page_one_tool",
        "page_two_tool",
    ]
    assert "This is the first stored observation" in markdown_report.read_text(encoding="utf-8")
    assert "Stored snapshot 1 for pagination-lab: 2 tools." in result.stdout


def test_inventory_command_rejects_colliding_output_paths(tmp_path: Path) -> None:
    """A report can never overwrite the SQLite history file."""
    collision = tmp_path / "same-file"

    result = CliRunner().invoke(
        app,
        [
            "inventory",
            "--server-id",
            "lab",
            "--database",
            str(collision),
            "--json-report",
            str(collision),
            "--",
            "unused-command",
        ],
    )

    assert result.exit_code != 0
    assert "must be different" in result.output
    assert not collision.exists()


def test_inventory_command_rejects_non_finite_timeout_before_launch() -> None:
    """NaN cannot bypass the finite timeout invariant or start a process."""
    result = CliRunner().invoke(
        app,
        [
            "inventory",
            "--server-id",
            "lab",
            "--catalog-timeout",
            "nan",
            "--",
            "unused-command",
        ],
        env={"FORCE_COLOR": "1"},
    )

    assert result.exit_code == 2
    output = unstyle(result.output)
    assert "Usage: mcp-privprof inventory" in output
    assert "positive" in output
    assert "finite" in output
