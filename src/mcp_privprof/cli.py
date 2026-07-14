"""Command-line entry point.

The command surface is intentionally small while the security boundary is built.
"""

from __future__ import annotations

import typer

from mcp_privprof import __version__

app = typer.Typer(
    name="mcp-privprof",
    help="Task-scoped MCP least-privilege profiler.",
    no_args_is_help=True,
)


@app.callback()
def main() -> None:
    """Provide a stable command group for future security workflows."""


@app.command()
def version() -> None:
    """Print the installed version."""
    typer.echo(__version__)
