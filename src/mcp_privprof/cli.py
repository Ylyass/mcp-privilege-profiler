"""Command-line composition root for verified project workflows."""

from __future__ import annotations

import os
import tempfile
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Annotated

import anyio
import typer

from mcp_privprof import __version__
from mcp_privprof.adapters.mcp.inventory import McpToolsetSource
from mcp_privprof.adapters.mcp.transparent_proxy import (
    DownstreamProcess,
    open_downstream_session,
)
from mcp_privprof.adapters.sqlite import SqliteInventoryRepository
from mcp_privprof.application import InventoryService
from mcp_privprof.application.reports import (
    build_inventory_report,
    render_inventory_json,
    render_inventory_markdown,
)
from mcp_privprof.contracts.inventory import InventoryReportV1

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


@app.command()
def inventory(
    downstream: Annotated[
        list[str],
        typer.Argument(help="Downstream command and arguments; place after --."),
    ],
    server_id: Annotated[
        str,
        typer.Option("--server-id", help="Trusted identity for this one downstream server."),
    ],
    database: Annotated[
        Path,
        typer.Option("--database", help="Append-only SQLite inventory history."),
    ] = Path(".mcp-privprof/inventory.sqlite3"),
    json_report: Annotated[
        Path,
        typer.Option("--json-report", help="Machine-readable versioned report path."),
    ] = Path("inventory-report.json"),
    markdown_report: Annotated[
        Path,
        typer.Option("--markdown-report", help="Human-readable summary path."),
    ] = Path("inventory-report.md"),
    cwd: Annotated[
        Path | None,
        typer.Option("--cwd", help="Working directory for the downstream process."),
    ] = None,
    startup_timeout: Annotated[
        float,
        typer.Option("--startup-timeout", min=0.001, help="Initialization timeout in seconds."),
    ] = 10.0,
    catalog_timeout: Annotated[
        float,
        typer.Option("--catalog-timeout", min=0.001, help="Total catalog timeout in seconds."),
    ] = 30.0,
) -> None:
    """Inventory one local stdio MCP server and write JSON and Markdown reports."""
    if not downstream:
        raise typer.BadParameter(
            "provide a downstream command after --",
            param_hint="COMMAND",
        )
    if not server_id.strip():
        raise typer.BadParameter("must not be blank", param_hint="--server-id")
    _require_distinct_paths(database, json_report, markdown_report)

    try:
        process = DownstreamProcess(
            command=downstream[0],
            args=tuple(downstream[1:]),
            cwd=cwd,
            startup_timeout_seconds=startup_timeout,
            call_timeout_seconds=catalog_timeout,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="DOWNSTREAM/TIMEOUT") from exc
    try:
        report = anyio.run(
            partial(
                _collect_inventory,
                process=process,
                server_id=server_id,
                database=database,
            )
        )
        _atomic_write(json_report, render_inventory_json(report))
        _atomic_write(markdown_report, render_inventory_markdown(report).encode())
    except Exception as exc:
        typer.echo(
            f"Inventory failed safely ({type(exc).__name__}). No tool call was made.",
            err=True,
        )
        raise typer.Exit(code=1) from exc

    typer.echo(
        f"Stored snapshot {report.snapshot_id} for {report.server_id}: {report.tool_count} tools."
    )
    typer.echo(f"JSON report: {json_report}")
    typer.echo(f"Markdown report: {markdown_report}")


async def _collect_inventory(
    *,
    process: DownstreamProcess,
    server_id: str,
    database: Path,
) -> InventoryReportV1:
    database.parent.mkdir(parents=True, exist_ok=True)
    repository = SqliteInventoryRepository(database)
    async with open_downstream_session(process) as session:
        service = InventoryService(
            McpToolsetSource(
                session,
                server_id,
                catalog_timeout_seconds=process.call_timeout_seconds,
            ),
            repository,
        )
        await service.initialize()
        refresh = await service.refresh(captured_at=datetime.now(UTC))
    return build_inventory_report(refresh, generated_at=datetime.now(UTC))


def _require_distinct_paths(*paths: Path) -> None:
    resolved = [path.resolve(strict=False) for path in paths]
    if len(resolved) != len(set(resolved)):
        raise typer.BadParameter(
            "database and report paths must be different",
            param_hint="OUTPUT PATHS",
        )


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
        temporary_path.replace(path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()
