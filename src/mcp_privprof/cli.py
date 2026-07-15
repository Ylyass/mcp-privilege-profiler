"""Command-line composition root for verified project workflows."""

from __future__ import annotations

import os
import tempfile
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Annotated, Never

import anyio
import typer

from mcp_privprof import __version__
from mcp_privprof.adapters.mcp.enforcement_proxy import run_enforcement_proxy
from mcp_privprof.adapters.mcp.inventory import McpToolsetSource
from mcp_privprof.adapters.mcp.profile_proxy import run_profile_proxy
from mcp_privprof.adapters.mcp.transparent_proxy import (
    DownstreamProcess,
    open_downstream_session,
)
from mcp_privprof.adapters.sqlite import SqliteInventoryRepository, SqliteProfileRepository
from mcp_privprof.application import InventoryService, ProfileService
from mcp_privprof.application.constraints import (
    constraint_domain,
    prepare_path_roots,
)
from mcp_privprof.application.policies import policy_contract, policy_domain, render_policy_json
from mcp_privprof.application.profile_reports import (
    build_review_template,
    render_profile_evidence_json,
    render_profile_evidence_markdown,
    render_review_decisions_json,
)
from mcp_privprof.application.reports import (
    build_inventory_report,
    render_inventory_json,
    render_inventory_markdown,
)
from mcp_privprof.contracts.inventory import InventoryReportV1
from mcp_privprof.contracts.policy import PolicyV1
from mcp_privprof.contracts.profile import ProfileEvidenceReportV1, ReviewDecisionsV1
from mcp_privprof.domain.policy import Policy
from mcp_privprof.domain.profile import ProfileSession, ProfileStatus, ReviewDecision, RunStatus

MAX_INPUT_FILE_BYTES = 1024 * 1024

app = typer.Typer(
    name="mcp-privprof",
    help="Task-scoped MCP least-privilege profiler.",
    no_args_is_help=True,
)
profile_app = typer.Typer(help="Collect labeled, privacy-safe task evidence.", no_args_is_help=True)
review_app = typer.Typer(help="Complete an evidence-bound human review.", no_args_is_help=True)
policy_app = typer.Typer(help="Generate policy only from a completed review.", no_args_is_help=True)
app.add_typer(profile_app, name="profile")
app.add_typer(review_app, name="review")
app.add_typer(policy_app, name="policy")


@app.callback()
def main() -> None:
    """Provide a stable command group for future security workflows."""


@app.command()
def version() -> None:
    """Print the installed version."""
    typer.echo(__version__)


@app.command()
def enforce(
    downstream: Annotated[
        list[str],
        typer.Argument(help="Downstream command and arguments; place after --."),
    ],
    policy_file: Annotated[
        Path,
        typer.Option("--policy", help="Reviewed policy-v1 JSON file."),
    ],
    path_root: Annotated[
        list[str] | None,
        typer.Option(
            "--path-root",
            help="Trusted symbolic path binding as ALIAS=DIRECTORY; repeat as needed.",
        ),
    ] = None,
    cwd: Annotated[
        Path | None,
        typer.Option("--cwd", help="Working directory for the downstream process."),
    ] = None,
    startup_timeout: Annotated[
        float,
        typer.Option("--startup-timeout", min=0.001, help="Initialization timeout in seconds."),
    ] = 10.0,
    call_timeout: Annotated[
        float,
        typer.Option("--call-timeout", min=0.001, help="Per-call timeout in seconds."),
    ] = 30.0,
) -> None:
    """Run a reviewed, exact-match, deny-by-default MCP enforcement proxy."""
    _require_downstream(downstream)
    try:
        contract = PolicyV1.model_validate_json(_read_bounded(policy_file))
        policy = policy_domain(contract)
        roots = prepare_path_roots(_parse_path_root_bindings(path_root or []))
        process = _downstream_process(
            downstream,
            cwd=cwd,
            startup_timeout=startup_timeout,
            call_timeout=call_timeout,
        )
        anyio.run(
            partial(
                run_enforcement_proxy,
                process=process,
                policy=policy,
                path_roots=roots,
            )
        )
    except typer.BadParameter:
        raise
    except BaseException as exc:
        # This command's stdout is the MCP transport; diagnostics must use stderr.
        typer.echo(f"Enforcement failed safely ({type(exc).__name__}): {exc}", err=True)
        raise typer.Exit(code=1) from exc


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


@profile_app.command("create")
def profile_create(
    downstream: Annotated[
        list[str],
        typer.Argument(help="Downstream command and arguments; place after --."),
    ],
    profile_id: Annotated[str, typer.Option("--profile-id", help="Unique trusted profile ID.")],
    task_type: Annotated[str, typer.Option("--task-type", help="Trusted task classification.")],
    agent_id: Annotated[str, typer.Option("--agent-id", help="Trusted agent identity.")],
    server_id: Annotated[str, typer.Option("--server-id", help="Trusted MCP server identity.")],
    scenario: Annotated[
        list[str],
        typer.Option("--scenario", help="Planned scenario ID; repeat for every scenario."),
    ],
    database: Annotated[
        Path,
        typer.Option("--database", help="SQLite inventory and profile evidence store."),
    ] = Path(".mcp-privprof/state.sqlite3"),
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
        typer.Option("--catalog-timeout", min=0.001, help="Catalog timeout in seconds."),
    ] = 30.0,
) -> None:
    """Bind trusted task context to a freshly inventoried exact MCP catalog."""
    _require_downstream(downstream)
    _require_nonblank(
        ("--profile-id", profile_id),
        ("--task-type", task_type),
        ("--agent-id", agent_id),
        ("--server-id", server_id),
    )
    if not scenario:
        raise typer.BadParameter("provide at least one scenario", param_hint="--scenario")
    _require_nonblank(*(("--scenario", item) for item in scenario))
    try:
        process = _downstream_process(
            downstream,
            cwd=cwd,
            startup_timeout=startup_timeout,
            call_timeout=catalog_timeout,
        )
        profile, snapshot_id = anyio.run(
            partial(
                _create_profile,
                process=process,
                database=database,
                profile_id=profile_id,
                task_type=task_type,
                agent_id=agent_id,
                server_id=server_id,
                scenarios=tuple(scenario),
            )
        )
    except typer.BadParameter:
        raise
    except Exception as exc:
        _fail("Profile creation", exc)

    typer.echo(f"Created open profile {profile.profile_id} from inventory snapshot {snapshot_id}.")
    typer.echo(f"Bound toolset: {profile.toolset_fingerprint}")


@profile_app.command("run")
def profile_run(
    downstream: Annotated[
        list[str],
        typer.Argument(help="Downstream command and arguments; place after --."),
    ],
    profile_id: Annotated[str, typer.Option("--profile-id", help="Open profile ID.")],
    run_id: Annotated[str, typer.Option("--run-id", help="Unique scenario-run ID.")],
    scenario_id: Annotated[
        str,
        typer.Option("--scenario-id", help="One scenario planned at profile creation."),
    ],
    database: Annotated[
        Path,
        typer.Option("--database", help="SQLite inventory and profile evidence store."),
    ] = Path(".mcp-privprof/state.sqlite3"),
    cwd: Annotated[
        Path | None,
        typer.Option("--cwd", help="Working directory for the downstream process."),
    ] = None,
    startup_timeout: Annotated[
        float,
        typer.Option("--startup-timeout", min=0.001, help="Initialization timeout in seconds."),
    ] = 10.0,
    call_timeout: Annotated[
        float,
        typer.Option("--call-timeout", min=0.001, help="Per-call timeout in seconds."),
    ] = 30.0,
) -> None:
    """Run a transparent stdio proxy and record names, times, and outcomes only."""
    _require_downstream(downstream)
    _require_nonblank(
        ("--profile-id", profile_id),
        ("--run-id", run_id),
        ("--scenario-id", scenario_id),
    )
    try:
        process = _downstream_process(
            downstream,
            cwd=cwd,
            startup_timeout=startup_timeout,
            call_timeout=call_timeout,
        )
        anyio.run(
            partial(
                _serve_profile_run,
                process=process,
                database=database,
                profile_id=profile_id,
                run_id=run_id,
                scenario_id=scenario_id,
            )
        )
    except typer.BadParameter:
        raise
    except BaseException as exc:
        # This command's stdout is the MCP transport; diagnostics must use stderr.
        typer.echo(f"Profile run failed safely ({type(exc).__name__}): {exc}", err=True)
        raise typer.Exit(code=1) from exc


@profile_app.command("abort-run")
def profile_abort_run(
    run_id: Annotated[str, typer.Option("--run-id", help="Open run to mark aborted.")],
    database: Annotated[
        Path,
        typer.Option("--database", help="SQLite inventory and profile evidence store."),
    ] = Path(".mcp-privprof/state.sqlite3"),
) -> None:
    """Recover an open run left behind by an ungraceful host termination."""
    _require_nonblank(("--run-id", run_id))
    try:
        anyio.run(partial(_abort_profile_run, database=database, run_id=run_id))
    except Exception as exc:
        _fail("Run abort", exc)
    typer.echo(f"Marked run {run_id} as aborted.")


@profile_app.command("seal")
def profile_seal(
    profile_id: Annotated[str, typer.Option("--profile-id", help="Profile to seal or report.")],
    database: Annotated[
        Path,
        typer.Option("--database", help="SQLite inventory and profile evidence store."),
    ] = Path(".mcp-privprof/state.sqlite3"),
    json_report: Annotated[
        Path,
        typer.Option("--json-report", help="Machine-readable evidence report."),
    ] = Path("profile-evidence.json"),
    markdown_report: Annotated[
        Path,
        typer.Option("--markdown-report", help="Human-readable evidence report."),
    ] = Path("profile-evidence.md"),
    review_template: Annotated[
        Path,
        typer.Option("--review-template", help="Editable deny-by-default review file."),
    ] = Path("review-decisions.json"),
) -> None:
    """Freeze evidence and produce reports plus a deny-by-default review template."""
    _require_nonblank(("--profile-id", profile_id))
    _require_distinct_paths(database, json_report, markdown_report, review_template)
    try:
        profile, report = anyio.run(
            partial(_seal_profile, database=database, profile_id=profile_id)
        )
        evidence_json = render_profile_evidence_json(report)
        evidence_markdown = render_profile_evidence_markdown(report).encode()
        decisions_json = render_review_decisions_json(build_review_template(report))
        _atomic_write(json_report, evidence_json)
        _atomic_write(markdown_report, evidence_markdown)
        _atomic_write(review_template, decisions_json)
    except Exception as exc:
        _fail("Profile sealing", exc)

    typer.echo(f"Sealed profile {profile.profile_id}; evidence is now immutable.")
    typer.echo(f"Evidence fingerprint: {report.evidence_fingerprint}")
    typer.echo(f"Review template (DENY by default): {review_template}")


@review_app.command("complete")
def review_complete(
    review_id: Annotated[str, typer.Option("--review-id", help="Unique completed-review ID.")],
    reviewer: Annotated[str, typer.Option("--reviewer", help="Human reviewer identity.")],
    decisions_file: Annotated[
        Path,
        typer.Option("--decisions", help="Edited review-decisions-v1 JSON file."),
    ],
    database: Annotated[
        Path,
        typer.Option("--database", help="SQLite inventory and profile evidence store."),
    ] = Path(".mcp-privprof/state.sqlite3"),
) -> None:
    """Persist one human decision for every available tool in sealed evidence."""
    _require_nonblank(("--review-id", review_id), ("--reviewer", reviewer))
    _require_distinct_paths(database, decisions_file)
    try:
        decisions = ReviewDecisionsV1.model_validate_json(_read_bounded(decisions_file))
        anyio.run(
            partial(
                _complete_review,
                database=database,
                review_id=review_id,
                reviewer=reviewer,
                decisions=decisions,
            )
        )
    except Exception as exc:
        _fail("Review completion", exc)
    typer.echo(f"Completed review {review_id} for profile {decisions.profile_id}.")


@policy_app.command("generate")
def policy_generate(
    review_id: Annotated[str, typer.Option("--review-id", help="Completed-review ID.")],
    policy_id: Annotated[str, typer.Option("--policy-id", help="Unique policy artifact ID.")],
    output: Annotated[Path, typer.Option("--output", help="Reviewed policy-v1 JSON path.")],
    database: Annotated[
        Path,
        typer.Option("--database", help="SQLite inventory and profile evidence store."),
    ] = Path(".mcp-privprof/state.sqlite3"),
) -> None:
    """Generate policy only through the completed-review gate."""
    _require_nonblank(("--review-id", review_id), ("--policy-id", policy_id))
    _require_distinct_paths(database, output)
    try:
        policy = anyio.run(
            partial(
                _generate_policy,
                database=database,
                review_id=review_id,
                policy_id=policy_id,
            )
        )
        _atomic_write(output, render_policy_json(policy_contract(policy)))
    except Exception as exc:
        _fail("Policy generation", exc)
    typer.echo(f"Generated reviewed policy {policy_id}: {output}")


async def _create_profile(
    *,
    process: DownstreamProcess,
    database: Path,
    profile_id: str,
    task_type: str,
    agent_id: str,
    server_id: str,
    scenarios: tuple[str, ...],
) -> tuple[ProfileSession, int]:
    database.parent.mkdir(parents=True, exist_ok=True)
    profile_repository = SqliteProfileRepository(database)
    profile_service = ProfileService(profile_repository)
    await profile_service.initialize()
    if await profile_repository.get_profile(profile_id) is not None:
        raise ValueError("profile_id already exists")

    inventory_repository = SqliteInventoryRepository(database)
    async with open_downstream_session(process) as session:
        inventory_service = InventoryService(
            McpToolsetSource(
                session,
                server_id,
                catalog_timeout_seconds=process.call_timeout_seconds,
            ),
            inventory_repository,
        )
        await inventory_service.initialize()
        refresh = await inventory_service.refresh(captured_at=datetime.now(UTC))

    profile = ProfileSession(
        profile_id=profile_id,
        task_type=task_type,
        agent_id=agent_id,
        server_id=server_id,
        toolset_fingerprint=refresh.current.snapshot.fingerprint,
        planned_scenarios=scenarios,
        status=ProfileStatus.OPEN,
        created_at=datetime.now(UTC),
    )
    await profile_service.create(profile, refresh.current)
    return profile, refresh.current.snapshot_id


async def _serve_profile_run(
    *,
    process: DownstreamProcess,
    database: Path,
    profile_id: str,
    run_id: str,
    scenario_id: str,
) -> None:
    service = ProfileService(SqliteProfileRepository(database))
    await service.initialize()
    profile = await service.profile(profile_id)
    run = await service.start_run(
        profile_id,
        run_id=run_id,
        scenario_id=scenario_id,
        started_at=datetime.now(UTC),
    )
    try:
        await run_profile_proxy(process, profile, run, service)
    except BaseException:
        with anyio.CancelScope(shield=True):
            await service.finish_run(
                run_id,
                status=RunStatus.ABORTED,
                completed_at=datetime.now(UTC),
            )
        raise
    else:
        await service.finish_run(
            run_id,
            status=RunStatus.COMPLETED,
            completed_at=datetime.now(UTC),
        )


async def _abort_profile_run(*, database: Path, run_id: str) -> None:
    service = ProfileService(SqliteProfileRepository(database))
    await service.initialize()
    await service.finish_run(
        run_id,
        status=RunStatus.ABORTED,
        completed_at=datetime.now(UTC),
    )


async def _seal_profile(
    *,
    database: Path,
    profile_id: str,
) -> tuple[ProfileSession, ProfileEvidenceReportV1]:
    service = ProfileService(SqliteProfileRepository(database))
    await service.initialize()
    profile = await service.profile(profile_id)
    if profile.status is ProfileStatus.OPEN:
        profile = await service.seal(profile_id, sealed_at=datetime.now(UTC))
    report = await service.evidence_report(profile_id, generated_at=datetime.now(UTC))
    return profile, report


async def _complete_review(
    *,
    database: Path,
    review_id: str,
    reviewer: str,
    decisions: ReviewDecisionsV1,
) -> None:
    service = ProfileService(SqliteProfileRepository(database))
    await service.initialize()
    await service.complete_review(
        decisions.profile_id,
        review_id=review_id,
        reviewer=reviewer,
        reviewed_at=datetime.now(UTC),
        evidence_fingerprint=decisions.evidence_fingerprint,
        decisions=tuple(
            ReviewDecision(
                tool_name=decision.tool_name,
                effect=decision.effect,
                constraints=tuple(constraint_domain(item) for item in decision.constraints),
            )
            for decision in decisions.decisions
        ),
    )


async def _generate_policy(
    *,
    database: Path,
    review_id: str,
    policy_id: str,
) -> Policy:
    service = ProfileService(SqliteProfileRepository(database))
    await service.initialize()
    return await service.policy_from_review(review_id, policy_id)


def _downstream_process(
    downstream: list[str],
    *,
    cwd: Path | None,
    startup_timeout: float,
    call_timeout: float,
) -> DownstreamProcess:
    try:
        return DownstreamProcess(
            command=downstream[0],
            args=tuple(downstream[1:]),
            cwd=cwd,
            startup_timeout_seconds=startup_timeout,
            call_timeout_seconds=call_timeout,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="DOWNSTREAM/TIMEOUT") from exc


def _require_downstream(downstream: list[str]) -> None:
    if not downstream:
        raise typer.BadParameter(
            "provide a downstream command after --",
            param_hint="COMMAND",
        )


def _require_nonblank(*values: tuple[str, str]) -> None:
    for label, value in values:
        if not value.strip():
            raise typer.BadParameter("must not be blank", param_hint=label)


def _read_bounded(path: Path) -> bytes:
    with path.open("rb") as source:
        content = source.read(MAX_INPUT_FILE_BYTES + 1)
    if len(content) > MAX_INPUT_FILE_BYTES:
        raise ValueError(f"input document exceeds {MAX_INPUT_FILE_BYTES} bytes")
    return content


def _parse_path_root_bindings(values: list[str]) -> tuple[tuple[str, Path], ...]:
    bindings: list[tuple[str, Path]] = []
    for value in values:
        alias, separator, raw_path = value.partition("=")
        if not separator or not alias or not raw_path:
            raise typer.BadParameter(
                "must use ALIAS=DIRECTORY",
                param_hint="--path-root",
            )
        bindings.append((alias, Path(raw_path)))
    return tuple(bindings)


def _fail(action: str, exc: Exception) -> Never:
    typer.echo(f"{action} failed safely ({type(exc).__name__}): {exc}", err=True)
    raise typer.Exit(code=1) from exc


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
