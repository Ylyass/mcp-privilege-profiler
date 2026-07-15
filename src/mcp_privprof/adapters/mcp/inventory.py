"""Complete MCP catalog collection and RFC 8785 fingerprints."""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from typing import cast

import anyio
import mcp.types as types
from mcp import ClientSession

from mcp_privprof.application.fingerprints import fingerprint_json
from mcp_privprof.domain.inventory import ToolsetSnapshot, ToolSnapshot

type JsonScalar = bool | int | float | str | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]

MAX_CATALOG_PAGES = 100


@dataclass(frozen=True, slots=True)
class CollectedCatalog:
    """One complete raw catalog plus its exact security fingerprint."""

    snapshot: ToolsetSnapshot
    tools: tuple[types.Tool, ...]


class McpToolsetSource:
    """Collect a launch-bound server's catalog through one MCP session."""

    def __init__(
        self,
        session: ClientSession,
        server_id: str,
        *,
        catalog_timeout_seconds: float = 30.0,
    ) -> None:
        if not server_id:
            raise ValueError("server_id must not be empty")
        _validate_catalog_timeout(catalog_timeout_seconds)
        self._session = session
        self._server_id = server_id
        self._catalog_timeout_seconds = catalog_timeout_seconds

    @property
    def server_id(self) -> str:
        """Return the trusted server identity supplied at construction."""
        return self._server_id

    async def collect(self) -> ToolsetSnapshot:
        """Collect every catalog page from the bound MCP session."""
        return await collect_toolset(
            self._session,
            self._server_id,
            catalog_timeout_seconds=self._catalog_timeout_seconds,
        )


def snapshot_tool(tool: types.Tool) -> ToolSnapshot:
    """Fingerprint the complete known Tool object returned by the SDK."""
    dumped = cast(
        JsonValue,
        tool.model_dump(mode="json", by_alias=True, exclude_none=True),
    )
    if not isinstance(dumped, dict):
        raise TypeError("MCP Tool must serialize to a JSON object")
    canonical, fingerprint = fingerprint_json(dumped)
    return ToolSnapshot(
        name=tool.name,
        fingerprint=fingerprint,
        canonical_json=canonical,
    )


def snapshot_toolset(
    server_id: str,
    tools: list[types.Tool],
) -> ToolsetSnapshot:
    """Create an order-independent snapshot with duplicate-name rejection."""
    snapshots = tuple(sorted((snapshot_tool(tool) for tool in tools), key=lambda item: item.name))
    names = [snapshot.name for snapshot in snapshots]
    if len(names) != len(set(names)):
        raise ValueError("downstream catalog contains duplicate tool names")

    catalog_document: JsonValue = [
        {"name": snapshot.name, "fingerprint": snapshot.fingerprint} for snapshot in snapshots
    ]
    _, fingerprint = fingerprint_json(catalog_document)
    return ToolsetSnapshot(
        server_id=server_id,
        fingerprint=fingerprint,
        tools=snapshots,
    )


async def collect_toolset(
    session: ClientSession,
    server_id: str,
    *,
    catalog_timeout_seconds: float = 30.0,
) -> ToolsetSnapshot:
    """Collect all tools/list pages within one finite total timeout."""
    catalog = await collect_catalog(
        session,
        server_id,
        catalog_timeout_seconds=catalog_timeout_seconds,
    )
    return catalog.snapshot


async def collect_catalog(
    session: ClientSession,
    server_id: str,
    *,
    catalog_timeout_seconds: float = 30.0,
) -> CollectedCatalog:
    """Collect raw tool definitions and their exact snapshot atomically."""
    if not server_id:
        raise ValueError("server_id must not be empty")
    _validate_catalog_timeout(catalog_timeout_seconds)
    with anyio.fail_after(catalog_timeout_seconds):
        return await _collect_catalog_pages(session, server_id)


async def _collect_catalog_pages(
    session: ClientSession,
    server_id: str,
) -> CollectedCatalog:
    tools: list[types.Tool] = []
    cursor: str | None = None
    seen_cursors: set[str] = set()

    for _ in range(MAX_CATALOG_PAGES):
        params = types.PaginatedRequestParams(cursor=cursor) if cursor is not None else None
        result = await session.list_tools(params=params)
        tools.extend(result.tools)

        cursor = result.nextCursor
        if cursor is None:
            snapshot = snapshot_toolset(server_id=server_id, tools=tools)
            tools_by_name = {tool.name: tool for tool in tools}
            return CollectedCatalog(
                snapshot=snapshot,
                tools=tuple(tools_by_name[name] for name in sorted(tools_by_name)),
            )
        if cursor in seen_cursors:
            raise ValueError("downstream tools/list pagination cursor cycle detected")
        seen_cursors.add(cursor)

    raise ValueError(f"downstream tools/list exceeded {MAX_CATALOG_PAGES} pages")


def _validate_catalog_timeout(value: float) -> None:
    if not isfinite(value) or value <= 0:
        raise ValueError("catalog timeout must be positive and finite")
