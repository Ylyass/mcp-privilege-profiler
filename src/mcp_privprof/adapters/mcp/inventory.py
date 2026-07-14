"""Complete MCP catalog collection and RFC 8785 fingerprints."""

from __future__ import annotations

from hashlib import sha256
from typing import cast

import mcp.types as types
import rfc8785
from mcp import ClientSession

from mcp_privprof.domain.inventory import ToolsetSnapshot, ToolSnapshot

type JsonScalar = bool | int | float | str | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]

MAX_CATALOG_PAGES = 100


def canonicalize_json(document: JsonValue) -> bytes:
    """Return RFC 8785 canonical bytes for a JSON-compatible value."""
    return rfc8785.dumps(document)


def fingerprint_json(document: JsonValue) -> tuple[bytes, str]:
    """Return canonical bytes and a prefixed SHA-256 digest."""
    canonical = canonicalize_json(document)
    return canonical, f"sha256:{sha256(canonical).hexdigest()}"


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
        {"name": snapshot.name, "fingerprint": snapshot.fingerprint}
        for snapshot in snapshots
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
) -> ToolsetSnapshot:
    """Collect every tools/list page and reject cycles or unreasonable depth."""
    tools: list[types.Tool] = []
    cursor: str | None = None
    seen_cursors: set[str] = set()

    for _ in range(MAX_CATALOG_PAGES):
        params = types.PaginatedRequestParams(cursor=cursor) if cursor is not None else None
        result = await session.list_tools(params=params)
        tools.extend(result.tools)

        cursor = result.nextCursor
        if cursor is None:
            return snapshot_toolset(server_id=server_id, tools=tools)
        if cursor in seen_cursors:
            raise ValueError("downstream tools/list pagination cursor cycle detected")
        seen_cursors.add(cursor)

    raise ValueError(f"downstream tools/list exceeded {MAX_CATALOG_PAGES} pages")

