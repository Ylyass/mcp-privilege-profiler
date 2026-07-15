"""Non-blocking MCP catalog-change notification handling."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

import anyio
import anyio.lowlevel
import mcp.types as types
from mcp.shared.session import RequestResponder

type ClientIncomingMessage = (
    RequestResponder[types.ServerRequest, types.ClientResult] | types.ServerNotification | Exception
)


class ToolListChangedMonitor:
    """Coalesce catalog-change signals and refresh outside the MCP receive loop."""

    def __init__(self, on_signal: Callable[[], None] | None = None) -> None:
        self._sender, self._receiver = anyio.create_memory_object_stream[None](max_buffer_size=1)
        self._running = False
        self._on_signal = on_signal

    async def handle_message(self, message: ClientIncomingMessage) -> None:
        """Queue a signal without waiting for catalog I/O on the receive loop."""
        if isinstance(message, types.ServerNotification) and isinstance(
            message.root,
            types.ToolListChangedNotification,
        ):
            if self._on_signal is not None:
                self._on_signal()
            try:
                self._sender.send_nowait(None)
            except anyio.WouldBlock:
                # One pending signal is sufficient because a refresh collects
                # the complete current catalog rather than applying deltas.
                pass
            except (anyio.BrokenResourceError, anyio.ClosedResourceError):
                # Orderly shutdown can race with a final downstream notification.
                pass
        await anyio.lowlevel.checkpoint()

    async def run(self, refresh: Callable[[], Awaitable[None]]) -> None:
        """Run one refresh worker; callback failures propagate to its task group."""
        if self._running:
            raise RuntimeError("tool-list monitor already has a running worker")
        self._running = True
        try:
            async with self._receiver:
                async for _ in self._receiver:
                    await refresh()
        finally:
            self._running = False

    async def aclose(self) -> None:
        """Stop accepting signals and let the worker drain the pending refresh."""
        await self._sender.aclose()
