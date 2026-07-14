"""Run a short-startup-timeout proxy around the hanging fixture."""

from __future__ import annotations

import sys
from pathlib import Path

import anyio

from mcp_privprof.adapters.mcp.transparent_proxy import (
    DownstreamProcess,
    run_transparent_proxy,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    """Start the proxy that must terminate its unresponsive child."""
    process = DownstreamProcess(
        command=sys.executable,
        args=("-m", "lab.hanging_server"),
        cwd=PROJECT_ROOT,
        startup_timeout_seconds=0.1,
    )
    anyio.run(run_transparent_proxy, process)


if __name__ == "__main__":
    main()

