"""Run the transparent proxy with the deterministic lab downstream."""

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
    """Run one proxy process wrapping one lab server process."""
    process = DownstreamProcess(
        command=sys.executable,
        args=("-m", "lab.server"),
        cwd=PROJECT_ROOT,
    )
    anyio.run(run_transparent_proxy, process)


if __name__ == "__main__":
    main()
