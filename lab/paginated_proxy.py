"""Run the transparent proxy around the pagination fixture."""

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
    """Start the pagination-test proxy."""
    process = DownstreamProcess(
        command=sys.executable,
        args=("-m", "lab.paginated_server"),
        cwd=PROJECT_ROOT,
    )
    anyio.run(run_transparent_proxy, process)


if __name__ == "__main__":
    main()
