"""Run a short-timeout proxy around the disposable fault lab."""

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
    """Start the fault-test proxy with deliberately short call limits."""
    process = DownstreamProcess(
        command=sys.executable,
        args=("-m", "lab.fault_server"),
        cwd=PROJECT_ROOT,
        call_timeout_seconds=0.2,
    )
    anyio.run(run_transparent_proxy, process)


if __name__ == "__main__":
    main()

