"""Run pytest with a private, cross-platform OS temporary directory."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest


def basetemp_path() -> Path:
    """Return a process-unique pytest base inside the operating-system temp tree."""
    return Path(tempfile.gettempdir()) / f"mcp-privprof-pytest-{os.getpid()}"


def main(arguments: list[str] | None = None) -> int:
    """Run the repository suite without relying on pytest's shared user temp root."""
    forwarded = list(sys.argv[1:] if arguments is None else arguments)
    options = [
        "-p",
        "no:cacheprovider",
        "--basetemp",
        str(basetemp_path()),
        *forwarded,
    ]
    return int(pytest.main(options))


if __name__ == "__main__":
    raise SystemExit(main())
