"""Downstream fixture that intentionally never completes MCP startup."""

from __future__ import annotations

import time

if __name__ == "__main__":
    time.sleep(30)

