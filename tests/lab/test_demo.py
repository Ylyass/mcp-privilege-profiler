"""One-command safe-demo acceptance test."""

from pathlib import Path

import pytest

from lab.demo import VISIBLE_TOOLS, run_demo


@pytest.fixture
def anyio_backend() -> str:
    """Use the project's supported asyncio backend."""
    return "asyncio"


@pytest.mark.anyio
async def test_safe_demo_proves_allow_minimize_deny_and_audit(tmp_path: Path) -> None:
    """The beginner demo must exercise the real proxy without leaving raw evidence."""
    result = await run_demo(tmp_path)

    assert set(result.visible_tools) == VISIBLE_TOOLS
    assert result.denied_tool == "write_sandbox_patch"
    assert result.denial_reason == "MCP_PRIVPROF_POLICY_DENY"
    assert result.audit_event_count == 7
