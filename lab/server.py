"""Local stdio MCP server for deterministic security scenarios."""

from __future__ import annotations

from pathlib import Path

from mcp.server.fastmcp import FastMCP

from lab.tools import LabTools

PROJECT_ROOT = Path(__file__).resolve().parents[1]
tools = LabTools(
    fixture_root=PROJECT_ROOT / "lab" / "fixtures",
    sandbox_root=PROJECT_ROOT / "runtime" / "lab-sandbox",
)
mcp = FastMCP("mcp-privilege-profiler-lab")


@mcp.tool()
def list_fixture_directory() -> list[str]:
    """List the safe fixture files available to the lab agent."""
    return tools.list_fixture_directory()


@mcp.tool()
def read_fixture(relative_path: str) -> str:
    """Read a UTF-8 file from the safe lab fixture directory."""
    return tools.read_fixture(relative_path)


@mcp.tool()
def fetch_fixture_advisory(advisory_id: str) -> dict[str, str]:
    """Fetch a deterministic local advisory without using the network."""
    return tools.fetch_fixture_advisory(advisory_id)


@mcp.tool()
def write_sandbox_patch(relative_path: str, content: str) -> str:
    """Write a bounded file only inside the disposable lab sandbox."""
    return tools.write_sandbox_patch(relative_path, content)


@mcp.tool()
def simulated_credential_read() -> str:
    """Simulate credential access by returning a public canary."""
    return tools.simulated_credential_read()


@mcp.tool()
def simulated_command_run(command: str) -> str:
    """Simulate command execution without spawning any process."""
    return tools.simulated_command_run(command)


@mcp.tool()
def simulated_external_post(destination: str, payload: str) -> str:
    """Simulate outbound posting without making a network connection."""
    return tools.simulated_external_post(destination, payload)


if __name__ == "__main__":
    mcp.run(transport="stdio")

