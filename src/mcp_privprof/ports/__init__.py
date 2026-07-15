"""Dependency-inversion boundaries implemented by external adapters."""

from mcp_privprof.ports.inventory import InventoryRepository, ToolsetSource
from mcp_privprof.ports.profile import ProfileRepository

__all__ = ["InventoryRepository", "ProfileRepository", "ToolsetSource"]
