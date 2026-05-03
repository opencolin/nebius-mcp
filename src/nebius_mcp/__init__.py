"""Nebius MCP — a Model Context Protocol server for Nebius Cloud."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("nebius-mcp")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
