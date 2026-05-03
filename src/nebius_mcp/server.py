"""FastMCP server entrypoint."""

from __future__ import annotations

import os

from fastmcp import FastMCP

from . import __version__

INSTRUCTIONS = """\
nebius-mcp exposes Nebius Cloud (compute, managed Kubernetes, AI Endpoints, VPC,
container registry, IAM, MysteryBox secrets) as MCP tools.

By default the server runs in read-only mode. Set NEBIUS_MCP_MODE=write to enable
destructive operations; destructive tools then require a dry_run -> confirm_token
two-step.

Authentication is resolved in this order:
  1. NEBIUS_IAM_TOKEN env var
  2. NEBIUS_PROFILE env var (with a service-account keyfile in ~/.nebius/config.yaml)
  3. The current-profile in ~/.nebius/config.yaml
"""


def _build_app() -> FastMCP:
    app: FastMCP = FastMCP(
        name="nebius-mcp",
        version=__version__,
        instructions=INSTRUCTIONS,
        website_url="https://github.com/opencolin/nebius-mcp",
    )
    _register_tools(app)
    return app


def _register_tools(app: FastMCP) -> None:
    from .tools import ops

    ops.register(app)


def is_write_mode() -> bool:
    return os.environ.get("NEBIUS_MCP_MODE", "read").lower() == "write"


def main() -> None:
    app = _build_app()
    app.run()  # default transport: stdio


if __name__ == "__main__":
    main()
