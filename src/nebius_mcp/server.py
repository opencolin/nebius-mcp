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
    from .audit import make_middleware

    app.add_middleware(make_middleware())
    _register_tools(app)
    return app


def _register_tools(app: FastMCP) -> None:
    from .tools import ai, compute, generic, iam, k8s, ops, registry, secrets, vpc

    ops.register(app)
    iam.register(app)
    compute.register(app)
    k8s.register(app)
    ai.register(app)
    vpc.register(app)
    registry.register(app)
    secrets.register(app)
    generic.register(app)


def is_write_mode() -> bool:
    return os.environ.get("NEBIUS_MCP_MODE", "read").lower() == "write"


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        prog="nebius-mcp",
        description=(
            "MCP server for Nebius Cloud. With no arguments it serves over stdio, "
            "which is how an MCP client launches it."
        ),
        epilog="Docs: https://github.com/opencolin/nebius-mcp",
    )
    parser.add_argument("--version", action="version", version=f"nebius-mcp {__version__}")
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "Print a credential and environment preflight as JSON, then exit. "
            "Use this to debug setup without going through an MCP client."
        ),
    )
    args = parser.parse_args()

    if args.check:
        _print_check()
        return

    app = _build_app()
    app.run()  # default transport: stdio


def _print_check() -> None:
    """Print the same report as the ``check_environment`` tool, for humans.

    Safe to write to stdout: this path exits instead of serving, so there is no
    JSON-RPC stream to corrupt.
    """
    import json
    import sys

    from .tools.ops import _build_report

    report = _build_report()
    print(json.dumps(report.model_dump(), indent=2, default=str))
    if not report.has_credentials:
        for step in report.next_steps:
            print(f"\n! {step}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
