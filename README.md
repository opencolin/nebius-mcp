# nebius-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server for [Nebius Cloud](https://nebius.com).

Exposes Nebius compute, managed Kubernetes, AI Endpoints, VPC, container registry, IAM, and MysteryBox secrets to MCP-aware LLM clients (Claude Desktop, Claude Code, etc.) as typed, validated tools.

> **Status: alpha.** Read-only by default; destructive operations are gated behind `NEBIUS_MCP_MODE=write` and a `dry_run → confirm_token` two-step.

## Install

```bash
uv tool install nebius-mcp
```

## Configure

The server reads Nebius credentials in this precedence:

1. `NEBIUS_IAM_TOKEN` env var — short-lived bearer token
2. `NEBIUS_PROFILE` env var pointing to a profile in `~/.nebius/config.yaml` (with a service-account keyfile)
3. The `current-profile` set in `~/.nebius/config.yaml`

To enable write/destructive operations:

```bash
export NEBIUS_MCP_MODE=write
```

## Use with Claude Desktop

```json
{
  "mcpServers": {
    "nebius": {
      "command": "uvx",
      "args": ["nebius-mcp"],
      "env": {
        "NEBIUS_PROFILE": "default"
      }
    }
  }
}
```

## Develop

```bash
uv sync
uv run pytest
uv run ruff check .
uv run mypy src
```

## License

Apache-2.0
