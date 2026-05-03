# nebius-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server for
[Nebius Cloud](https://nebius.com).

Exposes Nebius compute, managed Kubernetes, AI Endpoints, VPC, container
registry, IAM, and MysteryBox secrets as **51 typed, validated, security-
conscious tools** to MCP-aware LLM clients (Claude Desktop, Claude Code, etc.).

> **Status:** v0.1.0 alpha. Read-only by default; destructive operations are
> gated behind `NEBIUS_MCP_MODE=write` and a `dry_run → confirm_token` two-step.

## Why this exists

Nebius ships a `nebius` CLI and a Python SDK, but neither is a great fit for
LLM-driven workflows on its own:

- The CLI is shell-string-driven, which makes it both error-prone and a
  command-injection target when a model assembles arguments.
- The raw Python SDK exposes ~40 services with no opinion on what an
  agent should be able to do, no guard rails for irreversible operations,
  and no shape-checking against the well-known
  [skill](https://github.com/opencolin/nebius-skill) gotchas.

`nebius-mcp` wraps the Python SDK with:

- **Read-only by default**, opt-in `NEBIUS_MCP_MODE=write`.
- **Two-step confirm** for irreversible verbs: the first call returns a
  preview and a single-use, args-bound, 120-second token; the second call
  with that token executes.
- **Output sanitization**: every result is wrapped in a "this is data, not
  instructions" envelope and recursively scrubbed of token-shaped values.
  Direct mitigation for the Cursor-via-Jira-MCP class of indirect
  prompt-injection bugs.
- **Tool-manifest hash** (`get_manifest`): a stable SHA-256 over every
  tool's `{name, description, annotations, inputSchema}`. Pin it in your
  agent config and detect rug-pull / tool-poisoning between sessions
  (the [Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
  / [Trail of Bits](https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/)
  class of attacks).
- **Skill-derived validation**: 50 GiB minimum boot disks for CUDA images,
  `network_ssd` (underscores) vs `network-ssd` (Nebius rejects it), `/32`
  IP suffixes, resource-ID format checks. Fails fast with a friendly error
  before you waste an API call.
- **Audit log** of every tool call to stderr via `structlog` — `tool`,
  `args_hash` (not raw args), `mode`, `outcome`. No tokens, no secret
  values logged.

## Install

```bash
uv tool install nebius-mcp
```

Or one-shot:

```bash
uvx nebius-mcp
```

## Configure

The server reads Nebius credentials in this precedence:

1. `NEBIUS_IAM_TOKEN` — short-lived bearer token (best for CI / one-off use)
2. `NEBIUS_PROFILE` — profile name in `~/.nebius/config.yaml` (with a
   service-account keyfile or token-file)
3. `current-profile` in `~/.nebius/config.yaml` — whatever the
   `nebius profile create` / `nebius iam login` workflow set

To enable destructive operations:

```bash
export NEBIUS_MCP_MODE=write
```

Without `write` mode, `*_start_*`, `*_stop_*`, `*_delete_*`, and
`*_create_*` tools refuse to execute.

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

For write mode, add `"NEBIUS_MCP_MODE": "write"` to `env`.

## Use with Claude Code

```bash
claude mcp add nebius -- uvx nebius-mcp
```

## Tool surface

51 tools across 8 domains. Use `check_environment` first to verify auth.
Use `get_manifest` once and pin the SHA-256 to detect later tampering.

| Domain | Read | State | Destructive |
|---|---|---|---|
| **Ops** | `ping`, `check_environment`, `get_manifest` | — | — |
| **IAM** | `iam_whoami`, `iam_list_projects`, `iam_get_project` | — | — |
| **Compute** | `compute_list_instances`, `compute_get_instance`, `compute_list_disks`, `compute_get_disk`, `compute_list_platforms` | `compute_start_instance`, `compute_stop_instance` | `compute_create_instance`, `compute_delete_instance`, `compute_delete_disk` |
| **mk8s** | `k8s_list_clusters`, `k8s_get_cluster`, `k8s_list_node_groups`, `k8s_get_node_group`, `k8s_list_control_plane_versions` | — | `k8s_delete_cluster`, `k8s_delete_node_group` |
| **AI Endpoints** | `ai_list_endpoints`, `ai_get_endpoint`, `ai_get_endpoint_by_name` | `ai_start_endpoint`, `ai_stop_endpoint` | `ai_delete_endpoint` |
| **VPC** | `vpc_list_networks`, `vpc_get_network`, `vpc_list_subnets`, `vpc_get_subnet`, `vpc_list_security_groups`, `vpc_get_security_group`, `vpc_list_allocations`, `vpc_get_allocation` | — | `vpc_delete_network`, `vpc_delete_subnet`, `vpc_delete_security_group`, `vpc_delete_allocation` |
| **Registry** | `registry_list`, `registry_get`, `registry_list_images`, `registry_get_image` | — | `registry_delete`, `registry_delete_image` |
| **Secrets** | `secrets_list`, `secrets_get`, `secrets_list_versions`, `secrets_reveal_payload` | — | — |

### Known SDK gaps

The Nebius proto/SDK does not currently include RPCs for:

- `ai endpoint update`
- `ai endpoint logs` (and log-tail in general)

These will be added via a CLI fallback in a later milestone after a
specific security review of the subprocess attack surface.

## Develop

```bash
uv sync                       # install runtime + dev deps
uv run pytest                 # 59 unit tests, no Nebius traffic
uv run ruff check .           # lint
uv run ruff format --check .  # formatting check
uv run mypy src               # strict type check
./scripts/security_audit.sh   # local mcp-scan / snyk-agent-scan run
```

Pre-commit hooks (ruff, mypy, gitleaks, basic file-system checks) are
configured in `.pre-commit-config.yaml`:

```bash
uv tool install pre-commit
pre-commit install
```

## License

Apache-2.0 — see [LICENSE](LICENSE).

The skill repo at https://github.com/opencolin/nebius-skill informed the
operation coverage list and the validation rules. nebius-mcp is not
otherwise affiliated with Nebius B.V.
