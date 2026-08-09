# nebius-mcp

Manage [Nebius Cloud](https://nebius.com) from Claude, Codex, Cursor, or VS Code.

A [Model Context Protocol](https://modelcontextprotocol.io) server that gives an
AI assistant **57 tools** covering compute, managed Kubernetes, AI endpoints,
object storage, VPC, IAM, secrets, and every other resource type in the Nebius
Python SDK.

It is **read-only until you opt in**, and destructive operations need a second
confirming call — so you can point an agent at your cloud account without it
being able to delete anything by accident. What that does and does not protect
you from is written down in [Safety model](#safety-model).

This is infrastructure, not inference: it manages the resources in your Nebius
account. Nebius Token Factory — inference, fine-tuning, Data Lab, Sandboxes —
is a separate API and is [not covered](#not-covered).

> **Status: alpha, and not yet on PyPI** — install from git, as shown below.
> Tool names and arguments may still change. See the
> [changelog](https://github.com/opencolin/nebius-mcp/blob/main/CHANGELOG.md),
> the [threat model](https://github.com/opencolin/nebius-mcp/blob/main/SECURITY.md),
> and the [roadmap](https://github.com/opencolin/nebius-mcp/blob/main/docs/ROADMAP.md).
> Not affiliated with Nebius B.V.

**Jump to:** [What you can ask for](#what-you-can-ask-for) ·
[Quick start](#quick-start) · [Safety model](#safety-model) ·
[Tool surface](#tool-surface) · [Troubleshooting](#troubleshooting)

**Set up:** [Claude Code](#claude-code) · [Claude Desktop](#claude-desktop) ·
[Codex CLI](#codex-cli) · [Cursor](#cursor) · [VS Code](#vs-code)

## What you can ask for

Read-only out of the box:

> What GPU platforms are available in my tenant?

> Show me every running instance, and which GPU platform each one is on.

> Which of my storage buckets have no lifecycle policy?

> My mk8s cluster is unhealthy — show me the cluster and its node groups.

> What Nebius resource types can you see? I'm looking for something DNS-related.

After enabling [write mode](#write-mode):

> Stop the instance named `training-box`.

> Create a 4×H100 VM on the `default` subnet with my SSH key.

<a id="why-this-exists"></a>

## Why not the Nebius CLI or SDK?

Nebius ships both. Neither suits an agent on its own:

- The CLI is assembled as shell strings, which is both error-prone and a
  command-injection surface when a model builds the arguments.
- The SDK exposes 80+ service clients with no opinion about what an agent
  should be allowed to do, no guard rails on irreversible operations, and no
  checks against the well-known
  [skill](https://github.com/opencolin/nebius-skill) gotchas.

`nebius-mcp` adds the [safety model](#safety-model) below, plus validation drawn
from real failures — 50 GiB minimum boot disks for CUDA images, and
`network_ssd` with underscores rather than the `network-ssd` Nebius rejects —
each failing fast with an explanation instead of an opaque gRPC error.

## Quick start

### 1. Install `uv`

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Windows, or other options: see [the uv install docs](https://docs.astral.sh/uv/getting-started/installation/).

### 2. Get Nebius credentials

Install the [Nebius CLI](https://docs.nebius.com/cli/install) and log in:

```bash
nebius profile create
nebius iam login
```

That writes `~/.nebius/config.yaml`, which this server reads automatically.

Prefer not to install the CLI? Export a token instead — see
[Authentication](#authentication).

### 3. Check it before wiring it up

This installs the package and prints exactly what the server can see —
credentials, active profile, project. Doing it now means any problem surfaces
here rather than as a silent failure inside your editor.

```bash
uvx --from git+https://github.com/opencolin/nebius-mcp nebius-mcp --check
```

It exits non-zero and tells you what to fix if credentials are missing.

This also matters because the first run downloads and builds the package, which
can take a minute — long enough for some clients to time out if they are the
ones doing it.

### 4. Add it to your client

For Claude Code, one command:

```bash
claude mcp add nebius -- uvx --from git+https://github.com/opencolin/nebius-mcp nebius-mcp
```

Anything else — [Claude Desktop](#claude-desktop), [Codex CLI](#codex-cli),
[Cursor](#cursor), [VS Code](#vs-code) — see [Client setup](#client-setup).

### 5. Check it works

Ask your assistant:

> Check my Nebius environment.

It should call `check_environment` and report your SDK version, active profile,
and project. If anything is missing, that tool's `next_steps` field says exactly
what to fix. Then try:

> List my Nebius compute instances.

## Client setup

`nebius-mcp` itself takes no arguments and needs no environment variables, so
every client runs the same command:

```bash
uvx --from git+https://github.com/opencolin/nebius-mcp nebius-mcp
```

What differs between clients is the file format, the top-level key, and — for
Codex only — a startup timeout.

| Client | Where the config lives | Top-level key |
|---|---|---|
| [Claude Code](#claude-code) | managed by `claude mcp add`; or `.mcp.json` in the project root | `mcpServers` |
| [Claude Desktop](#claude-desktop) | `~/Library/Application Support/Claude/claude_desktop_config.json`, or `%APPDATA%\Claude\claude_desktop_config.json` | `mcpServers` |
| [Codex CLI](#codex-cli) | `~/.codex/config.toml` — **TOML** | `mcp_servers` |
| [Cursor](#cursor) | `~/.cursor/mcp.json`, or `.cursor/mcp.json` for one project | `mcpServers` |
| [VS Code](#vs-code) | `.vscode/mcp.json` | **`servers`** |

This entry is identical for every JSON client — only the key it sits under
changes. If you already have other servers configured, add it alongside them:

```json
{
  "mcpServers": {
    "nebius": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "git+https://github.com/opencolin/nebius-mcp", "nebius-mcp"]
    }
  }
}
```

Two things bite people regardless of client:

- **GUI-launched clients do not inherit your shell.** Claude Desktop, Cursor and
  VS Code start from the desktop, so neither your `PATH` nor your exported
  variables reach the server. If it will not start, replace `"uvx"` with the
  absolute path from `which uvx` (usually `~/.local/bin/uvx`, written out in
  full). For the same reason, set variables in an `env` block rather than with
  `export`.
- **The first start builds the package**, so run
  [step 3](#3-check-it-before-wiring-it-up) before wiring anything up.

> Once this is on PyPI, every `--from git+https://...` on this page collapses
> to plain `uvx nebius-mcp`.

### Claude Code

```bash
claude mcp add nebius -- uvx --from git+https://github.com/opencolin/nebius-mcp nebius-mcp
```

The `--` is required — it separates Claude's own flags from the server command.
Verify with `claude mcp list` (look for `✔ Connected`), or `/mcp` in a session.

`--scope user` enables it in every project; `--scope project` writes a
`.mcp.json` you can commit for your team. Claude Code expands `${VAR}` and
`${VAR:-default}` in `command`, `args` and `env`, so a committed file can keep
settings in your shell:

```json
"env": { "NEBIUS_MCP_MODE": "${NEBIUS_MCP_MODE:-read}" }
```

A project-scoped server needs interactive approval the first time.

### Claude Desktop

Open **Claude menu → Settings… → Developer → Edit Config**, or edit the file
directly at the path in the table above, and paste in
[the entry above](#client-setup) unchanged.

**Quit Claude Desktop completely and reopen it** — closing the window is not
enough. Then find the server under the **+** button → **Connectors**.

### Codex CLI

`startup_timeout_sec` defaults to **10 seconds**, which a cold `uvx` run will
usually exceed. Raise it as shown below, or run
[step 3](#3-check-it-before-wiring-it-up) first. Verify with `codex mcp list`,
or `/mcp` in the TUI.

```bash
codex mcp add nebius -- uvx --from git+https://github.com/opencolin/nebius-mcp nebius-mcp
```

<details>
<summary>Hand-editing <code>~/.codex/config.toml</code></summary>

This is the one client whose format genuinely differs — TOML, and the table is
`mcp_servers` with an underscore:

```toml
[mcp_servers.nebius]
command = "uvx"
args = ["--from", "git+https://github.com/opencolin/nebius-mcp", "nebius-mcp"]
startup_timeout_sec = 60

[mcp_servers.nebius.env]
NEBIUS_MCP_MODE = "read"
```

Note that `env` is a nested table, not an inline key. To pass a token from your
shell without writing it into the file, allowlist it instead of setting it:

```toml
env_vars = ["NEBIUS_IAM_TOKEN"]
```

</details>

### Cursor

**Restart Cursor, then enable the server under Customize in the sidebar** — it
does not start until you do. Logs:
<kbd>Cmd</kbd>+<kbd>Shift</kbd>+<kbd>U</kbd> → **MCP Logs**.

Paste in [the entry above](#client-setup) unchanged. Cursor expands `${env:NAME}`, so
`"NEBIUS_IAM_TOKEN": "${env:NEBIUS_IAM_TOKEN}"` in an `env` block keeps the token
out of the file.

### VS Code

**VS Code uses `servers`, not `mcpServers`** — this is the single most common
mistake when copying config between clients, so here it is spelled out rather
than left as an edit for you to make:

```json
{
  "servers": {
    "nebius": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "git+https://github.com/opencolin/nebius-mcp", "nebius-mcp"]
    }
  }
}
```

VS Code asks you to trust the server the first time it starts. Manage it with
**MCP: List Servers** in the Command Palette; **Show Output** there is where
errors appear.

<details>
<summary>The CLI one-liner, and being prompted for a token instead of storing one</summary>

```bash
code --add-mcp '{"name":"nebius","command":"uvx","args":["--from","git+https://github.com/opencolin/nebius-mcp","nebius-mcp"]}'
```

VS Code is the only client with a built-in secret prompt:

```json
{
  "inputs": [
    {
      "type": "promptString",
      "id": "nebius-iam-token",
      "description": "Nebius IAM Token",
      "password": true
    }
  ],
  "servers": {
    "nebius": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "git+https://github.com/opencolin/nebius-mcp", "nebius-mcp"],
      "env": { "NEBIUS_IAM_TOKEN": "${input:nebius-iam-token}" }
    }
  }
}
```

</details>

## Safety model

**Read-only by default.** Nothing mutates until you set
`NEBIUS_MCP_MODE=write`. Without it, every create, delete, start, and stop tool
refuses to run.

**Two-step confirm for irreversible things.** A delete returns a preview and a
single-use token bound to the exact arguments, valid for 120 seconds. Only a
second call carrying that token executes. Cancelling a job counts as
irreversible and takes the same path. This is a mistake guard, not an injection
defense — the model holds the token and can replay it without asking anyone.

**Results are labelled as data.** Every response is wrapped in an envelope
telling the model that resource names, tags, and descriptions are untrusted
input, not instructions. Token-shaped values are stripped recursively. That
raises the cost of indirect prompt injection through your own cloud metadata;
it is advice to a model, not enforcement.

**Secrets stay behind three doors.** The generic tools cannot reach any
secret-returning API. `secrets_reveal_payload` is the only tool that returns
plaintext, and it needs all of: write mode, `NEBIUS_MCP_ALLOW_SECRET_REVEAL=1`,
and the two-step confirm token. It is annotated `readOnlyHint: false,
destructiveHint: true` — not because it changes anything, but because those are
the two fields clients read when deciding what to auto-approve, and a plaintext
secret must never leave without a prompt.

**You can pin the tool surface.** `get_manifest` returns a SHA-256 over every
tool name, description, annotation, and schema. Pin it and compare between
sessions to detect tool poisoning.

**Every call is audited** to stderr as JSON: tool name, a hash of the arguments,
mode, and outcome. Never raw arguments, tokens, or secret values.

**What it does not defend against is written down too.**
[SECURITY.md](https://github.com/opencolin/nebius-mcp/blob/main/SECURITY.md) carries the threat model: one row per threat, each
marked mitigated, partial, or not mitigated, with the enforcing code named.
Read it before pointing this at an account that matters. It is also where to
report a vulnerability.

### Write mode

```bash
export NEBIUS_MCP_MODE=write
```

That works for a terminal-launched client. GUI clients do not inherit your
shell, so add it to the `env` block instead — and consider keeping two entries,
a read-only one for daily use and a write-enabled one you point at deliberately:

```json
"nebius-write": {
  "type": "stdio",
  "command": "uvx",
  "args": ["--from", "git+https://github.com/opencolin/nebius-mcp", "nebius-mcp"],
  "env": { "NEBIUS_MCP_MODE": "write" }
}
```

Give that entry a credential scoped to the project you intend to change. Write
mode is one global boolean with no per-resource scoping — [SECURITY.md](https://github.com/opencolin/nebius-mcp/blob/main/SECURITY.md)
says what that means.

## Authentication

Credentials resolve in this order:

1. **`NEBIUS_IAM_TOKEN`** — a bearer token. Best for CI. Expires after 12 hours.
2. **`NEBIUS_PROFILE`** — a named profile in `~/.nebius/config.yaml`. Set this
   only if you want a profile other than the file's own default; setting it to a
   name that does not exist is a common way to break a working setup.
3. **The default profile** in `~/.nebius/config.yaml`, set by `nebius iam login`.

Run `check_environment` to see which one resolved. It reports the problem
precisely if a profile exists but cannot authenticate.

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `NEBIUS_IAM_TOKEN` | — | Bearer token; highest precedence |
| `NEBIUS_PROFILE` | — | Profile name in `~/.nebius/config.yaml`; omit to use the file's default |
| `NEBIUS_MCP_MODE` | `read` | Set to `write` to allow mutations |
| `NEBIUS_MCP_ALLOW_SECRET_REVEAL` | unset | Set to `1` to let `secrets_reveal_payload` return plaintext secrets. Write mode and the confirm token are still required |
| `NEBIUS_MCP_LOG_LEVEL` | `INFO` | Audit log level on stderr |

Which project a tool acts on comes from the active profile's `parent-id` unless
you pass `parent_id` explicitly. `check_environment` reports the one in effect.

## Tool surface

57 tools. Call `check_environment` first; call `get_manifest` once and pin the
hash.

### Purpose-built tools (51)

| Domain | Read | State | Destructive |
|---|---|---|---|
| **Ops** | `ping`, `check_environment`, `get_manifest` | — | — |
| **IAM** | `iam_whoami`, `iam_list_projects`, `iam_get_project` | — | — |
| **Compute** | `compute_list_instances`, `compute_get_instance`, `compute_list_disks`, `compute_get_disk`, `compute_list_platforms` | `compute_start_instance`, `compute_stop_instance` | `compute_create_instance`, `compute_delete_instance`, `compute_delete_disk` |
| **mk8s** | `k8s_list_clusters`, `k8s_get_cluster`, `k8s_list_node_groups`, `k8s_get_node_group`, `k8s_list_control_plane_versions` | — | `k8s_delete_cluster`, `k8s_delete_node_group` |
| **AI Endpoints** | `ai_list_endpoints`, `ai_get_endpoint`, `ai_get_endpoint_by_name` | `ai_start_endpoint`, `ai_stop_endpoint` | `ai_delete_endpoint` |
| **VPC** | `vpc_list_networks`, `vpc_get_network`, `vpc_list_subnets`, `vpc_get_subnet`, `vpc_list_security_groups`, `vpc_get_security_group`, `vpc_list_allocations`, `vpc_get_allocation` | — | `vpc_delete_network`, `vpc_delete_subnet`, `vpc_delete_security_group`, `vpc_delete_allocation` |
| **Registry** | `registry_list`, `registry_get`, `registry_list_images`, `registry_get_image` | — | `registry_delete`, `registry_delete_image` |
| **Secrets** | `secrets_list`, `secrets_get`, `secrets_list_versions` | — | `secrets_reveal_payload` † |

The columns group tools by how they are gated, which is close to but not exactly
their MCP annotations: `compute_create_instance` sits under Destructive because it
takes the same two-step confirm, though it is annotated `destructiveHint: false`.
† `secrets_reveal_payload` destroys nothing. It carries a delete's annotations
because `readOnlyHint` and `destructiveHint` are the fields clients consult when
deciding what to auto-approve — a hint, not a guarantee. See
[Safety model](#safety-model).

**Not listed here?** Every other resource type the SDK exposes is reachable
through the six generic tools below.

### Generic tools (6) — everything else

The SDK exposes 59 resource types and 305 operations. One tool per resource per
verb would be ~300 tools, which measurably degrades tool selection in every MCP
client. Six tools take a `resource_type` instead, covering **all 59 resource
types and 215 of the 305 operations** — every read, delete, and lifecycle
action.

| Tool | Purpose |
|---|---|
| `nebius_list_resource_types` | Discovery. What exists, what operations it has, what `parent_id` means for it. Start here. |
| `nebius_resource_list` | List any resource type |
| `nebius_resource_get` | Get one by ID |
| `nebius_resource_get_by_name` | Get one by name within a parent |
| `nebius_resource_delete` | Delete. Write mode plus two-step confirm |
| `nebius_resource_action` | `start`, `stop`, `restart`, `resume`, `activate`, `deactivate`, `undelete`, `cancel` |

In practice that means asking for a bucket looks like
`nebius_resource_list` with `resource_type: "storage.bucket"`. Call
`nebius_list_resource_types` first if you do not know the key.

This is what makes object storage, DNS, KMS, quotas, capacity blocks, audit
events, managed PostgreSQL and MLflow, application tunnels, Kubernetes
application releases, IAM service accounts and keys, disk snapshots,
filesystems, GPU clusters, images, and long-running operations reachable.

**`parent_id` is not always a project.** Node groups belong to a cluster,
security rules to a security group, access keys to a service account, secret
versions to a secret. `nebius_list_resource_types` reports this per resource,
and an empty list result says which parent it actually wanted.

The remaining 90 operations are creates, updates, and key-issuing calls, left
purpose-built deliberately: nested request bodies benefit from typed tools, and
keeping `issue` and `get_secret_once` out of the generic layer is what keeps
plaintext credentials behind the single tool annotated for it.

### Not covered

- **Nebius Token Factory** — inference, fine-tuning, Data Lab, dedicated
  endpoints, Sandboxes. A separate REST API with API-key auth. See
  [the roadmap](https://github.com/opencolin/nebius-mcp/blob/main/docs/ROADMAP.md).
- `ai endpoint update` and log tailing — no SDK RPC exists.
- `mk8s cluster get-credentials` (kubeconfig) — CLI only, no SDK RPC.

## Troubleshooting

**Start here.** Run the preflight from a terminal — it needs no client:

```bash
uvx --from git+https://github.com/opencolin/nebius-mcp nebius-mcp --check
```

Its `next_steps` field names the specific problem. Inside a client, the
`check_environment` tool reports the same thing.

<details>
<summary>The server does not appear, or fails to start</summary>

Run the command yourself — the error is usually obvious:

```bash
uvx --from git+https://github.com/opencolin/nebius-mcp nebius-mcp
```

It should print a startup banner and then wait. <kbd>Ctrl</kbd>+<kbd>C</kbd> to exit.

If that works but your client still fails, it is almost always `PATH`: GUI apps
do not inherit your shell environment. Use the absolute path from `which uvx`.

</details>

<details>
<summary>It times out on first start</summary>

The first run resolves and builds the package. Pre-warm it:

```bash
uvx --from git+https://github.com/opencolin/nebius-mcp nebius-mcp --check
```

In Codex, also raise `startup_timeout_sec` — the default is 10 seconds.

</details>

<details>
<summary>"Nebius profile is not usable" / "No Nebius credentials found"</summary>

Your profile exists but cannot authenticate — for example `auth-type:
federation` with no `federation-id`. Re-run:

```bash
nebius iam login
```

Or bypass the profile with a token:

```bash
export NEBIUS_IAM_TOKEN=$(nebius iam get-access-token)
```

Tokens last 12 hours.

</details>

<details>
<summary>"profile '...' is not defined in the config file"</summary>

`NEBIUS_PROFILE` is set to a name that does not exist in `~/.nebius/config.yaml`,
and it overrides the file's own default. Unset it, or set it to a name that is
actually in the file:

```bash
unset NEBIUS_PROFILE
```

If your client sets it in an `env` block, remove it there. You only need it when
you want a profile other than the default.

</details>

<details>
<summary>A tool returns an empty list</summary>

Usually the wrong `parent_id`. Many resources are not parented by a project —
node groups belong to a cluster, security rules to a security group. The
response's `_note` says which parent that resource wanted. Call
`nebius_list_resource_types` to confirm.

</details>

<details>
<summary>"write mode is disabled"</summary>

Working as intended. Set `NEBIUS_MCP_MODE=write` in your client's `env` block
and restart the server. See [Write mode](#write-mode).

</details>

<details>
<summary>"secrets_reveal_payload: disabled"</summary>

Also working as intended. Revealing a plaintext secret needs a second opt-in
beyond write mode: add `"NEBIUS_MCP_ALLOW_SECRET_REVEAL": "1"` to your client's
`env` block and restart. Prefer `secrets_get`, which returns metadata only.

</details>

<details>
<summary>Where are the logs?</summary>

The server writes JSON audit lines to stderr. Your client captures them:

- **Claude Code**: `claude mcp list`, or `/mcp` in session
- **Claude Desktop**: `~/Library/Logs/Claude/mcp-server-nebius.log` on macOS,
  `%APPDATA%\Claude\logs\mcp-server-nebius.log` on Windows. `mcp.log` in the
  same directory carries the client side of the connection. Follow it with
  `tail -F ~/Library/Logs/Claude/mcp-server-nebius.log`
- **Cursor**: <kbd>Cmd</kbd>+<kbd>Shift</kbd>+<kbd>U</kbd> → MCP Logs
- **VS Code**: **MCP: List Servers** → your server → **Show Output**
- **Codex**: `codex mcp list`

Raise detail with `NEBIUS_MCP_LOG_LEVEL=DEBUG`.

</details>

## Development

```bash
git clone https://github.com/opencolin/nebius-mcp
cd nebius-mcp
uv sync

uv run pytest                 # unit tests, no Nebius traffic
uv run ruff check .           # lint
uv run ruff format --check .  # formatting
uv run mypy src               # strict type check
./scripts/security_audit.sh   # snyk-agent-scan over the tool surface
```

Requires Python 3.11+. Run the server straight from a checkout:

```bash
uv run nebius-mcp
```

Pre-commit hooks (ruff, mypy, gitleaks) are in `.pre-commit-config.yaml`:

```bash
uv tool install pre-commit && pre-commit install
```

Planning docs live in [docs/](https://github.com/opencolin/nebius-mcp/blob/main/docs/): the [roadmap](https://github.com/opencolin/nebius-mcp/blob/main/docs/ROADMAP.md),
[per-release plans](https://github.com/opencolin/nebius-mcp/blob/main/docs/plans/), and a [findings log](https://github.com/opencolin/nebius-mcp/blob/main/docs/REVIEW-FINDINGS.md)
recording defects and how each was caught.

## License

Apache-2.0 — see [LICENSE](https://github.com/opencolin/nebius-mcp/blob/main/LICENSE).

The [nebius-skill](https://github.com/opencolin/nebius-skill) repo informed the
operation coverage list and the validation rules.
