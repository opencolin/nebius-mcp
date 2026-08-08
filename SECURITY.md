# Security

`nebius-mcp` hands a language model a credential that can delete production
infrastructure. This document says what the server actually defends against,
what it does not, and where the enforcing code is. Rows marked **not
mitigated** are not oversights being hidden — they are the reason this file
exists.

## Reporting a vulnerability

Report privately, not in a public issue.

Use GitHub private vulnerability reporting: the **Security** tab of
[the repository](https://github.com/opencolin/nebius-mcp), then **Report a
vulnerability** — or go straight to
<https://github.com/opencolin/nebius-mcp/security/advisories/new>.

If that form is unavailable, open a public issue that says only that you have
a security report and asks for a private channel. Do not put details in it.

Expect an acknowledgement within seven days. This is a single-maintainer
project with no on-call rotation; there is no faster path and claiming one
would be false.

## Supported versions

| Version | Supported |
|---|---|
| Latest `0.x` release | Yes |
| Any earlier `0.x` release | No |

The project is pre-1.0. There are no maintenance branches and no backports: a
fix ships in the next release and nowhere else. Upgrade before reporting.

## Trust boundary

The server is a local process launched by an MCP client over stdio. It trusts:

- **The client**, completely. It runs in the client's process tree, reads the
  client's environment, and writes its audit log to the client's stderr.
- **The credentials it resolves** (`src/nebius_mcp/auth.py:69`), completely.
  It never narrows them.

It does not trust:

- **Anything the Nebius API returns.** Resource names, descriptions, labels
  and Kubernetes annotations are attacker-writable by anyone with write access
  to the account, including a previous compromise of the account itself.
- **The model.** Every gate assumes the model may be trying to do the wrong
  thing, whether through injection or its own error.

## Threat model

| Threat | Status | Enforcing code | What that actually buys you |
|---|---|---|---|
| Indirect prompt injection through cloud metadata | Partial | `src/nebius_mcp/sanitize.py:65`, `src/nebius_mcp/sanitize.py:131` | Every tool result is wrapped in an envelope telling the model the content is data, not instructions. This is advice to a model, not enforcement. It raises the cost of an attack; it does not make one impossible, and nothing measures how often it works. |
| Accidental destruction by the model | Partial | `src/nebius_mcp/confirm.py:113`, `src/nebius_mcp/confirm.py:41` | A delete refuses on the first call and returns a preview plus a single-use token bound to the exact arguments, valid 120 seconds. It stops a single mis-aimed call and puts the target in the transcript before anything happens. It is **not** an injection defense: the token goes to the model, the model replays it, and no human is required — `tests/unit/test_destructive_flow.py:98` mints and consumes one in two back-to-back calls. |
| Tool poisoning and rug pull | Partial | `src/nebius_mcp/manifest.py:49`, `src/nebius_mcp/tools/ops.py:160` | `get_manifest` returns a SHA-256 over every tool name, description, annotation and input schema, so a changed tool surface is detectable between sessions. Detection only, and only if you record the hash out of band and compare it. A server that is already hostile can return any hash it likes. |
| Credential blast radius | **Not mitigated** | `src/nebius_mcp/server.py:54`, `src/nebius_mcp/confirm.py:104` | The server acts with the full permissions of whatever token or profile it resolved, and never narrows them. Write mode is one global boolean — see below. |
| Secret exfiltration | Partial | `src/nebius_mcp/sanitize.py:26`, `src/nebius_mcp/tools/secrets.py:133` | Known-sensitive field names and token-shaped values are redacted recursively from every response that goes through the sanitizer. This is a denylist: a field the list does not name is returned verbatim. `secrets_reveal_payload` returns plaintext by design and is exempt. |
| Audit tampering | **Not mitigated** | `src/nebius_mcp/audit.py:56`, `src/nebius_mcp/audit.py:45` | Every tool call is logged as JSON to the server's own stderr: tool name, a truncated SHA-256 of the arguments, mode, outcome. There is no integrity protection, no sequence numbering and no remote sink, so anyone who can run the server can drop or forge lines. The log also records an argument *hash*, not the arguments, so it tells you a delete happened but not what was deleted. |
| Supply-chain compromise | Partial | `.github/workflows/release.yml:94`, `.github/workflows/ci.yml:64` | Releases publish through PyPI Trusted Publishing (OIDC), so there is no long-lived API token in the repository to steal. gitleaks runs in CI and as a pre-commit hook. Against that: every GitHub Action is pinned to a mutable tag rather than a commit SHA, so a compromised tag executes in the release job; `uv.lock` binds CI only, and anyone installing from PyPI resolves dependencies freshly within the version ranges in `pyproject.toml`; and nothing in this repository verifies a published artifact after the fact. |

## Write mode is one boolean, with no scoping

`NEBIUS_MCP_MODE=write` (`src/nebius_mcp/server.py:54`) is a single global
switch. There is no per-resource, per-project, per-tool or per-verb scoping —
it is on for everything or off for everything.

Counted from `src/nebius_mcp/catalog.py:97` against the installed SDK: the
catalog holds **59 resource types**, of which **46 expose a `delete` RPC**.
Setting write mode makes all 46 reachable through the single generic
`nebius_resource_delete` tool, alongside eleven purpose-built delete tools and
the eight lifecycle verbs dispatched by `nebius_resource_action`
(`src/nebius_mcp/tools/generic.py:49`). Regenerate the count with:

```bash
uv run python -c "from nebius_mcp import catalog; \
print(sum(catalog.supports(s.key, 'delete') for s in catalog.RESOURCES), 'of', len(catalog.RESOURCES))"
```

The only thing standing between write mode and any of those resources is the
confirm-token two-step, which the row above explains is a mistake guard rather
than an access control. If your credential can reach a project, so can the
model.

The practical mitigation today is operational, not enforced by this server:
run a read-only server for daily use, add a separate write-enabled entry only
when you need it, and give that entry a credential scoped to the project you
intend to change.

Scoping is planned work, not a shipped feature. See task T7 in
[docs/plans/v0.3.0.md](docs/plans/v0.3.0.md), which specifies a policy file
with allow/deny globs over tool names and resource types, enforcement at the
same middleware choke point as the audit log, and a `NEBIUS_MCP_ALLOWED_PARENTS`
project boundary.

## Known gaps, open as of this document

These are tracked, not hidden. Each names the task that closes it.

- **The error path does not go through the sanitizer.**
  `src/nebius_mcp/errors.py:25` interpolates the raw exception into the message
  returned to the model, and the audit log records the raw exception string.
  An API error that echoes request metadata therefore bypasses redaction.
  Closed by v0.2.0-T6.
- **`secrets_reveal_payload` is annotated `readOnlyHint: true`.** A client
  configured to auto-approve read-only tools will call it without prompting.
  Closed by v0.2.0-T4.
- **Redaction misses camelCase and several high-value keys.** Key matching
  lowercases but does not strip underscores, so `secretKey` is not caught.
  Closed by v0.2.0-T5.

See [docs/plans/v0.2.0.md](docs/plans/v0.2.0.md) for the full text of each.

## Out of scope

- **A malicious MCP client.** It launches the process and controls its
  environment; there is nothing to defend.
- **A compromised Nebius account.** The server enforces what the credential
  allows. If the credential is already in an attacker's hands, this server is
  not the relevant control.
- **Denial of service.** List page sizes are clamped
  (`src/nebius_mcp/pagination.py:14`) to protect the model's context window,
  not as a rate-limiting control. There is no rate limiting, no retry budget,
  and no cap on the size of a single serialized resource.
