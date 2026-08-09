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
| Indirect prompt injection through cloud metadata | Partial | `src/nebius_mcp/sanitize.py:227`, `src/nebius_mcp/sanitize.py:332` | Every tool result carrying Nebius API content is wrapped in an envelope telling the model the content is data, not instructions. (Three tools return an unwrapped value today — `ping`, `check_environment`, `get_manifest` — and none of them touches the Nebius API.) This is advice to a model, not enforcement. It raises the cost of an attack; it does not make one impossible, and nothing measures how often it works. |
| Accidental destruction by the model | Partial | `src/nebius_mcp/confirm.py:122`, `src/nebius_mcp/confirm.py:41` | A delete refuses on the first call and returns a preview plus a single-use token bound to the exact arguments, valid 120 seconds. It stops a single mis-aimed call and puts the target in the transcript before anything happens. It is **not** an injection defense: the token goes to the model, the model replays it, and no human is required — `tests/unit/test_destructive_flow.py:98` mints and consumes one in two back-to-back calls. |
| Tool poisoning and rug pull | Partial | `src/nebius_mcp/manifest.py:49`, `src/nebius_mcp/tools/ops.py:174` | `get_manifest` returns a SHA-256 over every tool name, description, annotation and input schema, so a changed tool surface is detectable between sessions. Detection only, and only if you record the hash out of band and compare it. A server that is already hostile can return any hash it likes. |
| Credential blast radius | **Not mitigated** | `src/nebius_mcp/server.py:54`, `src/nebius_mcp/confirm.py:113` | The server acts with the full permissions of whatever token or profile it resolved, and never narrows them. Write mode is one global boolean — see below. |
| Secret exfiltration | Partial | `src/nebius_mcp/sanitize.py:28`, `src/nebius_mcp/sanitize.py:140`, `src/nebius_mcp/tools/secrets.py:234` | Known-sensitive field names and token-shaped values are redacted recursively from every response that goes through the sanitizer. This is a denylist: a field the list does not name is returned verbatim. The value patterns run on both paths and cover JWTs, `ne1…` Nebius tokens, PEM private-key blocks, presigned-URL parameters, URL userinfo, and GitHub, Slack, AWS and Azure credential shapes — but they are still a denylist, and every issuer not on that list is returned in the clear. Two API-sourced values do not go through the sanitizer at all, and both are deliberate: `secrets_reveal_payload`'s plaintext, and every paginated list tool's `next_page_token` (whose own field name matches the denylist, so redacting it would replace every pagination cursor). The separate rule that catches a credential written as `name=value` *inside* a string runs on the error path only — see Known gaps. |
| Audit tampering | **Not mitigated** | `src/nebius_mcp/audit.py:172`, `src/nebius_mcp/audit.py:143` | Every tool call is logged as JSON to the server's own stderr: tool name, a truncated SHA-256 of the arguments, mode, outcome. There is no integrity protection, no sequence numbering and no remote sink, so anyone who can run the server can drop or forge lines — which is why this row is *not mitigated* regardless of what the record contains. The outcome now distinguishes `previewed` from `ok` (`src/nebius_mcp/audit.py:209`), so the log does answer "did this delete actually happen?" where it previously could not. It still records an argument *hash* rather than the arguments, so it does not tell you what the delete targeted — see Known gaps. |
| Supply-chain compromise | Partial | `.github/workflows/release.yml:94`, `.github/workflows/ci.yml:67` | Releases publish through PyPI Trusted Publishing (OIDC), so there is no long-lived API token in the repository to steal. gitleaks runs in CI and as a pre-commit hook. Against that: every GitHub Action is pinned to a full commit SHA with the human-readable tag kept as a trailing comment, so re-pointing a tag no longer changes what runs — but nothing renews those pins, so they go stale silently and a pinned action stops receiving its own security fixes; `uv.lock` binds CI only, and anyone installing from PyPI resolves dependencies freshly within the version ranges in `pyproject.toml`; and nothing in this repository verifies a published artifact after the fact. |

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

These are tracked, not hidden. Each names the review finding that carries the
detail. Neither has a task that closes it yet, and naming one here would be
inventing a schedule that does not exist.

- **The audit log records only a hash of the arguments.** Every tool call is
  logged with `args_hash` (`src/nebius_mcp/audit.py:172`), a truncated SHA-256,
  rather than the arguments themselves. The log can now tell you that a delete
  executed rather than only previewed — see the threat table — but not what it
  targeted. Recovering the target means knowing the arguments in advance and
  re-deriving the hash, which is only useful for confirming a guess. Widening
  this is task 10 of v0.4.0 in [docs/ROADMAP.md](https://github.com/opencolin/nebius-mcp/blob/main/docs/ROADMAP.md), which specifies
  `NEBIUS_MCP_AUDIT_ARGS` defaulting to redacted rather than hashed.

- **The in-string assignment rule runs on one path only.** The sanitizer has
  two ways to catch a credential. Field names are matched wherever the payload
  is a mapping, and the value patterns run on both paths. But a secret written
  as `name=value` *inside* a string — `db_password=hunter2` in an error
  message, a query string, a cloud-init fragment quoted into a description —
  needs `_redact_assignments` (`src/nebius_mcp/sanitize.py:488`), and that rule
  runs only in `redact_text` (`src/nebius_mcp/sanitize.py:517`), which is the
  error path. `redact` (`src/nebius_mcp/sanitize.py:306`), which every
  successful response goes through, applies the value patterns and nothing
  else. So the same credential is removed from a failure and returned from a
  success. Three attempts have now been made. Two moved the rule and were
  reverted for damage only benchmarking found; the third rewrote it in place
  and deliberately did not move it, because on the success path the rule still
  strips the port off `token-service.internal:8443` and the tag off
  `my-secrets-app:v1.4.2`. Tracked as R-015 in
  [docs/REVIEW-FINDINGS.md](docs/REVIEW-FINDINGS.md).

  Two narrower findings under this heading are now **closed** and are no longer
  gaps: R-012, the quoted spelling (`{"secret_key": "…"}`) defeating the rule
  on the error path, and R-013, the credential shapes no rule named at all —
  URL userinfo, GitHub, Slack, AWS and Azure — which became value patterns and
  so close on both paths.
- **`previewed` is a self-report, not enforcement.** The outcome above is set
  by `confirm.preview_or_execute` (`src/nebius_mcp/confirm.py:156`), so it is
  accurate for every destructive tool that routes through the confirm gate —
  which is all of them today. A future tool that hand-rolls its own dry-run
  envelope instead would be logged `ok`, and no test fails if it does. There is
  a registry-wide test that every destructive tool is write-gated
  (`tests/unit/test_write_gate_coverage.py`); there is no equivalent for the
  confirm gate. Recorded under R-011 in
  [docs/REVIEW-FINDINGS.md](docs/REVIEW-FINDINGS.md).

The three gaps this section listed until v0.2.0 — the unsanitized error path,
`secrets_reveal_payload` annotated `readOnlyHint: true`, and key matching that
missed `secretKey` — are closed. See tasks T6, T4 and T5 in
[docs/plans/v0.2.0.md](docs/plans/v0.2.0.md).

Two more closed since: **R-011**, the audit log being unable to tell a previewed
delete from an executed one, and **R-012/R-013**, the quoted-field-name bypass
and the credential shapes no rule named. The bullets above are what remains of
each, not the whole of what they were.

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
