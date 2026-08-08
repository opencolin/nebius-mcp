# Handoff

State of the work, so another agent or person can continue without replaying
the session. Update this when you finish a chunk.

**Last updated:** 2026-08-08, after the review, README, and v0.2.0 fan-out.

## Where things stand

`main` is green: 97 unit tests, ruff, ruff format, mypy strict, and a docs
link check, on Python 3.11/3.12/3.13. Verified end to end over a real stdio
transport, not just in process.

The server exposes 57 tools — 51 purpose-built, plus 6 generic ones that reach
all 59 SDK resource types. See [the README](../README.md#tool-surface).

### Merged this session

| PR | What |
|---|---|
| [#1](https://github.com/opencolin/nebius-mcp/pull/1) | Generic catalog layer; SDK upgraded to 0.4.x; three bug fixes |
| [#2](https://github.com/opencolin/nebius-mcp/pull/2) | Corrected an inflated coverage claim |
| [#3](https://github.com/opencolin/nebius-mcp/pull/3) | Audit log moved off stdout, which was corrupting JSON-RPC |
| [#4](https://github.com/opencolin/nebius-mcp/pull/4) | Profile authentication made to work at all |
| [#5](https://github.com/opencolin/nebius-mcp/pull/5) | Cloud-init user data redacted; it was leaking provisioning secrets |
| [#6](https://github.com/opencolin/nebius-mcp/pull/6) | README rewrite, `--version`/`--check` CLI, write-gate invariant, roadmap and plans |
| [#7](https://github.com/opencolin/nebius-mcp/pull/7) | Tag-driven PyPI release pipeline with Trusted Publishing |
| [#8](https://github.com/opencolin/nebius-mcp/pull/8) | Security audit script, which had been silently checking nothing |

Every defect is written up in [REVIEW-FINDINGS.md](REVIEW-FINDINGS.md),
including how each was caught. Read that before reviewing — the techniques
section lists what actually finds bugs here, and repeating them is cheaper
than rediscovering them.

### In flight

Five v0.2.0 tasks are being implemented in parallel git worktrees under
`../nebius-mcp-worktrees/`, each on its own branch, each adversarially
verified before merge:

| Branch | Task |
|---|---|
| `v0.2.0-T2-release-hygiene-gate` | Version/changelog drift check on every PR |
| `v0.2.0-T4-secrets-reveal-gate` | `secrets_reveal_payload` is annotated identically to `ping` on the two hints clients gate on — verified true |
| `v0.2.0-T5-redaction-bypasses` | Key normalization misses camelCase; PEM and presigned-URL patterns |
| `v0.2.0-T6-error-path-redaction` | Errors bypass the sanitizer entirely |
| `v0.2.0-T7-honest-security-doc` | `SECURITY.md`; delete the false "spec-recommended mitigation" claim |

If you are picking this up cold and those branches exist but are unmerged,
review each against its acceptance criteria in
[plans/v0.2.0.md](plans/v0.2.0.md), then merge and remove the worktree:

```bash
git worktree remove ../nebius-mcp-worktrees/T5 --force
```

Already done from the v0.2.0 plan: T1 (release pipeline, #7), T9 (CLI front
door, #6), and parts of T3 (docs link gate) and T5 (cloud-init, #5).

## What to do next

1. **Register the PyPI trusted publisher** — the pipeline is built and
   verified, but the one-time registration can only be done by the repo
   owner. Steps are in `.github/workflows/release.yml` and R-004. Until then
   every install goes through the git URL. This is the highest-value item.
2. **Enable GitHub private vulnerability reporting**, which `SECURITY.md`
   names as the disclosure channel. Also owner-only.
3. **Land the five in-flight branches**, then continue with
   [plans/v0.3.0.md](plans/v0.3.0.md).

## Things worth knowing before you change anything

**Unit tests mock the service layer**, so `get_sdk` never runs and credential
resolution is untested by them. Two critical bugs (R-005, R-006) lived there.
If you touch `auth.py`, verify against a real profile or a real token, not
just the suite.

**In-process `Client(app)` cannot catch transport bugs.** It never opens a
pipe, so anything written to stdout looks harmless. That hid R-003, where the
audit log was corrupting the protocol stream on every call. To check the real
thing:

```python
from fastmcp.client.transports import StdioTransport
t = StdioTransport(command="uv", args=["run", "--directory", "/path/to/repo", "nebius-mcp"])
```

**The catalog derives request classes at runtime.** `catalog.py` parses the
SDK's private annotation aliases because `typing.get_type_hints` fails on
several generated modules — one unresolvable name poisons the whole module.
If an SDK upgrade changes that alias format, `tests/unit/test_catalog.py`
fails loudly, which is the intended behaviour. Do not paper over it by
hard-coding request classes.

**`parent_id` is not always a project.** Node groups belong to a cluster,
security rules to a security group, access keys to a service account. This is
encoded per resource in `catalog.RESOURCES` and is the most common source of
confusing empty results.

**Two validators are dead.** `validate_id` and `validate_static_ip_cidr` are
never called. Do not wire them in casually — the ID patterns are inferred, not
documented, so a too-strict pattern would reject valid IDs. See R-007.

## Quality gates

All of these must pass; CI runs them on 3.11, 3.12, and 3.13. Do not write a
count here — it said "four" while listing five.

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run python scripts/check_docs_links.py
uv run python scripts/check_release_hygiene.py
uv run python scripts/check_security_doc.py
```

## Conventions

- Branch per change, PR into `main`, squash merge. No direct pushes to `main`.
- Commit messages explain *why*, and state what a change does not do.
- New defects go in [REVIEW-FINDINGS.md](REVIEW-FINDINGS.md) with a note on
  how they were found.
- A claim in the README is a promise. Verify it or do not write it — three of
  the defects this session were the README describing behaviour the code did
  not have.
