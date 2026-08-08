# Handoff

State of the work, so another agent or person can continue without replaying
the session. Update this when you finish a chunk.

**Last updated:** 2026-08-08, after the review-and-README pass.

## Where things stand

`main` is green: 94 unit tests, ruff, ruff format, mypy strict, and a docs
link check, on Python 3.11/3.12/3.13.

The server exposes 57 tools — 51 purpose-built, plus 6 generic ones that reach
all 59 SDK resource types. See [the README](../README.md#tool-surface).

### Merged this session

| PR | What |
|---|---|
| [#1](https://github.com/opencolin/nebius-mcp/pull/1) | Generic catalog layer; SDK upgraded to 0.4.x; three bug fixes |
| [#2](https://github.com/opencolin/nebius-mcp/pull/2) | Corrected an inflated coverage claim |
| [#3](https://github.com/opencolin/nebius-mcp/pull/3) | Audit log moved off stdout, which was corrupting JSON-RPC |
| [#4](https://github.com/opencolin/nebius-mcp/pull/4) | Profile authentication made to work at all |

Every defect is written up in [REVIEW-FINDINGS.md](REVIEW-FINDINGS.md),
including how each was caught. Read that before reviewing — the techniques
section lists what actually finds bugs here, and repeating them is cheaper
than rediscovering them.

### In flight

Branch `readme-overhaul` — a full README rewrite plus:

- a real CLI (`--version`, `--check`) where `--help` previously printed nothing
- `scripts/check_docs_links.py`, wired into CI
- the write gate enforced as a tested invariant over the whole tool surface
- one dead helper removed and one false README claim corrected

It cannot merge until `docs/ROADMAP.md` and `docs/plans/` exist, because the
README links to them and the new link check fails otherwise. The roadmap
council writes those.

## What to do next

1. **Merge `readme-overhaul`** once the roadmap docs land.
2. **Publish to PyPI** — the single highest-value item. Until then every
   install goes through the git URL. See R-004.
3. **Work the roadmap** — [ROADMAP.md](ROADMAP.md), then the matching file in
   [plans/](plans/).

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

All four must pass; CI runs them on 3.11, 3.12, and 3.13.

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run python scripts/check_docs_links.py
```

## Conventions

- Branch per change, PR into `main`, squash merge. No direct pushes to `main`.
- Commit messages explain *why*, and state what a change does not do.
- New defects go in [REVIEW-FINDINGS.md](REVIEW-FINDINGS.md) with a note on
  how they were found.
- A claim in the README is a promise. Verify it or do not write it — three of
  the defects this session were the README describing behaviour the code did
  not have.
