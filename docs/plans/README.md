# Release plans

One document per release, from `v0.2.0` through `v2.0.0`. Each is written so an
agent with no prior context can open it, pick a task, and finish it without
asking anyone a question.

| Plan | Theme | Items |
|---|---|---|
| [v0.2.0.md](v0.2.0.md) | Ship what exists, truthfully | 9 |
| [v0.3.0.md](v0.3.0.md) | It can build things, and you can bound what it builds | 9 |
| [v0.4.0.md](v0.4.0.md) | The second plane, and proof that any of it works | 11 |
| [v1.0.0.md](v1.0.0.md) | Recommend it to strangers | 14 |
| [v2.0.0.md](v2.0.0.md) | Shared infrastructure, and coverage that maintains itself | 14 |

The sequencing rationale, the conflicts that were resolved to produce it, and
the ground truth it was written against live in [../ROADMAP.md](../ROADMAP.md).
Defects already found and their status live in
[../REVIEW-FINDINGS.md](../REVIEW-FINDINGS.md). The current state of the tree,
what is in flight, and the traps that have already cost this project time live
in [../HANDOFF.md](../HANDOFF.md) — read it before touching `auth.py`,
`catalog.py`, or anything that writes output.

## How to pick up work

1. Read [../ROADMAP.md](../ROADMAP.md) first. It explains why the releases are
   ordered the way they are, which matters when a task looks like it could be
   done earlier.
2. Open the plan for the **lowest unshipped release**. Do not start a v0.4.0
   item while v0.3.0 items are open unless the plan says the item is
   independent. The ordering encodes real dependencies — for example, retries
   are impossible until `errors.safe` is replaced with a request factory,
   because `nebius.aio.request.Request.__await__` raises on re-await.
3. Inside a plan, tasks are ordered. Take the first one whose dependencies are
   met and that nobody has claimed.
4. Claim it by opening a pull request whose title starts with the task
   identifier, for example `v0.3.0-T4:`. There is no separate claim mechanism.
5. Work the task's acceptance criteria literally. They are written as commands
   and assertions, not as intent. If a criterion cannot be met as written,
   change the plan document in the same pull request and say why — do not
   quietly satisfy a weaker version.
6. Run the quality gates before opening the pull request.

## Quality gates

Every pull request must leave these green. They are what
`.github/workflows/ci.yml` runs today on Python 3.11, 3.12 and 3.13.

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src            # configured strict in pyproject.toml
uv run pytest tests/unit
uv run python scripts/check_docs_links.py
```

Additional rules that CI does not yet enforce but reviewers do:

- **New behaviour needs a test.** The two most serious defects this project has
  shipped — the audit log on stdout, and a bare `SDK()` that ignored
  `~/.nebius/config.yaml` — both passed a fully green suite. Mocking at the
  service-client boundary means `get_sdk` never executes, and in-process
  `Client(app)` never opens a pipe. Prefer a subprocess test at the transport
  boundary and a live test at the credential boundary.
- **Never write to stdout from server code.** On the stdio transport, stdout is
  the JSON-RPC channel. Logging goes to stderr through the structlog factory
  configured in `src/nebius_mcp/audit.py`. The only stdout writes allowed are
  in code paths that exit instead of serving, such as `--version` and
  `--check` in `src/nebius_mcp/server.py`.
- **Tool descriptions are hashed.** `get_manifest` returns a SHA-256 over every
  tool's name, description, annotations and input schema. Editing a docstring
  changes it. Any pull request that changes the hash must record the old and
  new values in `CHANGELOG.md`.

## Conventions used in these documents

**Task identifiers.** `v0.3.0-T4` is the fourth task in the v0.3.0 plan. They
are stable; if a task is dropped, its number is retired rather than reused.

**Sizes.** `S` is under a day for one agent. `M` is one to three days. `L` is a
week or more, or depends on infrastructure that does not exist yet.

**Acceptance criteria** are written so that another agent can verify them
without judgement. "Returns a helpful error" is not acceptance; "raises
`ToolError` whose message contains `iam_list_projects`, asserted in
`tests/unit/test_errors.py`" is. Where a criterion names a number measured from
the current tree, that number is stated so a change to it is visible.

**Files likely touched** is a starting point, not a boundary. It exists so an
agent can judge overlap with someone else's in-flight task before starting.

**Unknowns are stated as unknowns.** Several tasks depend on facts nobody in
this project has verified — Token Factory endpoint paths, whether Data Lab has
a public REST surface, whether `validate_id`'s inferred patterns match the real
API. Those tasks begin with a discovery step and treat a documented negative
result as a valid outcome. Do not guess and ship.

## Repository layout an agent will need

```
src/nebius_mcp/
  server.py         _build_app(), is_write_mode(), main() and the CLI flags
  auth.py           credential resolution, AuthError, get_sdk() singleton
  client.py         service() client cache, process-global today
  catalog.py        RESOURCES (59 specs), verbs(), request_class()
  confirm.py        dry-run and confirm-token machinery, _active dict
  errors.py         to_tool_error(), safe()
  sanitize.py       proto_to_dict(), redact(), wrap(), DATA_PREAMBLE
  audit.py          structlog middleware, stderr-bound
  manifest.py       build_manifest(), hash_manifest(), manifest_summary()
  operation.py      maybe_wait()
  pagination.py     page-size defaults and cap
  validation.py     validate_disk_type, validate_boot_disk_size, and two
                    validators with no call sites (see REVIEW-FINDINGS R-007)
  tools/            ops, iam, compute, k8s, ai, vpc, registry, secrets, generic
tests/
  unit/             92 tests, all mocked at the service-client boundary
  integration/      empty __init__.py only, as of 0.1.0
scripts/
  check_docs_links.py   runs in CI
  security_audit.sh     not wired into CI
.github/workflows/
  ci.yml            the only workflow
```
