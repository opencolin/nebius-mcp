# Review findings

A running log of defects found while reviewing completeness and functionality,
with the state of each. Newest first. Every entry names how it was found, so
the same technique can be reapplied.

This file is for *findings*. Forward-looking work lives in
[ROADMAP.md](ROADMAP.md) and [plans/](plans/).

## Open

### R-004 — `nebius-mcp` is not published to PyPI

**Severity:** high. Every install path in the README fails.

`https://pypi.org/pypi/nebius-mcp/json` returns 404. The README documents
`uv tool install nebius-mcp`, `uvx nebius-mcp`, and
`claude mcp add nebius -- uvx nebius-mcp`. All three fail for anyone who has
not cloned the repo.

Two paths do work today and were verified end to end:

```bash
uvx --from git+https://github.com/opencolin/nebius-mcp nebius-mcp
```

```bash
uv run --directory /path/to/nebius-mcp nebius-mcp
```

**Fix:** document the git-based invocation now; publish to PyPI and switch the
docs back. Tracked as a v0.2.0 item.

**Found by:** querying the PyPI JSON API for the name the README tells people
to install.

### R-007 — Two validators are written but never called

**Severity:** low, but the README asserted them as features.

`validation.py` defines `validate_id` and `validate_static_ip_cidr`. Neither
is referenced by any tool — only by their own unit tests. The README claimed
`/32` suffix and resource-ID format checking among the guard rails; that
claim has been corrected to describe only what is enforced
(`validate_disk_type`, `validate_boot_disk_size`).

Wiring `validate_id` broadly is not obviously safe: the patterns in
`_ID_PATTERNS` are inferred rather than documented, so a stricter-than-reality
pattern would reject valid IDs and break working setups. Decide deliberately —
either confirm the formats against the API and wire them in, or delete them.

**Found by:** grepping for references to every public helper, rather than
assuming exported functions are used.

## Fixed

### R-006 — `check_environment` reported credentials that cannot authenticate

**Severity:** high.

A profile being *present* is not the same as it being *usable*. A
`federation` profile with no `federation-id`, or a service-account profile
missing its key, parses fine and then fails on the first API call. The
preflight tool reported `has_credentials: true` with a resolved `parent_id`,
which is maximally misleading precisely when someone is trying to work out
why every tool errors.

**Fix:** `resolve_credentials` now returns `profile_problem`, checking only
shapes confirmed to fail. `check_environment` surfaces it and puts it first
in `next_steps`. `has_any` accounts for it, and `get_sdk` reports the
specific problem instead of the generic "no credentials found" message that
tells you to create a profile you already have.

An explicit `NEBIUS_IAM_TOKEN` still wins over a broken profile, per
precedence rule 1 — that ordering bug appeared in the first cut of this fix
and is covered by a test now.

**Found by:** calling a live tool and comparing what happened to what
`check_environment` had just claimed.

### R-005 — Profile and `NEBIUS_PROFILE` authentication never worked

**Severity:** critical.

`get_sdk()` constructed a bare `SDK()` on the stated assumption that its
"built-in Config" would apply the documented precedence. It does not. A bare
`SDK()` falls back to `EnvBearer` and raises
`NoTokenInEnvError: No token found in the environment variable: NEBIUS_IAM_TOKEN`
unless that variable is set.

So precedence rules 2 and 3 — `NEBIUS_PROFILE` and `~/.nebius/config.yaml` —
were dead. Every tool failed for anyone who set up the documented way, with
`nebius profile create` / `nebius iam login`. Only an exported token worked.

**Fix:** build the SDK with an explicit
`config_reader=nebius.aio.cli_config.Config(...)`, which implements the whole
precedence including the env token, so one path covers all three sources.
Also passes `federation_invitation_no_browser_open=True`: this process is an
MCP server attached to a client's stdio, and must never try to open a
browser. `no_parent_id=True` because parent is resolved per tool, and
`NoParentIdError` at construction would break every tool on a profile with no
default project.

**Found by:** calling a read-only tool against the live API. No unit test
could catch this — they all mock the service layer, so `get_sdk` never runs.
**The lesson: mocking at the client boundary leaves credential resolution
completely untested.**

### R-003 — Audit log written to stdout, corrupting the JSON-RPC stream

**Severity:** critical. Fixed in #3 (`fd3eae4`).

The server speaks MCP over stdio, so stdout is the protocol channel. Every
tool call wrote its audit record there, and clients parsed each one as a
JSON-RPC message, producing a `JSONRPCError` per call.

`audit.py` called `logging.basicConfig(stream=sys.stderr)`, which appears to
handle this but does not — structlog is not routed through stdlib logging
here, and its default `PrintLoggerFactory` writes to stdout. The module
docstring, README, and CHANGELOG all already claimed stderr.

**Fix:** `logger_factory=structlog.PrintLoggerFactory(file=sys.stderr)`.
Regression test in `tests/unit/test_audit_stream.py` runs a real subprocess
and asserts stdout is empty.

**Found by:** driving the server over a real stdio transport instead of
in-process `Client(app)`. In-process clients never open a pipe, so stdout and
the protocol stream are different objects and the collision cannot occur.
**This is the lesson worth keeping: some defects only exist at the transport
boundary.**

### R-002 — `proto_to_dict` broken on `nebius>=0.4`

**Severity:** critical. Fixed in #1 (`af5a52b`).

Serialized every tool result through `google.protobuf`'s `MessageToDict`,
which raises `AttributeError: DESCRIPTOR` on the self-contained message
classes the 0.4 codegen produces. Every tool call would have failed with a
generic API error after the SDK upgrade.

**Fix:** use the SDK's native `to_json`, keeping the protobuf path as a
fallback for the 0.3 line.

**Found by:** upgrading the SDK and running the suite.

### R-001 — Unit tests read the developer's real `~/.nebius/config.yaml`

**Severity:** medium. Fixed in #1 (`af5a52b`).

The "no parent configured" branches resolved a live project ID, so two tests
failed on any machine that had used the `nebius` CLI. CI passed only because
the runner has no `~/.nebius`.

**Fix:** `tests/conftest.py` pins the config path somewhere guaranteed absent.

**Found by:** running the suite on a developer machine rather than trusting CI.

### R-000 — SDK pin excluded the entire 0.4 line

**Severity:** medium. Fixed in #1 (`af5a52b`).

`nebius>=0.3.63,<0.4` locked out KMS, application tunnels, disk snapshots,
NVLink instance groups, DNS writes, capacity allowances, and `restart` on
endpoints and jobs.

**Fix:** `nebius>=0.4.4,<0.5`. Note this is what surfaced R-002.

### C-001 — CI `security scan` job had never passed

**Severity:** medium. Fixed in #1 (`af5a52b`).

`gitleaks-action` diffs `<sha>^..<sha>`, which needs the parent commit; the
default shallow checkout has one, so git errored and the job exited 1 after
scanning ~0 bytes. Red on every run in the repo's history, having never
inspected anything.

**Fix:** `fetch-depth: 0` on the checkout.

**Found by:** reading the job log of a check that was assumed to be a known
failure.

## Review techniques that paid off

Recorded so future reviews start here rather than rediscovering them.

1. **Drive the server over a real stdio transport.** Found R-003, which no
   in-process test could ever catch.
2. **Call a tool against the live API.** Found R-005 and R-006. The unit
   suite mocks the service layer, so `get_sdk` — and therefore all credential
   resolution — never executes in tests.
3. **Check that documented install commands actually resolve.** Found R-004.
4. **Run the test suite on a machine with real credentials present.** Found
   R-001.
5. **Read the logs of CI jobs that are failing, even long-standing ones.**
   Found C-001.
6. **Verify claims in the README against the code and the network**, rather
   than assuming the author checked.
7. **Compare what a diagnostic tool reports against what actually happens.**
   Found R-006.
