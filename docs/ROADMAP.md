# Roadmap

Sequenced plan from today's `0.1.0` working tree through `2.0.0`.

This file is the index and the decision record. The authoritative task list,
with full acceptance criteria, files touched, risks, and a definition of done,
lives in one plan document per release under [plans/](plans/). The tables here
carry a condensed, checkable form of each acceptance criterion; the plan doc is
what an agent picks up work from.

Defects already found live in [REVIEW-FINDINGS.md](REVIEW-FINDINGS.md). This
file is forward-looking only.

## How this was decided

Five product managers each reviewed the repository through one lens and
proposed an independent roadmap. This document merges them.

| Lens | Core argument |
|---|---|
| Developer experience | Time to first successful tool call is currently infinite: `uvx nebius-mcp` 404s on PyPI. A 57-tool server nobody can install has a real-world tool-call count of zero. |
| Platform coverage | 90 of 305 catalog operations are unreachable and Token Factory is 0% reachable. The server is an excellent inspection tool and a near-useless infrastructure tool. |
| Security and trust | The project has the vocabulary of security without the mechanics. The confirm token is minted and consumed by the same party; `secrets_reveal_payload` is annotated identically to `ping`; redaction misses `cloud_init_user_data`. |
| Adoption and ecosystem | Nothing is findable. PyPI 404, no git tags, no GitHub releases, zero results in the MCP registry. Nothing in the first release should be a new tool. |
| Reliability | The last two commits each fixed a bug that made the server completely unusable, and both shipped green. Nothing in this repository has ever made one authenticated call to Nebius. |

### Conflicts resolved

Each line is a decision the five proposals disagreed on, with the reason.

1. **Coverage wanted generic create/update in the first release; DX, adoption
   and reliability wanted install and truth.** Install and truth win. A create
   tool nobody can install is worth zero, and `nebius_resource_create` plus
   `nebius_describe_operation` is genuinely M-sized work that cannot ship in
   days. Write coverage is the headline of v0.3.0 instead.
2. **Token Factory: coverage wanted it at v0.3.0, adoption at v2.0.0.**
   v0.4.0. It needs an HTTP client and a second credential axis that do not
   exist yet, so pairing it with v0.3.0's write coverage doubles the untested
   surface in one release. It must land before v1.0.0 because "no capability
   answers go use the console" is the v1.0.0 bar.
3. **Remote HTTP transport: security wanted it at v0.4.0, DX and adoption
   wanted a hosted service at v2.0.0.** Split. `auth._sdk_instance`,
   `client._clients` and `confirm._active` are all process-global; three lenses
   found this independently. Session-scoped state plus a loopback-only HTTP
   transport land at v1.0.0. A hosted, multi-tenant, OAuth-fronted service is
   an operational commitment, not a code change, and earns the major version.
4. **Growing the tool surface versus the per-turn schema cost.** Both are
   right, so `NEBIUS_MCP_TOOLSETS` lands in v0.3.0 — the same release that
   starts adding tools. Progressive disclosure via `notifications/tools/list_changed`
   is v2.0.0 because it requires capability negotiation and a fallback path.
5. **The confirm token.** Security proved it is a typo guard, not an injection
   defense. Correcting the false claim in `src/nebius_mcp/confirm.py` is free
   and lands at v0.2.0. Replacing it with MCP elicitation needs client
   capability negotiation and a documented fallback, so it lands at v1.0.0.
6. **Telemetry. Direct conflict.** DX proposed opt-in onboarding telemetry so
   time-to-first-successful-tool-call is measured; adoption proposed a test
   asserting the server never makes an outbound call outside the Nebius SDK
   path. Adoption wins: a server holding cloud credentials that phones home is
   disqualifying for the security-conscious audience this project targets.
   Onboarding times are recorded as dated, hand-run transcripts under
   `docs/onboarding-runs/` instead.
7. **Documentation site.** Adoption wanted a generated Starlight site early.
   v1.0.0. A generated tool reference whose generator has no committed manifest
   lock is more surface to rot; the lock file lands first.
8. **soperator and Slurm.** Coverage put it at v1.0.0 as the Nebius
   differentiator. v2.0.0. Its acceptance requires a gated nightly install on a
   real two-node GPU cluster, which is a standing cost and an operations
   commitment. v1.0.0 states the gap in the README rather than pretending to
   cover it.
9. **Composite deploy tools.** Coverage put them at v0.4.0. v1.0.0. They depend
   on create coverage (v0.3.0), idempotency keys (v0.4.0), and rollback
   assertions that only a live integration suite can make (v0.4.0).
10. **MCP resources and prompts.** DX wanted them at v0.4.0, coverage at
    v2.0.0. v1.0.0, paired with the manifest schema change that hashes them,
    so `get_manifest` never silently omits part of the surface it claims to
    cover.

### Sizes

`S` is under a day for one agent. `M` is one to three days. `L` is a week or
more, or depends on infrastructure that does not exist yet.

## Ground truth this plan was written against

Verified by running the code in the working tree on 2026-08-08, not by reading
documentation.

This is a dated snapshot of the tree the plan was written against, kept as the
record of *why* each release was scoped the way it was. Some of it has since
been fixed by the releases below and by the entries in
[REVIEW-FINDINGS.md](REVIEW-FINDINGS.md). Where a bullet is no longer true it
is struck through with a pointer, rather than deleted — the original
observation is what justifies the plan item.

- `_build_app()` registers exactly **57 tools**. `manifest_summary()` returns
  sha256 `4282464cd0f99a17bba2cc7223379865dbbf834c0ee758df90b44e99765257e5`.
- `catalog.RESOURCES` holds **59** entries deriving **305** operations. Verb
  histogram: list 57, get 55, create 46, delete 46, update 40, get_by_name 33,
  undelete 5, start 4, stop 4, activate 3, deactivate 3, restart 2, cancel 2,
  resume 1, upgrade 1, purge 1, issue 1, revoke 1. **215** are reachable
  through the generic tools; **90** are not.
- `pytest tests/unit` collects and passes **92** tests in this working tree.
  `README.md:537` says "90 unit tests" and
  [HANDOFF.md](HANDOFF.md) says 94 on the in-flight branch. The number has now
  been wrong at 82, 84, 85, 90, 92 and 94 across four documents — which is the
  argument for generating it rather than asserting it, and why no plan document
  below states a target test count.
- `tests/integration/` contains only an empty `__init__.py`. CI runs
  `pytest tests/unit` explicitly. Nothing has ever made an authenticated call.
- `.github/workflows/ci.yml` is the only workflow: a py3.11/3.12/3.13 matrix
  running ruff, ruff format, `mypy src`, `pytest tests/unit -v`, and
  `scripts/check_docs_links.py`, plus a gitleaks `security-scan` job. No
  release workflow, no dependency audit, no SBOM, no signing.
- ~~`validation.validate_id` and `validation.validate_static_ip_cidr` have no
  call sites.~~ Both deleted; a test now asserts every public validator is
  reachable from `src/`. See R-007.
- `src/nebius_mcp/tools/k8s.py:167` names `k8s_create_cluster`, which is not
  registered, and that string is inside the hashed manifest.
  `src/nebius_mcp/tools/secrets.py:6` names `secrets_get_payload_metadata`,
  which is not registered.
- `grep '@app.resource\|@app.prompt' src/` returns nothing. `grep 'httpx\|tokenfactory'`
  over `src/` and `pyproject.toml` returns nothing.
- ~~`sanitize.py` matches 13 exact key names and 4 substrings, lowercasing but
  not stripping underscores, so `secretKey` and `accessKeySecret` pass
  through. Its module docstring claims "We also cap response sizes"; no size
  cap exists in the file.~~ Key names are now normalized (case and separators
  both folded), so `secretKey` and `accessKeySecret` are redacted; the retracted
  size-cap sentence is gone from the docstring. The counts have moved to 19
  exact names and 5 substrings, plus a benign-name exemption list. See v0.2.0
  item 5, and R-019, R-012 and R-013. A response size cap is still not
  implemented — that part remains open, as v0.4.0 item 10.
- ~~`errors.to_tool_error` collapses every failure to
  `NebiusAPIError (<ClassName>): <str(exc)>` and does not pass the message
  through `sanitize.redact`.~~ It now routes the detail through
  `sanitize.redact_text` and frames it with the data preamble. See v0.2.0
  item 6. The taxonomy half — error codes and retryability — is still open as
  v0.3.0 item 5.
- ~~`audit.log_call` records `sha256(args)[:16]` and writes `str(exc)[:200]`
  unredacted.~~ The error text is redacted before it is truncated, in that
  order deliberately. The argument hash is unchanged and is still the gap
  `SECURITY.md` records under Known gaps; widening it is v0.4.0 item 10.
- `client.service()`, `auth.get_sdk()` and `confirm._active` are all
  process-global.
- The working tree carries uncommitted changes adding `--version` and
  `--check` to `src/nebius_mcp/server.py`, and a README rewritten to cover
  Claude Code, Claude Desktop, Codex CLI, Cursor and VS Code with a
  git-based install. The roadmap assumes these land.

---

## v0.2.0 — Ship what exists, truthfully

**Goal.** Everything in this repository already works well enough to be worth
installing, and nobody can install it. This release publishes the package,
deletes every claim the code does not support, and closes the two safety
defects that are cheap to fix and expensive to leave. No new Nebius capability
is added. It should be shippable in days by one agent, and the measure of
success is that a stranger following the README reaches `iam_whoami` and that
every sentence they read on the way is true.

Full plan: [plans/v0.2.0.md](plans/v0.2.0.md)

| # | Item | Size | Acceptance (condensed) |
|---|---|---|---|
| 1 | Publish to PyPI with a tag-driven Trusted Publishing workflow | M | `curl https://pypi.org/pypi/nebius-mcp/json` returns 200 with `info.version == "0.2.0"`; `uvx nebius-mcp@0.2.0 --version` exits 0; `.github/workflows/release.yml` triggers on `v*` tags with `id-token: write` and no `PYPI_API_TOKEN` in the repo. |
| 2 | Version, changelog and release hygiene gate | S | A CI job fails when `pyproject.toml` version, the git tag, and the top `CHANGELOG.md` section disagree; `RELEASING.md` exists; `uv build` emits no PEP 639 classifier warning. |
| 3 | Docs-truth CI gate, and fix every false claim | M | `scripts/check_docs.py` fails on today's tree with at least four findings and passes after the fix; no tool name appears in any doc or docstring that `list_tools()` does not return; counts are generated, not typed. |
| 4 | Reclassify `secrets_reveal_payload` and gate it independently | S | Its annotations become `readOnlyHint: False, destructiveHint: True`; with `NEBIUS_MCP_ALLOW_SECRET_REVEAL` unset the tool raises and `PayloadServiceClient` is never constructed; the tool requires the confirm two-step. |
| 5 | Close the redaction bypasses | M | A table-driven test in `tests/unit/test_sanitize.py` returns `<redacted>` for `secretKey`, `accessKeySecret`, `cloud_init_user_data`, `client_key_data`, `kubeconfig`, a PEM header, and an `X-Amz-Signature` URL; seven of those pass through in the clear today. |
| 6 | Redact and cap the error path | S | `errors.to_tool_error` and `audit.log_call` both pass their message through `sanitize.redact`; a test raising an exception whose text contains a JWT asserts `<redacted>` in both the ToolError and the captured audit line. |
| 7 | An honest `SECURITY.md`, and delete the false security claims | M | `SECURITY.md` has a threat-model table marking each threat mitigated, partial or not mitigated with a `file:line` link; a CI grep asserts the strings "spec-recommended mitigation" and "so well-behaved clients prompt the user" appear nowhere in `src/`. |
| 8 | stdio protocol conformance test | S | `tests/unit/test_stdio_protocol.py` spawns the installed console script, completes `initialize` → `tools/list` → `tools/call ping`, and asserts every stdout line parses as JSON-RPC and `tools/list` returns 57 tools. |
| 9 | Finish the command-line front door | S | `--help` documents every flag and every environment variable; `--print-config {claude-code,claude-desktop,codex,cursor,vscode}` emits that client's exact snippet and exits 2 on an unknown value; bare invocation passes `show_banner=False` and emits no third-party text. |

**Done when.** All nine items pass their plan-document acceptance criteria; a
`v0.2.0` tag exists and its release workflow published to PyPI; `uvx nebius-mcp`
works from a cold cache on macOS and Linux; `scripts/check_docs.py`,
`ruff check`, `ruff format --check`, `mypy src --strict` and `pytest tests/unit`
are green in CI; and the manifest sha256 changed (items 3 and 7 edit hashed
descriptions), with the old and new values both recorded in `CHANGELOG.md`.

---

## v0.3.0 — It can build things, and you can bound what it builds

**Goal.** Close the largest capability gap in the repository — 46 create and 40
update operations reachable by nothing — using the schema-driven path rather
than 86 hand-written tools, and in the same release give an operator a way to
say which of those operations the agent may reach. Adding write reach without
adding a bound is the version of this release that no security team would
accept, so the two ship together. The tool surface starts growing here, so the
toolset selector that makes the growth opt-out ships here too.

Full plan: [plans/v0.3.0.md](plans/v0.3.0.md)

| # | Item | Size | Acceptance (condensed) |
|---|---|---|---|
| 1 | `nebius_resource_create` and `nebius_resource_update` | M | Requests built via `catalog.request_class(key, verb)` then `RequestCls.from_json(body)`; `require_write()` runs before verb validation so a read-mode server returns a byte-identical error for supported and unsupported types; an unknown JSON field raises naming the field. |
| 2 | `nebius_describe_operation` | M | Returns the request field tree from `get_descriptor().fields_by_name` for any `(resource_type, verb)`; a parametrized test walks all 305 pairs and asserts none raises; `mk8s.cluster/create` output contains `metadata.parent_id` and `spec.control_plane`. |
| 3 | Typed `k8s_create_cluster` and `k8s_create_node_group` | M | Control-plane version validated against `list_control_plane_versions` before any create RPC; an invalid version returns an error listing valid versions with a recorded create-call count of zero. |
| 4 | `k8s_get_kubeconfig` | M | Returns YAML that `yaml.safe_load` parses, with `users[0].exec.command == "nebius"` and no embedded credential; `sanitize.redact(output)` is byte-identical to the input; no `subprocess` import is added to `src/`. |
| 5 | Error taxonomy with codes, retryability and a next step | M | `to_tool_error` maps gRPC status to a closed set of 12 `NEBIUS_*` codes, each carrying `retryable` and a one-line `next_step`; `tests/unit/test_errors.py` covers all 12. |
| 6 | Operation tools, and no false success | S | `nebius_operation_get` and `nebius_operation_wait` registered; `maybe_wait` raises `NEBIUS_OPERATION_FAILED` when done and unsuccessful; `grep 'maybe_wait(' src/nebius_mcp/tools/` shows no call outside the error mapper. |
| 7 | Policy file and project boundary pinning | L | `NEBIUS_MCP_POLICY` allow/deny globs over tool names and resource-type keys, enforced in middleware and in `confirm.require_write`; denied tools are absent from `list_tools()`; `NEBIUS_MCP_ALLOWED_PARENTS` refuses an out-of-list `parent_id` before any SDK call. |
| 8 | Toolsets | M | `NEBIUS_MCP_TOOLSETS` and `--toolsets` accept a comma list; `core` registers 12 or fewer tools and a test asserts its serialized manifest is under 15,000 characters; unset registers everything, unchanged. |
| 9 | Destructive rate limit and ticket cap | S | `NEBIUS_MCP_MAX_DESTRUCTIVE_PER_SESSION` (default 5) is enforced across every path reaching a delete or irreversible action; a test issues six valid confirm cycles and asserts the sixth SDK call never happens; `confirm._active` gains a size cap. |

**Done when.** Every catalog resource exposing `create` can build its request
class from `{}` without raising, proven by a parametrized test; a read-mode
server is not an operation-existence oracle, proven by byte-identical error
comparison; a policy file limited to `compute_*` and `ops_*` measurably reduces
`list_tools()` and blocks `nebius_resource_delete` on an IAM service account
even in write mode with a valid confirm token; and the four quality gates stay
green.

---

## v0.4.0 — The second plane, and proof that any of it works

**Goal.** Two things this project has never had. First, a live test: every
assertion about Nebius behaviour in this repository is currently made against a
mock, and the last two shipped bugs were both invisible to mocks. Second,
Token Factory — inference, files, fine-tuning — which is what Nebius sells to
AI builders and which is unreachable today for the mundane reason that there is
no HTTP client and no API-key auth path. Around them, the reliability substrate
that 57 tools have been sitting on without: retries, idempotency keys, a rate
budget, correct pagination, and a request id a user can hand to support.

Full plan: [plans/v0.4.0.md](plans/v0.4.0.md)

| # | Item | Size | Acceptance (condensed) |
|---|---|---|---|
| 1 | Integration harness and a CI job that runs it | S | `tests/integration/conftest.py` provides `requires_iam` and `requires_token_factory` markers; `pytest tests/integration` with no credentials exits 0 by skipping; a gated CI job runs it with repository secrets and is skipped for fork pull requests. |
| 2 | Live read smoke suite | M | At least ten live tests covering `iam_whoami`, `iam_list_projects`, the four list tools, `check_environment`, and `nebius_resource_list` for five or more resource types, all passing against a real tenant. |
| 3 | HTTP client and the Token Factory credential axis | M | `httpx` **promoted** to a declared dependency (fastmcp already requires it, so zero new wheels); `auth.resolve_token_factory_credentials()` reads `NEBIUS_TOKEN_FACTORY_API_KEY`, then `NEBIUS_API_KEY` **only when the value is not a JWT and not the `ne1…` IAM shape** — Nebius's own Sandboxes docs use that variable for an IAM token, so a blind fallback ships a production-delete credential to an inference endpoint — then the profile; resolves `ai_project_id` from environment and profile only, never as a tool argument; `check_environment` reports both planes side by side; a 401 surfaces as a typed error, never an httpx traceback. |
| 4 | Model catalog and base-URL resolution | S | `GET /v1/models?verbose=true` returns `RichModel`, whose required fields include `pricing` and `context_length` — returning `{id, owned_by}` discards them; pricing is passed through as the raw strings the API sends, because the units are undocumented; a unit test asserts **neither** `api.studio.nebius.com` **nor** `api.studio.nebius.ai` appears under `src/` (both legacy hosts are live and answer identically); `tokenfactory_resolve_base_url` warns that regional hosts serve subsets. |
| 5 | `tokenfactory_chat_completion` and `tokenfactory_embeddings` | M | Returns a distilled shape wrapped by `sanitize.wrap()`, because model output is untrusted text entering the agent's context; embeddings omit float arrays unless `include_vectors=True`; streaming is explicitly out of scope in the tool description. |
| 6 | Token Factory files and fine-tuning | L | Two dispatchers, not nine tools, and they must cover both checkpoint endpoints — `fine_tuned_model_checkpoint` is the id passed back to chat completion, so omitting them ships a surface that starts a job and cannot collect its output. **`create` goes through `preview_or_execute`, not just `delete`/`cancel`**: cancel stops spend, create commits it. Endpoint paths come from the public OpenAPI document, not a live tenant; `docs/token-factory-api.md` is **generated** from the vendored spec with a `git diff --exit-code` check, because this project has already had a hand-maintained count wrong six times. |
| 7 | Retryable call path | M | `errors.safe_call(factory, *, idempotent, timeout)` replaces `safe`; `grep 'await safe(' src/` returns zero, down from 46; retries only on transient codes and only when `idempotent=True`; create, delete and action verbs make exactly one attempt. |
| 8 | Idempotency keys on every mutation | S | A deterministic key derived from tool name, canonical arguments and confirm token is set on every create, delete and lifecycle request; a live test issues the same create twice and asserts exactly one resource exists afterwards. |
| 9 | Rate budget and pagination correctness | M | A token bucket caps requests per second and in-flight calls; an unsupported `page_token` or `filter` raises naming the resource type instead of being silently dropped; a test enumerates every list-capable resource and asserts its response exposes both `items` and `next_page_token`. |
| 10 | Correlatable, redacted, size-bounded observability | M | Audit records gain `request_id`, `trace_id`, `duration_ms`, `error_code`, `resource_id` and `result_bytes`; `NEBIUS_MCP_AUDIT_ARGS` defaults to redacted rather than hashed; `sanitize.wrap` enforces a response byte cap with a `truncated` flag. (The `decision` field this item originally listed is partly delivered: `outcome` already distinguishes `previewed` from `ok` and `error` — see R-011 — so what remains is the policy decision from v0.3.0 item 7, not the preview/execute one. The byte cap is also no longer a docstring-truth fix: `wrap`'s docstring stopped claiming truncation when the retracted claims were removed in v0.2.0, so this is now a plain feature addition.) |
| 11 | SDK contract suite and a nightly dependency canary | M | A golden verb histogram pins the 305-operation total and fails on drift; a matrix job runs the contract suite against the lowest and highest allowed `nebius`; a nightly `uv lock --upgrade` run opens an issue on failure. |

**Done when.** `pytest tests/integration` passes against a live tenant in CI on
a schedule; `tokenfactory_chat_completion` returns text from a real model;
`check_environment` reports both credential planes; the golden verb histogram
matches 305; and a `uv lock --upgrade` failure reaches a GitHub issue before it
reaches a user.

---

## v1.0.0 — Recommend it to strangers

**Goal.** The bar is that nothing a competent user wants is answered with "go
use the console", every one of those capabilities has been executed against a
real tenant on the exact commit being tagged, the artifact they install is
verifiable, and the surface they build against is under a written contract.
This is the release where claims stop being self-assessed and start being
mechanically enforced: the tag itself is blocked if the live conformance run is
not green.

Full plan: [plans/v1.0.0.md](plans/v1.0.0.md)

| # | Item | Size | Acceptance (condensed) |
|---|---|---|---|
| 1 | 100% catalog reachability with a CI-enforced coverage report | M | `scripts/coverage_report.py` writes `coverage.json`; `test_no_unreachable_verbs` fails today against 90 operations and passes against all 305; CI fails when the percentage printed in the README disagrees with the file. |
| 2 | Full-surface live conformance, gating the tag | L | Every registered tool is exercised against a live tenant; a meta-test asserts the set difference between registered and exercised names is empty; `release.yml` refuses to publish unless conformance is green on that exact SHA. |
| 3 | Write-path integration suite with guaranteed teardown | L | An ephemeral project is created and torn down in a `finally` block; the full create/start/stop/delete lifecycle runs through the real two-step confirm; a token minted for different arguments is rejected; a reaper deletes CI-labelled resources older than six hours and the nightly job fails when anything leaked. |
| 4 | Composite `nebius_deploy_vm` and `nebius_deploy_gpu_cluster` | L | Idempotent by name, proven by create-call counts across two invocations; one `preview_or_execute` gate covers the whole plan; a failure injected at the instance step leaves zero orphaned disks, subnets or networks. |
| 5 | Token Factory completion: Data Lab (which subsumes batch — there is no `/v1/batches`; batch inference is an `OperationType` on `POST /v1/operations`). Dedicated endpoints are **dropped**: they provision GPUs and bill continuously until deleted, the one cost shape no per-call gate bounds, on an unstable `/v0/` contract | M | Batch results are written to disk and never inlined into model context; every `tokenfactory_*` description begins with the plane and credential it uses and every `ai_*` description with the other, enforced across the live registry; a Data Lab negative result is an acceptable outcome if recorded with its verification date. |
| 6 | Session-scoped state, and a loopback HTTP transport | L | Confirm tickets, service-client caches and SDK instances are keyed by session; two concurrent sessions with different credentials get different SDK instances by identity and cannot redeem each other's confirm tokens; `--transport http` binds `127.0.0.1`, 401s unauthenticated requests, 403s unknown origins, and refuses a public bind without an explicit flag. |
| 7 | Real human-in-the-loop via MCP elicitation | M | Destructive tools elicit before any SDK call when the client advertises the capability; `NEBIUS_MCP_REQUIRE_ELICITATION=1` makes a non-supporting client a hard failure; declining the elicitation provably prevents the delete call. |
| 8 | Verifiable releases | L | Attestations, a CycloneDX SBOM and Sigstore signatures on every release; `gh attestation verify` exits 0; every `uses:` is pinned to a 40-character SHA; a dependency audit job fails on HIGH or CRITICAL. |
| 9 | Frozen tool surface and `nebius-mcp verify` | M | `manifest.lock.json` is committed and a contract test fails on any undeclared drift; a rename or removal requires a major bump; `nebius-mcp verify` exits non-zero naming the changed tool. |
| 10 | MCP resources and prompts, and a manifest that covers them | M | Catalog, environment and platform resources plus at least four prompts are returned by `list_resources()` and `list_prompts()`; `manifest.py` hashes them and gains a schema version field. |
| 11 | Documentation site with a generated tool reference | L | The tool reference is generated from `manifest_summary()` and CI fails on `git diff --exit-code`; a coverage gate fails when any registered tool lacks a worked request and response example; the site builds and deploys on release. |
| 12 | Verified onboarding matrix, `doctor`, and platform truth | M | `docs/COMPATIBILITY.md` has a client × version × OS × date table with a Windows row and a Linux row, every row verified within 30 days of the tag; `nebius-mcp doctor` output is provably redacted; the CI matrix, `requires-python` and the classifiers agree, with Python 3.14 resolved either way. |
| 13 | Failure-injection suite over the reliability core | M | Every mapped status code, a mid-stream disconnect, an expired token, a done-but-failed operation and a truncated page are each driven by an injected fault; branch coverage of at least 90% on `errors.py`, `operation.py`, `pagination.py`, `client.py` and `confirm.py`. |
| 14 | Release QA gate and the adoption gate | M | `release.yml` runs the full ordered gate including `pytest -W error` with an explicit third-party allowlist and an install-from-wheel stdio smoke; the tag is held until the package has been on PyPI 30 days with a non-zero download trend and at least one issue or pull request from someone who is not the author. |

**Done when.** All 14 items pass; the conformance job is green on the tagged
SHA; `coverage.json` reports 305 of 305; `gh attestation verify` succeeds
against the published wheel; `docs/COMPATIBILITY.md` has no row older than 30
days and none over five minutes; and the adoption gate in item 14 is satisfied
or `0.5.0` ships instead.

**Explicitly not in v1.0.0.** soperator and Slurm, Sandboxes, a hosted remote
service, per-caller credential exchange, and schema-driven synthesis of the
hand-written tool modules. The README must state the soperator gap rather than
imply coverage.

---

## v2.0.0 — Shared infrastructure, and coverage that maintains itself

**Goal.** Two shifts justify a major version. The server stops being a
per-developer process holding one ambient credential and becomes shared
infrastructure where each caller authenticates as themselves and the server
holds no standing cloud secret. And covering a new Nebius service stops being a
new hand-written module and becomes a data change, so the coverage number from
v1.0.0 is sustainable rather than a one-time sprint. On top of those, the
capabilities that only make sense once both hold: code execution, Slurm, and
cross-plane workflows no other client can express.

Full plan: [plans/v2.0.0.md](plans/v2.0.0.md)

| # | Item | Size | Acceptance (condensed) |
|---|---|---|---|
| 1 | Hosted remote server with OAuth 2.1 and per-caller credential exchange | L | RFC 9728 protected-resource metadata; audience validation rejecting tokens minted for other resources; scopes mapping to policy profiles so a read-scoped token sees no write tool in `list_tools()`; the server stores no long-lived cloud secret; two tenants proven isolated at the SDK-construction layer. |
| 2 | Zero-terminal install: per-platform `.mcpb` bundles | L | Bundles for darwin-arm64, darwin-x64, linux-x64 and win-x64, because the runtime tree is roughly 106 MB with platform-specific binary wheels and a universal bundle is not possible; write mode is an explicit enum in `user_config`; a clean machine with no Python installs by double-click. |
| 3 | Progressive tool disclosure | L | The initial `list_tools()` payload serializes under 4,000 characters; every generic-reachable operation stays reachable within one expansion step; clients without `list_changed` still see the full surface. |
| 4 | Schema-driven tool synthesis | L | Hand-written per-resource modules shrink to promotion declarations; total `src/` line count drops at least 30% from its v1.0.0 value with every input schema behaviourally equivalent; adding a fixture resource plus one promotion line yields working typed tools with no other code change. |
| 5 | soperator and Slurm lifecycle | L | Install validates a GPU node group and a mounted filesystem before issuing the release; a gated nightly installs on a two-node cluster, submits a job, asserts it completes, and uninstalls leaving zero releases. |
| 6 | ~~Sandboxes: code execution as a first-class surface~~ **DROPPED** | — | Nebius ships `contree-mcp` first-party: 0.3.0 on PyPI, 17 tools, plus a CLI and a Python SDK. Building this would reimplement a vendor-maintained server and add 28 operations to a surface already past the documented tool-count and token thresholds. It is also the wrong shape for this server's gates: a `sandbox_exec` tool would let an injection carried in a resource name — the channel the first threat row in `SECURITY.md` concedes is only *partially* mitigated — reach arbitrary code execution. The README points at `contree-mcp` instead. See [plans/v0.4.0-tokenfactory.md](plans/v0.4.0-tokenfactory.md). |
| 7 | Cross-surface composites | L | `nebius_finetune_and_deploy` and `nebius_train_on_slurm` chain both planes behind one credential resolver; both are resumable, proven by recording which steps re-executed; a nightly runs the full chain and asserts zero surviving files, jobs or endpoints. |
| 8 | Approval-queue write mode | L | `NEBIUS_MCP_WRITE_MODE=queue` enqueues a change request instead of executing; the MCP process never calls the destructive SDK method, asserted by monkeypatching it and proving it is unreachable; approval, rejection and expiry are audited with approver identity. |
| 9 | Tamper-evident audit with SIEM-native sinks | L | Hash-chained records; `nebius-mcp audit verify` detects a single mutated byte and names the broken link; file, syslog, OTLP and object-storage sinks; a fail-closed mode that refuses tool calls when the sink is down. |
| 10 | Policy as code with pre-flight simulation | L | `policy test` statically enumerates every reachable operation split into read, state-change and irreversible; `policy diff` shows what a change adds or removes; JSON output usable as a CI gate on widening destructive reach. |
| 11 | Continuous conformance and published SLOs | L | Hourly runs across at least two regions and three tenant shapes including an empty project, a 500-plus-resource project and a restricted-IAM project; per-tool 30-day pass rate and latency published; an exhausted error budget blocks a tag. |
| 12 | Structural injection resistance | L | Cloud-sourced strings are provenance-tagged, length-capped and control-character-stripped, and delivered in a structurally distinct position from server-authored guidance; the corpus grows to at least 100 payloads including encoded and homoglyph variants; the measured resistance rate is published per release. |
| 13 | Distribution the project does not control | M | Listed in at least two properties the author does not own, one of them a Nebius channel; versioned documentation so a user pinned to 1.x never reads 2.x tool names, verified by fetching both paths. |
| 14 | Self-healing catalog across unknown SDK versions | L | The pin widens with runtime capability probing; an SDK outside the tested set yields a probed catalog with per-resource confidence reported by `check_environment`; zero user-visible tool loss across three consecutive minors, asserted by diffing manifests. |

**Done when.** A team shares one URL, each member's `iam_whoami` returns their
own identity, and the server holds no standing cloud credential; a new Nebius
service is covered by editing data rather than writing a module; and "is
nebius-mcp working right now" has a public, data-backed answer.

---

## Item counts

| Release | Items | Theme |
|---|---|---|
| v0.2.0 | 9 | Ship what exists, truthfully |
| v0.3.0 | 9 | It can build things, and you can bound what it builds |
| v0.4.0 | 11 | The second plane, and proof that any of it works |
| v1.0.0 | 14 | Recommend it to strangers |
| v2.0.0 | 14 | Shared infrastructure, and coverage that maintains itself |
