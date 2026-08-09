#!/usr/bin/env bash
# Local security audit: scans the registered tool surface for known
# prompt-injection / tool-poisoning patterns using snyk-agent-scan
# (formerly mcp-scan from Invariant Labs).
#
# Run from the repo root:
#   ./scripts/security_audit.sh
#
# The scanner needs to launch this server as a subprocess to enumerate its
# tools. It does NOT invoke any tool, so no Nebius credentials are required
# and nothing in your cloud account is touched. To keep that true rather than
# merely intended, the scanner is run with a constructed environment instead of
# yours — see SCAN_ENV below.
#
# `scan` (full verification against Snyk's analysis service) needs SNYK_TOKEN.
# Without one, this falls back to `inspect`, which enumerates the tool surface
# locally and offline.

set -euo pipefail

# Pin the scanner. `@latest` resolved to whatever was published most recently,
# so two runs a day apart could audit the same tree with different code and
# different rules, and an upgrade landed with nothing to review. Bump this
# deliberately; check what is current with:
#   curl -s https://pypi.org/pypi/snyk-agent-scan/json | python3 -c \
#     'import json,sys; print(json.load(sys.stdin)["info"]["version"])'
SCANNER_VERSION="0.5.16"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
CONFIG="$ROOT/.mcp-config.local.json"
REPORT="$(mktemp -t nebius-mcp-audit)"
# A throwaway HOME for the scanner, so `~/.nebius/config.yaml` resolves to
# nothing for it and for every process it starts.
SCAN_HOME="$(mktemp -d -t nebius-mcp-audit-home)"

cleanup() { rm -f "$CONFIG" "$REPORT"; rm -rf "$SCAN_HOME"; }
trap cleanup EXIT

cat > "$CONFIG" <<JSON
{
  "mcpServers": {
    "nebius-mcp-local": {
      "command": "uv",
      "args": ["run", "--directory", "$ROOT", "nebius-mcp"]
    }
  }
}
JSON

# The environment handed to the scanner, built up rather than inherited.
#
# This is third-party code that launches subprocesses, and a machine set up for
# this project typically has NEBIUS_IAM_TOKEN exported and a populated
# ~/.nebius/config.yaml — live credentials for a real cloud account. Nothing in
# enumerating a tool surface needs them, so nothing here passes them on. What is
# left is what uv needs to resolve an interpreter and reuse its caches (without
# UV_CACHE_DIR and UV_PYTHON_INSTALL_DIR, the redirected HOME would make uv
# re-download everything into a directory this script then deletes).
#
# This narrows what the scanner is handed; it does not sandbox it. The process
# still runs as you and can read any file you can, ~/.nebius/config.yaml
# included, if it goes looking by absolute path.
SCAN_ENV=(
  PATH="$PATH"
  HOME="$SCAN_HOME"
  TMPDIR="${TMPDIR:-/tmp}"
  UV_CACHE_DIR="$(uv cache dir)"
  UV_PYTHON_INSTALL_DIR="$(uv python dir)"
)

if [ -n "${SNYK_TOKEN:-}" ]; then
  MODE=scan
  SCAN_ENV+=(SNYK_TOKEN="$SNYK_TOKEN")
  echo "[security_audit] SNYK_TOKEN set — running full verification"
else
  MODE=inspect
  echo "[security_audit] no SNYK_TOKEN — running local inspect only"
  echo "[security_audit] set SNYK_TOKEN (https://app.snyk.io/account) for full verification"
fi

# --dangerously-run-mcp-servers skips the interactive consent prompt. Without
# it the scanner blocks on stdin, or — if stdin is closed, as in CI — records
# "user_declined" and still exits 0, so the audit silently inspects nothing.
# Consent is implicit here: the only server in the config is this repo's own.
env -i "${SCAN_ENV[@]}" \
  uvx "snyk-agent-scan@$SCANNER_VERSION" "$MODE" "$CONFIG" \
  --no-skills \
  --dangerously-run-mcp-servers \
  --suppress-mcpserver-io=true \
  --json > "$REPORT" || true

cat "$REPORT"

# Exit non-zero on a declined or failed scan. A green exit must mean the tool
# surface was actually examined, not that the scanner gave up quietly.
python3 - "$REPORT" <<'PY'
import json, sys

try:
    with open(sys.argv[1]) as fh:
        report = json.load(fh)
except (OSError, json.JSONDecodeError) as exc:
    print(f"\n[security_audit] FAILED: could not parse scanner output: {exc}", file=sys.stderr)
    raise SystemExit(1)

declined, failed, issues = [], [], []

def walk(node):
    if isinstance(node, dict):
        if node.get("category") == "user_declined":
            declined.append(node)
        if node.get("is_failure"):
            failed.append(node)
        if isinstance(node.get("issues"), list):
            issues.extend(node["issues"])
        for value in node.values():
            walk(value)
    elif isinstance(node, list):
        for item in node:
            walk(item)

walk(report)

if declined:
    print("\n[security_audit] FAILED: scanner was not allowed to start the server, "
          "so nothing was inspected.", file=sys.stderr)
    raise SystemExit(1)
if failed:
    print(f"\n[security_audit] FAILED: {len(failed)} scan failure(s) reported.", file=sys.stderr)
    raise SystemExit(1)
if issues:
    print(f"\n[security_audit] {len(issues)} issue(s) found.", file=sys.stderr)
    raise SystemExit(1)

print("\n[security_audit] OK: tool surface inspected, no issues reported.")
PY
