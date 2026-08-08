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
# and nothing in your cloud account is touched.
#
# `scan` (full verification against Snyk's analysis service) needs SNYK_TOKEN.
# Without one, this falls back to `inspect`, which enumerates the tool surface
# locally and offline.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
CONFIG="$ROOT/.mcp-config.local.json"
REPORT="$(mktemp -t nebius-mcp-audit)"

cleanup() { rm -f "$CONFIG" "$REPORT"; }
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

if [ -n "${SNYK_TOKEN:-}" ]; then
  MODE=scan
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
uvx snyk-agent-scan@latest "$MODE" "$CONFIG" \
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
