#!/usr/bin/env bash
# Local security audit: scans the registered tool surface for known
# prompt-injection / tool-poisoning patterns using snyk-agent-scan
# (formerly mcp-scan from Invariant Labs).
#
# Run from the repo root:
#   ./scripts/security_audit.sh
#
# This does NOT require live Nebius credentials — the scanner only
# introspects tool descriptions/schemas, it does not invoke them.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
CONFIG="$ROOT/.mcp-config.local.json"

cat > "$CONFIG" <<'JSON'
{
  "mcpServers": {
    "nebius-mcp-local": {
      "command": "uv",
      "args": ["run", "--directory", ".", "nebius-mcp"]
    }
  }
}
JSON

trap 'rm -f "$CONFIG"' EXIT

echo "[security_audit] inspecting tool surface for injection patterns..."
uvx snyk-agent-scan@latest inspect "$CONFIG" --json
