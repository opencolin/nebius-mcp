#!/usr/bin/env python3
"""Keep the security documentation from drifting back into fiction.

Two checks, both cheap enough to run on every push:

1. Two specific claims were removed from module docstrings because they were
   false. Tool descriptions and docstrings get rewritten often, and both
   sentences read as reassuring boilerplate, so the failure mode is somebody
   reinstating them in good faith. This fails the build if either reappears
   anywhere under ``src/``.

2. ``SECURITY.md`` cites enforcing code as ``path:line``. A citation that
   points past the end of a file, or at a file that no longer exists, is worse
   than no citation — it looks verified. This resolves every one of them.

    python scripts/check_security_doc.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Retracted claims. Both are wrong about the MCP specification: no annotation
# obliges a client to prompt, and the confirm-token two-step is a mistake
# guard, not an injection defense (see src/nebius_mcp/confirm.py).
RETRACTED_CLAIMS: tuple[str, ...] = (
    "spec-recommended mitigation",
    "so well-behaved clients prompt the user",
)

# path/to/file.py:123 — the form used in the SECURITY.md threat table. The
# lookbehind rather than \b is deliberate: \b would not match before the dot of
# `.github/workflows/ci.yml`, silently truncating the path to `github/...` and
# reporting a real citation as missing.
_CITATION = re.compile(r"(?<![\w./-])((?:[\w.-]+/)*[\w.-]+\.(?:py|yml|yaml|toml)):(\d+)\b")

_WHITESPACE = re.compile(r"\s+")


def find_retracted_claims(src: Path) -> list[str]:
    problems: list[str] = []
    for path in sorted(src.rglob("*.py")):
        # Docstrings are hard-wrapped, so a claim can straddle a newline and a
        # line-oriented grep would miss it. Collapse whitespace runs first.
        flat = _WHITESPACE.sub(" ", path.read_text(encoding="utf-8")).lower()
        # Relative to the scanned root's parent, not to ROOT: the tests call
        # this against a temporary tree, where relative_to(ROOT) would raise.
        problems.extend(
            f"{path.relative_to(src.parent)}: retracted claim {claim!r} is back"
            for claim in RETRACTED_CLAIMS
            if claim in flat
        )
    return problems


def check_citations(doc: Path) -> list[str]:
    if not doc.exists():
        return [f"{doc.name} does not exist"]

    problems: list[str] = []
    for raw_path, raw_line in _CITATION.findall(doc.read_text(encoding="utf-8")):
        target = ROOT / raw_path
        if not target.exists():
            problems.append(f"{doc.name}: cites {raw_path}, which does not exist")
            continue
        lines = target.read_text(encoding="utf-8").splitlines()
        number = int(raw_line)
        if number > len(lines):
            problems.append(
                f"{doc.name}: cites {raw_path}:{raw_line} but that file has {len(lines)} lines"
            )
        elif not lines[number - 1].strip():
            # An edit above a citation shifts it. Landing on a blank line is the
            # loudest symptom of that drift and the cheapest one to detect. A
            # citation that drifts onto some *other* real line still passes here,
            # so re-read the cited lines when you move code around.
            problems.append(f"{doc.name}: cites {raw_path}:{raw_line}, which is a blank line")
    return problems


def main() -> int:
    problems = find_retracted_claims(ROOT / "src") + check_citations(ROOT / "SECURITY.md")

    if problems:
        print(f"Security-doc problems ({len(problems)}):", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    print("OK: no retracted claims under src/, and every SECURITY.md citation resolves")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
