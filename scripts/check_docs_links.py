#!/usr/bin/env python3
"""Verify every relative link and in-page anchor in the Markdown docs resolves.

The README is the main onboarding path, and a link that 404s there costs more
trust than the content it points at is worth. This runs in CI so a doc that
references a file someone later renamed fails the build.

Only local targets are checked — no network requests, so this is fast and
cannot flake.

    python scripts/check_docs_links.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# [text](target) — skip images, autolinks, and reference definitions.
_LINK = re.compile(r"(?<!\!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
_HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*$", re.MULTILINE)


def slugify(heading: str) -> str:
    """Approximate GitHub's heading-to-anchor conversion."""
    text = re.sub(r"`([^`]*)`", r"\1", heading)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    return re.sub(r"[\s_]+", "-", text)


def anchors_of(markdown: str) -> set[str]:
    slugs: set[str] = set()
    for heading in _HEADING.findall(markdown):
        slug = slugify(heading)
        # GitHub disambiguates repeats with -1, -2, ...
        if slug in slugs:
            for n in range(1, 20):
                if f"{slug}-{n}" not in slugs:
                    slugs.add(f"{slug}-{n}")
                    break
        else:
            slugs.add(slug)
    return slugs


def check(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    own_anchors = anchors_of(text)
    rel = path.relative_to(ROOT)
    problems: list[str] = []

    for target in _LINK.findall(text):
        if target.startswith(("http://", "https://", "mailto:")):
            continue

        file_part, _, anchor = target.partition("#")

        if not file_part:  # pure in-page anchor
            if anchor and anchor not in own_anchors:
                problems.append(f"{rel}: anchor '#{anchor}' has no matching heading")
            continue

        resolved = (path.parent / file_part).resolve()
        if not resolved.exists():
            problems.append(f"{rel}: '{file_part}' does not exist")
            continue

        if anchor and resolved.suffix == ".md":
            if anchor not in anchors_of(resolved.read_text(encoding="utf-8")):
                problems.append(f"{rel}: '{file_part}' has no anchor '#{anchor}'")

    return problems


def main() -> int:
    targets = sorted({*ROOT.glob("*.md"), *ROOT.glob("docs/**/*.md")})
    if not targets:
        print("no markdown files found", file=sys.stderr)
        return 1

    problems = [p for path in targets for p in check(path)]

    if problems:
        print(f"Broken links ({len(problems)}):", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    print(f"OK: all local links and anchors resolve across {len(targets)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
