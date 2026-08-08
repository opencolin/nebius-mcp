#!/usr/bin/env python3
"""Verify the version, the changelog, and the installed package metadata agree.

`.github/workflows/release.yml` already refuses to publish when the git tag and
`pyproject.toml` disagree, but that check runs after the tag is pushed — the
point at which a mistake is most expensive to undo. This runs on every pull
request instead, so the same class of drift is caught while it is still a
one-line fix.

What it asserts:

- `pyproject.toml` `project.version` and `nebius_mcp.__version__` agree.
- `CHANGELOG.md` has an `[Unreleased]` section.
- Every version heading in `CHANGELOG.md` is a valid semver, and they appear in
  descending precedence order.
- `pyproject.toml` names either the top released heading or something newer.

Standard library only, no network, no subprocesses.

    python scripts/check_release_hygiene.py
"""

from __future__ import annotations

import itertools
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The reference grammar published at https://semver.org, anchored with fullmatch
# at every call site.
_SEMVER = re.compile(
    r"(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+(?P<build>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?"
)

_H2 = re.compile(r"##[ \t]+(.+?)\s*$")
_LABEL = re.compile(r"\[([^\]]+)\]")

UNRELEASED = "unreleased"

# A pre-release identifier is encoded as a triple so that tuple comparison
# reproduces the rules in https://semver.org/#spec-item-11: numeric identifiers
# rank below alphanumeric ones, and are compared as numbers rather than as text.
PrereleaseKey = tuple[tuple[int, int, str], ...]
PrecedenceKey = tuple[int, int, int, int, PrereleaseKey]


def precedence_key(version: str) -> PrecedenceKey:
    """Return a sort key ordering versions by semver precedence.

    Build metadata is excluded, because the specification says it is ignored
    when determining precedence.

    Raises ValueError if `version` is not a valid semver string.
    """
    match = _SEMVER.fullmatch(version)
    if match is None:
        raise ValueError(f"not a valid semver: {version!r}")

    core = (int(match["major"]), int(match["minor"]), int(match["patch"]))
    prerelease = match["prerelease"]
    if prerelease is None:
        # A release outranks every pre-release of the same core version.
        return (*core, 1, ())

    identifiers = tuple(
        (0, int(part), "") if part.isdigit() else (1, 0, part) for part in prerelease.split(".")
    )
    return (*core, 0, identifiers)


def is_semver(version: str) -> bool:
    return _SEMVER.fullmatch(version) is not None


def section_labels(markdown: str) -> list[str]:
    """Return the bracketed label of every level-2 heading, in document order.

    `## [0.1.0] - 2026-05-03` yields `0.1.0`. Level-2 headings without a
    bracketed label are prose and are skipped, as is anything inside a fenced
    code block.
    """
    labels: list[str] = []
    fence: str | None = None

    for line in markdown.splitlines():
        stripped = line.strip()
        if fence is not None:
            if stripped.startswith(fence):
                fence = None
            continue
        if stripped.startswith(("```", "~~~")):
            fence = stripped[:3]
            continue

        heading = _H2.match(line)
        if heading is None:
            continue
        label = _LABEL.match(heading.group(1).strip())
        if label is not None:
            labels.append(label.group(1).strip())

    return labels


def check_changelog(markdown: str) -> tuple[list[str], list[str]]:
    """Return (problems, the semver-valid released versions in document order).

    Headings that are not valid semver are reported and then dropped, so the
    caller never has to compare a version it cannot parse.
    """
    problems: list[str] = []
    labels = section_labels(markdown)

    if not any(label.lower() == UNRELEASED for label in labels):
        problems.append(
            "CHANGELOG.md has no '## [Unreleased]' section; every change since the "
            "last release needs somewhere to go"
        )

    released = [label for label in labels if label.lower() != UNRELEASED]

    valid = [version for version in released if is_semver(version)]
    problems.extend(
        f"CHANGELOG.md heading '[{version}]' is not a valid semver"
        for version in released
        if not is_semver(version)
    )

    for newer, older in itertools.pairwise(valid):
        if precedence_key(newer) <= precedence_key(older):
            problems.append(
                f"CHANGELOG.md headings are out of order: '[{newer}]' appears above "
                f"'[{older}]' but is not newer than it"
            )

    return problems, valid


def check(pyproject_version: str, package_version: str, changelog: str) -> list[str]:
    """Return every hygiene problem found, as human-readable lines."""
    problems: list[str] = []

    if pyproject_version != package_version:
        problems.append(
            f"pyproject.toml declares version {pyproject_version!r} but "
            f"nebius_mcp.__version__ is {package_version!r}. That version comes from "
            "the installed distribution metadata, so a stale editable install is the "
            "usual cause: run `uv sync`."
        )

    changelog_problems, released = check_changelog(changelog)
    problems.extend(changelog_problems)

    if not is_semver(pyproject_version):
        problems.append(f"pyproject.toml version {pyproject_version!r} is not a valid semver")
    elif released and precedence_key(pyproject_version) < precedence_key(released[0]):
        problems.append(
            f"pyproject.toml version {pyproject_version!r} is older than the top "
            f"released CHANGELOG.md heading '[{released[0]}]'"
        )

    return problems


def read_pyproject_version(path: Path) -> str:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    version = data["project"]["version"]
    if not isinstance(version, str):
        raise TypeError(f"pyproject.toml project.version is {type(version).__name__}, not a string")
    return version


def main() -> int:
    try:
        from nebius_mcp import __version__ as package_version
    except ImportError:
        print(
            "nebius_mcp is not importable; run this under `uv run` so the package "
            "metadata being checked is the one that would ship",
            file=sys.stderr,
        )
        return 1

    pyproject_version = read_pyproject_version(ROOT / "pyproject.toml")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    problems = check(pyproject_version, package_version, changelog)

    if problems:
        print(f"Release hygiene problems ({len(problems)}):", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    print(f"OK: version {pyproject_version} agrees with the package metadata and CHANGELOG.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
