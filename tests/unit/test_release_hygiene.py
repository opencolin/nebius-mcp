"""Tests for the release hygiene gate's parsing and comparison logic.

The script lives in ``scripts/`` rather than in the package, so it is loaded by
path instead of imported. Keeping it out of the package is deliberate: it is
build tooling, and shipping it in the wheel would put a CI concern on every
user's disk.
"""

from __future__ import annotations

import importlib.util
import textwrap
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_release_hygiene.py"


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_release_hygiene", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hygiene = _load_script()


def changelog(*sections: str) -> str:
    body = "\n\n".join(textwrap.dedent(section).strip() for section in sections)
    return f"# Changelog\n\n{body}\n"


UNRELEASED = "## [Unreleased]\n\n### Added\n- something"


def test_agreeing_versions_produce_no_problems() -> None:
    problems = hygiene.check("0.2.0", "0.2.0", changelog(UNRELEASED, "## [0.2.0] - 2026-08-08"))
    assert problems == []


def test_disagreeing_versions_are_reported() -> None:
    problems = hygiene.check("0.2.0", "0.1.0", changelog(UNRELEASED, "## [0.2.0] - 2026-08-08"))
    assert len(problems) == 1
    assert "0.2.0" in problems[0] and "0.1.0" in problems[0]


def test_missing_unreleased_is_reported() -> None:
    problems = hygiene.check("0.2.0", "0.2.0", changelog("## [0.2.0] - 2026-08-08"))
    assert any("Unreleased" in problem for problem in problems)


def test_out_of_order_headings_are_reported() -> None:
    problems = hygiene.check(
        "0.3.0",
        "0.3.0",
        changelog(UNRELEASED, "## [0.1.0] - 2026-05-03", "## [0.3.0] - 2026-08-08"),
    )
    assert any("out of order" in problem for problem in problems)


def test_repeated_heading_is_out_of_order() -> None:
    problems = hygiene.check(
        "0.2.0",
        "0.2.0",
        changelog(UNRELEASED, "## [0.2.0] - 2026-08-08", "## [0.2.0] - 2026-08-01"),
    )
    assert any("out of order" in problem for problem in problems)


def test_non_semver_heading_is_reported() -> None:
    problems = hygiene.check("0.2.0", "0.2.0", changelog(UNRELEASED, "## [v0.2] - 2026-08-08"))
    assert any("not a valid semver" in problem for problem in problems)


def test_pyproject_older_than_top_release_is_reported() -> None:
    problems = hygiene.check("0.1.0", "0.1.0", changelog(UNRELEASED, "## [0.2.0] - 2026-08-08"))
    assert any("older than" in problem for problem in problems)


def test_pyproject_newer_than_top_release_is_allowed() -> None:
    """A version bumped ahead of the changelog is the normal mid-release state."""
    problems = hygiene.check("0.3.0", "0.3.0", changelog(UNRELEASED, "## [0.2.0] - 2026-08-08"))
    assert problems == []


def test_pyproject_version_must_be_semver() -> None:
    problems = hygiene.check("0.2", "0.2", changelog(UNRELEASED))
    assert any("not a valid semver" in problem for problem in problems)


def test_changelog_with_no_releases_is_allowed() -> None:
    assert hygiene.check("0.1.0", "0.1.0", changelog(UNRELEASED)) == []


def test_headings_inside_fenced_blocks_are_ignored() -> None:
    fenced = changelog(
        UNRELEASED,
        "```\n## [9.9.9] - not a heading\n```",
        "## [0.2.0] - 2026-08-08",
    )
    assert hygiene.section_labels(fenced) == ["Unreleased", "0.2.0"]


def test_level_three_headings_are_not_versions() -> None:
    assert hygiene.section_labels("### [0.2.0] - 2026-08-08") == []


def test_unbracketed_headings_are_ignored() -> None:
    assert hygiene.section_labels("## Migration notes") == []


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("0.1.0", "0.2.0"),
        ("0.9.9", "1.0.0"),
        ("1.0.0-alpha", "1.0.0"),
        ("1.0.0-alpha", "1.0.0-alpha.1"),
        ("1.0.0-alpha.1", "1.0.0-beta"),
        ("1.0.0-alpha.1", "1.0.0-alpha.2"),
        ("1.0.0-alpha.2", "1.0.0-alpha.10"),
        ("1.0.0-rc.1", "1.0.0"),
    ],
)
def test_precedence_ordering(lower: str, higher: str) -> None:
    assert hygiene.precedence_key(lower) < hygiene.precedence_key(higher)


def test_build_metadata_does_not_affect_precedence() -> None:
    assert hygiene.precedence_key("1.0.0+build.5") == hygiene.precedence_key("1.0.0+other")


def test_precedence_key_rejects_non_semver() -> None:
    with pytest.raises(ValueError, match="not a valid semver"):
        hygiene.precedence_key("1.0")


def _tree(root: Path, version: str, changelog_text: str) -> None:
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "nebius-mcp"\nversion = "{version}"\n', encoding="utf-8"
    )
    (root / "CHANGELOG.md").write_text(changelog_text, encoding="utf-8")


def test_main_exits_zero_on_a_consistent_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _tree(tmp_path, "0.2.0", changelog(UNRELEASED, "## [0.2.0] - 2026-08-08"))
    monkeypatch.setattr(hygiene, "ROOT", tmp_path)
    monkeypatch.setattr("nebius_mcp.__version__", "0.2.0")
    assert hygiene.main() == 0


def test_main_exits_nonzero_when_the_package_metadata_drifts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _tree(tmp_path, "0.2.0", changelog(UNRELEASED, "## [0.2.0] - 2026-08-08"))
    monkeypatch.setattr(hygiene, "ROOT", tmp_path)
    monkeypatch.setattr("nebius_mcp.__version__", "0.1.0")
    assert hygiene.main() == 1


def test_repository_changelog_passes() -> None:
    """The gate is only useful if the tree it guards actually satisfies it."""
    problems, released = hygiene.check_changelog(
        (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    )
    assert problems == []
    assert released


def test_repository_pyproject_is_consistent_with_changelog() -> None:
    version = hygiene.read_pyproject_version(ROOT / "pyproject.toml")
    changelog_text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert hygiene.check(version, version, changelog_text) == []
