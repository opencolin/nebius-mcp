"""Tests for the security-documentation honesty check.

A check that cannot fail is worse than no check, because it reads as coverage.
Two of these tests plant a violation and assert the checker catches it; the
other two assert the tree is clean today.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_security_doc.py"


def _load() -> ModuleType:
    """Import the script by path — ``scripts/`` is not an importable package."""
    spec = importlib.util.spec_from_file_location("check_security_doc", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check = _load()


def test_repository_has_no_retracted_claims() -> None:
    assert check.find_retracted_claims(ROOT / "src") == []


def test_every_security_md_citation_resolves() -> None:
    assert check.check_citations(ROOT / "SECURITY.md") == []


@pytest.mark.parametrize("claim", check.RETRACTED_CLAIMS)
def test_a_reinstated_claim_is_caught_even_when_hard_wrapped(tmp_path: Path, claim: str) -> None:
    # Docstrings are wrapped at 100 columns, so the realistic way a claim comes
    # back is split across a newline. A line-oriented grep would miss that.
    head, _, tail = claim.partition(" ")
    (tmp_path / "module.py").write_text(f'"""Prose.\n\n{head}\n{tail} of something.\n"""\n')

    problems = check.find_retracted_claims(tmp_path)

    assert len(problems) == 1
    assert claim in problems[0]


def test_a_citation_past_the_end_of_a_file_is_caught(tmp_path: Path) -> None:
    doc = tmp_path / "SECURITY.md"
    doc.write_text("See `src/nebius_mcp/confirm.py:99999` for the gate.\n")

    problems = check.check_citations(doc)

    assert len(problems) == 1
    assert "99999" in problems[0]


def test_a_citation_to_a_missing_file_is_caught(tmp_path: Path) -> None:
    doc = tmp_path / "SECURITY.md"
    doc.write_text("See `src/nebius_mcp/does_not_exist.py:1` for the gate.\n")

    problems = check.check_citations(doc)

    assert len(problems) == 1
    assert "does not exist" in problems[0]


def test_a_citation_that_drifted_onto_a_blank_line_is_caught(tmp_path: Path) -> None:
    # Editing a docstring shifts every citation below it. This happened while
    # writing SECURITY.md: three sanitize.py citations moved by one line and two
    # landed on blank lines, which the line-count check alone accepted.
    blank = _first_blank_line(ROOT / "src/nebius_mcp/sanitize.py")
    doc = tmp_path / "SECURITY.md"
    doc.write_text(f"See `src/nebius_mcp/sanitize.py:{blank}` for redaction.\n")

    problems = check.check_citations(doc)

    assert len(problems) == 1
    assert "blank line" in problems[0]


def _first_blank_line(path: Path) -> int:
    lines = path.read_text(encoding="utf-8").splitlines()
    return next(i for i, line in enumerate(lines, start=1) if not line.strip())
