"""Tests for validation rules from the skill gotchas.

Two shapes of test here, and the second is the one that was missing. Rejection
tests prove a rule catches what it is for. Acceptance tests prove it does not
catch anything else — and the boot-disk rule shipped for months without one,
which is exactly how it came to refuse every non-CUDA instance under 50 GiB
(R-016).
"""

from __future__ import annotations

import pytest
from fastmcp.exceptions import ToolError

from nebius_mcp.validation import (
    MIN_CUDA_BOOT_DISK_BYTES,
    gib_to_bytes,
    validate_boot_disk_size,
    validate_disk_type,
)


def test_validate_disk_type_underscore() -> None:
    validate_disk_type("network_ssd")
    validate_disk_type("network_ssd_io_m3")


def test_validate_disk_type_rejects_hyphen() -> None:
    with pytest.raises(ToolError, match="underscores"):
        validate_disk_type("network-ssd")


def test_gib_to_bytes() -> None:
    assert gib_to_bytes(50) == 50 * 1024**3


# --- the CUDA boot-disk floor ------------------------------------------------


@pytest.mark.parametrize(
    "image_family",
    ["ubuntu22.04-cuda12", "ubuntu24.04-cuda12", "UBUNTU22.04-CUDA12"],
)
def test_cuda_images_keep_the_50_gib_floor(image_family: str) -> None:
    """The rule still does the job it was written for."""
    validate_boot_disk_size(MIN_CUDA_BOOT_DISK_BYTES, image_family=image_family)

    with pytest.raises(ToolError, match="CUDA image families"):
        validate_boot_disk_size(gib_to_bytes(20), image_family=image_family)


@pytest.mark.parametrize(
    "image_family",
    ["ubuntu22.04", "ubuntu24.04", "debian12", "rocky9", None, ""],
)
def test_non_cuda_images_have_no_floor(image_family: str | None) -> None:
    """R-016, the regression guard.

    A 20 GiB plain-Ubuntu boot disk is a legitimate request. The rule used to
    refuse it — ``image_family`` was accepted and then used only inside the
    error string, so the CUDA floor applied to every image. There was no
    acceptance test, so nothing failed when it shipped.

    Note this asserts an absence, which is unusual: the correct behaviour is
    that no local rule fires and Nebius decides. If a floor is ever added back
    for these families it must come with a documented source, not an inferred
    one.
    """
    validate_boot_disk_size(gib_to_bytes(20), image_family=image_family)
    validate_boot_disk_size(gib_to_bytes(1), image_family=image_family)


def test_the_floor_is_keyed_on_the_image_not_the_size() -> None:
    """Same size, opposite outcomes — which is the whole point of the fix."""
    twenty = gib_to_bytes(20)

    validate_boot_disk_size(twenty, image_family="ubuntu22.04")
    with pytest.raises(ToolError):
        validate_boot_disk_size(twenty, image_family="ubuntu22.04-cuda12")


def test_every_public_validator_has_a_call_site() -> None:
    """R-007: two validators sat here for months, tested but never called.

    Their unit tests passed, so coverage looked fine and nothing indicated the
    rules were not running. `validate_id` in particular inferred ID grammars
    that were never documented, so wiring it up risked rejecting valid input —
    the same failure the boot-disk rule actually shipped. Both were deleted
    rather than wired.

    This test stops the situation recurring: a public helper here must be
    reachable from `src/`, or it is not a rule, it is a decoration.
    """
    import inspect
    from pathlib import Path

    from nebius_mcp import validation

    src = Path(validation.__file__).parent
    callers = "\n".join(
        p.read_text(encoding="utf-8") for p in src.rglob("*.py") if p.name != "validation.py"
    )

    public = [
        name
        for name, obj in vars(validation).items()
        if not name.startswith("_")
        and inspect.isfunction(obj)
        and obj.__module__ == validation.__name__
    ]
    assert public, "no public functions found — did the module move?"

    unused = [name for name in public if name not in callers]
    assert not unused, f"defined in validation.py but called from nowhere in src/: {unused}"
