"""Validation rules distilled from the nebius-skill "Common Gotchas" tables.

These are server-side checks the model can run before requesting a mutation.
They surface as ToolError so the model can correct itself, rather than
shipping a malformed request to Nebius and waiting for an opaque grpc error.

Every rule here has to earn its place twice: it must catch a real failure, and
it must not reject input Nebius would have accepted. The second half is the
harder one. A rule that fires on correct input is worse than no rule at all,
because an agreeable model silently complies with it rather than arguing — so
the mistake ships, permanently, and nobody learns why. R-007 and R-016 in
``docs/REVIEW-FINDINGS.md`` are both instances of that, which is why the only
rules left here are ones whose bounds are documented rather than inferred.
"""

from __future__ import annotations

from fastmcp.exceptions import ToolError

# 50 GiB is the documented minimum for the CUDA image families, which ship a
# driver stack the smaller default does not fit. It is NOT a general minimum,
# and applying it as one rejected legitimate small CPU-only instances — see
# _cuda_image_family below.
MIN_CUDA_BOOT_DISK_BYTES = 50 * 1024**3

# Disk types use underscores in Nebius API: "network_ssd", "network_ssd_io_m3".
# Skill gotcha: users frequently submit "network-ssd" (hyphen), which fails.
VALID_DISK_TYPES = {
    "network_ssd",
    "network_ssd_io_m3",
    "network_ssd_non_replicated",
    "network_hdd",
}


def validate_disk_type(disk_type: str) -> None:
    if disk_type not in VALID_DISK_TYPES:
        valid = ", ".join(sorted(VALID_DISK_TYPES))
        raise ToolError(
            f"Invalid disk type '{disk_type}'. Use one of: {valid}. "
            "Note Nebius uses underscores (network_ssd), not hyphens."
        )


def _cuda_image_family(image_family: str | None) -> bool:
    """Whether this image family carries a CUDA driver stack.

    A substring test on a free-form string, which is normally the kind of
    inferred grammar this module now avoids. It is safe here only because of
    which way it fails. A false positive asks for a 50 GiB boot disk on an image
    that might not need one — exactly what the rule did unconditionally before,
    so no worse than the previous behaviour. A false negative applies no floor
    and defers to Nebius, which answers authoritatively. Neither direction can
    reject something Nebius would have accepted.
    """
    return "cuda" in (image_family or "").lower()


def validate_boot_disk_size(size_bytes: int, image_family: str | None = None) -> None:
    """Enforce the CUDA boot-disk floor, and nothing else.

    This previously took ``image_family`` and ignored it, applying the 50 GiB
    floor to every image — so a correct 20 GiB plain-Ubuntu instance was refused
    by a rule that only ever applied to the CUDA families, and refused twice,
    because the tool's own schema carried ``ge=50`` as well.

    No floor is invented for the non-CUDA case. The 10 GiB figure that appears
    in the skill's reference table is not independently verified, and swapping
    one unverified constant for two would repeat the original mistake. Where no
    documented bound exists, Nebius is the authority: an undersized disk comes
    back as an API error naming the real minimum, which is a loud, recoverable
    failure rather than a silent local one.
    """
    if not _cuda_image_family(image_family):
        return
    if size_bytes < MIN_CUDA_BOOT_DISK_BYTES:
        gib = size_bytes / 1024**3
        raise ToolError(
            f"Boot disk too small: {gib:.1f} GiB. The CUDA image families need "
            f">= {MIN_CUDA_BOOT_DISK_BYTES // 1024**3} GiB for the driver stack "
            f"(image_family={image_family!r}). Non-CUDA images have no such floor."
        )


def gib_to_bytes(gib: int | float) -> int:
    return int(gib * 1024**3)
