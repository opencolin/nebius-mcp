"""Validation rules distilled from the nebius-skill "Common Gotchas" tables.

These are server-side checks the model can run before requesting a mutation.
They surface as ToolError so the model can correct itself, rather than
shipping a malformed request to Nebius and waiting for an opaque grpc error.
"""

from __future__ import annotations

import re

from fastmcp.exceptions import ToolError

# 50 GiB - minimum boot disk for ubuntu22.04-cuda12 image family.
MIN_BOOT_DISK_BYTES = 50 * 1024**3

# Disk types use underscores in Nebius API: "network_ssd", "network_ssd_io_m3".
# Skill gotcha: users frequently submit "network-ssd" (hyphen), which fails.
VALID_DISK_TYPES = {
    "network_ssd",
    "network_ssd_io_m3",
    "network_ssd_non_replicated",
    "network_hdd",
}

# Allocation IPs are IPv4/32 - the `/32` suffix is required.
_IP_CIDR_32 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/32$")

# Resource ID prefixes we expect (pattern from the skill + observed in proto).
_ID_PATTERNS: dict[str, re.Pattern[str]] = {
    "project": re.compile(r"^project-[a-z0-9]{12,}$"),
    "tenant": re.compile(r"^tenant-[a-z0-9]{12,}$"),
    "instance": re.compile(r"^computeinstance-[a-z0-9]{12,}$"),
    "disk": re.compile(r"^computedisk-[a-z0-9]{12,}$"),
    "cluster": re.compile(r"^mk8scluster-[a-z0-9]{12,}$"),
    "subnet": re.compile(r"^vpcsubnet-[a-z0-9]{12,}$"),
    "network": re.compile(r"^vpcnetwork-[a-z0-9]{12,}$"),
}


def validate_id(kind: str, value: str) -> None:
    """Validate a resource ID format. ``kind`` is one of the keys in ``_ID_PATTERNS``."""
    pat = _ID_PATTERNS.get(kind)
    if pat is None:
        return  # unknown kind; defer to server-side
    if not pat.match(value):
        raise ToolError(
            f"Invalid {kind} ID '{value}': expected format {pat.pattern!r}. "
            "Did you confuse a tenant ID with a project ID?"
        )


def validate_disk_type(disk_type: str) -> None:
    if disk_type not in VALID_DISK_TYPES:
        valid = ", ".join(sorted(VALID_DISK_TYPES))
        raise ToolError(
            f"Invalid disk type '{disk_type}'. Use one of: {valid}. "
            "Note Nebius uses underscores (network_ssd), not hyphens."
        )


def validate_boot_disk_size(size_bytes: int, image_family: str | None = None) -> None:
    """Boot disks for cuda images need at least 50 GiB. Generic check applies always."""
    if size_bytes < MIN_BOOT_DISK_BYTES:
        gib = size_bytes / 1024**3
        raise ToolError(
            f"Boot disk too small: {gib:.1f} GiB. Nebius requires "
            f">= {MIN_BOOT_DISK_BYTES // 1024**3} GiB"
            + (f" for image_family={image_family!r}" if image_family else "")
            + "."
        )


def validate_static_ip_cidr(ip: str) -> None:
    if not _IP_CIDR_32.match(ip):
        raise ToolError(
            f"Static IP must be an IPv4 address with /32 suffix (got {ip!r}). Example: 1.2.3.4/32"
        )


def gib_to_bytes(gib: int | float) -> int:
    return int(gib * 1024**3)
