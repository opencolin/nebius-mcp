"""Tests for validation rules from the skill gotchas."""

from __future__ import annotations

import pytest
from fastmcp.exceptions import ToolError

from nebius_mcp.validation import (
    MIN_BOOT_DISK_BYTES,
    gib_to_bytes,
    validate_boot_disk_size,
    validate_disk_type,
    validate_id,
    validate_static_ip_cidr,
)


def test_validate_id_accepts_well_formed() -> None:
    validate_id("project", "project-abcdef123456")  # no exception


def test_validate_id_rejects_wrong_prefix() -> None:
    with pytest.raises(ToolError) as ei:
        validate_id("project", "tenant-abcdef123456")
    assert "project" in str(ei.value).lower()


def test_validate_id_unknown_kind_passes() -> None:
    validate_id("registry", "anything")  # unknown kind - allow through


def test_validate_disk_type_underscore() -> None:
    validate_disk_type("network_ssd")  # no exception
    validate_disk_type("network_hdd")


def test_validate_disk_type_rejects_hyphen() -> None:
    with pytest.raises(ToolError) as ei:
        validate_disk_type("network-ssd")
    assert "underscore" in str(ei.value).lower()


def test_validate_boot_disk_size_minimum() -> None:
    validate_boot_disk_size(MIN_BOOT_DISK_BYTES)
    validate_boot_disk_size(MIN_BOOT_DISK_BYTES + 1)


def test_validate_boot_disk_size_too_small() -> None:
    with pytest.raises(ToolError) as ei:
        validate_boot_disk_size(gib_to_bytes(20), image_family="ubuntu22.04-cuda12")
    assert "GiB" in str(ei.value)
    assert "ubuntu22.04-cuda12" in str(ei.value)


def test_static_ip_cidr_accepts_32_suffix() -> None:
    validate_static_ip_cidr("1.2.3.4/32")


def test_static_ip_cidr_rejects_wrong_suffix() -> None:
    with pytest.raises(ToolError):
        validate_static_ip_cidr("1.2.3.4")
    with pytest.raises(ToolError):
        validate_static_ip_cidr("1.2.3.4/24")


def test_gib_to_bytes() -> None:
    assert gib_to_bytes(50) == 50 * 1024**3
    assert gib_to_bytes(1) == 1024**3
