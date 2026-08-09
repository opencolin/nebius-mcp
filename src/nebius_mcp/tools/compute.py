"""Compute tools.

Read:

- ``compute_list_instances``    -> instances under a project
- ``compute_get_instance``      -> single instance detail
- ``compute_list_disks``        -> disks under a project
- ``compute_get_disk``          -> single disk detail
- ``compute_list_platforms``    -> compute platforms (cpu / gpu families)

Write (all behind NEBIUS_MCP_MODE=write):

- ``compute_start_instance`` / ``compute_stop_instance``  -> reversible
- ``compute_delete_instance`` / ``compute_delete_disk``   -> two-step confirm
- ``compute_create_instance``                             -> two-step confirm
"""

from __future__ import annotations

import base64
import hashlib
from typing import Annotated, Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from pydantic import Field

from ..auth import resolve_credentials
from ..client import service
from ..confirm import preview_or_execute, require_write
from ..errors import safe
from ..operation import DEFAULT_WAIT_TIMEOUT_SECONDS, maybe_wait
from ..pagination import clamp_page_size
from ..sanitize import safe_proto, wrap
from ..validation import (
    gib_to_bytes,
    validate_boot_disk_size,
    validate_disk_type,
)
from ._ops_helpers import CREATE_ANNOTATIONS, DESTRUCTIVE_ANNOTATIONS, STATE_ANNOTATIONS

READ_ANNOTATIONS = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": True,
}


def _profile_parent_id() -> str | None:
    return resolve_credentials().parent_id


def _resolve_parent(parent_id: str | None) -> str | None:
    return parent_id or _profile_parent_id()


# Cap on how much of a caller-supplied key line may be reflected into a
# preview field. Real key types run to ~34 characters ("sk-ecdsa-sha2-
# nistp256@openssh.com") and real comments to a "user@host"; anything longer
# is padding a reader will not check, and echoing it unbounded turns the
# preview into a channel for arbitrary text.
_MAX_ECHO_CHARS = 120


def _bounded(text: str) -> str:
    """Return ``text`` capped at :data:`_MAX_ECHO_CHARS` with a visible marker if cut."""
    if len(text) <= _MAX_ECHO_CHARS:
        return text
    return f"{text[:_MAX_ECHO_CHARS]}... [truncated, {len(text)} characters total]"


def _first_unsafe_char(text: str) -> str | None:
    """Return the first character outside printable ASCII (0x20-0x7E), or None."""
    for ch in text:
        if not 0x20 <= ord(ch) <= 0x7E:
            return ch
    return None


def _parse_ssh_public_key(text: str) -> tuple[str, bytes] | None:
    """Parse one OpenSSH public key line into ``(key_type, blob)``, or None.

    ``text`` is expected to be already stripped. A line parses when its first
    two whitespace-separated fields are an algorithm name and a base64 blob
    whose own first length-prefixed field repeats that name — which is what
    separates a real key from two arbitrary words that happen to be valid
    base64. Trailing fields (the comment) are not inspected here.

    This never raises: both callers need a verdict, not an exception.
    """
    parts = text.split()
    if len(parts) < 2:
        return None
    key_type, blob = parts[0], parts[1]
    try:
        # binascii.Error and UnicodeEncodeError (non-ASCII input) are both
        # ValueError subclasses, so this catch covers every rejection
        # b64decode can make.
        raw = base64.b64decode(blob, validate=True)
    except ValueError:
        return None
    name = key_type.encode("utf-8", "replace")
    header = len(name).to_bytes(4, "big") + name
    if not raw.startswith(header):
        return None
    return key_type, raw


def _validate_ssh_public_key(public_key: str) -> str:
    """Return the normalised key line, or raise ``ToolError`` explaining the refusal.

    ``compute_create_instance`` interpolates this value into a cloud-config
    document that cloud-init parses as root, on the line under
    ``ssh_authorized_keys:``. A line break in the value therefore ends that
    list item and continues the YAML at whatever indentation follows, which is
    enough to add a second authorized key or a top-level ``runcmd:``. So the
    refusal is deliberately wider than "no ``\\n``": the whole line must be
    printable ASCII (0x20-0x7E). ``\\n`` is not the only codepoint something
    downstream may treat as a line break — Python's own ``str.splitlines``
    also breaks on ``\\r``, ``\\x0b``, ``\\x0c``, ``\\x85``, ``\\u2028`` and
    ``\\u2029`` — and this code cannot know which set the guest's YAML parser
    honours, so it refuses everything outside printable ASCII rather than try
    to enumerate.

    The value must also parse as exactly one OpenSSH public key line
    (:func:`_parse_ssh_public_key`). That is stricter than the injection fix
    requires, and it is what lets the preview state a single fingerprint
    without qualification.

    Leading and trailing whitespace is trimmed first, so a pasted key with a
    trailing newline is accepted and the returned value is what gets bound,
    previewed and written to cloud-init.

    The offending value is never quoted back in full, in case it is a private
    key; only the single offending character is named.
    """
    text = public_key.strip()
    if not text:
        raise ToolError(
            "Invalid ssh_public_key: empty after trimming whitespace. Pass one "
            "OpenSSH public key line, e.g. the contents of ~/.ssh/id_ed25519.pub."
        )
    bad = _first_unsafe_char(text)
    if bad is not None:
        raise ToolError(
            f"Invalid ssh_public_key: contains {bad!r} (U+{ord(bad):04X}), which is not "
            "printable ASCII. An SSH public key is a single line; a line break or "
            "control character here would inject extra cloud-config into the "
            "instance's user-data, so it is refused rather than escaped. Pass exactly "
            "one key line, '<type> <base64-blob> [comment]', dropping any non-ASCII "
            "comment."
        )
    if _parse_ssh_public_key(text) is None:
        raise ToolError(
            "Invalid ssh_public_key: not a well-formed OpenSSH public key line. "
            "Expected '<type> <base64-blob> [comment]', where the blob is base64 that "
            "names <type> in its first field — for example 'ssh-ed25519 AAAAC3Nz... "
            "you@host'. The value is not quoted back here in case it is a private key; "
            "derive the public half with `ssh-keygen -y -f <private-key>`."
        )
    return text


def _ssh_key_summary(public_key: str) -> dict[str, str]:
    """Describe an SSH public key for the ``compute_create_instance`` preview.

    The dry run exists so a person reading the transcript can veto the call,
    and the question they need answered here is *whose key gets shell on this
    VM* — the key is written into cloud-init with passwordless sudo. The
    ``SHA256:...`` form below is byte-for-byte what ``ssh-keygen -lf`` prints,
    so it can be compared against a key the reader already trusts. It
    describes one key: ``compute_create_instance`` runs
    :func:`_validate_ssh_public_key` first, so by the time a summary reaches a
    preview the argument cannot have held a second key or any other
    cloud-config.

    This never raises. Callers other than that one may pass anything, and this
    runs inside the path that is supposed to *stop* a bad call, so a mistyped
    key has to degrade into something a human can reject rather than into a
    stack trace. Anything that does not parse as an OpenSSH public key line is
    reported as a labelled digest of the text and none of the text itself: a
    private key pasted here by mistake must not be echoed into the transcript.
    In the branch that does parse, the two fields taken from the input
    (``key_type`` and ``comment``) are each capped at :data:`_MAX_ECHO_CHARS`
    characters with a visible truncation marker, so no input can make this
    function return more than a few hundred characters.
    """
    text = public_key.strip()
    parsed = _parse_ssh_public_key(text)
    if parsed is not None:
        key_type, raw = parsed
        digest = base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
        summary = {"key_type": _bounded(key_type), "fingerprint": f"SHA256:{digest}"}
        comment = " ".join(text.split()[2:])
        if comment:
            summary["comment"] = _bounded(comment)
        return summary
    return {
        "key_type": "unrecognized",
        "fingerprint": "text-sha256:" + hashlib.sha256(text.encode("utf-8", "replace")).hexdigest(),
        "note": (
            "Not parseable as an OpenSSH public key line. The digest above is of the "
            "supplied text, not of a key blob, and the text is withheld in case it is "
            "a private key."
        ),
    }


def register(app: FastMCP) -> None:
    @app.tool(
        name="compute_list_instances",
        description=(
            "List compute instances (VMs) under a project. parent_id should be a "
            "project ID (e.g. 'project-...'). If omitted, uses parent-id from the "
            "active profile. Use compute_get_instance for full detail of a "
            "single VM."
        ),
        annotations=READ_ANNOTATIONS,
    )
    async def compute_list_instances(
        parent_id: Annotated[
            str | None,
            Field(description="Project ID. Omit to use active profile.", default=None),
        ] = None,
        page_size: Annotated[
            int | None,
            Field(description="Items per page (capped to 200, default 50).", default=None, ge=1),
        ] = None,
        page_token: Annotated[
            str | None,
            Field(description="Opaque pagination token.", default=None),
        ] = None,
    ) -> dict[str, Any]:
        from nebius.api.nebius.compute.v1 import InstanceServiceClient, ListInstancesRequest

        resolved = _resolve_parent(parent_id)
        if not resolved:
            return wrap(
                {"items": [], "next_page_token": None},
                note="No parent_id supplied and no parent-id in active profile.",
            )

        client = service(InstanceServiceClient)
        kwargs: dict[str, Any] = {
            "parent_id": resolved,
            "page_size": clamp_page_size(page_size),
        }
        if page_token:
            kwargs["page_token"] = page_token

        resp = await safe(client.list(ListInstancesRequest(**kwargs)))
        items = [safe_proto(it) for it in (resp.items or [])]
        return wrap(
            {
                "items": items,
                "next_page_token": resp.next_page_token or None,
                "parent_id": resolved,
            }
        )

    @app.tool(
        name="compute_get_instance",
        description=(
            "Get a single compute instance by ID. Returns metadata, spec "
            "(platform, preset, disks, network), and status (state, addresses)."
        ),
        annotations=READ_ANNOTATIONS,
    )
    async def compute_get_instance(
        id: Annotated[
            str,
            Field(description="Instance ID, e.g. 'computeinstance-...'.", min_length=1),
        ],
    ) -> dict[str, Any]:
        from nebius.api.nebius.compute.v1 import GetInstanceRequest, InstanceServiceClient

        client = service(InstanceServiceClient)
        resp = await safe(client.get(GetInstanceRequest(id=id)))
        return wrap(safe_proto(resp))

    @app.tool(
        name="compute_list_disks",
        description="List disks (block storage volumes) under a project.",
        annotations=READ_ANNOTATIONS,
    )
    async def compute_list_disks(
        parent_id: Annotated[
            str | None,
            Field(description="Project ID. Omit to use active profile.", default=None),
        ] = None,
        page_size: Annotated[
            int | None,
            Field(description="Items per page (capped to 200, default 50).", default=None, ge=1),
        ] = None,
        page_token: Annotated[
            str | None,
            Field(description="Opaque pagination token.", default=None),
        ] = None,
        filter: Annotated[
            str | None,
            Field(description="Server-side filter expression.", default=None),
        ] = None,
    ) -> dict[str, Any]:
        from nebius.api.nebius.compute.v1 import DiskServiceClient, ListDisksRequest

        resolved = _resolve_parent(parent_id)
        if not resolved:
            return wrap(
                {"items": [], "next_page_token": None},
                note="No parent_id supplied and no parent-id in active profile.",
            )

        client = service(DiskServiceClient)
        kwargs: dict[str, Any] = {
            "parent_id": resolved,
            "page_size": clamp_page_size(page_size),
        }
        if page_token:
            kwargs["page_token"] = page_token
        if filter:
            kwargs["filter"] = filter

        resp = await safe(client.list(ListDisksRequest(**kwargs)))
        items = [safe_proto(it) for it in (resp.items or [])]
        return wrap(
            {
                "items": items,
                "next_page_token": resp.next_page_token or None,
                "parent_id": resolved,
            }
        )

    @app.tool(
        name="compute_get_disk",
        description="Get a single disk by ID.",
        annotations=READ_ANNOTATIONS,
    )
    async def compute_get_disk(
        id: Annotated[str, Field(description="Disk ID.", min_length=1)],
    ) -> dict[str, Any]:
        from nebius.api.nebius.compute.v1 import DiskServiceClient, GetDiskRequest

        client = service(DiskServiceClient)
        resp = await safe(client.get(GetDiskRequest(id=id)))
        return wrap(safe_proto(resp))

    @app.tool(
        name="compute_start_instance",
        description=(
            "Start a stopped compute instance. Reversible; gated by write mode "
            "(NEBIUS_MCP_MODE=write)."
        ),
        annotations=STATE_ANNOTATIONS,
    )
    async def compute_start_instance(
        id: Annotated[str, Field(description="Instance ID.", min_length=1)],
        wait: Annotated[
            bool, Field(description="Block until operation completes.", default=True)
        ] = True,
        timeout_seconds: Annotated[
            int,
            Field(description="Wait timeout.", default=DEFAULT_WAIT_TIMEOUT_SECONDS, ge=1),
        ] = DEFAULT_WAIT_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        from nebius.api.nebius.compute.v1 import InstanceServiceClient, StartInstanceRequest

        require_write("compute_start_instance")
        client = service(InstanceServiceClient)
        op = await safe(client.start(StartInstanceRequest(id=id)))
        summary = await maybe_wait(op, wait=wait, timeout_seconds=timeout_seconds)
        return wrap(summary)

    @app.tool(
        name="compute_stop_instance",
        description=("Stop a running compute instance. Reversible; gated by write mode."),
        annotations=STATE_ANNOTATIONS,
    )
    async def compute_stop_instance(
        id: Annotated[str, Field(description="Instance ID.", min_length=1)],
        wait: Annotated[
            bool, Field(description="Block until operation completes.", default=True)
        ] = True,
        timeout_seconds: Annotated[
            int,
            Field(description="Wait timeout.", default=DEFAULT_WAIT_TIMEOUT_SECONDS, ge=1),
        ] = DEFAULT_WAIT_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        from nebius.api.nebius.compute.v1 import InstanceServiceClient, StopInstanceRequest

        require_write("compute_stop_instance")
        client = service(InstanceServiceClient)
        op = await safe(client.stop(StopInstanceRequest(id=id)))
        summary = await maybe_wait(op, wait=wait, timeout_seconds=timeout_seconds)
        return wrap(summary)

    @app.tool(
        name="compute_delete_instance",
        description=(
            "Delete a compute instance. IRREVERSIBLE. First call returns a "
            "preview and a single-use confirm_token (expires in 120s); call "
            "again with the token to execute. Gated by write mode."
        ),
        annotations=DESTRUCTIVE_ANNOTATIONS,
    )
    async def compute_delete_instance(
        id: Annotated[str, Field(description="Instance ID.", min_length=1)],
        confirm_token: Annotated[
            str | None,
            Field(description="Token from a prior dry-run call.", default=None),
        ] = None,
        wait: Annotated[
            bool, Field(description="Block until deletion completes.", default=True)
        ] = True,
        timeout_seconds: Annotated[
            int,
            Field(description="Wait timeout.", default=DEFAULT_WAIT_TIMEOUT_SECONDS, ge=1),
        ] = DEFAULT_WAIT_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        from nebius.api.nebius.compute.v1 import DeleteInstanceRequest, InstanceServiceClient

        gate = preview_or_execute(
            tool="compute_delete_instance",
            args={"id": id},
            confirm_token=confirm_token,
            preview={"action": f"Delete compute instance {id}", "id": id},
        )
        if gate is not None:
            return gate  # type: ignore[return-value]

        client = service(InstanceServiceClient)
        op = await safe(client.delete(DeleteInstanceRequest(id=id)))
        summary = await maybe_wait(op, wait=wait, timeout_seconds=timeout_seconds)
        return wrap(summary)

    @app.tool(
        name="compute_delete_disk",
        description=("Delete a disk. IRREVERSIBLE. Two-step confirm; gated by write mode."),
        annotations=DESTRUCTIVE_ANNOTATIONS,
    )
    async def compute_delete_disk(
        id: Annotated[str, Field(description="Disk ID.", min_length=1)],
        confirm_token: Annotated[
            str | None,
            Field(description="Token from a prior dry-run call.", default=None),
        ] = None,
        wait: Annotated[
            bool, Field(description="Block until deletion completes.", default=True)
        ] = True,
        timeout_seconds: Annotated[
            int,
            Field(description="Wait timeout.", default=DEFAULT_WAIT_TIMEOUT_SECONDS, ge=1),
        ] = DEFAULT_WAIT_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        from nebius.api.nebius.compute.v1 import DeleteDiskRequest, DiskServiceClient

        gate = preview_or_execute(
            tool="compute_delete_disk",
            args={"id": id},
            confirm_token=confirm_token,
            preview={"action": f"Delete disk {id}", "id": id},
        )
        if gate is not None:
            return gate  # type: ignore[return-value]

        client = service(DiskServiceClient)
        op = await safe(client.delete(DeleteDiskRequest(id=id)))
        summary = await maybe_wait(op, wait=wait, timeout_seconds=timeout_seconds)
        return wrap(summary)

    @app.tool(
        name="compute_list_platforms",
        description=(
            "List available compute platforms (CPU and GPU families) in this "
            "tenant. Use to discover valid platform names for new instances. "
            "parent_id is a tenant ID; omit to use the active profile's "
            "parent-id (which may be a project — in that case the call may fail "
            "and you should call iam_whoami to get the tenant)."
        ),
        annotations=READ_ANNOTATIONS,
    )
    async def compute_list_platforms(
        parent_id: Annotated[
            str | None,
            Field(description="Tenant ID. Omit to use active profile parent-id.", default=None),
        ] = None,
        page_size: Annotated[
            int | None,
            Field(description="Items per page (capped to 200, default 50).", default=None, ge=1),
        ] = None,
        page_token: Annotated[
            str | None,
            Field(description="Opaque pagination token.", default=None),
        ] = None,
    ) -> dict[str, Any]:
        from nebius.api.nebius.compute.v1 import ListPlatformsRequest, PlatformServiceClient

        resolved = _resolve_parent(parent_id)
        if not resolved:
            return wrap(
                {"items": [], "next_page_token": None},
                note="No parent_id supplied and no parent-id in active profile.",
            )

        client = service(PlatformServiceClient)
        kwargs: dict[str, Any] = {
            "parent_id": resolved,
            "page_size": clamp_page_size(page_size),
        }
        if page_token:
            kwargs["page_token"] = page_token

        resp = await safe(client.list(ListPlatformsRequest(**kwargs)))
        items = [safe_proto(it) for it in (resp.items or [])]
        return wrap(
            {
                "items": items,
                "next_page_token": resp.next_page_token or None,
                "parent_id": resolved,
            }
        )

    @app.tool(
        name="compute_create_instance",
        description=(
            "Create a compute VM instance. INCURS COST. First call returns a "
            "preview and a single-use confirm_token; call again with the token "
            "to execute. The token is bound to the arguments that shape the VM, "
            "the SSH key included, so the second call must repeat those "
            "unchanged; wait and timeout_seconds are outside the binding and "
            "may differ. ssh_public_key must be exactly one OpenSSH public key "
            "line of printable ASCII — multi-line values are rejected — and the "
            "preview reports that key's ssh-keygen fingerprint rather than the "
            "key itself. Boot disk minimum is 50 GiB. Disk types use underscores "
            "(network_ssd, not network-ssd). The key is authorized for user "
            "'nebius', who has passwordless sudo. Gated by write mode."
        ),
        annotations=CREATE_ANNOTATIONS,
    )
    async def compute_create_instance(
        name: Annotated[
            str, Field(description="Instance name (must be unique in project).", min_length=1)
        ],
        platform: Annotated[
            str,
            Field(description="Platform name. Discover via compute_list_platforms.", min_length=1),
        ],
        preset: Annotated[
            str,
            Field(description="Preset within the platform, e.g. '4vcpu-16gb'.", min_length=1),
        ],
        image_family: Annotated[
            str,
            Field(description="Source image family, e.g. 'ubuntu22.04-cuda12'.", min_length=1),
        ],
        subnet_id: Annotated[str, Field(description="VPC subnet ID.", min_length=1)],
        ssh_public_key: Annotated[
            str,
            Field(
                description="SSH public key, full line. Authorized for user 'nebius'.",
                min_length=1,
            ),
        ],
        parent_id: Annotated[
            str | None,
            Field(description="Project ID. Omit to use active profile.", default=None),
        ] = None,
        boot_disk_size_gib: Annotated[
            int,
            # ge=1, not ge=50. The 50 GiB floor belongs to the CUDA image
            # families and is enforced in validation.py where the image family
            # is known; carrying it in the schema refused legitimate small
            # CPU-only instances before the tool body could ever look. The
            # default stays 50 because the CUDA families are the common case.
            Field(
                description=(
                    "Boot disk size in GiB. The CUDA image families need at least 50; "
                    "other images have no floor beyond what Nebius enforces."
                ),
                default=50,
                ge=1,
            ),
        ] = 50,
        boot_disk_type: Annotated[
            str,
            Field(description="Disk type. network_ssd / network_hdd / etc.", default="network_ssd"),
        ] = "network_ssd",
        public_ip: Annotated[
            bool,
            Field(description="Assign an ephemeral public IP.", default=False),
        ] = False,
        gpu_cluster_id: Annotated[
            str | None,
            Field(description="Optional GPU cluster ID.", default=None),
        ] = None,
        service_account_id: Annotated[
            str | None,
            Field(description="Optional service-account ID to attach.", default=None),
        ] = None,
        confirm_token: Annotated[
            str | None,
            Field(description="Token from a prior dry-run call.", default=None),
        ] = None,
        wait: Annotated[
            bool, Field(description="Block until creation completes.", default=True)
        ] = True,
        timeout_seconds: Annotated[
            int,
            Field(description="Wait timeout.", default=DEFAULT_WAIT_TIMEOUT_SECONDS, ge=1),
        ] = DEFAULT_WAIT_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        from nebius.api.nebius.common.v1 import ResourceMetadata
        from nebius.api.nebius.compute.v1 import (
            AttachedDiskSpec,
            CreateInstanceRequest,
            DiskSpec,
            InstanceGpuClusterSpec,
            InstanceServiceClient,
            InstanceSpec,
            ManagedDisk,
            NetworkInterfaceSpec,
            PublicIPAddress,
            ResourcesSpec,
            SourceImageFamily,
        )

        # Mode first: in read-only mode the answer is "write mode is disabled",
        # not a complaint about arguments that were never going to be used.
        require_write("compute_create_instance")

        # Then validate, before issuing a token, so the preview never hands back
        # a token for a request that is guaranteed to fail.
        validate_disk_type(boot_disk_type)
        size_bytes = gib_to_bytes(boot_disk_size_gib)
        validate_boot_disk_size(size_bytes, image_family=image_family)
        # Normalised (and refused) here, before any token exists and before the
        # SDK client is built: an embedded newline in this value ends the
        # ssh_authorized_keys list item below and appends arbitrary top-level
        # cloud-config, so it must not reach a preview that would make it look
        # approved. Stripping once, here, also means the token, the preview and
        # cloud-init all agree on the exact key — binding the raw parameter
        # would let padding whitespace invalidate a freshly issued token even
        # though the VM would come out identical.
        ssh_key = _validate_ssh_public_key(ssh_public_key)

        resolved = parent_id or _profile_parent_id()
        if not resolved:
            raise ToolError(
                "compute_create_instance: parent_id is required (project ID), and no "
                "parent-id is set in the active profile."
            )

        cloud_init = (
            "#cloud-config\n"
            "users:\n"
            "  - name: nebius\n"
            "    sudo: ALL=(ALL) NOPASSWD:ALL\n"
            "    shell: /bin/bash\n"
            "    ssh_authorized_keys:\n"
            f"      - {ssh_key}\n"
        )

        # Every field that changes the resulting VM belongs here: the hash of
        # this dict is the whole of what the confirm token attests to, so an
        # omission is a field the second call can silently swap. ssh_public_key
        # in particular decides who gets shell.
        args = {
            "name": name,
            "parent_id": resolved,
            "platform": platform,
            "preset": preset,
            "image_family": image_family,
            "subnet_id": subnet_id,
            "ssh_public_key": ssh_key,
            "boot_disk_size_gib": boot_disk_size_gib,
            "boot_disk_type": boot_disk_type,
            "public_ip": public_ip,
            "gpu_cluster_id": gpu_cluster_id,
            "service_account_id": service_account_id,
        }
        gate = preview_or_execute(
            tool="compute_create_instance",
            args=args,
            confirm_token=confirm_token,
            preview={
                "action": f"Create instance {name!r} in project {resolved}",
                "platform": platform,
                "preset": preset,
                "image_family": image_family,
                "boot_disk_size_gib": boot_disk_size_gib,
                "subnet_id": subnet_id,
                "public_ip": public_ip,
                "ssh_key": _ssh_key_summary(ssh_key),
            },
        )
        if gate is not None:
            return gate  # type: ignore[return-value]

        boot_disk = AttachedDiskSpec(
            attach_mode=AttachedDiskSpec.AttachMode.READ_WRITE,
            managed_disk=ManagedDisk(
                spec=DiskSpec(
                    size_bytes=size_bytes,
                    type=getattr(DiskSpec.DiskType, boot_disk_type.upper()),
                    source_image_family=SourceImageFamily(image_family=image_family),
                )
            ),
        )

        nic_kwargs: dict[str, Any] = {"subnet_id": subnet_id, "name": "eth0"}
        if public_ip:
            nic_kwargs["public_ip_address"] = PublicIPAddress(static=False)
        nic = NetworkInterfaceSpec(**nic_kwargs)

        spec_kwargs: dict[str, Any] = {
            "resources": ResourcesSpec(platform=platform, preset=preset),
            "boot_disk": boot_disk,
            "network_interfaces": [nic],
            "cloud_init_user_data": cloud_init,
        }
        if gpu_cluster_id:
            spec_kwargs["gpu_cluster"] = InstanceGpuClusterSpec(id=gpu_cluster_id)
        if service_account_id:
            spec_kwargs["service_account_id"] = service_account_id

        client = service(InstanceServiceClient)
        op = await safe(
            client.create(
                CreateInstanceRequest(
                    metadata=ResourceMetadata(name=name, parent_id=resolved),
                    spec=InstanceSpec(**spec_kwargs),
                )
            )
        )
        summary = await maybe_wait(op, wait=wait, timeout_seconds=timeout_seconds)
        return wrap(summary)
