"""Registry of every Nebius resource the SDK can reach.

This is the single source of truth for the generic ``nebius_resource_*`` tools
and for the per-domain tool modules. Each :class:`ResourceSpec` names a service
client; the *request* classes for each verb are derived from the client at
runtime rather than hard-coded, so an SDK upgrade that renames a request
message cannot silently desync this table from reality.

Why derivation needs care
-------------------------
The generated clients annotate methods with private alias names
(``_NebiusType_nebius_iam_v1_GetProjectRequest_ae906318``).
``typing.get_type_hints`` is the obvious way to resolve them, but it evaluates
*every* annotation in the defining module's namespace, and several generated
modules contain at least one alias that does not resolve (e.g.
``_NebiusType_nebius_iam_v1_Container_e9853e81``). One bad alias raises
``NameError`` and takes down resolution for every method in that module.

So we try ``get_type_hints`` first and fall back to parsing the alias name,
which encodes the proto path directly.
"""

from __future__ import annotations

import importlib
import re
import typing
from dataclasses import dataclass
from functools import cache

# _NebiusType_<proto_path_with_underscores>_<8 hex chars>
_ALIAS = re.compile(r"^_NebiusType_(?P<path>.+)_(?P<digest>[0-9a-f]{8})$")

# Verbs we know how to expose generically. Order is significant only for docs.
READ_VERBS = ("list", "get", "get_by_name")
WRITE_VERBS = ("create", "update", "start", "stop", "restart", "resume", "upgrade", "issue")
DESTRUCTIVE_VERBS = ("delete", "purge", "revoke", "cancel")
ALL_VERBS = (
    READ_VERBS
    + WRITE_VERBS
    + DESTRUCTIVE_VERBS
    + (
        "activate",
        "deactivate",
        "undelete",
        "estimate",
    )
)


@dataclass(frozen=True)
class ResourceSpec:
    """One Nebius resource type, addressable by ``key``."""

    key: str
    """Stable identifier used by the generic tools, e.g. ``storage.bucket``."""

    module: str
    """Python module exporting the service client, e.g. ``nebius.api.nebius.storage.v1``."""

    client: str
    """Service client class name, e.g. ``BucketServiceClient``."""

    label: str
    """Human-readable singular label used in tool descriptions."""

    parent: str
    """What ``parent_id`` means for this resource. Several resources are NOT
    parented by a project — getting this wrong is the most common Nebius API
    error, so it is surfaced verbatim in every generic tool response."""

    stability: str = "stable"
    """``stable`` for v1 APIs, ``alpha`` for v1alpha1/v2 previews."""


def _r(
    key: str,
    module: str,
    client: str,
    label: str,
    parent: str = "project",
    stability: str = "stable",
) -> ResourceSpec:
    return ResourceSpec(
        key=key,
        module="nebius.api.nebius." + module,
        client=client,
        label=label,
        parent=parent,
        stability=stability,
    )


PROJECT = "project ID (project-...)"
TENANT = "tenant ID (tenant-...)"

RESOURCES: tuple[ResourceSpec, ...] = (
    # --- AI endpoints & jobs -------------------------------------------------
    _r("ai.endpoint", "ai.v1", "EndpointServiceClient", "AI endpoint", PROJECT),
    _r("ai.job", "ai.v1", "JobServiceClient", "AI job", PROJECT),
    # --- Compute -------------------------------------------------------------
    _r("compute.instance", "compute.v1", "InstanceServiceClient", "compute instance", PROJECT),
    _r("compute.disk", "compute.v1", "DiskServiceClient", "disk", PROJECT),
    _r(
        "compute.disk_snapshot", "compute.v1", "DiskSnapshotServiceClient", "disk snapshot", PROJECT
    ),
    _r("compute.filesystem", "compute.v1", "FilesystemServiceClient", "shared filesystem", PROJECT),
    _r("compute.gpu_cluster", "compute.v1", "GpuClusterServiceClient", "GPU cluster", PROJECT),
    _r("compute.image", "compute.v1", "ImageServiceClient", "compute image", PROJECT),
    _r(
        "compute.nvl_instance_group",
        "compute.v1",
        "NVLInstanceGroupServiceClient",
        "NVLink instance group",
        PROJECT,
    ),
    _r("compute.platform", "compute.v1", "PlatformServiceClient", "compute platform", TENANT),
    # --- Managed Kubernetes --------------------------------------------------
    _r("mk8s.cluster", "mk8s.v1", "ClusterServiceClient", "mk8s cluster", PROJECT),
    _r(
        "mk8s.node_group",
        "mk8s.v1",
        "NodeGroupServiceClient",
        "mk8s node group",
        "mk8s CLUSTER ID (mk8scluster-...), NOT a project",
    ),
    # --- VPC -----------------------------------------------------------------
    _r("vpc.network", "vpc.v1", "NetworkServiceClient", "VPC network", PROJECT),
    _r("vpc.subnet", "vpc.v1", "SubnetServiceClient", "VPC subnet", PROJECT),
    _r("vpc.allocation", "vpc.v1", "AllocationServiceClient", "IP allocation", PROJECT),
    _r("vpc.pool", "vpc.v1", "PoolServiceClient", "IP pool", PROJECT),
    _r("vpc.route", "vpc.v1", "RouteServiceClient", "route", PROJECT),
    _r("vpc.route_table", "vpc.v1", "RouteTableServiceClient", "route table", PROJECT),
    _r("vpc.security_group", "vpc.v1", "SecurityGroupServiceClient", "security group", PROJECT),
    _r(
        "vpc.security_rule",
        "vpc.v1",
        "SecurityRuleServiceClient",
        "security rule",
        "SECURITY GROUP ID, NOT a project",
    ),
    _r("vpc.target_group", "vpc.v1", "TargetGroupServiceClient", "target group", PROJECT),
    # --- Object storage ------------------------------------------------------
    _r("storage.bucket", "storage.v1", "BucketServiceClient", "storage bucket", PROJECT),
    _r("storage.transfer", "storage.v1", "TransferServiceClient", "storage transfer", PROJECT),
    # --- Container registry --------------------------------------------------
    _r("registry.registry", "registry.v1", "RegistryServiceClient", "container registry", PROJECT),
    _r(
        "registry.artifact",
        "registry.v1",
        "ArtifactServiceClient",
        "registry artifact",
        "REGISTRY ID, NOT a project",
    ),
    # --- Secrets -------------------------------------------------------------
    _r("mysterybox.secret", "mysterybox.v1", "SecretServiceClient", "secret", PROJECT),
    _r(
        "mysterybox.secret_version",
        "mysterybox.v1",
        "SecretVersionServiceClient",
        "secret version",
        "SECRET ID, NOT a project",
    ),
    # --- IAM -----------------------------------------------------------------
    _r("iam.project", "iam.v1", "ProjectServiceClient", "project", TENANT),
    _r("iam.tenant", "iam.v1", "TenantServiceClient", "tenant", "none (tenant is the root)"),
    _r(
        "iam.service_account",
        "iam.v1",
        "ServiceAccountServiceClient",
        "service account",
        PROJECT,
    ),
    _r(
        "iam.access_key",
        "iam.v1",
        "AccessKeyServiceClient",
        "IAM access key",
        "SERVICE ACCOUNT ID, NOT a project",
    ),
    _r(
        "iam.static_key",
        "iam.v1",
        "StaticKeyServiceClient",
        "static key (S3 credentials)",
        "SERVICE ACCOUNT ID, NOT a project",
    ),
    _r(
        "iam.auth_public_key",
        "iam.v1",
        "AuthPublicKeyServiceClient",
        "auth public key",
        "SERVICE ACCOUNT ID, NOT a project",
    ),
    _r("iam.group", "iam.v1", "GroupServiceClient", "IAM group", TENANT),
    _r(
        "iam.group_membership",
        "iam.v1",
        "GroupMembershipServiceClient",
        "group membership",
        "GROUP ID, NOT a project",
    ),
    _r("iam.access_permit", "iam.v1", "AccessPermitServiceClient", "access permit", PROJECT),
    _r("iam.federation", "iam.v1", "FederationServiceClient", "identity federation", TENANT),
    _r(
        "iam.federated_credentials",
        "iam.v1",
        "FederatedCredentialsServiceClient",
        "federated credentials",
        "SERVICE ACCOUNT ID",
    ),
    _r("iam.invitation", "iam.v1", "InvitationServiceClient", "tenant invitation", TENANT),
    _r(
        "iam.tenant_user_account",
        "iam.v1",
        "TenantUserAccountServiceClient",
        "tenant user account",
        TENANT,
    ),
    # --- DNS -----------------------------------------------------------------
    _r("dns.zone", "dns.v1", "ZoneServiceClient", "DNS zone", PROJECT),
    _r("dns.record", "dns.v1", "RecordServiceClient", "DNS record", "DNS ZONE ID, NOT a project"),
    # --- KMS -----------------------------------------------------------------
    _r("kms.symmetric_key", "kms.v1", "SymmetricKeyServiceClient", "KMS symmetric key", PROJECT),
    _r("kms.asymmetric_key", "kms.v1", "AsymmetricKeyServiceClient", "KMS asymmetric key", PROJECT),
    # --- Quotas, billing, capacity ------------------------------------------
    _r("quotas.allowance", "quotas.v1", "QuotaAllowanceServiceClient", "quota allowance", TENANT),
    _r(
        "capacity.block_group",
        "capacity.v1",
        "CapacityBlockGroupServiceClient",
        "capacity block group",
        TENANT,
    ),
    _r(
        "capacity.interval",
        "capacity.v1",
        "CapacityIntervalServiceClient",
        "capacity interval",
        TENANT,
    ),
    _r(
        "capacity.resource_advice",
        "capacity.v1",
        "ResourceAdviceServiceClient",
        "capacity resource advice",
        TENANT,
    ),
    _r(
        "capacity.allowance",
        "capacity.v1",
        "CapacityAllowanceServiceClient",
        "capacity allowance",
        TENANT,
    ),
    _r(
        "billing.one_time_export",
        "billing.v1alpha1",
        "OneTimeExportServiceClient",
        "billing export",
        TENANT,
        "alpha",
    ),
    # --- Observability -------------------------------------------------------
    _r("audit.event", "audit.v2", "AuditEventServiceClient", "audit event", TENANT),
    _r("audit.export", "audit.v2", "AuditEventExportServiceClient", "audit event export", TENANT),
    _r(
        "maintenance.maintenance",
        "maintenance.v1alpha1",
        "MaintenanceServiceClient",
        "maintenance event",
        PROJECT,
        "alpha",
    ),
    # --- Managed services ----------------------------------------------------
    _r(
        "msp.postgresql_cluster",
        "msp.postgresql.v1alpha1",
        "ClusterServiceClient",
        "managed PostgreSQL cluster",
        PROJECT,
        "alpha",
    ),
    _r(
        "msp.postgresql_backup",
        "msp.postgresql.v1alpha1",
        "BackupServiceClient",
        "PostgreSQL backup",
        PROJECT,
        "alpha",
    ),
    _r(
        "msp.mlflow_cluster",
        "msp.mlflow.v1alpha1",
        "ClusterServiceClient",
        "managed MLflow cluster",
        PROJECT,
        "alpha",
    ),
    _r(
        "applications.k8s_release",
        "applications.v1alpha1",
        "K8sReleaseServiceClient",
        "Kubernetes application release",
        "mk8s CLUSTER ID",
        "alpha",
    ),
    _r("tunnel.tunnel", "tunnel.v1", "TunnelServiceClient", "application tunnel", PROJECT),
    # --- Operations ----------------------------------------------------------
    _r(
        "common.operation",
        "common.v1",
        "OperationServiceClient",
        "long-running operation",
        "the resource whose operation you are polling",
    ),
)

BY_KEY: dict[str, ResourceSpec] = {spec.key: spec for spec in RESOURCES}


@cache
def client_class(key: str) -> type:
    """Import and return the service-client class for ``key``."""
    spec = BY_KEY[key]
    module = importlib.import_module(spec.module)
    cls = getattr(module, spec.client)
    if not isinstance(cls, type):  # pragma: no cover - generated code is well-formed
        raise TypeError(f"{spec.module}.{spec.client} is not a class")
    return cls


def _resolve_alias(alias: str) -> type | None:
    """Resolve a ``_NebiusType_...`` annotation alias to its message class.

    The alias encodes the full proto path, so ``nebius_iam_v1_GetProjectRequest``
    means ``nebius.api.nebius.iam.v1.GetProjectRequest``. Proto message names are
    CamelCase and never contain underscores, so the final segment is the class.
    """
    match = _ALIAS.match(alias)
    if match is None:
        return None
    parts = match.group("path").split("_")
    if len(parts) < 2:
        return None
    class_name = parts[-1]
    module_path = "nebius.api." + ".".join(parts[:-1])
    try:
        module = importlib.import_module(module_path)
    except ImportError:
        return None
    resolved = getattr(module, class_name, None)
    return resolved if isinstance(resolved, type) else None


@cache
def request_class(key: str, verb: str) -> type | None:
    """Return the request message class for ``key``/``verb``, or None if absent."""
    method = getattr(client_class(key), verb, None)
    if method is None:
        return None

    try:
        hint = typing.get_type_hints(method).get("request")
        if isinstance(hint, type):
            return hint
    except Exception:  # noqa: S110 - see module docstring
        # One unresolvable alias anywhere in the defining module poisons the
        # whole call; fall through to parsing this method's alias directly.
        pass

    alias = getattr(method, "__annotations__", {}).get("request")
    return _resolve_alias(alias) if isinstance(alias, str) else None


@cache
def verbs(key: str) -> frozenset[str]:
    """Verbs actually available on this resource in the installed SDK."""
    return frozenset(v for v in ALL_VERBS if request_class(key, v) is not None)


def supports(key: str, verb: str) -> bool:
    return verb in verbs(key)


@cache
def list_items_field(key: str) -> str | None:
    """Name of the repeated field holding results in this resource's list response.

    Most services call it ``items``, but not all: managed PostgreSQL returns
    ``clusters`` and ``backups``, and OperationService returns ``operations``.
    Assuming ``items`` makes those three return an empty list, which is
    indistinguishable from an account that genuinely has none — a wrong answer
    that looks like a correct one.

    Returns None if no collection field can be identified.
    """
    method = getattr(client_class(key), "list", None)
    if method is None:
        return None

    alias = getattr(method, "__annotations__", {}).get("return")
    if not isinstance(alias, str):
        return None

    # Return annotation is Request[<Req>, <Resp>]; the response alias is last.
    response_aliases = re.findall(r"_NebiusType_[a-z0-9_]+_[A-Za-z0-9]+_[0-9a-f]{8}", alias)
    if not response_aliases:
        return None
    response_cls = _resolve_alias(response_aliases[-1])
    if response_cls is None:
        return None

    try:
        fields = list(response_cls._public_fields_by_python_name())  # type: ignore[attr-defined]
    except Exception:  # pragma: no cover - generated classes all expose this
        return None

    if "items" in fields:
        return "items"
    candidates = [f for f in fields if f != "next_page_token"]
    return candidates[0] if len(candidates) == 1 else None


def describe(spec: ResourceSpec) -> dict[str, object]:
    """Machine-readable summary used by ``nebius_list_resource_types``."""
    return {
        "resource_type": spec.key,
        "label": spec.label,
        "parent_id_means": spec.parent,
        "stability": spec.stability,
        "operations": sorted(verbs(spec.key)),
    }
