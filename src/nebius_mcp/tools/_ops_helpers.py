"""Shared annotations and helpers for state-change / destructive tools.

Centralizing the annotation dicts keeps every tool consistent and makes the
manifest hash less likely to drift accidentally.

Note: this module deliberately does NOT use ``from __future__ import annotations``
because the registration helpers build ``Annotated[..., Field(description=closure_var)]``
expressions whose Field default needs to be evaluated when the function is defined
(otherwise pydantic's late-evaluation pass tries to resolve the closure variable
in module globals and fails with NameError).
"""

from typing import Annotated, Any

from fastmcp import FastMCP
from pydantic import Field

from ..client import service
from ..confirm import preview_or_execute
from ..errors import safe
from ..operation import DEFAULT_WAIT_TIMEOUT_SECONDS, maybe_wait
from ..sanitize import wrap

# Reversible state changes (start/stop). Gated by write mode but no dry-run.
STATE_ANNOTATIONS = {
    "readOnlyHint": False,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": True,
}

# Irreversible operations (delete) - require dry_run/confirm.
DESTRUCTIVE_ANNOTATIONS = {
    "readOnlyHint": False,
    "destructiveHint": True,
    "idempotentHint": False,
    "openWorldHint": True,
}

# Create operations - same as destructive (irreversible side effects on cost).
CREATE_ANNOTATIONS = {
    "readOnlyHint": False,
    "destructiveHint": False,
    "idempotentHint": False,
    "openWorldHint": True,
}


def register_delete_tool(
    app: FastMCP,
    *,
    tool_name: str,
    resource_label: str,
    client_cls: type,
    request_cls: type,
    id_description: str = "Resource ID.",
    extra_description: str = "",
) -> None:
    """Register a uniform ``<service>_delete_<resource>`` tool.

    Pattern: dry_run preview → confirm_token → execute → maybe_wait.
    """
    description = (
        f"Delete {resource_label}. IRREVERSIBLE. First call returns a preview "
        "and a single-use confirm_token (expires in 120s); call again with the "
        "token to execute. Gated by write mode."
    )
    if extra_description:
        description = description + " " + extra_description

    @app.tool(
        name=tool_name,
        description=description,
        annotations=DESTRUCTIVE_ANNOTATIONS,
    )
    async def _tool(
        id: Annotated[str, Field(description=id_description, min_length=1)],
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
        gate = preview_or_execute(
            tool=tool_name,
            args={"id": id},
            confirm_token=confirm_token,
            preview={"action": f"Delete {resource_label} {id}", "id": id},
        )
        if gate is not None:
            return gate  # type: ignore[return-value]

        client: Any = service(client_cls)
        op = await safe(client.delete(request_cls(id=id)))
        summary = await maybe_wait(op, wait=wait, timeout_seconds=timeout_seconds)
        return wrap(summary)


def register_state_tool(
    app: FastMCP,
    *,
    tool_name: str,
    description: str,
    client_cls: type,
    request_cls: type,
    method_name: str,
    id_description: str = "Resource ID.",
) -> None:
    """Register a state-change tool (start/stop). Reversible — no dry-run."""

    @app.tool(name=tool_name, description=description, annotations=STATE_ANNOTATIONS)
    async def _tool(
        id: Annotated[str, Field(description=id_description, min_length=1)],
        wait: Annotated[
            bool, Field(description="Block until operation completes.", default=True)
        ] = True,
        timeout_seconds: Annotated[
            int,
            Field(description="Wait timeout.", default=DEFAULT_WAIT_TIMEOUT_SECONDS, ge=1),
        ] = DEFAULT_WAIT_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        from ..confirm import require_write

        require_write(tool_name)
        client: Any = service(client_cls)
        method = getattr(client, method_name)
        op = await safe(method(request_cls(id=id)))
        summary = await maybe_wait(op, wait=wait, timeout_seconds=timeout_seconds)
        return wrap(summary)
