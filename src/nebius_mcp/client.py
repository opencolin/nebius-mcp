"""Cached service-client factories.

Each Nebius gRPC service exposes a ``*ServiceClient`` constructed against the
SDK channel. Constructing them is cheap, but routing every tool call through
the same instances keeps logging/instrumentation centralized.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, TypeVar

from .auth import get_sdk

if TYPE_CHECKING:
    pass

T = TypeVar("T")

_clients: dict[type, Any] = {}


def service(client_cls: type[T]) -> T:
    """Return a cached instance of ``client_cls`` bound to the singleton SDK."""
    if client_cls not in _clients:
        sdk = get_sdk()
        _clients[client_cls] = client_cls(sdk)  # type: ignore[call-arg]
    instance: T = _clients[client_cls]
    return instance


def reset_clients() -> None:
    """Drop cached service clients. Intended for tests."""
    _clients.clear()
