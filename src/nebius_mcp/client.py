"""Cached service-client factories.

Each Nebius gRPC service exposes a ``*ServiceClient`` constructed against the
SDK channel. Constructing them is cheap, but routing every tool call through
the same instances keeps logging/instrumentation centralized.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any, TypeVar

from .auth import get_sdk

if TYPE_CHECKING:
    pass

T = TypeVar("T")

_clients: dict[type, Any] = {}
_clients_lock = threading.Lock()


def service(client_cls: type[T]) -> T:
    """Return a cached instance of ``client_cls`` bound to the singleton SDK.

    The lock closes a check-then-set race: ``auth._sdk_lock`` guards SDK
    construction, but nothing guarded this dict, so two threads could each build
    a stub and one would silently win. Harmless under stdio, where calls are
    serialized; not harmless under the HTTP/session transport on the roadmap.

    ``get_sdk()`` is called outside the lock deliberately — it takes its own
    lock, and holding both in opposite orders anywhere else would deadlock.
    """
    cached = _clients.get(client_cls)
    if cached is not None:
        hit: T = cached
        return hit

    sdk = get_sdk()
    with _clients_lock:
        # Another thread may have won while we were building; prefer whatever is
        # stored so every caller shares one stub per class.
        existing = _clients.get(client_cls)
        if existing is None:
            existing = client_cls(sdk)  # type: ignore[call-arg]
            _clients[client_cls] = existing
    instance: T = existing
    return instance


def reset_clients() -> None:
    """Drop cached service clients.

    Called by ``auth.reset_sdk`` as well as by tests, so the SDK cache and the
    stubs bound to it cannot drift apart.
    """
    with _clients_lock:
        _clients.clear()
