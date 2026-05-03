"""Pagination conventions shared by all list tools.

Server-side caps protect the model context: even if the caller asks for
1000 items, we cap to ``HARD_PAGE_LIMIT``. Callers paginate via the opaque
``next_page_token`` returned in each response.
"""

from __future__ import annotations

DEFAULT_PAGE_SIZE = 50
HARD_PAGE_LIMIT = 200


def clamp_page_size(requested: int | None) -> int:
    if requested is None or requested <= 0:
        return DEFAULT_PAGE_SIZE
    return min(requested, HARD_PAGE_LIMIT)
