"""Package version and the User-Agent built from it.

A leaf module (no imports from this package) so ``client`` and the wallet adapters can
read the version at import time without a circular import through ``__init__``.
"""

from __future__ import annotations

from typing import Any

from importlib.metadata import PackageNotFoundError as _PackageNotFoundError
from importlib.metadata import version as _pkg_version

import httpx

# Used only when running from a source checkout that was never pip-installed;
# installed copies always read the version from package metadata, so it can't
# drift from pyproject.toml (the single source of truth).
_FALLBACK_VERSION = "0.8.0"

try:
    __version__ = _pkg_version("l402-requests")
except _PackageNotFoundError:  # pragma: no cover
    __version__ = _FALLBACK_VERSION

#: Sent on every HTTP request the library makes unless the caller sets their own
#: ``User-Agent``. Servers classify paid L402 traffic by this product token; keep
#: the spelling exactly as is.
USER_AGENT = f"l402-requests/{__version__}"


def with_default_user_agent(headers: Any = None) -> httpx.Headers:
    """Return ``headers`` with our User-Agent added unless one is already set.

    Header names are compared case-insensitively, so a caller's ``user-agent``
    replaces ours rather than producing a duplicate.
    """
    merged = httpx.Headers({"User-Agent": USER_AGENT})
    if headers is not None:
        merged.update(httpx.Headers(headers))
    return merged
