"""LRU credential cache for L402 tokens, keyed by (domain, path_prefix)."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field


@dataclass
class L402Credential:
    """A cached L402 credential (macaroon + preimage)."""

    macaroon: str
    preimage: str
    created_at: float = field(default_factory=time.time)
    expires_at: float | None = None

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.time() >= self.expires_at

    @property
    def authorization_header(self) -> str:
        return f"L402 {self.macaroon}:{self.preimage}"


def _cache_key(domain: str, path: str) -> tuple[str, str]:
    """Normalize domain and path into a cache key.

    Groups paths by their first segment so /api/v1/foo and /api/v1/bar
    share the same credential if the server issued a broad macaroon.
    """
    domain = domain.lower().strip()
    # Use first two path segments as prefix: /api/v1/anything -> /api/v1
    parts = [p for p in path.split("/") if p]
    prefix = "/" + "/".join(parts[:2]) if len(parts) >= 2 else "/" + "/".join(parts)
    return (domain, prefix)


class CredentialCache:
    """Thread-safe LRU cache for L402 credentials."""

    def __init__(self, max_size: int = 256, default_ttl: float | None = 3600.0):
        self._max_size = max_size
        self._default_ttl = default_ttl
        self._cache: OrderedDict[tuple[str, str], L402Credential] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, domain: str, path: str) -> L402Credential | None:
        """Retrieve a cached credential for the given domain and path."""
        key = _cache_key(domain, path)
        with self._lock:
            cred = self._cache.get(key)
            if cred is None:
                return None
            if cred.is_expired():
                del self._cache[key]
                return None
            # Move to end (most recently used)
            self._cache.move_to_end(key)
            return cred

    def put(
        self,
        domain: str,
        path: str,
        macaroon: str,
        preimage: str,
        expires_at: float | None = None,
    ) -> L402Credential:
        """Store a credential in the cache."""
        key = _cache_key(domain, path)

        if expires_at is None and self._default_ttl is not None:
            expires_at = time.time() + self._default_ttl

        cred = L402Credential(
            macaroon=macaroon,
            preimage=preimage,
            expires_at=expires_at,
        )

        with self._lock:
            if key in self._cache:
                del self._cache[key]
            self._cache[key] = cred
            # Evict oldest if over capacity
            while len(self._cache) > self._max_size:
                self._cache.popitem(last=False)

        return cred

    def clear(self) -> None:
        """Remove all cached credentials."""
        with self._lock:
            self._cache.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._cache)
