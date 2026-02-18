"""Budget controls for L402 payments.

Enforces per-request, hourly, and daily spending limits. Safety-first:
budgets are enabled by default so users don't accidentally overspend.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field

from l402_requests.exceptions import BudgetExceededError, DomainNotAllowedError


@dataclass
class BudgetController:
    """Configurable spending limits for L402 payments.

    Args:
        max_sats_per_request: Maximum sats for a single payment (default 1000).
        max_sats_per_hour: Maximum sats in a sliding 1-hour window (default 10000).
        max_sats_per_day: Maximum sats in a sliding 24-hour window (default 50000).
        allowed_domains: If set, only pay invoices from these domains.
    """

    max_sats_per_request: int = 1_000
    max_sats_per_hour: int = 10_000
    max_sats_per_day: int = 50_000
    allowed_domains: set[str] | None = None
    _payments: deque[tuple[float, int]] = field(default_factory=deque, repr=False)

    def check(self, amount_sats: int, domain: str | None = None) -> None:
        """Verify a payment is within budget. Raises if not.

        Args:
            amount_sats: The invoice amount in satoshis.
            domain: The domain the request is going to.

        Raises:
            DomainNotAllowedError: If domain is not in allowed_domains.
            BudgetExceededError: If any budget limit would be exceeded.
        """
        if self.allowed_domains is not None and domain:
            if domain.lower() not in {d.lower() for d in self.allowed_domains}:
                raise DomainNotAllowedError(domain)

        # Per-request limit
        if amount_sats > self.max_sats_per_request:
            raise BudgetExceededError(
                "per_request", self.max_sats_per_request, 0, amount_sats
            )

        now = time.time()
        self._prune(now)

        # Hourly limit
        hour_ago = now - 3600
        spent_hour = sum(amt for ts, amt in self._payments if ts >= hour_ago)
        if spent_hour + amount_sats > self.max_sats_per_hour:
            raise BudgetExceededError(
                "per_hour", self.max_sats_per_hour, spent_hour, amount_sats
            )

        # Daily limit
        day_ago = now - 86400
        spent_day = sum(amt for ts, amt in self._payments if ts >= day_ago)
        if spent_day + amount_sats > self.max_sats_per_day:
            raise BudgetExceededError(
                "per_day", self.max_sats_per_day, spent_day, amount_sats
            )

    def record_payment(self, amount_sats: int) -> None:
        """Record a successful payment against the budget."""
        self._payments.append((time.time(), amount_sats))

    def spent_last_hour(self) -> int:
        """Total sats spent in the last hour."""
        now = time.time()
        self._prune(now)
        hour_ago = now - 3600
        return sum(amt for ts, amt in self._payments if ts >= hour_ago)

    def spent_last_day(self) -> int:
        """Total sats spent in the last 24 hours."""
        now = time.time()
        self._prune(now)
        day_ago = now - 86400
        return sum(amt for ts, amt in self._payments if ts >= day_ago)

    def _prune(self, now: float) -> None:
        """Remove payments older than 24 hours."""
        cutoff = now - 86400
        while self._payments and self._payments[0][0] < cutoff:
            self._payments.popleft()
