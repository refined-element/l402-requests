"""Budget controls for L402 payments.

Enforces per-request, hourly, and daily spending limits. Safety-first:
budgets are enabled by default so users don't accidentally overspend.
"""

from __future__ import annotations

import threading
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

    Concurrency: enforcement runs through the atomic
    :meth:`reserve`/:meth:`commit`/:meth:`release` lifecycle rather than the
    legacy :meth:`check` + :meth:`record_payment` pair. ``check`` and
    ``record_payment`` were a check-then-act TOCTOU — two concurrent payments
    could each pass ``check`` against the same still-unrecorded total, both
    settle, and the window blow past the cap. ``reserve`` evaluates the limits
    *including* the sats already held by other in-flight reservations and books
    a reservation in the same locked critical section, so two concurrent
    reserves over the cap can't both succeed. The lock guards only the in-memory
    counter mutations; it is never held across the wallet payment (the caller
    reserves, releases the lock, awaits the wallet, then commits/releases).
    """

    max_sats_per_request: int = 1_000
    max_sats_per_hour: int = 10_000
    max_sats_per_day: int = 50_000
    allowed_domains: set[str] | None = None
    _payments: deque[tuple[float, int]] = field(default_factory=deque, repr=False)
    # Active (uncommitted) reservations: id -> reserved sats. Counted against
    # every window limit while live so concurrent reserves can't overcommit.
    _reservations: dict[int, int] = field(
        default_factory=dict, repr=False, compare=False
    )
    _next_reservation_id: int = field(default=0, repr=False, compare=False)
    # Guards _payments, _reservations, and _next_reservation_id so the
    # check-and-reserve is one atomic step under both threads and the asyncio
    # loop. Non-reentrant: helpers called while holding it (e.g. _prune) must
    # not re-acquire it.
    _lock: "threading.Lock" = field(
        default_factory=threading.Lock, repr=False, compare=False
    )

    def check(self, amount_sats: int, domain: str | None = None) -> None:
        """Verify a payment is within budget. Raises if not.

        Legacy advisory check kept for backward compatibility. It does NOT
        account for in-flight reservations and is not the enforcement path —
        use :meth:`reserve` for anything that gates a real payment.

        Args:
            amount_sats: The invoice amount in satoshis.
            domain: The domain the request is going to.

        Raises:
            DomainNotAllowedError: If domain is not in allowed_domains.
            BudgetExceededError: If any budget limit would be exceeded.
        """
        self._check_domain(domain)

        # Per-request limit
        if amount_sats > self.max_sats_per_request:
            raise BudgetExceededError(
                "per_request", self.max_sats_per_request, 0, amount_sats
            )

        with self._lock:
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

    def reserve(self, amount_sats: int, domain: str | None = None) -> int:
        """Atomically check the limits and book a reservation for ``amount_sats``.

        The check and the reservation happen in one locked critical section, and
        the evaluation counts sats already held by other live reservations, so
        two concurrent callers can't both pass when only one fits. Returns a
        reservation id to hand to :meth:`commit` (on a settled payment) or
        :meth:`release` (on failure/refusal). The lock is released before this
        method returns — callers must NOT hold anything across the wallet call.

        Raises:
            DomainNotAllowedError: If domain is not in allowed_domains.
            BudgetExceededError: If any budget limit would be exceeded once the
                in-flight reservations are taken into account.
        """
        self._check_domain(domain)

        # Per-request limit is independent of window/reservation state.
        if amount_sats > self.max_sats_per_request:
            raise BudgetExceededError(
                "per_request", self.max_sats_per_request, 0, amount_sats
            )

        with self._lock:
            now = time.time()
            self._prune(now)
            reserved = sum(self._reservations.values())

            hour_ago = now - 3600
            spent_hour = sum(amt for ts, amt in self._payments if ts >= hour_ago)
            if spent_hour + reserved + amount_sats > self.max_sats_per_hour:
                raise BudgetExceededError(
                    "per_hour", self.max_sats_per_hour, spent_hour + reserved, amount_sats
                )

            day_ago = now - 86400
            spent_day = sum(amt for ts, amt in self._payments if ts >= day_ago)
            if spent_day + reserved + amount_sats > self.max_sats_per_day:
                raise BudgetExceededError(
                    "per_day", self.max_sats_per_day, spent_day + reserved, amount_sats
                )

            self._next_reservation_id += 1
            reservation_id = self._next_reservation_id
            self._reservations[reservation_id] = amount_sats
            return reservation_id

    def commit(self, reservation_id: int, actual_amount_sats: int) -> None:
        """Finalize a reservation as a settled payment of ``actual_amount_sats``.

        ``actual_amount_sats`` is what was really spent, which may exceed the
        reserved principal when the wallet surfaces a routing fee. Dropping the
        reservation and recording the payment happen atomically so the window
        total is always consistent. Unknown ids are ignored (idempotent).
        """
        with self._lock:
            # Idempotent: only record spend if the reservation was still live. A
            # double-commit, or a commit of an already-released/unknown id, must NOT
            # append a phantom payment that would over-count the window and starve the
            # budget. Matches release()'s idempotency.
            if self._reservations.pop(reservation_id, None) is not None:
                self._payments.append((time.time(), actual_amount_sats))

    def release(self, reservation_id: int) -> None:
        """Drop a reservation without recording any spend (payment failed/refused).

        Unknown ids are ignored so a double-release or a release after commit is
        harmless.
        """
        with self._lock:
            self._reservations.pop(reservation_id, None)

    def record_payment(self, amount_sats: int) -> None:
        """Record a successful payment against the budget.

        Legacy direct-record path retained for backward compatibility. The
        enforcement path is reserve/commit; prefer :meth:`commit`.
        """
        with self._lock:
            self._payments.append((time.time(), amount_sats))

    def spent_last_hour(self) -> int:
        """Total sats spent (committed) in the last hour."""
        with self._lock:
            now = time.time()
            self._prune(now)
            hour_ago = now - 3600
            return sum(amt for ts, amt in self._payments if ts >= hour_ago)

    def spent_last_day(self) -> int:
        """Total sats spent (committed) in the last 24 hours."""
        with self._lock:
            now = time.time()
            self._prune(now)
            day_ago = now - 86400
            return sum(amt for ts, amt in self._payments if ts >= day_ago)

    def _check_domain(self, domain: str | None) -> None:
        """Enforce the domain allowlist. Lock-free (allowed_domains is immutable)."""
        if self.allowed_domains is not None and domain:
            if domain.lower() not in {d.lower() for d in self.allowed_domains}:
                raise DomainNotAllowedError(domain)

    def _prune(self, now: float) -> None:
        """Remove payments older than 24 hours.

        Caller MUST hold ``self._lock`` (the lock is non-reentrant).
        """
        cutoff = now - 86400
        while self._payments and self._payments[0][0] < cutoff:
            self._payments.popleft()
