"""Payment history tracker for L402 spending introspection."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field


@dataclass
class PaymentRecord:
    """A single L402 payment event."""

    domain: str
    path: str
    amount_sats: int
    preimage: str
    timestamp: float = field(default_factory=time.time)
    success: bool = True


class SpendingLog:
    """Records all L402 payments for introspection and auditing."""

    def __init__(self) -> None:
        self._records: list[PaymentRecord] = []

    def record(
        self,
        domain: str,
        path: str,
        amount_sats: int,
        preimage: str,
        success: bool = True,
    ) -> PaymentRecord:
        """Record a payment attempt."""
        entry = PaymentRecord(
            domain=domain,
            path=path,
            amount_sats=amount_sats,
            preimage=preimage,
            success=success,
        )
        self._records.append(entry)
        return entry

    @property
    def records(self) -> list[PaymentRecord]:
        return list(self._records)

    def total_spent(self) -> int:
        """Total sats spent across all successful payments."""
        return sum(r.amount_sats for r in self._records if r.success)

    def spent_last_hour(self) -> int:
        """Total sats spent in the last hour."""
        cutoff = time.time() - 3600
        return sum(
            r.amount_sats for r in self._records if r.success and r.timestamp >= cutoff
        )

    def spent_today(self) -> int:
        """Total sats spent in the last 24 hours."""
        cutoff = time.time() - 86400
        return sum(
            r.amount_sats for r in self._records if r.success and r.timestamp >= cutoff
        )

    def by_domain(self) -> dict[str, int]:
        """Total sats spent per domain."""
        totals: dict[str, int] = {}
        for r in self._records:
            if r.success:
                totals[r.domain] = totals.get(r.domain, 0) + r.amount_sats
        return totals

    def to_json(self) -> str:
        """Serialize all records to JSON."""
        return json.dumps([asdict(r) for r in self._records], indent=2)

    def __len__(self) -> int:
        return len(self._records)
