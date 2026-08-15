"""Tests for budget controls."""

import threading
import time
from unittest.mock import patch

import pytest

from l402_requests.budget import BudgetController
from l402_requests.exceptions import BudgetExceededError, DomainNotAllowedError


class TestBudgetController:
    def test_allows_within_per_request_limit(self):
        budget = BudgetController(max_sats_per_request=1000)
        budget.check(500)  # Should not raise

    def test_rejects_over_per_request_limit(self):
        budget = BudgetController(max_sats_per_request=1000)
        with pytest.raises(BudgetExceededError, match="per_request"):
            budget.check(1001)

    def test_tracks_hourly_spending(self):
        budget = BudgetController(
            max_sats_per_request=10000, max_sats_per_hour=500
        )
        budget.record_payment(300)
        budget.check(100)  # 300 + 100 = 400, under 500
        budget.record_payment(100)
        with pytest.raises(BudgetExceededError, match="per_hour"):
            budget.check(200)  # 400 + 200 = 600, over 500

    def test_tracks_daily_spending(self):
        budget = BudgetController(
            max_sats_per_request=100000,
            max_sats_per_hour=100000,
            max_sats_per_day=1000,
        )
        budget.record_payment(800)
        with pytest.raises(BudgetExceededError, match="per_day"):
            budget.check(300)  # 800 + 300 = 1100, over 1000

    def test_old_payments_expire(self):
        budget = BudgetController(
            max_sats_per_request=10000,
            max_sats_per_hour=500,
        )
        # Record a payment "2 hours ago"
        old_time = time.time() - 7200
        budget._payments.append((old_time, 400))
        # This should pass since the old payment is outside the hour window
        budget.check(400)

    def test_domain_allowlist(self):
        budget = BudgetController(
            allowed_domains={"api.example.com", "store.lightningenable.com"}
        )
        budget.check(100, domain="api.example.com")  # OK
        with pytest.raises(DomainNotAllowedError):
            budget.check(100, domain="evil.com")

    def test_domain_allowlist_case_insensitive(self):
        budget = BudgetController(
            allowed_domains={"API.Example.COM"}
        )
        budget.check(100, domain="api.example.com")

    def test_no_domain_allowlist_allows_all(self):
        budget = BudgetController()
        budget.check(100, domain="any.domain.com")

    def test_spent_last_hour(self):
        budget = BudgetController()
        budget.record_payment(100)
        budget.record_payment(200)
        assert budget.spent_last_hour() == 300

    def test_spent_last_day(self):
        budget = BudgetController()
        budget.record_payment(100)
        assert budget.spent_last_day() == 100

    def test_budget_exceeded_error_details(self):
        budget = BudgetController(max_sats_per_request=100)
        with pytest.raises(BudgetExceededError) as exc_info:
            budget.check(200)
        assert exc_info.value.limit_type == "per_request"
        assert exc_info.value.limit_sats == 100
        assert exc_info.value.invoice_sats == 200


class TestBudgetReservation:
    """Reserve/commit/release lifecycle — the atomic enforcement path.

    ``check()`` then later ``record_payment()`` is a check-then-act TOCTOU: two
    payments can each pass ``check()`` against the same still-unrecorded total,
    both settle, and the window total blows past the cap. ``reserve()`` folds
    the check and the state mutation into one atomic step (active reservations
    count toward the limit), so a second concurrent reserve over the cap is
    refused before the wallet is ever touched.
    """

    def test_reserve_within_limit_returns_id(self):
        budget = BudgetController(max_sats_per_request=1000, max_sats_per_hour=5000)
        rid = budget.reserve(1000)
        assert rid is not None

    def test_reserve_rejects_over_per_request(self):
        budget = BudgetController(max_sats_per_request=1000)
        with pytest.raises(BudgetExceededError, match="per_request"):
            budget.reserve(1001)

    def test_active_reservation_counts_against_hourly_cap(self):
        # The whole point: a live reservation reduces headroom for the next
        # reserve, even though nothing has been recorded/committed yet.
        budget = BudgetController(max_sats_per_request=1000, max_sats_per_hour=1500)
        budget.reserve(1000)  # 1000 reserved, 0 committed
        with pytest.raises(BudgetExceededError, match="per_hour"):
            budget.reserve(1000)  # 1000 + 1000 = 2000 > 1500

    def test_active_reservation_counts_against_daily_cap(self):
        budget = BudgetController(
            max_sats_per_request=1000,
            max_sats_per_hour=100000,
            max_sats_per_day=1500,
        )
        budget.reserve(1000)
        with pytest.raises(BudgetExceededError, match="per_day"):
            budget.reserve(1000)

    def test_commit_records_actual_spend_and_frees_reservation(self):
        budget = BudgetController(max_sats_per_request=1000, max_sats_per_hour=1500)
        rid = budget.reserve(1000)
        budget.commit(rid, 1000)
        # Reservation dropped, spend recorded.
        assert budget.spent_last_hour() == 1000
        # Headroom now reflects committed spend only (500 left under 1500).
        with pytest.raises(BudgetExceededError, match="per_hour"):
            budget.reserve(1000)
        budget.reserve(500)  # fits in remaining headroom

    def test_commit_may_include_routing_fee(self):
        # commit() takes the ACTUAL amount, which may exceed the reserved
        # principal when the wallet surfaces a routing fee.
        budget = BudgetController(max_sats_per_request=1000, max_sats_per_hour=5000)
        rid = budget.reserve(1000)
        budget.commit(rid, 1050)  # principal 1000 + 50 fee
        assert budget.spent_last_hour() == 1050

    def test_release_frees_reservation_without_spending(self):
        budget = BudgetController(max_sats_per_request=1000, max_sats_per_hour=1500)
        rid = budget.reserve(1000)
        budget.release(rid)
        assert budget.spent_last_hour() == 0
        # Full headroom restored — a fresh reserve for the same amount fits.
        rid2 = budget.reserve(1000)
        budget.commit(rid2, 1000)
        assert budget.spent_last_hour() == 1000

    def test_reserve_enforces_domain_allowlist(self):
        budget = BudgetController(allowed_domains={"api.example.com"})
        budget.reserve(100, domain="api.example.com")  # OK
        with pytest.raises(DomainNotAllowedError):
            budget.reserve(100, domain="evil.com")

    def test_concurrent_reserves_only_one_passes(self):
        """The core race: many threads reserve the whole cap at once; the lock
        must let exactly one through. Without atomic check+reserve, several
        threads read the same 0-spent total and all pass."""
        budget = BudgetController(
            max_sats_per_request=1000,
            max_sats_per_hour=1000,
            max_sats_per_day=1000,
        )
        n = 16
        barrier = threading.Barrier(n)
        granted: list[int] = []
        granted_lock = threading.Lock()

        def attempt() -> None:
            barrier.wait()  # release all threads at once
            try:
                rid = budget.reserve(1000)
            except BudgetExceededError:
                return
            with granted_lock:
                granted.append(rid)

        threads = [threading.Thread(target=attempt) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert len(granted) == 1
        # Reservation ids are unique.
        assert len(set(granted)) == len(granted)
