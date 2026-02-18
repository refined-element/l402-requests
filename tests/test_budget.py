"""Tests for budget controls."""

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
