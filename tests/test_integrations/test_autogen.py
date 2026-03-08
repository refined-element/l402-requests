"""Tests for AutoGen (AG2) integration tools."""

from __future__ import annotations

import json

import pytest

pytest.importorskip("autogen", reason="ag2 not installed")

from l402_requests.integrations import autogen as autogen_integration
from l402_requests.integrations.autogen import (
    configure_client,
    l402_get,
    l402_post,
    l402_spending_summary,
)


@pytest.fixture(autouse=True)
def reset_autogen_client():
    """Reset the module-level client before each test."""
    autogen_integration._l402_client = None
    yield
    autogen_integration._l402_client = None


class TestConfigureClient:
    def test_configure_sets_module_client(self, l402_client):
        configure_client(l402_client)
        assert autogen_integration._l402_client is l402_client

    def test_configure_replaces_existing(self, l402_client, free_client):
        configure_client(l402_client)
        configure_client(free_client)
        assert autogen_integration._l402_client is free_client


class TestL402Get:
    def test_get_with_l402_payment(self, l402_client):
        configure_client(l402_client)
        result = l402_get(url="https://api.example.com/data")

        parsed = json.loads(result)
        assert parsed["status"] == 200
        assert parsed["body"] == {"data": "paid content"}

    def test_get_free_endpoint(self, free_client):
        configure_client(free_client)
        result = l402_get(url="https://api.example.com/free")

        parsed = json.loads(result)
        assert parsed["status"] == 200
        assert parsed["body"] == {"data": "free content"}

    def test_non_json_response(self, text_client):
        configure_client(text_client)
        result = l402_get(url="https://api.example.com/text")

        parsed = json.loads(result)
        assert parsed["status"] == 200
        assert "Hello plain text" in parsed["body"]

    def test_budget_exceeded_returns_error_json(self, budget_exceeded_client):
        configure_client(budget_exceeded_client)
        result = l402_get(url="https://api.example.com/data")

        parsed = json.loads(result)
        assert parsed["error"] == "budget_exceeded"

    def test_payment_failed_returns_error_json(self, failing_client):
        configure_client(failing_client)
        result = l402_get(url="https://api.example.com/data")

        parsed = json.loads(result)
        assert parsed["error"] == "payment_failed"

    def test_lazy_client_creation_without_configure(self):
        """Calling l402_get without configure_client should lazily create a client."""
        # This will create a client with no wallet configured,
        # which should raise NoWalletError on a 402 response.
        # We can't test the full flow without a real wallet,
        # but we can verify the function doesn't crash on invocation.
        # Since there's no mock transport, this would try a real network call,
        # so we just verify the module state.
        assert autogen_integration._l402_client is None
        # After _get_client(), it should be set
        client = autogen_integration._get_client()
        assert autogen_integration._l402_client is not None


class TestL402Post:
    def test_post_with_body(self, post_client):
        configure_client(post_client)
        result = l402_post(
            url="https://api.example.com/data",
            body='{"key": "value"}',
        )

        parsed = json.loads(result)
        assert parsed["status"] == 200
        assert parsed["body"]["received"] is True

    def test_post_with_empty_body(self, post_client):
        configure_client(post_client)
        result = l402_post(url="https://api.example.com/data", body="")

        parsed = json.loads(result)
        assert parsed["status"] == 200

    def test_invalid_json_body_returns_error(self, post_client):
        configure_client(post_client)
        result = l402_post(
            url="https://api.example.com/data",
            body="not valid json{{{",
        )

        parsed = json.loads(result)
        assert parsed["error"] == "invalid_json_body"

    def test_budget_exceeded_returns_error_json(self, budget_exceeded_client):
        configure_client(budget_exceeded_client)
        result = l402_post(url="https://api.example.com/data", body="")

        parsed = json.loads(result)
        assert parsed["error"] == "budget_exceeded"


class TestL402SpendingSummary:
    def test_no_client_returns_zero(self):
        result = l402_spending_summary()

        parsed = json.loads(result)
        assert parsed["total_sats"] == 0
        assert parsed["by_domain"] == {}

    def test_spending_after_payment(self, l402_client):
        configure_client(l402_client)

        # Make a payment
        l402_get(url="https://api.example.com/data")

        result = l402_spending_summary()
        parsed = json.loads(result)
        assert parsed["total_sats"] == 1000
        assert parsed["by_domain"]["api.example.com"] == 1000

    def test_spending_tracks_multiple_calls(self, l402_client):
        configure_client(l402_client)

        l402_get(url="https://api.example.com/data")
        # Second call uses cached credential, no additional spend
        l402_get(url="https://api.example.com/data")

        result = l402_spending_summary()
        parsed = json.loads(result)
        # Only 1000 sats — second call used cached credential
        assert parsed["total_sats"] == 1000


class TestRegisterL402Tools:
    def test_register_creates_functions(self):
        """Verify register_l402_tools registers all 3 functions."""
        from unittest.mock import MagicMock, patch

        caller = MagicMock()
        executor = MagicMock()

        # register_function is imported inside the function body from autogen,
        # so we patch it on the autogen (ag2) module itself
        with patch("autogen.register_function") as mock_register:
            from l402_requests.integrations.autogen import register_l402_tools

            register_l402_tools(caller=caller, executor=executor)

            assert mock_register.call_count == 3
            names = [c.kwargs["name"] for c in mock_register.call_args_list]
            assert "l402_get" in names
            assert "l402_post" in names
            assert "l402_spending_summary" in names

            # Verify caller/executor are passed correctly
            for c in mock_register.call_args_list:
                assert c.kwargs["caller"] is caller
                assert c.kwargs["executor"] is executor
