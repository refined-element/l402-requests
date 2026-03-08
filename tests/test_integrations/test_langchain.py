"""Tests for LangChain integration tools."""

from __future__ import annotations

import json

import pytest

pytest.importorskip("langchain_core", reason="langchain-core not installed")

from l402_requests.integrations.langchain import L402FetchTool, L402SpendingTool


class TestL402FetchTool:
    def test_get_with_l402_payment(self, l402_client):
        tool = L402FetchTool(client=l402_client)
        result = tool._run(url="https://api.example.com/data")

        parsed = json.loads(result)
        assert parsed == {"data": "paid content"}

    def test_get_free_endpoint(self, free_client):
        tool = L402FetchTool(client=free_client)
        result = tool._run(url="https://api.example.com/free")

        parsed = json.loads(result)
        assert parsed == {"data": "free content"}

    def test_post_with_l402_payment(self, post_client):
        tool = L402FetchTool(client=post_client)
        result = tool._run(
            url="https://api.example.com/data",
            method="POST",
            body='{"key": "value"}',
        )

        parsed = json.loads(result)
        assert parsed["received"] is True

    def test_post_with_empty_body(self, post_client):
        tool = L402FetchTool(client=post_client)
        result = tool._run(
            url="https://api.example.com/data",
            method="POST",
            body=None,
        )

        parsed = json.loads(result)
        assert parsed["received"] is True

    def test_non_json_response_returns_text(self, text_client):
        tool = L402FetchTool(client=text_client)
        result = tool._run(url="https://api.example.com/text")

        assert "Hello plain text" in result

    def test_budget_exceeded_returns_error_string(self, budget_exceeded_client):
        tool = L402FetchTool(client=budget_exceeded_client)
        result = tool._run(url="https://api.example.com/data")

        assert "Error:" in result
        assert "Budget" in result or "budget" in result

    def test_payment_failed_returns_error_string(self, failing_client):
        tool = L402FetchTool(client=failing_client)
        result = tool._run(url="https://api.example.com/data")

        assert "Error:" in result
        assert "payment failed" in result.lower() or "mock failure" in result.lower()

    def test_invalid_json_body_returns_error(self, post_client):
        tool = L402FetchTool(client=post_client)
        result = tool._run(
            url="https://api.example.com/data",
            method="POST",
            body="not valid json{{{",
        )

        assert "Error:" in result
        assert "JSON" in result

    def test_tool_metadata(self, l402_client):
        tool = L402FetchTool(client=l402_client)
        assert tool.name == "l402_fetch"
        assert "L402" in tool.description or "402" in tool.description

    def test_shared_client_spending(self, l402_client):
        fetch_tool = L402FetchTool(client=l402_client)
        spending_tool = L402SpendingTool(client=l402_client)

        fetch_tool._run(url="https://api.example.com/data")

        result = spending_tool._run()
        parsed = json.loads(result)
        assert parsed["total_sats"] == 1000
        assert "api.example.com" in parsed["by_domain"]


class TestL402SpendingTool:
    def test_no_spending_returns_message(self, l402_client):
        tool = L402SpendingTool(client=l402_client)
        result = tool._run()

        assert "No L402 payments made yet" in result

    def test_spending_after_payment(self, l402_client):
        # Make a payment first
        l402_client.get("https://api.example.com/data")

        tool = L402SpendingTool(client=l402_client)
        result = tool._run()

        parsed = json.loads(result)
        assert parsed["total_sats"] == 1000
        assert parsed["by_domain"]["api.example.com"] == 1000

    def test_tool_metadata(self, l402_client):
        tool = L402SpendingTool(client=l402_client)
        assert tool.name == "l402_spending"
