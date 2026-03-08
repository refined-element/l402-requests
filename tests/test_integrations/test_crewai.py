"""Tests for CrewAI integration tools."""

from __future__ import annotations

import json

import pytest

from l402_requests.integrations.crewai import L402GetTool, L402PostTool, L402SpendingTool


class TestL402GetTool:
    def test_get_with_l402_payment(self, l402_client):
        tool = L402GetTool(client=l402_client)
        result = tool._run(url="https://api.example.com/data")

        parsed = json.loads(result)
        assert parsed == {"data": "paid content"}

    def test_get_free_endpoint(self, free_client):
        tool = L402GetTool(client=free_client)
        result = tool._run(url="https://api.example.com/free")

        parsed = json.loads(result)
        assert parsed == {"data": "free content"}

    def test_non_json_response_returns_text(self, text_client):
        tool = L402GetTool(client=text_client)
        result = tool._run(url="https://api.example.com/text")

        assert "Hello plain text" in result

    def test_budget_exceeded_returns_error_string(self, budget_exceeded_client):
        tool = L402GetTool(client=budget_exceeded_client)
        result = tool._run(url="https://api.example.com/data")

        assert "Error:" in result
        assert "Budget" in result or "budget" in result

    def test_payment_failed_returns_error_string(self, failing_client):
        tool = L402GetTool(client=failing_client)
        result = tool._run(url="https://api.example.com/data")

        assert "Error:" in result
        assert "payment failed" in result.lower() or "mock failure" in result.lower()

    def test_tool_metadata(self, l402_client):
        tool = L402GetTool(client=l402_client)
        assert tool.name == "L402 GET"
        assert "GET" in tool.description


class TestL402PostTool:
    def test_post_with_l402_payment(self, post_client):
        tool = L402PostTool(client=post_client)
        result = tool._run(
            url="https://api.example.com/data",
            body='{"key": "value"}',
        )

        parsed = json.loads(result)
        assert parsed["received"] is True

    def test_post_with_no_body(self, post_client):
        tool = L402PostTool(client=post_client)
        result = tool._run(url="https://api.example.com/data", body=None)

        parsed = json.loads(result)
        assert parsed["received"] is True

    def test_invalid_json_body_returns_error(self, post_client):
        tool = L402PostTool(client=post_client)
        result = tool._run(
            url="https://api.example.com/data",
            body="not valid json{{{",
        )

        assert "Error:" in result
        assert "JSON" in result

    def test_budget_exceeded_returns_error_string(self, budget_exceeded_client):
        tool = L402PostTool(client=budget_exceeded_client)
        result = tool._run(url="https://api.example.com/data")

        assert "Error:" in result
        assert "Budget" in result or "budget" in result

    def test_tool_metadata(self, l402_client):
        tool = L402PostTool(client=l402_client)
        assert tool.name == "L402 POST"
        assert "POST" in tool.description


class TestL402SpendingTool:
    def test_no_spending_returns_message(self, l402_client):
        tool = L402SpendingTool(client=l402_client)
        result = tool._run()

        assert "No L402 payments made yet" in result

    def test_spending_after_payment(self, l402_client):
        l402_client.get("https://api.example.com/data")

        tool = L402SpendingTool(client=l402_client)
        result = tool._run()

        parsed = json.loads(result)
        assert parsed["total_sats"] == 1000
        assert parsed["by_domain"]["api.example.com"] == 1000

    def test_shared_client_across_tools(self, l402_client):
        """All tools sharing the same client see unified spending."""
        get_tool = L402GetTool(client=l402_client)
        spending_tool = L402SpendingTool(client=l402_client)

        get_tool._run(url="https://api.example.com/data")

        result = spending_tool._run()
        parsed = json.loads(result)
        assert parsed["total_sats"] == 1000

    def test_tool_metadata(self, l402_client):
        tool = L402SpendingTool(client=l402_client)
        assert tool.name == "L402 Spending Summary"
