"""CrewAI tool integration for l402-requests.

Gives any CrewAI agent the ability to access L402-protected APIs
with automatic Lightning micropayments.

Install:
    pip install l402-requests[crewai]

Usage:
    from l402_requests.integrations.crewai import L402GetTool, L402PostTool

    agent = Agent(role="Researcher", tools=[L402GetTool(), L402PostTool()])
"""

from __future__ import annotations

import json
from typing import Any, Optional

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from l402_requests import BudgetController, L402Client
from l402_requests.exceptions import (
    BudgetExceededError,
    DomainNotAllowedError,
    L402Error,
    NoWalletError,
    PaymentFailedError,
)


class _GetInput(BaseModel):
    url: str = Field(description="The full URL to GET.")


class _PostInput(BaseModel):
    url: str = Field(description="The full URL to POST to.")
    body: Optional[str] = Field(
        default=None,
        description="JSON string body for the POST request.",
    )


def _handle_error(e: Exception) -> str:
    if isinstance(e, NoWalletError):
        return (
            "Error: No Lightning wallet configured. Set one of: "
            "STRIKE_API_KEY, NWC_CONNECTION_STRING, or "
            "LND_REST_HOST + LND_MACAROON_HEX."
        )
    if isinstance(e, BudgetExceededError):
        return f"Error: Budget limit exceeded — {e}"
    if isinstance(e, DomainNotAllowedError):
        return f"Error: Domain not in allowed list — {e}"
    if isinstance(e, PaymentFailedError):
        return f"Error: Lightning payment failed — {e}"
    if isinstance(e, L402Error):
        return f"Error: L402 protocol error — {e}"
    return f"Error: {type(e).__name__}: {e}"


class L402GetTool(BaseTool):
    """GET a URL that may require an L402 Lightning micropayment."""

    name: str = "L402 GET"
    description: str = (
        "Fetches a URL using HTTP GET. If the server responds with HTTP 402 "
        "(Payment Required), the Lightning invoice is paid automatically "
        "and the request is retried. Returns the response body."
    )
    args_schema: type[BaseModel] = _GetInput

    _client: L402Client

    def __init__(self, client: L402Client | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        object.__setattr__(self, "_client", client or L402Client())

    def _run(self, url: str) -> str:
        try:
            response = self._client.get(url)
            try:
                return json.dumps(response.json(), indent=2)
            except Exception:
                return response.text[:4000]
        except Exception as e:
            return _handle_error(e)


class L402PostTool(BaseTool):
    """POST to a URL that may require an L402 Lightning micropayment."""

    name: str = "L402 POST"
    description: str = (
        "Sends an HTTP POST with an optional JSON body. If the server "
        "responds with HTTP 402 (Payment Required), the Lightning invoice "
        "is paid automatically and the request is retried. Returns the response body."
    )
    args_schema: type[BaseModel] = _PostInput

    _client: L402Client

    def __init__(self, client: L402Client | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        object.__setattr__(self, "_client", client or L402Client())

    def _run(self, url: str, body: str | None = None) -> str:
        try:
            json_body = json.loads(body) if body else None
            response = self._client.post(url, json=json_body)
            try:
                return json.dumps(response.json(), indent=2)
            except Exception:
                return response.text[:4000]
        except json.JSONDecodeError as e:
            return f"Error: Invalid JSON body — {e}"
        except Exception as e:
            return _handle_error(e)


class L402SpendingTool(BaseTool):
    """Check how many sats have been spent in this session."""

    name: str = "L402 Spending Summary"
    description: str = (
        "Returns a summary of Lightning payments made so far: "
        "total sats spent, payment count, and per-domain breakdown."
    )

    _client: L402Client

    def __init__(self, client: L402Client | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        object.__setattr__(self, "_client", client or L402Client())

    def _run(self) -> str:
        log = self._client.spending_log
        total = log.total_spent()
        if total == 0:
            return "No L402 payments made yet."
        return json.dumps(
            {
                "total_sats": total,
                "spent_last_hour": log.spent_last_hour(),
                "by_domain": log.by_domain(),
            },
            indent=2,
        )
