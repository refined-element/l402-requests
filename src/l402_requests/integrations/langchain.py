"""LangChain tool integration for l402-requests.

Gives any LangChain agent the ability to access L402-protected APIs
with automatic Lightning micropayments.

Install:
    pip install l402-requests[langchain]

Usage:
    from l402_requests.integrations.langchain import L402FetchTool

    tools = [L402FetchTool()]
    agent = create_react_agent(llm, tools)
"""

from __future__ import annotations

import json
from typing import Any, Optional

from langchain_core.callbacks import CallbackManagerForToolRun
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field

from l402_requests import BudgetController, L402Client
from l402_requests.exceptions import (
    BudgetExceededError,
    DomainNotAllowedError,
    L402Error,
    NoWalletError,
    PaymentFailedError,
)


class L402FetchInput(BaseModel):
    """Input for the L402 fetch tool."""

    url: str = Field(description="The full URL to request.")
    method: str = Field(
        default="GET",
        description="HTTP method: GET or POST.",
    )
    body: Optional[str] = Field(
        default=None,
        description="JSON string body for POST requests.",
    )


class L402FetchTool(BaseTool):
    """Fetch a URL that may require an L402 Lightning micropayment.

    Automatically handles HTTP 402 responses by paying the Lightning invoice
    and retrying with L402 credentials. Supports GET and POST.

    The tool auto-detects your Lightning wallet from environment variables:
    - STRIKE_API_KEY (recommended)
    - NWC_CONNECTION_STRING
    - LND_REST_HOST + LND_MACAROON_HEX
    - OPENNODE_API_KEY
    """

    name: str = "l402_fetch"
    description: str = (
        "Fetch a URL that may be behind an L402 Lightning paywall. "
        "If the server returns HTTP 402 (Payment Required), the Lightning "
        "invoice is paid automatically and the request is retried. "
        "Use this for any API that requires Lightning micropayments. "
        "Supports GET and POST methods."
    )
    args_schema: type[BaseModel] = L402FetchInput

    _client: L402Client

    def __init__(self, client: L402Client | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        object.__setattr__(self, "_client", client or L402Client())

    def _run(
        self,
        url: str,
        method: str = "GET",
        body: str | None = None,
        run_manager: CallbackManagerForToolRun | None = None,
    ) -> str:
        try:
            if method.upper() == "POST":
                json_body = json.loads(body) if body else None
                response = self._client.post(url, json=json_body)
            else:
                response = self._client.get(url)

            try:
                data = response.json()
                return json.dumps(data, indent=2)
            except Exception:
                return response.text[:4000]

        except NoWalletError:
            return (
                "Error: No Lightning wallet configured. Set one of: "
                "STRIKE_API_KEY, NWC_CONNECTION_STRING, or "
                "LND_REST_HOST + LND_MACAROON_HEX."
            )
        except BudgetExceededError as e:
            return f"Error: Budget limit exceeded — {e}"
        except DomainNotAllowedError as e:
            return f"Error: Domain not in allowed list — {e}"
        except PaymentFailedError as e:
            return f"Error: Lightning payment failed — {e}"
        except L402Error as e:
            return f"Error: L402 protocol error — {e}"
        except json.JSONDecodeError as e:
            return f"Error: Invalid JSON body — {e}"


class L402SpendingTool(BaseTool):
    """Check how many sats have been spent in this session."""

    name: str = "l402_spending"
    description: str = (
        "Returns a summary of Lightning payments made so far: "
        "total sats spent, payment count, and per-domain breakdown."
    )

    _client: L402Client

    def __init__(self, client: L402Client | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        object.__setattr__(self, "_client", client or L402Client())

    def _run(
        self,
        run_manager: CallbackManagerForToolRun | None = None,
    ) -> str:
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
