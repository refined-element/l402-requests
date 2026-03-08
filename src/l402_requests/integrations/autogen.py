"""AutoGen (AG2) tool integration for l402-requests.

Gives any AutoGen agent the ability to access L402-protected APIs
with automatic Lightning micropayments.

Install:
    pip install l402-requests[autogen]

Usage:
    from l402_requests.integrations.autogen import register_l402_tools

    register_l402_tools(caller=assistant, executor=user_proxy)
"""

from __future__ import annotations

import json
from typing import Annotated, Any

from l402_requests import BudgetController, L402Client
from l402_requests.exceptions import (
    BudgetExceededError,
    DomainNotAllowedError,
    L402Error,
    NoWalletError,
    PaymentFailedError,
)

_l402_client: L402Client | None = None


def _get_client() -> L402Client:
    global _l402_client
    if _l402_client is None:
        _l402_client = L402Client()
    return _l402_client


def configure_client(client: L402Client) -> None:
    """Set a custom L402Client for all AutoGen tool calls.

    Call this before starting the conversation to configure budget limits,
    wallet, or domain restrictions:

        from l402_requests import L402Client, BudgetController
        from l402_requests.integrations.autogen import configure_client

        configure_client(L402Client(
            budget=BudgetController(max_sats_per_request=500),
        ))
    """
    global _l402_client
    _l402_client = client


def _handle_error(e: Exception) -> str:
    if isinstance(e, NoWalletError):
        return json.dumps(
            {
                "error": "no_wallet",
                "message": (
                    "No Lightning wallet configured. Set one of: "
                    "STRIKE_API_KEY, NWC_CONNECTION_STRING, or "
                    "LND_REST_HOST + LND_MACAROON_HEX."
                ),
            }
        )
    if isinstance(e, BudgetExceededError):
        return json.dumps({"error": "budget_exceeded", "message": str(e)})
    if isinstance(e, DomainNotAllowedError):
        return json.dumps({"error": "domain_not_allowed", "message": str(e)})
    if isinstance(e, PaymentFailedError):
        return json.dumps({"error": "payment_failed", "message": str(e)})
    if isinstance(e, L402Error):
        return json.dumps({"error": "l402_error", "message": str(e)})
    return json.dumps({"error": "unexpected", "message": str(e)})


def l402_get(
    url: Annotated[str, "Full URL of the L402-protected resource to GET"],
) -> str:
    """GET a URL that may require an L402 Lightning micropayment.

    If the server returns HTTP 402, the Lightning invoice is paid
    automatically and the request is retried with L402 credentials.
    """
    client = _get_client()
    try:
        response = client.get(url)
        try:
            data = response.json()
            return json.dumps({"status": response.status_code, "body": data}, indent=2)
        except Exception:
            return json.dumps({"status": response.status_code, "body": response.text[:4000]})
    except Exception as e:
        return _handle_error(e)


def l402_post(
    url: Annotated[str, "Full URL of the L402-protected resource to POST to"],
    body: Annotated[str, "JSON string body for the POST request"] = "",
) -> str:
    """POST to a URL that may require an L402 Lightning micropayment.

    If the server returns HTTP 402, the Lightning invoice is paid
    automatically and the request is retried with L402 credentials.
    The body must be a valid JSON string.
    """
    client = _get_client()
    try:
        json_body: Any = json.loads(body) if body.strip() else None
        response = client.post(url, json=json_body)
        try:
            data = response.json()
            return json.dumps({"status": response.status_code, "body": data}, indent=2)
        except Exception:
            return json.dumps({"status": response.status_code, "body": response.text[:4000]})
    except json.JSONDecodeError as e:
        return json.dumps({"error": "invalid_json_body", "message": str(e)})
    except Exception as e:
        return _handle_error(e)


def l402_spending_summary() -> str:
    """Get a summary of all Lightning payments made in this session.

    Returns total sats spent, per-domain breakdown, and payment count.
    """
    if _l402_client is None:
        return json.dumps({"total_sats": 0, "by_domain": {}})

    log = _l402_client.spending_log
    return json.dumps(
        {
            "total_sats": log.total_spent(),
            "spent_last_hour": log.spent_last_hour(),
            "by_domain": log.by_domain(),
        },
        indent=2,
    )


def register_l402_tools(caller: Any, executor: Any) -> None:
    """Register all L402 tools with an AutoGen caller/executor pair.

    Args:
        caller: The AssistantAgent whose LLM decides when to call tools.
        executor: The UserProxyAgent that executes tool calls.

    Example:
        from autogen import AssistantAgent, UserProxyAgent
        from l402_requests.integrations.autogen import register_l402_tools

        assistant = AssistantAgent("assistant", llm_config=llm_config)
        user_proxy = UserProxyAgent("user", human_input_mode="NEVER")
        register_l402_tools(caller=assistant, executor=user_proxy)
    """
    from autogen import register_function

    register_function(
        l402_get,
        caller=caller,
        executor=executor,
        name="l402_get",
        description=(
            "GET a URL that may be behind an L402 Lightning paywall. "
            "Automatically pays the invoice and retries if needed."
        ),
    )

    register_function(
        l402_post,
        caller=caller,
        executor=executor,
        name="l402_post",
        description=(
            "POST to a URL that may be behind an L402 Lightning paywall. "
            "Automatically pays the invoice and retries if needed."
        ),
    )

    register_function(
        l402_spending_summary,
        caller=caller,
        executor=executor,
        name="l402_spending_summary",
        description=(
            "Get a summary of Lightning payments made so far in this session."
        ),
    )
