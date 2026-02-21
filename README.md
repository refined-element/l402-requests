# L402-Requests

Auto-paying L402 HTTP client for Python. APIs behind Lightning paywalls just work.

`L402-Requests` wraps [httpx](https://www.python-httpx.org/) and automatically handles HTTP 402 responses by paying Lightning invoices and retrying with L402 credentials. It's a drop-in HTTP client where any API behind an L402 paywall "just works."

## Install

```bash
pip install l402-requests
```

## Quick Start

```python
import l402_requests

# Any L402-protected API just works — invoice is paid automatically
response = l402_requests.get("https://api.example.com/paid-resource")
print(response.json())
```

That's it. The library detects your wallet from environment variables, pays the Lightning invoice when it gets a 402 response, and retries with L402 credentials.

## Wallet Configuration

Set environment variables for your preferred wallet. The library auto-detects in this order:

| Priority | Wallet | Environment Variables | Preimage Support |
|----------|--------|-----------------------|------------------|
| 1 | LND | `LND_REST_HOST`, `LND_MACAROON_HEX` | Yes |
| 2 | NWC | `NWC_CONNECTION_STRING` | Yes (CoinOS, CLINK) |
| 3 | Strike | `STRIKE_API_KEY` | Yes |
| 4 | OpenNode | `OPENNODE_API_KEY` | Limited |

**Recommended:** Strike (full preimage support, no infrastructure required).

### Strike (Recommended)

```bash
export STRIKE_API_KEY="your-strike-api-key"
```

### LND

```bash
export LND_REST_HOST="https://localhost:8080"
export LND_MACAROON_HEX="your-admin-macaroon-hex"
export LND_TLS_CERT_PATH="/path/to/tls.cert"  # optional
```

### NWC (Nostr Wallet Connect)

```bash
pip install l402-requests[nwc]
export NWC_CONNECTION_STRING="nostr+walletconnect://pubkey?relay=wss://relay&secret=hex"
```

### OpenNode

```bash
export OPENNODE_API_KEY="your-opennode-key"
```

> **Note:** OpenNode does not return payment preimages, which limits L402 functionality. For full L402 support, use Strike, LND, or a compatible NWC wallet.

## Budget Controls

Safety first — budgets are enabled by default to prevent accidental overspending:

```python
from l402_requests import L402Client, BudgetController

# Custom budget limits
client = L402Client(
    budget=BudgetController(
        max_sats_per_request=500,     # Max per single payment (default: 1000)
        max_sats_per_hour=5000,       # Hourly rolling limit (default: 10000)
        max_sats_per_day=25000,       # Daily rolling limit (default: 50000)
        allowed_domains={"api.example.com"},  # Optional domain allowlist
    )
)

# Disable budgets entirely (not recommended)
client = L402Client(budget=None)
```

If a payment would exceed any limit, `BudgetExceededError` is raised *before* the payment is attempted.

## Explicit Wallet

```python
from l402_requests import L402Client, StrikeWallet

client = L402Client(
    wallet=StrikeWallet(api_key="your-key"),
)
response = client.get("https://api.example.com/paid-resource")
```

## Async Support

```python
from l402_requests import AsyncL402Client

async with AsyncL402Client() as client:
    response = await client.get("https://api.example.com/paid-resource")
    print(response.json())
```

## Spending Introspection

Track every payment made during a session:

```python
from l402_requests import L402Client

client = L402Client()
client.get("https://api.example.com/data")
client.get("https://api.example.com/more-data")

# Inspect spending
print(f"Total spent: {client.spending_log.total_spent()} sats")
print(f"Last hour: {client.spending_log.spent_last_hour()} sats")
print(f"By domain: {client.spending_log.by_domain()}")

# Export as JSON
print(client.spending_log.to_json())
```

## How It Works

1. Your code makes an HTTP request via `L402Client`
2. If the server returns **200**, the response is returned as-is
3. If the server returns **402** with an L402 challenge:
   - The `WWW-Authenticate: L402 macaroon="...", invoice="..."` header is parsed
   - The BOLT11 invoice amount is checked against your budget
   - The invoice is paid via your configured Lightning wallet
   - The request is retried with `Authorization: L402 {macaroon}:{preimage}`
4. Credentials are cached so subsequent requests to the same endpoint don't require re-payment

## Two-Step L402 Flows (Commerce)

Some servers intentionally use a two-step L402 flow where payment and claim are separate endpoints. This is common for physical goods — it separates payment from fulfillment and allows the claim URL to be shared with a gift recipient.

For example, the [Lightning Enable Store](https://store.lightningenable.com) returns a 402 on `POST /checkout`, and after payment you claim the order at `POST /claim` with the L402 credential.

In these cases, `L402-Requests` pays the invoice automatically. Use the `spending_log` to retrieve the preimage, then make the claim request:

```python
from l402_requests import L402Client, BudgetController

client = L402Client(budget=BudgetController(max_sats_per_request=50000))
checkout = client.post("https://store.lightningenable.com/api/store/checkout",
    json={"items": [{"productId": 2, "quantity": 1, "size": "L", "color": "Black"}]})

# Payment was made — retrieve credentials from the spending log
record = client.spending_log.records[-1]
print(f"Paid {record.amount_sats} sats, preimage: {record.preimage}")
```

See the [full documentation](https://docs.lightningenable.com/tools/l402-requests) for the complete store purchasing example.

## Usage with AI Agents

L402-Requests is the consumer-side complement to the [Lightning Enable MCP Server](https://github.com/refined-element/lightning-enable-mcp). While the MCP server gives AI agents wallet tools, L402-Requests lets your Python code access paid APIs without any agent framework.

### LangChain Tool

```python
from langchain.tools import tool
from l402_requests import L402Client, BudgetController

_client = L402Client(budget=BudgetController(max_sats_per_request=100))

@tool
def fetch_paid_api(url: str) -> str:
    """Fetch data from an L402-protected API. Payment is handled automatically."""
    response = _client.get(url)
    return response.text
```

### Standalone Script

```python
import l402_requests

# Any L402-protected API just works
data = l402_requests.get("https://api.example.com/premium-data").json()
```

## What is L402?

L402 (formerly LSAT) is a protocol for monetizing APIs with Lightning Network micropayments. Instead of API keys or subscriptions, servers return HTTP 402 ("Payment Required") with a Lightning invoice. Once paid, the client receives a credential (macaroon + payment preimage) that grants access.

Learn more: [docs.lightningenable.com](https://docs.lightningenable.com)

## Example: MaximumSats API

[MaximumSats](https://maximumsats.com) provides paid Lightning Network APIs including AI DVM, WoT reports, Nostr analysis, and more. Use L402-Requests to automatically pay for these endpoints:

```python
import l402_requests

# Call MaximumSats AI DVM endpoint — invoice is paid automatically
response = l402_requests.get("https://maximumsats.com/api/dvm")
data = response.json()
```

Set your wallet via environment variable:

```bash
export STRIKE_API_KEY="your-strike-api-key"
```

The library automatically handles the L402 payment protocol — you just get the data.

## License

MIT — see [LICENSE](LICENSE).
