"""L402 exceptions."""


class L402Error(Exception):
    """Base exception for l402-requests."""


class BudgetExceededError(L402Error):
    """Payment would exceed configured budget limits."""

    def __init__(self, limit_type: str, limit_sats: int, current_sats: int, invoice_sats: int):
        self.limit_type = limit_type
        self.limit_sats = limit_sats
        self.current_sats = current_sats
        self.invoice_sats = invoice_sats
        super().__init__(
            f"Budget exceeded: {limit_type} limit is {limit_sats} sats, "
            f"already spent {current_sats} sats, invoice requires {invoice_sats} sats"
        )


class PaymentFailedError(L402Error):
    """Lightning payment failed."""

    def __init__(self, reason: str, bolt11: str | None = None):
        self.reason = reason
        self.bolt11 = bolt11
        super().__init__(f"Payment failed: {reason}")


class InvoiceExpiredError(L402Error):
    """Lightning invoice has expired."""

    def __init__(self, bolt11: str | None = None):
        self.bolt11 = bolt11
        super().__init__("Invoice has expired")


class ChallengeParseError(L402Error):
    """Failed to parse L402 challenge from WWW-Authenticate header."""

    def __init__(self, header: str, reason: str):
        self.header = header
        self.reason = reason
        super().__init__(f"Failed to parse L402 challenge: {reason}")


class NoWalletError(L402Error):
    """No wallet configured or auto-detected."""

    def __init__(self) -> None:
        super().__init__(
            "No wallet configured. Set environment variables for one of: "
            "STRIKE_API_KEY, OPENNODE_API_KEY, NWC_CONNECTION_STRING, "
            "LND_REST_HOST + LND_MACAROON_HEX"
        )


class DomainNotAllowedError(L402Error):
    """Domain is not in the allowed domains list."""

    def __init__(self, domain: str):
        self.domain = domain
        super().__init__(f"Domain not in allowed list: {domain}")
