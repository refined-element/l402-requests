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
    """Failed to parse payment challenge from WWW-Authenticate header."""

    def __init__(self, header: str, reason: str):
        self.header = header
        self.reason = reason
        super().__init__(f"Failed to parse challenge: {reason}")


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


_MISSING_AMOUNT_DETAIL = {
    "no-amount-encoded": "the invoice encodes no amount",
    "unparseable": "the invoice could not be parsed as BOLT11",
}


class InvoiceAmountUnknownError(L402Error):
    """The invoice amount could not be determined, so payment was refused.

    Raised *before* the payment is attempted. An amount we cannot read is an
    amount we cannot check against the budget limits or the domain allowlist,
    and one that would never reach the spending log — so paying it would spend
    an unknown sum with every control silently skipped. No funds are spent.

    Like :class:`UnsupportedWalletError` this is a precondition failure rather
    than a payment failure: code catching :class:`PaymentFailedError` to retry
    or log payment problems should not expect it.

    Attributes:
        reason: Either ``"no-amount-encoded"`` (a zero-amount / "any amount"
            invoice) or ``"unparseable"`` (not readable as BOLT11). Both are
            refused; the distinction points at the cause.
        bolt11: The offending invoice, when available.
    """

    def __init__(self, reason: str, bolt11: str | None = None):
        self.reason = reason
        self.bolt11 = bolt11
        detail = _MISSING_AMOUNT_DETAIL.get(reason, reason)
        super().__init__(
            f"Refusing to pay: {detail}, so its amount cannot be checked "
            f"against your budget. Only invoices with an explicit amount "
            f"are supported."
        )


class UnsupportedWalletError(L402Error):
    """The configured wallet cannot fulfill L402's preimage requirement.

    Raised *before* the payment is attempted when the wallet's
    ``supports_preimage`` is explicitly False (e.g. OpenNode). L402 needs the
    preimage to build the Authorization header, so paying would spend funds for
    no access. This is a configuration failure, not a payment failure — code
    catching :class:`PaymentFailedError` should not expect it. No funds spent.
    """

    def __init__(self, wallet_reason: str):
        self.wallet_reason = wallet_reason
        super().__init__(f"Wallet cannot be used for L402: {wallet_reason}")
