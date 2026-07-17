# Changelog

## 0.6.0

**Security fix — upgrade recommended.** An invoice whose amount could not be read was treated as "no amount to check" and paid anyway, skipping `budget.check()` altogether. That went well beyond the sats limits:

- **The domain allowlist was bypassed.** `allowed_domains` is enforced inside the same `check()` call the missing amount skipped, so an amountless invoice was paid from *any* domain, allowlisted or not.
- **The spend was never recorded.** It never reached the `SpendingLog`, so it stayed out of every later budget check and out of any audit of what the client had already spent.

A server that wanted a blank cheque only had to send an invoice with no amount.

**Breaking:** invoices with no readable amount now raise `InvoiceAmountUnknownError` instead of being paid. A negative MPP `amount` is refused the same way — `check()` waved it through, then `record_payment()` subtracted it from the running total and handed back headroom for later payments.

**Breaking:** wallets that cannot return a preimage (OpenNode) now raise `UnsupportedWalletError` *before* paying, rather than paying and failing afterwards. `UnsupportedWalletError` is not a `PaymentFailedError` subclass, so `except PaymentFailedError` blocks that used to catch this will now let it propagate.

Both clients are covered: the sync `L402Client` and the async `AsyncL402Client`.
