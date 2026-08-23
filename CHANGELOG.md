# Changelog

## 0.8.0

**MPP draft-00 client support** (draft-ryan-httpauth-payment-00 + draft-lightning-charge-00), additive interop with third-party MPP servers. Existing L402 and legacy `Payment` behavior is unchanged.

- **Modern challenge parsing** (`MppDraft00Challenge`): a `Payment` challenge with a non-empty `request` param is parsed as draft-00 — `id`/`realm`/`method`/`intent`/`request`/`expires` plus optional `digest`/`description`/`opaque`; the base64url `request` decodes to `{amount, currency, methodDetails:{invoice, paymentHash, network}}`. Superset headers that also carry legacy `invoice=`/`amount=`/`currency=` params parse as modern; the legacy params are used only as a fallback when the modern `request` encoding is malformed. Preference order on a 402: L402 (unchanged) → modern Payment → legacy Payment.
- **Modern credential** (`build_payment_credential`): `Authorization: Payment <base64url(JSON, no padding)>` echoing every received challenge param byte-exact (the encoded `request` string is never decoded and re-encoded) with `payload.preimage` in lowercase hex. Modern credentials are **single-use server-side and are never put in the credential cache**; L402 caching is unchanged.
- **Sanity checks before paying**: `method` must be `lightning`, `intent` must be `charge`, `currency` must be `sat` when present, and a challenge whose `expires` is already past raises the new `ChallengeExpiredError` *before* any payment.
- **`Payment-Receipt` parsing** (`PaymentReceipt`, `parse_payment_receipt`): the success response's receipt header is parsed tolerantly (absent or malformed → `None`, never a failed payment) and exposed as `response.payment_receipt`. The receipt carries only the payment hash — safe to store.

## 0.6.1

**Security fix — upgrade recommended.** Completes 0.6.0's "refuse an invoice whose amount can't be positively bounded" guarantee by closing two remaining ways an unbounded or ambiguous invoice could still be paid:

- **Literal-zero invoices.** A BOLT11 invoice encoding a literal `0` amount (e.g. `lnbc0p1...`) decoded to `0`, which slipped past the "no amount" check, passed the budget check, and reached the wallet as an effectively-amountless invoice (the wallet then chooses the actual spend). The resolved amount must now be **strictly positive from every source** (BOLT11 decode and MPP fallback); `0` or negative is refused.
- **Decoder amount injection (HRP-anchoring).** The amount regex was terminated by the first `1`, so a crafted invoice could smuggle digits from the bech32 data part and decode to a bogus positive that passed the budget check with a fabricated number. The amount is now read **only from the human-readable part** (isolated at the true last-`1` separator), so data-part digits can't influence it.

## 0.6.0

**Security fix — upgrade recommended.** An invoice whose amount could not be read was treated as "no amount to check" and paid anyway, skipping `budget.check()` altogether. That went well beyond the sats limits:

- **The domain allowlist was bypassed.** `allowed_domains` is enforced inside the same `check()` call the missing amount skipped, so an amountless invoice was paid from *any* domain, allowlisted or not.
- **The spend was never recorded.** It never reached the `SpendingLog`, so it stayed out of every later budget check and out of any audit of what the client had already spent.

A server that wanted a blank cheque only had to send an invoice with no amount.

**Breaking:** invoices with no readable amount now raise `InvoiceAmountUnknownError` instead of being paid. A negative MPP `amount` is refused the same way — `check()` waved it through, then `record_payment()` subtracted it from the running total and handed back headroom for later payments.

**Breaking:** wallets that cannot return a preimage (OpenNode) now raise `UnsupportedWalletError` *before* paying, rather than paying and failing afterwards. `UnsupportedWalletError` is not a `PaymentFailedError` subclass, so `except PaymentFailedError` blocks that used to catch this will now let it propagate.

Both clients are covered: the sync `L402Client` and the async `AsyncL402Client`.
