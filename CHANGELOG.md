# Changelog

## 0.6.0

- Fixes budget limits being skipped for invoices with no parseable amount — upgrade recommended. Such invoices are now refused with `InvoiceAmountUnknownError` instead of paid, a negative MPP `amount` no longer credits budget headroom, and wallets that can't produce a preimage (OpenNode) are rejected with `UnsupportedWalletError` before paying rather than after.
