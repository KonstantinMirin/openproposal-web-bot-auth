"""The seller's offer logic: reading an issued proposal, answering a `commit`, issuing one.

Nothing here reads a header or a credential, and nothing imports HTTP, the
Web Bot Auth library, or a storage engine (the offers-framework-free import
contract). Each operation takes the frozen caller the identity boundary
returned and the ports it needs, and returns its answer as a value: a
`CommitResult`, a document, or a `Rejected` (seller/errors.py). seller/http.py
renders it.

- `checks`: the § 5.6.1 checks of a new `commit`, in order, as named steps.
- `ledger`: what a replayed `idempotency_key` gets.
- `acceptance`: `answer_commit`, which runs the ledger, then the checks, and
  stores the decision, in one transaction.
- `reading`: the Full Representation, and the request body as a `Commit`.
- `issuance`: an issued proposal, from the template, for one principal.

The status rules (§ 4.3.2, § 4.3.3) are protocol rules, in protocol/status.py.
"""
