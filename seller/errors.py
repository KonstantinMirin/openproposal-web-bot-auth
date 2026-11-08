"""How the seller's logic says no, as values. Nothing here renders; seller/http.py does.

- `Rejected`: the offer logic's answer when it rejects a request, one
  `ErrorObject` (§ 2.4). It is returned, never raised.
- `UnknownPrincipal`: the operator named a principal this seller has no row for.
- `IdentityChanged`: the settings name a recorded principal under another domain
  or legal name, which onboarding never rewrites (seller/seed.py).
"""

from __future__ import annotations

from dataclasses import dataclass

from openproposal import ErrorObject, ErrorObjectCode, ErrorObjectRetry

from protocol.operations import is_stored_result

from .ports import Principal


@dataclass(frozen=True)
class Rejected:
    """A rejection (§ 2.4). With `retry` other than `same`, a commit's rejection is a stored
    result (§ 5.6.1)."""

    error: ErrorObject

    @classmethod
    def of(
        cls,
        code: ErrorObjectCode,
        detail: str,
        *,
        retry: ErrorObjectRetry = "none",
        version: int | None = None,
    ) -> Rejected:
        if version is None:  # the requester may not read the proposal (§ 2.4)
            return cls(ErrorObject(code=code, detail=detail, retry=retry))
        return cls(ErrorObject(code=code, detail=detail, retry=retry, version=version))

    @property
    def stored(self) -> bool:
        """Whether a commit's ledger keeps it (`protocol.operations.is_stored_result`)."""
        return is_stored_result([self.error])


class UnknownPrincipal(LookupError):
    """No principal has this id in the seller's records."""


class IdentityChanged(Exception):
    """The settings name a recorded principal under another identity. The proposals issued
    to it name the recorded one, so it is never rewritten, and the seller doesn't start."""

    def __init__(self, recorded: Principal, configured: Principal) -> None:
        super().__init__(
            f"principal {recorded.id} is recorded as {recorded.domain} ({recorded.legal_name}),"
            f" and the settings name {configured.domain} ({configured.legal_name}); a"
            " principal's identity is never rewritten under the records issued to it, so"
            " onboard another buyer into a database of its own"
        )
