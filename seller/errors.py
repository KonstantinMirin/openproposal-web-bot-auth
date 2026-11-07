"""How the offer logic rejects a request: `OfferError`, with `errors[]` (§ 2.4).

The identity boundary's own refusal, `Refused`, is in seller/boundary.py.
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi.responses import JSONResponse
from openproposal import ErrorObject

# The informative HTTP status of each core code (§ 2.4).
_STATUS = {
    "validation": 400,
    "not_offered": 400,
    "unresolved_reference": 400,
    "not_eligible": 403,
    "not_found": 404,
    "not_committable": 409,
    "stale_version": 409,
    "record_mismatch": 409,
    "expired": 410,
    "idempotency_conflict": 422,
}


class OfferError(Exception):
    """One `ErrorObject` (§ 2.4)."""

    def __init__(
        self,
        code: str,
        detail: str,
        *,
        retry: Literal["same", "refetch", "none"],
        version: int | None = None,
        pointer: str | None = None,
        headers: dict | None = None,
    ) -> None:
        super().__init__(detail)
        self.error: dict[str, Any] = {"code": code, "detail": detail, "retry": retry}
        if version is not None:
            self.error["version"] = version
        if pointer is not None:
            self.error["pointer"] = pointer
        self.headers = headers or {}
        # § 2.4: an error with retry `same` fits 503.
        self.status = 503 if retry == "same" else _STATUS[code]

    def error_object(self) -> ErrorObject:
        """The rejection as the ledger stores it (§ 5.6.1). Its status follows from its code."""
        return ErrorObject.model_validate(self.error)

    @classmethod
    def stored(cls, error: ErrorObject) -> OfferError:
        """The rejection a replay returns: the stored result (§ 5.6.1)."""
        return cls(
            error.code,
            error.detail,
            retry=error.retry,
            version=error.version,
            pointer=error.pointer,
        )

    def response(self) -> JSONResponse:
        return JSONResponse({"errors": [self.error]}, status_code=self.status, headers=self.headers)
