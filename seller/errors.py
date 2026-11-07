"""The two ways the seller refuses a request.

- `Refused`: the identity boundary refused the credential. The handler never ran.
- `OfferError`: the offer logic rejected the request, with `errors[]` (§ 2.4).
"""

from __future__ import annotations

import json
from typing import Any, Literal

from fastapi.responses import JSONResponse


class Refused(Exception):
    def __init__(self, status: int, reason: str, detail: str, *, headers: dict | None = None):
        super().__init__(detail)
        self.status, self.reason, self.detail, self.headers = status, reason, detail, headers or {}

    def response(self) -> JSONResponse:
        body = {"refused_at": "identity-boundary", "reason": self.reason, "detail": self.detail}
        return JSONResponse(body, status_code=self.status, headers=self.headers)


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

    def stored_form(self) -> tuple[int, list[dict[str, Any]]]:
        return self.status, [self.error]

    @classmethod
    def stored(cls, errors_json: str) -> OfferError:
        """The rejection a replay returns: the stored result (§ 5.6.1)."""
        error = json.loads(errors_json)[0]
        return cls(
            error["code"],
            error["detail"],
            retry=error["retry"],
            version=error.get("version"),
            pointer=error.get("pointer"),
        )

    def response(self) -> JSONResponse:
        return JSONResponse({"errors": [self.error]}, status_code=self.status, headers=self.headers)
