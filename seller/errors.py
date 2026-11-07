"""How the seller's logic says no, as values. Nothing here renders; seller/http.py does.

- `Rejected`: the offer logic's answer when it rejects a request, one
  `ErrorObject` (§ 2.4). It is returned, never raised.
- `UnknownPrincipal`: the operator named a principal this seller has no row for.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from openproposal import ErrorObject, ErrorObjectCode, ErrorObjectRetry


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
        """Whether a commit's ledger keeps it: an error with `retry: same` is not a stored
        result (§ 2.4)."""
        return self.error.retry != "same"


class UnknownPrincipal(LookupError):
    """No principal has this id in the seller's records."""


def validation_detail(errors: Iterable[Mapping[str, object]]) -> str:
    """One line from pydantic's error list: `loc: msg` for each error, joined by `; `."""
    parts = []
    for error in errors:
        loc = error.get("loc", ())
        path = "/".join(map(str, loc)) if isinstance(loc, tuple | list) else str(loc)
        parts.append(f"{path}: {error.get('msg', '')}")
    return "; ".join(parts)
