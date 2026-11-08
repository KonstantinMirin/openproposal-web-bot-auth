"""How the module's answers look on the wire: one place for every status, header, and body.

:func:`refusal_response` turns a :class:`~.errors.WebBotAuthError` into the
response a verifier sends: the refusal's status, a JSON body
``{"error": <reason>, "detail": <detail>}``, ``Accept-Signature`` on ``403``
and ``429``, and ``Retry-After`` on ``503``. The ASGI middlewares send it, and
a framework route returns it.

The ASGI helpers' other answers come from here too: ``405`` on the directory
path, ``503`` when a key source publishes no keys, ``413`` for a body over the
limit, and ``500`` for a response the profile can't sign. Each function is
pure and returns an :class:`~.message.Answer`.
"""

from __future__ import annotations

import json

from .errors import SigningError, WebBotAuthError
from .message import Answer, HeaderLines
from .rules import accept_signature

#: The ``Retry-After`` of a directory whose key source publishes no keys, in seconds.
NO_KEYS_RETRY_AFTER = 5


def _json(status: int, error: str, detail: str, *extra: tuple[str, str]) -> Answer:
    body = json.dumps({"error": error, "detail": detail}).encode()
    return Answer(status, HeaderLines([("content-type", "application/json"), *extra]), body)


def refusal_response(error: WebBotAuthError, *, has_body: bool) -> Answer:
    """The response that refuses a message with ``error``.

    ``has_body`` says whether the refused request had a body, which sets the
    components ``Accept-Signature`` asks for.
    """
    refusal = error.refusal
    extra: list[tuple[str, str]] = []
    if refusal.accept_signature:
        extra.append(("accept-signature", accept_signature(has_body=has_body)))
    if refusal.retry_after is not None:
        extra.append(("retry-after", str(refusal.retry_after)))
    return _json(error.status, error.reason, str(error), *extra)


def unsignable_response(error: SigningError) -> Answer:
    """``500`` ``response-unsignable``: the application answered with a response the
    profile can't sign, which is sent in place of the unsigned answer."""
    return _json(500, "response-unsignable", str(error))


def body_too_large_response(limit: int) -> Answer:
    """``413`` ``body-too-large``: a request body over ``limit`` bytes."""
    return _json(413, "body-too-large", f"the request body exceeds {limit} bytes")


def method_not_allowed_response() -> Answer:
    """``405`` on the directory path, which answers ``GET`` and ``HEAD`` only."""
    return Answer(405, HeaderLines([("allow", "GET, HEAD")]), b"")


def no_keys_response() -> Answer:
    """``503`` from a directory whose key source publishes no keys now."""
    return Answer(503, HeaderLines([("retry-after", str(NO_KEYS_RETRY_AFTER))]), b"")


__all__ = [
    "NO_KEYS_RETRY_AFTER",
    "body_too_large_response",
    "method_not_allowed_response",
    "no_keys_response",
    "refusal_response",
    "unsignable_response",
]
