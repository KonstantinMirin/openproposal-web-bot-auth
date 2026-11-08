"""Adapters: one Web Bot Auth implementation behind the conformance operations.

The operations and their JSON shapes are those of ``PROTOCOL.md`` in this
package: ``sign_request``, ``sign_directory``, ``verify_request``,
``verify_directory``, ``sign_response``, and ``verify_response``.
:class:`LibraryAdapter` runs them on this library; :class:`CommandAdapter`
runs them on any executable that reads one JSON operation on standard input
and writes one JSON result. An adapter is a function from an
:data:`~.models.Operation` to a :data:`~.models.Result`, and it never raises.
"""

from __future__ import annotations

import asyncio
import shlex
import subprocess
from collections.abc import Callable, Mapping

from pydantic import ValidationError

from ..directory import publish_directory, verify_directory
from ..errors import ConfigurationError, WebBotAuthError
from ..keys import Ed25519Key
from ..replay import MemoryNonceStore
from ..resolver import DirectoryResolver
from ..signer import RequestSigner, ResponseSigner, SignerConfig
from ..testing import served_resolver
from ..values import Origin, ServerIdentity, UnixSeconds
from ..verifier import CONFORMANCE_KEYS, RequestVerifier, ResponseVerifier
from .models import (
    OPERATION,
    DirectoryDoc,
    KeysVerified,
    Operation,
    Refused,
    RequestDoc,
    ResponseDoc,
    Result,
    SignDirectory,
    SignRequest,
    SignResponse,
    Verified,
    VerifyDirectory,
    VerifyRequest,
    VerifyResponse,
    dump_json,
    result_of,
)

#: An implementation behind the protocol: one operation in, one result out, never a raise.
Adapter = Callable[[Operation], Result]


def refused(error: WebBotAuthError) -> Refused:
    """The result of a refusal: its status, its rule, and its detail."""
    return Refused(status=error.status, rule=error.reason, error=str(error))


def _is_origin(value: str) -> bool:
    try:
        Origin.parse(value)
    except ConfigurationError:
        return False
    return True


def _resolver(directories: Mapping[str, DirectoryDoc], now: UnixSeconds) -> DirectoryResolver:
    """A resolver over the operation's directories, fetched through the bounded read at ``now``.

    Only an origin's directory URL is ever fetched; a directory listed under
    anything else, such as an origin with a port, is never reached.
    """
    served = {Origin.parse(o): d.answer() for o, d in directories.items() if _is_origin(o)}
    return served_resolver(served, clock=lambda: now)


def _sign_request(op: SignRequest) -> RequestDoc:
    config = SignerConfig(Ed25519Key.from_jwk(op.key), op.origin, label=op.label)
    signer = RequestSigner(config)
    return RequestDoc.of(signer.sign(op.request.message(), now=op.now))


def _sign_directory(op: SignDirectory) -> DirectoryDoc:
    origin = op.origin
    answer = publish_directory(origin, [Ed25519Key.from_jwk(k) for k in op.keys], now=op.now)
    return DirectoryDoc.of(origin.directory_url, answer)


def _sign_response(op: SignResponse) -> ResponseDoc:
    config = SignerConfig(Ed25519Key.from_jwk(op.key), op.origin, label=op.label)
    signer = ResponseSigner(config)
    return ResponseDoc.of(signer.sign(op.response.message(op.request.message()), now=op.now))


def _verify_directory(op: VerifyDirectory) -> KeysVerified:
    origin = op.origin
    fetched = op.response.fetched(origin.directory_url, op.now)
    directory = verify_directory(fetched, origin, op.now)
    return KeysVerified(keyids=tuple(sorted(directory.keys)))


async def _verify_requests(op: VerifyRequest) -> Result:
    verifier = RequestVerifier(
        _resolver(op.directories, op.now),
        identity=ServerIdentity.from_config(f"https://{op.authority}"),
        nonces=MemoryNonceStore(clock=lambda: op.now),
        clock=lambda: op.now,
        keys=CONFORMANCE_KEYS,
    )
    for i, earlier in enumerate(op.prior):
        try:
            await verifier.verify(earlier.message())
        except WebBotAuthError as e:
            return Refused(status=e.status, rule=f"prior-{i}", error=str(e))
    verified = await verifier.verify(op.request.message())
    return Verified(
        identity=str(verified.origin), keyid=verified.keyid, body_covered=verified.body_covered
    )


def _verify_response(op: VerifyResponse) -> Verified:
    verifier = ResponseVerifier(
        _resolver(op.directories, op.now), clock=lambda: op.now, keys=CONFORMANCE_KEYS
    )
    expected = op.expected_origin
    response = op.response.message(op.request.message())
    verified = asyncio.run(verifier.verify(response, expected_origin=expected))
    return Verified(identity=str(verified.origin), keyid=verified.keyid, bound=verified.bound)


def _run(op: Operation) -> Result:
    match op:
        case SignRequest():
            return _sign_request(op)
        case SignDirectory():
            return _sign_directory(op)
        case SignResponse():
            return _sign_response(op)
        case VerifyRequest():
            return asyncio.run(_verify_requests(op))
        case VerifyDirectory():
            return _verify_directory(op)
        case VerifyResponse():
            return _verify_response(op)


class LibraryAdapter:
    """Runs the conformance operations on ``iab_agentic_primitives.web_bot_auth``.

    Published test keys are accepted, as the protocol requires of an adapter.
    A refusal is a :class:`~.models.Refused` with its rule; any other error is
    an ``adapter-error`` result.
    """

    def __call__(self, op: Operation) -> Result:
        try:
            return _run(op)
        except WebBotAuthError as e:
            return refused(e)
        except Exception as e:  # every failure is a result, never a crash
            return Refused.adapter_failure("adapter-error", f"{type(e).__name__}: {e}")

    def serve(self, line: str) -> str:
        """Runs one JSON operation and returns its JSON result, as the CLI adapter does."""
        try:
            op = OPERATION.validate_json(line)
        except ValidationError as e:
            return dump_json(Refused.adapter_failure("adapter-invalid", str(e)))
        return dump_json(self(op))


class CommandAdapter:
    """Runs each operation in a new process of ``command``.

    ``command`` is split with :func:`shlex.split` and run without a shell. A
    timeout, a crash, and an answer that isn't a protocol result each become
    an adapter result: ``adapter-timeout``, ``adapter-crash`` with the exit
    code, and ``adapter-invalid``.
    """

    def __init__(self, command: str, *, timeout: float = 60.0) -> None:
        self.argv = shlex.split(command)
        self.timeout = timeout

    def __call__(self, op: Operation) -> Result:
        try:
            done = subprocess.run(
                self.argv,
                input=dump_json(op),
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return Refused.adapter_failure("adapter-timeout", f"no answer in {self.timeout} s")
        except OSError as e:
            return Refused.adapter_failure("adapter-crash", f"can't start {self.argv[0]}: {e}")
        if done.returncode != 0:
            detail = (done.stderr or done.stdout).strip()
            return Refused.adapter_failure("adapter-crash", f"exit {done.returncode}: {detail}")
        try:
            return result_of(op, done.stdout)
        except (ValueError, ValidationError) as e:
            return Refused.adapter_failure("adapter-invalid", f"{e}: {done.stdout}")


__all__ = ["Adapter", "CommandAdapter", "LibraryAdapter", "refused"]
