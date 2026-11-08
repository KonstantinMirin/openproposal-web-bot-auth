"""Web Bot Auth profile: signed agent-to-agent HTTP messages and key discovery.

An identity is an origin ``https://<host>``. A signer names its signed key
directory, ``https://<host>/.well-known/http-message-signatures-directory``, in a
covered ``Signature-Agent`` member, and a verifier fetches the signer's keys
from that URL. A verifier also accepts the bare origin, the draft -00 form.
Requests carry one ``web-bot-auth`` signature with a nonce; responses carry one
bound to the request they answer. WEB_BOT_AUTH.md at the repository root states
the rules.

The library confirms a signature and returns a :class:`VerifiedRequest` or a
:class:`VerifiedResponse`; the caller maps its ``origin`` to the principal in
its own records.

Modules:

- :mod:`.values`: :class:`Origin`, :class:`ServerIdentity`, key ids, and time.
- :mod:`.rules`: the profile's rules, stated once, and :func:`accept_signature`.
- :mod:`.errors`: :class:`Refusal`, :class:`WebBotAuthError`,
  :class:`ConfigurationError`, and :class:`SigningError`.
- :mod:`.presentation`: :func:`refusal_response`, a refusal as an HTTP response.
- :mod:`.keys`: :class:`Ed25519Key` and JWK thumbprints.
- :mod:`.directory`: :func:`publish_directory`, :class:`DirectoryPublisher`,
  and :func:`verify_directory`, with :class:`DirectoryResponse`,
  :class:`KeySet`, and :class:`VerifiedDirectory`.
- :mod:`.ports`: :class:`KeyResolver`, :class:`DirectoryFetcher`, and
  :class:`DirectoryStore`.
- :mod:`.resolver`: :class:`DirectoryResolver`, :class:`MemoryDirectoryStore`,
  and :class:`StaticKeyResolver`.
- :mod:`.fetcher`: :class:`~.fetcher.HttpxDirectoryFetcher`, the default fetcher.
- :mod:`.replay`: the :class:`NonceStore` protocol and :class:`MemoryNonceStore`.
- :mod:`.signer`: :class:`RequestSigner` and :class:`ResponseSigner`.
- :mod:`.verifier`: :class:`RequestVerifier` and :class:`ResponseVerifier`.
- :mod:`.roles`: the role ports the edges take, :class:`RequestConfirmer`,
  :class:`ResponseConfirmer`, :class:`RequestSigning`, and :class:`ResponseSigning`.
- :mod:`.httpx`: :class:`WebBotAuth`, an ``httpx.Auth``.
- :mod:`.sync`: :class:`~.sync.SyncRuntime`, the one event loop synchronous code
  verifies on, and the sync façades.
- :mod:`.asgi`: response signing, the directory route, and an opt-in verifier.
- :mod:`.testing`: :func:`~.testing.directory_transport`, directories served from data.
- :mod:`.conformance`: the vectors and a runner. It alone imports the private
  raw signer, which signs what the profile refuses.

Requires the ``wba`` extra: ``pip install 'iab-agentic-primitives[wba]'``.
"""

# The guard runs first: without the extra, nothing below is imported.
from .extra import EXTRA_MODULES

# isort: split
from .directory import (
    DirectoryPublisher,
    DirectoryResponse,
    FetchLimits,
    KeySet,
    PublishPolicy,
    VerifiedDirectory,
    publish_directory,
    verify_directory,
)
from .errors import ConfigurationError, Refusal, SigningError, WebBotAuthError
from .keys import Ed25519Key, thumbprint
from .message import Answer, HeaderLines, Headers, HTTPRequest, HTTPResponse
from .ports import DirectoryFetcher, DirectoryStore, KeyResolver, ResolvedKey
from .presentation import refusal_response
from .replay import MemoryNonceStore, NonceStore, NonceStoreUnavailable
from .resolver import CachePolicy, DirectoryResolver, MemoryDirectoryStore, StaticKeyResolver
from .roles import RequestConfirmer, RequestSigning, ResponseConfirmer, ResponseSigning
from .rules import (
    ALGORITHM,
    CLOCK_SKEW,
    DIRECTORY_TAG,
    MAX_LIFETIME,
    SIGNATURE_TAG,
    accept_signature,
)
from .signer import RequestSigner, ResponseSigner
from .values import (
    DIRECTORY_MEDIA_TYPE,
    DIRECTORY_PATH,
    Authority,
    Clock,
    KeyId,
    Origin,
    RequestAuthority,
    Seconds,
    ServerIdentity,
    UnixSeconds,
    system_clock,
)
from .verifier import (
    CONFORMANCE_KEYS,
    SAME_ORIGIN,
    ExpectedOrigin,
    KeyPolicy,
    RequestVerifier,
    ResponseVerifier,
    VerifiedRequest,
    VerifiedResponse,
    is_signed,
)

__all__ = [
    "ALGORITHM",
    "CLOCK_SKEW",
    "CONFORMANCE_KEYS",
    "DIRECTORY_MEDIA_TYPE",
    "DIRECTORY_PATH",
    "DIRECTORY_TAG",
    "EXTRA_MODULES",
    "MAX_LIFETIME",
    "SAME_ORIGIN",
    "SIGNATURE_TAG",
    "Answer",
    "Authority",
    "CachePolicy",
    "Clock",
    "ConfigurationError",
    "DirectoryFetcher",
    "DirectoryPublisher",
    "DirectoryResolver",
    "DirectoryResponse",
    "DirectoryStore",
    "Ed25519Key",
    "ExpectedOrigin",
    "FetchLimits",
    "HTTPRequest",
    "HTTPResponse",
    "HeaderLines",
    "Headers",
    "KeyId",
    "KeyPolicy",
    "KeyResolver",
    "KeySet",
    "MemoryDirectoryStore",
    "MemoryNonceStore",
    "NonceStore",
    "NonceStoreUnavailable",
    "Origin",
    "PublishPolicy",
    "Refusal",
    "RequestAuthority",
    "RequestConfirmer",
    "RequestSigner",
    "RequestSigning",
    "RequestVerifier",
    "ResolvedKey",
    "ResponseConfirmer",
    "ResponseSigner",
    "ResponseSigning",
    "ResponseVerifier",
    "Seconds",
    "ServerIdentity",
    "SigningError",
    "StaticKeyResolver",
    "UnixSeconds",
    "VerifiedDirectory",
    "VerifiedRequest",
    "VerifiedResponse",
    "WebBotAuthError",
    "accept_signature",
    "is_signed",
    "publish_directory",
    "refusal_response",
    "system_clock",
    "thumbprint",
    "verify_directory",
]
