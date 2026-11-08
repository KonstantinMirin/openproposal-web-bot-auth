"""The profile's values: identities, key ids, time, and where a directory lives. No I/O.

An identity is an :class:`Origin`, ``https://<host>``: a canonical host
(IDNA-2008 A-labels in lowercase, or an IP literal) with no port, path, query,
fragment, or userinfo. Only two constructors make one, so holding an
:class:`Origin` means the value was checked:

- :meth:`Origin.parse` reads configuration and raises
  :class:`ConfigurationError`.
- :meth:`Origin.from_signature_agent` reads a ``Signature-Agent`` member and
  raises a refusal.

A server's own identity is a :class:`ServerIdentity`, built once from
configuration, which checks itself when it is made.

Time is :data:`UnixSeconds`, an instant in whole seconds, converted once, at
the clock; a duration is :data:`Seconds`. :func:`whole_number` and
:func:`identifier_set` check configuration values, and raise
:class:`ConfigurationError`, for every configuration type in the module.
"""

from __future__ import annotations

import base64
import enum
import ipaddress
import re
import time
from collections.abc import Callable, Collection
from dataclasses import dataclass
from typing import Final, NewType
from urllib.parse import urlsplit

import idna

from .errors import ConfigurationError, Refusal, refuse

#: The well-known path of a key directory.
DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
#: The media type of a key directory.
DIRECTORY_MEDIA_TYPE = "application/http-message-signatures-directory+json"

#: A point in time, in whole Unix seconds.
UnixSeconds = NewType("UnixSeconds", int)
#: A duration, in whole seconds.
Seconds = NewType("Seconds", int)
#: A clock returns the current time in Unix seconds.
Clock = Callable[[], UnixSeconds]

#: A key id: the RFC 7638 thumbprint of an Ed25519 public JWK.
KeyId = NewType("KeyId", str)
#: The authority of an identity: its host. Its directory is fetched on port 443.
Authority = NewType("Authority", str)
#: The ``@authority`` of a request URL, as RFC 9421 computes it: a lowercase
#: host and a port other than the scheme's default.
RequestAuthority = NewType("RequestAuthority", str)


class Omit(enum.Enum):
    """The one value that leaves a signature parameter or field out."""

    OMIT = "omit"


#: Leaves a signature parameter, or a field the signer would add, out.
OMIT: Final = Omit.OMIT

_SCHEME = "https://"
_DEFAULT_PORTS = {"http": 80, "https": 443}


def system_clock() -> UnixSeconds:
    """The system time in whole Unix seconds."""
    return UnixSeconds(int(time.time()))


def is_decimal(value: str) -> bool:
    """True for ASCII decimal digits only, which ``int`` reads as written."""
    return value.isascii() and value.isdecimal()


def whole_number(name: str, value: object, *, minimum: int, maximum: int | None = None) -> int:
    """``value`` when it is a whole number from ``minimum`` to ``maximum``.

    A ``bool`` isn't one. Anything else raises :class:`ConfigurationError`.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigurationError(f"{name} is a whole number, not {value!r}")
    if value < minimum or (maximum is not None and value > maximum):
        upper = "" if maximum is None else f" and at most {maximum}"
        raise ConfigurationError(f"{name} is at least {minimum}{upper}, not {value}")
    return value


def identifier_set(name: str, values: object) -> frozenset[str]:
    """``values`` as a set of strings; anything else, a bare string included, is refused.

    Raises :class:`ConfigurationError`.
    """
    if isinstance(values, (str, bytes)) or not isinstance(values, Collection):
        raise ConfigurationError(f"{name} is a collection of strings, not {values!r}")
    items = frozenset(values)
    if not all(isinstance(v, str) for v in items):
        raise ConfigurationError(f"{name} holds only strings, not {sorted(map(repr, items))}")
    return frozenset(str(v) for v in items)


def is_canonical_host(host: str) -> bool:
    """True when ``host`` is already in canonical form, with no port.

    A name is canonical when IDNA-2008 (UTS #46, non-transitional) encodes it to
    itself: lowercase ASCII A-labels, no trailing dot, and a last label that
    isn't a number. An IPv4 address in dotted-decimal form, or an IPv6 address
    in brackets with no zone, is canonical in its compressed form.
    """
    if not host or host.endswith(".") or "%" in host:
        return False
    literal = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        ip = ipaddress.ip_address(literal)
    except ValueError:
        pass
    else:
        expected = f"[{ip}]" if ip.version == 6 else str(ip)
        return host == expected
    # A name whose last label is a number reads as an IPv4 address to a URL parser
    # (WHATWG "ends in a number"): 127.1, 2130706433, 1.2.3.04, 0x7f.0.0.1.
    last = host.rsplit(".", 1)[-1]
    if last.isdigit() or last[:2].lower() == "0x":
        return False
    try:
        return idna.encode(host, uts46=True, transitional=False).decode("ascii") == host
    except (idna.IDNAError, UnicodeError):
        return False


def _canonical_host(host: str) -> str:
    """``host``, as ``urlsplit`` reads it, in the canonical form :func:`is_canonical_host` checks.

    A name that IDNA-2008 can't encode is returned as given, for the caller's
    check to refuse.
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return f"[{ip}]" if ip.version == 6 else str(ip)
    try:
        return idna.encode(host, uts46=True, transitional=False).decode("ascii")
    except (idna.IDNAError, UnicodeError):
        return host


def _split(value: object) -> tuple[str, str] | None:
    """Returns ``(host, rest)`` for ``https://<host><rest>`` with a canonical host, or ``None``."""
    if not isinstance(value, str) or not value.isascii() or not value.startswith(_SCHEME):
        return None
    host, slash, path = value[len(_SCHEME) :].partition("/")
    if not is_canonical_host(host):
        return None
    return host, slash + path


@dataclass(frozen=True, slots=True, order=True)
class Origin:
    """An identity origin, ``https://<host>``. ``str(origin)`` is its serialization."""

    host: str

    def __post_init__(self) -> None:
        if not isinstance(self.host, str) or not is_canonical_host(self.host):
            raise ConfigurationError(f"{self.host!r} is not a canonical host")

    @classmethod
    def parse(cls, value: object) -> Origin:
        """Reads an origin from configuration: exactly ``https://<host>``.

        Raises :class:`ConfigurationError` for anything else: ``http``, a port
        (``:443`` included), an uppercase host, a trailing ``/``, or a path,
        query, fragment, or userinfo.
        """
        split = _split(value)
        if split is None or split[1] != "":
            raise ConfigurationError(f"{value!r} is not an origin https://<host>")
        return cls(split[0])

    @classmethod
    def from_signature_agent(cls, value: object) -> Origin:
        """Reads the origin a ``Signature-Agent`` member value names.

        The value is exactly ``https://<host>/.well-known/http-message-signatures-directory``
        or exactly ``https://<host>``, with a lowercase host and no port. The
        first is the key directory URL that draft -01 fetches directly; the
        second is the draft -00 form, which resolves to the same URL. The value
        is compared with those two strings, never normalized. Raises
        :class:`WebBotAuthError` (``signature-agent-value``) for anything else.
        """
        split = _split(value)
        if split is None or split[1] not in ("", DIRECTORY_PATH):
            raise refuse(
                Refusal.SIGNATURE_AGENT_VALUE,
                f"Signature-Agent {value!r} is not https://<host>{DIRECTORY_PATH} or https://<host>",
            )
        return cls(split[0])

    @classmethod
    def of_url(cls, url: str) -> Origin:
        """The identity of the host ``url`` names, ``https://<host>``, whatever its scheme and port.

        This is the one mapping from a URL host to an identity. A name is
        mapped through IDNA-2008 (UTS #46, non-transitional), the
        canonicalization :func:`is_canonical_host` checks, so
        ``https://Bücher.example:8443/x`` names ``https://xn--bcher-kva.example``.
        An IP address is written in its compressed form. Raises
        :class:`ConfigurationError` when the URL has no host, or its host
        can't be an identity, such as one with a trailing dot.
        """
        try:
            host = urlsplit(url).hostname if isinstance(url, str) else None
        except ValueError as e:
            raise ConfigurationError(f"{url!r} is not a URL: {e}") from e
        if not host:
            raise ConfigurationError(f"{url!r} names no host")
        return cls(_canonical_host(host))

    @property
    def authority(self) -> Authority:
        """The ``@authority`` of the origin's URLs: its host."""
        return Authority(self.host)

    @property
    def directory_url(self) -> str:
        """The key directory URL, the value a signer sends in ``Signature-Agent``."""
        return f"{self}{DIRECTORY_PATH}"

    def __str__(self) -> str:
        return f"{_SCHEME}{self.host}"


def _url_authority(scheme: str, host: str, port: int | None) -> RequestAuthority:
    if ":" in host:
        host = f"[{host}]"
    if port is None or port == _DEFAULT_PORTS.get(scheme):
        return RequestAuthority(host)
    return RequestAuthority(f"{host}:{port}")


# ── the target URI: the one URL rule ──────────────────────────────────────

#: What a URL parser trims from both ends of a URL: C0 controls and space (WHATWG).
_TRIMMED = "".join(map(chr, range(0x21)))
#: What a URL parser removes from anywhere in a URL: tab and newline (WHATWG).
_REMOVED = str.maketrans("", "", "\t\n\r")
#: The printable ASCII characters a path carries percent-encoded on the wire: the
#: WHATWG path percent-encode set. Controls, DEL, and non-ASCII are always encoded.
_PATH_ENCODED = frozenset(' "#<>?`{}')
#: The printable ASCII characters an http(s) query carries percent-encoded on the
#: wire: the WHATWG special-query percent-encode set.
_QUERY_ENCODED = frozenset(" \"#<>'")
#: The path segments a URL parser reads as ``.`` and ``..`` (WHATWG), lowercased.
_SINGLE_DOT = frozenset({".", "%2e"})
_DOUBLE_DOT = frozenset({"..", ".%2e", "%2e.", "%2e%2e"})
_SCHEME_PREFIX = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*)://")


def _percent_encoded(text: str, encoded: frozenset[str]) -> str:
    """``text`` with ``encoded``, controls, DEL, and non-ASCII percent-encoded as UTF-8.

    An existing escape, ``%zz`` included, is left as it is.
    """
    out: list[str] = []
    for c in text:
        if " " < c < "\x7f" and c not in encoded:
            out.append(c)
        else:
            out.extend(f"%{b:02X}" for b in c.encode("utf-8", "surrogatepass"))
    return "".join(out)


def _without_dot_segments(path: str) -> str:
    """``path``, which starts with ``/``, with its dot segments removed (RFC 3986 § 5.2.4).

    A segment is a dot segment as WHATWG reads it, ``%2e`` included, and a
    trailing one leaves the path ending in ``/``.
    """
    segments = path.split("/")[1:]
    kept: list[str] = []
    for i, segment in enumerate(segments):
        last = i == len(segments) - 1
        lowered = segment.lower()
        if lowered in _DOUBLE_DOT:
            if kept:
                kept.pop()
        elif lowered not in _SINGLE_DOT:
            kept.append(segment)
            continue
        if last:
            kept.append("")
    return "/" + "/".join(kept)


def _host_and_port(authority: str) -> tuple[str, str]:
    """``host[:port]`` split, after any userinfo, with an IPv6 literal kept in brackets."""
    hostport = authority.rpartition("@")[2]
    if hostport.startswith("["):
        literal, bracket, after = hostport.partition("]")
        if not bracket or (after and not after.startswith(":")):
            raise ValueError(f"{authority!r} is not a host and port")
        return literal + bracket, after[1:]
    host, _, port = hostport.partition(":")
    return host, port


def _target_host(host: str) -> str:
    """``host`` as the wire carries it: an IP literal compressed, a name lowercased in A-labels."""
    if host.startswith("["):
        try:
            return f"[{ipaddress.IPv6Address(host[1:-1])}]"
        except ValueError as e:
            raise ValueError(f"{host!r} is not an IPv6 address") from e
    if not host:
        raise ValueError("the URL names no host")
    return _canonical_host(host).lower()


def _target_port(port: str, scheme: str) -> int | None:
    """No port for none, an empty one, or the scheme's default; ``ValueError`` for a bad one."""
    if not port:
        return None
    if not is_decimal(port) or int(port) > 65535:
        raise ValueError(f"{port!r} is not a port")
    number = int(port)
    return None if number == _DEFAULT_PORTS[scheme] else number


@dataclass(frozen=True, slots=True)
class TargetURI:
    """A request's target URI as it travels on the wire: the profile's one URL rule.

    The signer signs this value as ``@target-uri``, the verifier checks it, the
    server edge rebuilds it, and ``@authority`` is its :attr:`authority`, so a
    URL a signer signs is the URL a verifier recomputes. It is the URL an HTTP
    client sends, the WHATWG URL serialization that httpx and ``fetch``
    produce, normalized per RFC 3986 § 6.2.2:

    - the scheme and host are lowercase, a name in IDNA A-labels and an IP
      literal in compressed form, and a default port is dropped;
    - dot segments are removed, and an empty path is ``/``;
    - the characters WHATWG percent-encodes are percent-encoded: controls,
      space, non-ASCII (as UTF-8), ``" < >`` and, in the path, ``` ` { } ```
      or, in the query, ``'``. Everything else, such as ``| ^ [ ] { }`` in a
      query, stays as written, and an existing escape is never changed;
    - userinfo and the fragment, which never go on the wire, are dropped, and
      so is an empty query: a server can't tell ``/p?`` from ``/p``.

    ``str()`` is the serialization. :meth:`parse` is the one way to make one.
    """

    scheme: str
    host: str
    port: int | None
    path: str
    query: str | None

    @classmethod
    def parse(cls, url: str) -> TargetURI:
        """Reads an absolute ``http`` or ``https`` URL; ``ValueError`` for anything else."""
        if not isinstance(url, str):
            raise ValueError(f"a URL is a str, not {url!r}")
        text = url.strip(_TRIMMED).translate(_REMOVED).partition("#")[0]
        prefix = _SCHEME_PREFIX.match(text)
        scheme = prefix[1].lower() if prefix else ""
        if prefix is None or scheme not in _DEFAULT_PORTS:
            raise ValueError(f"{url!r} is not an absolute http or https URL")
        before, _, query = text[prefix.end() :].partition("?")
        authority, slash, path = before.replace("\\", "/").partition("/")
        host, port = _host_and_port(authority)
        return cls(
            scheme,
            _target_host(host),
            _target_port(port, scheme),
            _percent_encoded(_without_dot_segments(slash + path or "/"), _PATH_ENCODED),
            _percent_encoded(query, _QUERY_ENCODED) or None,
        )

    @property
    def authority(self) -> RequestAuthority:
        """The ``@authority`` (RFC 9421 § 2.2.3): the host, and a port other than the default."""
        return RequestAuthority(self.host if self.port is None else f"{self.host}:{self.port}")

    def __str__(self) -> str:
        query = "" if self.query is None else f"?{self.query}"
        return f"{self.scheme}://{self.authority}{self.path}{query}"


def authority_of(url: str) -> RequestAuthority:
    """Returns the ``@authority`` of an absolute URL (RFC 9421 section 2.2.3).

    It is :attr:`TargetURI.authority`, under the same URL rule as
    ``@target-uri``: the host is lowercased and a default port dropped.
    Raises ``ValueError`` for anything but an absolute ``http`` or ``https``
    URL.
    """
    return TargetURI.parse(url).authority


#: A host with an optional port: no path, userinfo, or space.
_AUTHORITY = re.compile(r"[^/@\s]+")


def parse_authority(value: object) -> RequestAuthority:
    """Reads a request authority from configuration, such as ``seller.example.com:8443``.

    The value is normalized as ``@authority`` is computed: a lowercase host and
    no default port. Raises :class:`ConfigurationError` for anything else.
    """
    if not isinstance(value, str) or _AUTHORITY.fullmatch(value) is None:
        raise ConfigurationError(f"an authority is a host with an optional port, not {value!r}")
    try:
        return authority_of(f"https://{value}")
    except ValueError as e:
        raise ConfigurationError(f"{value!r} is not an authority: {e}") from e


def key_id_set(values: object) -> frozenset[KeyId]:
    """Returns ``values`` as a set of key ids; :class:`ConfigurationError` for anything else."""
    return frozenset(KeyId(v) for v in identifier_set("the key ids", values))


#: A base URL: ``http`` or ``https``, an authority, and nothing after it.
_BASE_URL = re.compile(r"(?P<scheme>https?)://(?P<netloc>[^/?#@\s]+)")


@dataclass(frozen=True, slots=True)
class _BaseURL:
    """A base URL split into its scheme, canonical host, and port."""

    scheme: str
    host: str
    port: int | None

    @property
    def authority(self) -> RequestAuthority:
        return _url_authority(self.scheme, self.host, self.port)


def _netloc_parts(netloc: str) -> tuple[str, str]:
    if netloc.endswith("]") or ":" not in netloc:
        return netloc, ""
    host, _, port = netloc.rpartition(":")
    return host, port


def _decimal_port(port: str) -> int:
    """A port in canonical decimal, from 1 to 65535; :class:`ConfigurationError` else."""
    if is_decimal(port) and not port.startswith("0") and int(port) < 65536:
        return int(port)
    raise ConfigurationError(f"{port!r} is not a port")


def _port(port: str, scheme: str) -> int | None:
    """No port, or one other than the scheme's default."""
    if not port:
        return None
    number = _decimal_port(port)
    if number == _DEFAULT_PORTS[scheme]:
        raise ConfigurationError(f"a base URL names no default port, not :{port}")
    return number


def _base_url_match(value: object) -> re.Match[str]:
    match = _BASE_URL.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise ConfigurationError(
            f"base_url must be an origin such as https://seller.example.com, not {value!r}"
        )
    return match


def _base_url(value: object) -> _BaseURL:
    """Reads ``scheme://host[:port]`` with a canonical host; :class:`ConfigurationError` else."""
    match = _base_url_match(value)
    host, port = _netloc_parts(match["netloc"])
    if not is_canonical_host(host):
        raise ConfigurationError(f"base_url {value!r} needs a canonical host")
    return _BaseURL(match["scheme"], host.strip("[]"), _port(port, match["scheme"]))


@dataclass(frozen=True, slots=True)
class ServerIdentity:
    """A server's own identity, from configuration, never from a request.

    ``origin`` is the identity it signs as, ``https://<host>``. ``base_url`` is
    the scheme and authority of its public URLs, such as
    ``https://seller.example.com:8443``: the middlewares rebuild each request
    URL on it, whatever ``Host`` the client sends, and the request verifier
    accepts a URL for its authority, :attr:`request_authority`, alone. One
    fact sets both, so a request the edges rebuild is always one the verifier
    can accept.

    It checks itself when it is made: ``base_url`` has the origin's host.
    Anything else raises :class:`ConfigurationError`. :meth:`from_config`
    builds one from a string.
    """

    origin: Origin
    base_url: str

    def __post_init__(self) -> None:
        if not isinstance(self.origin, Origin):
            raise ConfigurationError(f"origin is an Origin, not {self.origin!r}")
        base = _base_url(self.base_url)
        if base.host != self.origin.host.strip("[]"):
            raise ConfigurationError(f"base_url {self.base_url} isn't on {self.origin}")

    @property
    def request_authority(self) -> RequestAuthority:
        """The ``@authority`` of the server's own URLs, from ``base_url``."""
        return _base_url(self.base_url).authority

    @classmethod
    def from_config(cls, base_url: str) -> ServerIdentity:
        """Builds the identity of the server whose public base URL is ``base_url``.

        ``base_url`` is ``https://<host>`` or ``http://<host>``, with a
        canonical host, an optional port other than the scheme's default, and
        an optional trailing ``/``. The identity origin is always
        ``https://<host>``. Raises :class:`ConfigurationError` for anything else.
        """
        value = base_url.removesuffix("/") if isinstance(base_url, str) else base_url
        base = _base_url(value)
        origin = Origin(f"[{base.host}]" if ":" in base.host else base.host)
        return cls(origin, str(value))


def b64url_decode(value: str) -> bytes:
    """Decodes unpadded or padded base64url."""
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64url_encode(data: bytes) -> str:
    """Encodes ``data`` as unpadded base64url."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


__all__ = [
    "DIRECTORY_MEDIA_TYPE",
    "DIRECTORY_PATH",
    "OMIT",
    "Authority",
    "Clock",
    "KeyId",
    "Omit",
    "Origin",
    "RequestAuthority",
    "Seconds",
    "ServerIdentity",
    "TargetURI",
    "UnixSeconds",
    "authority_of",
    "identifier_set",
    "is_canonical_host",
    "is_decimal",
    "system_clock",
    "whole_number",
]
