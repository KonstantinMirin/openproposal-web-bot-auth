"""The demo's `Origin` (persistence/values.py) accepts exactly what the library's accepts.

The demo holds origins in a pure type, so the offer logic and the control plane
can hold one without loading the Web Bot Auth library. This table is the
conformance oracle that keeps the two from drifting: every input goes to both
`Origin.parse` functions, and they accept and refuse the same set, with the
same host and the same text.
"""

from __future__ import annotations

import pytest
from iab_agentic_primitives.web_bot_auth import ConfigurationError
from iab_agentic_primitives.web_bot_auth import Origin as LibraryOrigin
from pydantic import ValidationError

from persistence.values import Origin

ACCEPTED = [
    "https://seller.wba-demo.noetis.dev",
    "https://example.com",
    "https://a.b.c.example",
    "https://xn--bcher-kva.example",  # an IDN A-label
    "https://192.0.2.1",
    "https://[2001:db8::1]",
    "https://[::1]",
    "https://localhost",
]

REFUSED = [
    "https://Seller.Example",  # uppercase
    "https://seller.example/",  # a trailing slash
    "https://seller.example:443",  # the default port
    "https://seller.example:8443",  # a port
    "https://seller.example/agent",  # a path
    "https://seller.example?x=1",  # a query
    "https://seller.example#top",  # a fragment
    "https://user@seller.example",  # userinfo
    "http://seller.example",  # not https
    "seller.example",  # no scheme
    "HTTPS://seller.example",  # an uppercase scheme
    "https://",  # no host
    "https://seller.example.",  # a trailing dot
    "https://bücher.example",  # an IDN U-label
    "https://xn--bcher-kva.example.",  # an A-label with a trailing dot
    "https://seller.123",  # a numeric last label
    "https://127.1",  # an IPv4 address a URL parser reads as 127.0.0.1
    "https://0x7f.0.0.1",  # a hexadecimal last label
    "https://seller.0x1f",
    "https://192.000.002.001",  # an IPv4 literal not in its canonical form
    "https://[2001:DB8::1]",  # an IPv6 literal in uppercase
    "https://[2001:db8:0:0:0:0:0:1]",  # an IPv6 literal not compressed
    "https://[fe80::1%25eth0]",  # an IPv6 literal with a zone
    "https://2001:db8::1",  # an IPv6 literal without brackets
    "https://sel ler.example",  # a space
    "https://seller_example.com",  # an underscore
    "https://-seller.example",  # a leading hyphen
]


def _library(text: str) -> str | None:
    try:
        return str(LibraryOrigin.parse(text))
    except ConfigurationError:
        return None


def _demo(text: str) -> str | None:
    try:
        return str(Origin.parse(text))
    except ValidationError:
        return None


@pytest.mark.parametrize("text", ACCEPTED + REFUSED)
def test_both_parse_functions_accept_and_refuse_the_same_text(text: str) -> None:
    assert _demo(text) == _library(text)
    assert (_demo(text) == text) is (text in ACCEPTED)


@pytest.mark.parametrize("text", ACCEPTED)
def test_an_accepted_origin_has_the_librarys_host(text: str) -> None:
    assert Origin.parse(text).host == LibraryOrigin.parse(text).host
