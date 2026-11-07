"""When a signature attributes an `assent[]` entry to a party (OpenProposal 3.0 § 4.1.2).

The signature attributes the entry to the record's party that `role` implies
when it covers the body, through `Content-Digest`, and the host of the signing
origin is that party's `domain` or a subdomain of it.
"""

from __future__ import annotations

import idna
import tldextract

# The Public Suffix List snapshot that ships with tldextract, PRIVATE section
# included (§ 2.2 `RegistrableDomain`). No network refresh and no disk cache.
_PSL = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)


def canonical_host(name: str) -> str:
    """A host or domain in lowercase A-label form (§ 2.2 `Domain`)."""
    return idna.encode(name.rstrip("."), uts46=True).decode("ascii")


def names_a_party(domain: str) -> bool:
    """False for a value that can't name a party: a public suffix, or a name under no suffix."""
    parts = _PSL(canonical_host(domain))
    return bool(parts.suffix and parts.domain)


def attributes(signing_host: str, party_domain: str, *, body_covered: bool) -> bool:
    """True when a signature from `signing_host` attributes an entry to the party at `party_domain`."""
    if not body_covered or not names_a_party(party_domain):
        return False
    host, domain = canonical_host(signing_host), canonical_host(party_domain)
    return host == domain or host.endswith("." + domain)
