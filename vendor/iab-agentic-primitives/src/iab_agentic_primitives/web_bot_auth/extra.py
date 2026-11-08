"""The ``wba`` extra, and the install check that refuses to import without it. No I/O.

The package imports this module first. :data:`EXTRA_MODULES` is the module's
own list of the libraries it needs, so a vendored copy, which has no package
metadata, still checks them. The check probes each library without importing
it: verifying with pinned keys loads no network client.
"""

from __future__ import annotations

from importlib.util import find_spec

__all__ = ["EXTRA_MODULES"]

#: The import names of the libraries the ``wba`` extra installs, one per
#: requirement of ``[project.optional-dependencies] wba`` in pyproject.toml.
EXTRA_MODULES = (
    "cryptography",
    "http_message_signatures",
    "http_sf",
    "httpx",
    "idna",
    "joserfc",
)

# Each library is probed, not imported: verifying with pinned keys loads no network client.
_missing = [name for name in EXTRA_MODULES if find_spec(name) is None]
if _missing:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "iab_agentic_primitives.web_bot_auth needs the 'wba' extra "
        f"(missing: {', '.join(_missing)}): pip install 'iab-agentic-primitives[wba]'"
    )
