"""How a caller authenticates to a seller: the two credential methods, named once.

A pure module, so the seller's identity types (seller/caller.py) can name the
methods without importing the Web Bot Auth wiring.
"""

from __future__ import annotations

from typing import Literal

#: A Web Bot Auth signature.
SignatureMethod = Literal["web_bot_auth"]
#: A bearer token the seller issued.
BearerMethod = Literal["bearer"]
#: How a caller authenticated.
AuthMethod = Literal[SignatureMethod, BearerMethod]
