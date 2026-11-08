"""Supply-chain transparency wire primitives (EP-10.3).

Models the OpenRTB (Open Real-Time Bidding) SupplyChain object (``schain``)
and a sellers.json entry so a deal can carry an auditable record of who is
in the monetisation path. These are the industry-standard transparency
objects the two agents must agree on to avoid the undisclosed-reseller and
spoofing problems that ads.txt / sellers.json / schain were created to
solve.

OpenRTB/AdCOM (Advertising Common Object Model) field names are kept
verbatim where they are the published standard — ``asi`` (advertising
system identifier), ``sid`` (seller id within that system), ``hp``
(handled-payment flag), ``rid`` (request id), ``name``, ``domain``,
``ext`` — so an adapter can map to the raw bid-stream encoding without a
rename table. Integer 0/1 flags (``complete``, ``hp``) follow the OpenRTB
encoding rather than being re-typed to bool.

See RECONCILIATION.md at the repo root for the classification decision.
"""

from enum import Enum
from typing import Any

from pydantic import Field

from ._util import WireModel


class SupplyChainNode(WireModel):
    """One hop in the OpenRTB supply chain (``schain`` node).

    Field names are the OpenRTB SupplyChainNode names verbatim. ``asi`` is
    the advertising system identifier (the canonical domain of the system
    the node operates in, e.g. ``"exchange.example.com"``); ``sid`` is the
    seller id **within that system** and matches a ``seller_id`` in that
    system's sellers.json.
    """

    asi: str = Field(description="Advertising system identifier (canonical domain of the system).")
    sid: str = Field(
        description="Seller id within the ``asi`` system; matches its sellers.json seller_id."
    )
    hp: int = Field(
        default=1,
        ge=0,
        le=1,
        description="Handled-payment flag (OpenRTB 0/1): 1 = node is paid for this inventory.",
    )
    rid: str | None = Field(
        default=None,
        description="Request id issued by the seller (OpenRTB ``rid``), when present.",
    )
    name: str | None = Field(
        default=None, description="Business name of the entity represented by this node."
    )
    domain: str | None = Field(
        default=None, description="Business domain of the entity represented by this node."
    )
    ext: dict[str, Any] | None = Field(default=None, description="Extension slot.")


class SupplyChain(WireModel):
    """OpenRTB SupplyChain object (``schain``): the ordered node path.

    ``complete`` is the OpenRTB 0/1 flag: 1 means every node from the
    initial impression to the final bidder is present (no undisclosed
    hops). Nodes are ordered from the first seller to the entity making the
    request. Carried optionally on the :class:`Deal` for transparency.
    """

    complete: int = Field(
        default=1,
        ge=0,
        le=1,
        description="OpenRTB 0/1: 1 = all nodes in the path are disclosed.",
    )
    ver: str = Field(default="1.0", description="SupplyChain object version (OpenRTB ``ver``).")
    nodes: list[SupplyChainNode] = Field(
        default_factory=list,
        description="Supply path, ordered first-seller -> requesting-entity.",
    )
    ext: dict[str, Any] | None = Field(default=None, description="Extension slot.")


class SellerType(str, Enum):
    """sellers.json ``seller_type``.

    - ``PUBLISHER``: the seller is the owner of the inventory
    - ``INTERMEDIARY``: the seller resells inventory it does not own
    - ``BOTH``: the seller acts as both on different inventory
    """

    PUBLISHER = "PUBLISHER"
    INTERMEDIARY = "INTERMEDIARY"
    BOTH = "BOTH"


class SellersJsonEntry(WireModel):
    """One entry from a system's sellers.json file.

    Mirrors the IAB Tech Lab sellers.json ``sellers[]`` object. ``name``
    and ``domain`` are omitted (``None``) for a confidential seller, in
    which case ``is_confidential`` is true. Modeled as a ``bool`` here
    rather than the sellers.json 0/1 integer for wire cleanliness; adapters
    translate at the edge.
    """

    seller_id: str = Field(description="Opaque seller id, unique within the publishing system.")
    name: str | None = Field(
        default=None, description="Seller business name; None when confidential."
    )
    domain: str | None = Field(
        default=None, description="Seller business domain; None when confidential."
    )
    seller_type: SellerType = Field(description="PUBLISHER, INTERMEDIARY, or BOTH.")
    is_confidential: bool = Field(
        default=False,
        description="True when name/domain are withheld (sellers.json is_confidential=1).",
    )
    comment: str | None = Field(default=None, description="Optional free-text comment.")
    ext: dict[str, Any] | None = Field(default=None, description="Extension slot.")


__all__ = [
    "SellerType",
    "SellersJsonEntry",
    "SupplyChain",
    "SupplyChainNode",
]
