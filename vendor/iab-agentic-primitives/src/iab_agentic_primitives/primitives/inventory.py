"""Inventory wire primitives: Product, Package, MediaKit.

Reconciled from the buyer agent's ``models/opendirect.py`` (Product) and
the seller agent's ``models/core.py`` (Product, CommercialTerms) /
``models/media_kit.py`` (Package). See RECONCILIATION.md at the repo root
for the field-level audit trail.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import Field

from ._util import Money, WireModel, utc_now
from .pricing import DealType, PricingModel, PricingType

# ---------------------------------------------------------------------------
# Product
# ---------------------------------------------------------------------------


class DeliveryType(str, Enum):
    """Delivery type for a product (OpenDirect vocabulary).

    PMP = private marketplace.
    """

    EXCLUSIVE = "Exclusive"
    GUARANTEED = "Guaranteed"
    PMP = "PMP"


class CommercialTerms(WireModel):
    """Commercial capabilities a product supports (not binding terms)."""

    supported_deal_types: list[DealType] = Field(
        default_factory=list,
        description="Supported deal types: 'PG' (Programmatic Guaranteed), "
        "'PD' (Preferred Deal), 'PA' (Private Auction).",
    )
    supported_pricing_models: list[PricingModel] = Field(default_factory=list)
    minimum_deal_value: Money | None = None
    guarantee_allowed: bool | None = None
    makegood_allowed: bool | None = None


class Product(WireModel):
    """Sellable unit of publisher inventory.

    Merges the buyer's OpenDirect (the IAB direct-buying API standard)
    ``Product`` with the seller's taxonomy-driven ``Product``. Targeting
    intent uses the three IAB (Interactive Advertising Bureau) taxonomies:
    Audience (who sees the ad), Ad Product (what is advertised), and
    Content (where ads appear).

    ``base_price`` is the seller's public/list price signal, if disclosed;
    the private negotiated rate for a buyer/seller pair lives on their
    RateCard (flagged decision FD-9), never here.

    ID minting: ``product_id`` is seller-issued.
    """

    product_id: str = Field(description="Seller-issued product identifier.")
    seller_organization_id: str = Field(
        description="Registry-issued id of the owning seller organization."
    )
    name: str = Field(max_length=128)
    description: str | None = None
    base_price: Money | None = Field(
        default=None,
        description="Public list price, if disclosed; None when pricing is on request.",
    )
    pricing_type: PricingType = PricingType.FIXED
    pricing_model: PricingModel = PricingModel.CPM
    delivery_type: DeliveryType = DeliveryType.GUARANTEED
    domain: str | None = None
    ad_formats: list[str] = Field(
        default_factory=list,
        description='OpenRTB (Open Real-Time Bidding) formats: "banner", "video", '
        '"native", "audio".',
    )
    audience_targeting: dict[str, Any] | None = Field(
        default=None, description="IAB Audience Taxonomy targeting intent."
    )
    ad_product_targeting: dict[str, Any] | None = Field(
        default=None, description="IAB Ad Product Taxonomy targeting intent."
    )
    content_targeting: dict[str, Any] | None = Field(
        default=None, description="IAB Content Taxonomy targeting intent."
    )
    available_impressions: int | None = Field(default=None, ge=0)
    commercial_terms: CommercialTerms | None = None
    ext: dict[str, Any] | None = Field(default=None, description="Extension slot.")


# ---------------------------------------------------------------------------
# Package
# ---------------------------------------------------------------------------


class PackageLayer(str, Enum):
    """How a package was created."""

    SYNCED = "synced"  # imported from an ad server
    CURATED = "curated"  # seller-created
    DYNAMIC = "dynamic"  # agent-assembled on the fly


class PackageStatus(str, Enum):
    """Lifecycle status of a package."""

    DRAFT = "draft"
    ACTIVE = "active"
    ARCHIVED = "archived"


class PackagePlacement(WireModel):
    """A product within a package with its inventory characteristics."""

    product_id: str = Field(description="Seller-issued product identifier.")
    product_name: str
    ad_formats: list[str] = Field(default_factory=list)
    device_types: list[int] = Field(
        default_factory=list,
        description="AdCOM (Advertising Common Object Model) DeviceType integers "
        "(1=Mobile, 2=PC, 3=CTV — connected television, ...).",
    )
    weight: float = Field(default=1.0, description="Relative weight in the package.")


class Package(WireModel):
    """Curated inventory package for media kit discovery.

    A curation layer on top of products. Taxonomy fields use IAB
    (Interactive Advertising Bureau) standard identifiers as canonical
    values; human-readable descriptions are derived at presentation time.

    ID minting: ``package_id`` is seller-issued.
    """

    package_id: str = Field(description="Seller-issued package identifier.")
    name: str
    description: str | None = None
    layer: PackageLayer = PackageLayer.CURATED
    status: PackageStatus = PackageStatus.DRAFT
    placements: list[PackagePlacement] = Field(default_factory=list)
    cat: list[str] = Field(
        default_factory=list,
        description='IAB Content Taxonomy category ids, e.g. ["IAB19"].',
    )
    cattax: int = Field(
        default=2, description="Content taxonomy version: 1=CT1.0, 2=CT2.0, 3=CT3.0."
    )
    audience_capabilities: dict[str, Any] | None = Field(
        default=None,
        description="Audience capability declaration. Kept as an open object here; "
        "the typed model lands with the audience-plan bead.",
    )
    device_types: list[int] = Field(default_factory=list, description="AdCOM DeviceType integers.")
    ad_formats: list[str] = Field(default_factory=list)
    geo_targets: list[str] = Field(
        default_factory=list, description='ISO 3166-2 codes, e.g. ["US", "US-NY"].'
    )
    pricing_type: PricingType = PricingType.FIXED
    base_price: Money | None = Field(
        default=None, description="Public/blended list price, if disclosed."
    )
    pricing_model: PricingModel = PricingModel.CPM
    tags: list[str] = Field(default_factory=list)
    is_featured: bool = False
    seasonal_label: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime | None = None


# ---------------------------------------------------------------------------
# MediaKit
# ---------------------------------------------------------------------------


class MediaKit(WireModel):
    """A seller's discoverable inventory catalog: the packages it offers buyers.

    The media kit is the buyer-facing discovery document; tier-gated views
    (public price ranges vs. authenticated exact pricing) are derived from
    it by the seller at serving time and are not separate wire primitives.

    ID minting: ``media_kit_id`` is seller-issued.
    """

    media_kit_id: str = Field(description="Seller-issued media kit identifier.")
    seller_organization_id: str = Field(
        description="Registry-issued id of the publishing seller organization."
    )
    name: str
    description: str | None = None
    packages: list[Package] = Field(default_factory=list)
    contact: str | None = None
    currency: str = Field(default="USD", description="ISO 4217 currency code.")
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime | None = None


__all__ = [
    "CommercialTerms",
    "DeliveryType",
    "MediaKit",
    "Package",
    "PackageLayer",
    "PackagePlacement",
    "PackageStatus",
    "Product",
]
