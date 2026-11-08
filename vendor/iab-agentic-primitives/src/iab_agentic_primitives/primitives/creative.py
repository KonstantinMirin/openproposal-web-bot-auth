"""Creative wire primitives: Creative, Assignment.

Reconciled from the buyer agent's ``models/opendirect.py`` (Creative,
Assignment) and the seller agent's ``models/core.py`` (Creative,
CreativeManifest, Assignment). Per the remediation plan §4.4, Creative is
a shared wire object with a seller-side approval state — the buyer
supplies the asset, the seller reviews and approves it. See
RECONCILIATION.md at the repo root for the field-level audit trail.
"""

from datetime import date, datetime
from enum import Enum
from typing import Any

from pydantic import Field

from ._util import WireModel, utc_now


class AdProfile(str, Enum):
    """Type of creative profile.

    AdCOM = Advertising Common Object Model (the IAB — Interactive
    Advertising Bureau — object model shared by OpenRTB and OpenDirect).
    """

    METADATA_ONLY = "metadata_only"
    FULL_ADCOM = "full_adcom"


class ReviewStatus(str, Enum):
    """Seller-side creative review status."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class RotationMode(str, Enum):
    """Creative rotation mode within an assignment."""

    EVEN = "even"
    WEIGHTED = "weighted"


class CreativeAsset(WireModel):
    """Individual asset within a creative manifest."""

    asset_id: str
    asset_url: str
    mime_type: str
    width: int | None = None
    height: int | None = None
    role: str = Field(description='"main", "companion", "icon", "endcard", "subtitle".')


class CreativeManifest(WireModel):
    """Creative metadata manifest — metadata only, no executable markup."""

    assets: list[CreativeAsset] = Field(default_factory=list)
    landing_page_urls: list[str] | None = None
    declared_advertiser_domains: list[str] | None = None
    duration_ms: int | None = None
    file_size_bytes: int | None = None


class ContentPolicy(WireModel):
    """Content adjacency restrictions for a creative."""

    allowed_categories: list[str] | None = None
    blocked_categories: list[str] | None = None


class Creative(WireModel):
    """Creative metadata for an advertising asset.

    Metadata only — never executable markup — so creative management stays
    platform-agnostic and counterparty text can never smuggle executable
    content across the wire. The buyer supplies the creative; the seller
    owns ``review_status``.

    ID minting: ``creative_id`` is seller-issued when the buyer registers
    the creative through the seller's API.
    """

    creative_id: str = Field(description="Seller-issued creative identifier.")
    account_id: str | None = Field(
        default=None, description="Seller-issued account the creative belongs to."
    )
    name: str | None = Field(default=None, max_length=255)
    language: str | None = Field(default=None, description="ISO 639-1 language code.")
    click_url: str | None = None
    ad_profile: AdProfile = AdProfile.METADATA_ONLY
    creative_manifest: CreativeManifest = Field(default_factory=CreativeManifest)
    ad_product_taxonomy: dict[str, Any] | None = Field(
        default=None, description="IAB Ad Product Taxonomy classification."
    )
    audience_taxonomy: dict[str, Any] | None = Field(
        default=None, description="IAB Audience Taxonomy classification."
    )
    content_policy: ContentPolicy | None = None
    review_status: ReviewStatus = Field(
        default=ReviewStatus.PENDING,
        description="Seller-side approval state (plan §4.4).",
    )
    is_placeholder: bool = False
    placeholder_type: str | None = None
    ext: dict[str, Any] | None = Field(default=None, description="Extension slot.")


class CreativeApproval(WireModel):
    """A durable seller-side creative approval decision (EP-10.5).

    :class:`Creative` carries the current ``review_status`` (its live
    approval state); this is the first-class, timestamped RECORD of a
    single approval decision — who reviewed it, the outcome, and why. The
    two are complementary: the seller flips ``Creative.review_status`` AND
    writes a ``CreativeApproval`` for the audit trail. Reuses
    :class:`ReviewStatus` so the vocabulary never forks.

    ID minting: ``approval_id`` is seller-issued (the seller owns creative
    review).
    """

    approval_id: str = Field(description="Seller-issued approval decision identifier.")
    creative_id: str = Field(description="Seller-issued id of the creative reviewed.")
    status: ReviewStatus = Field(description="Outcome of this review decision.")
    reviewer: str = Field(description="Actor id: 'system', 'human:<id>', or 'agent:<id>'.")
    reason: str | None = Field(
        default=None,
        description="Rationale, required in practice for a rejection.",
    )
    occurred_at: datetime = Field(
        default_factory=utc_now,
        description="Timezone-aware UTC timestamp of the review decision.",
    )
    ext: dict[str, Any] | None = Field(default=None, description="Extension slot.")


class Assignment(WireModel):
    """Binds a creative to a line with rotation rules.

    The wire-level execution unit is the Line; the seller repo's
    placement-level binding is a seller-internal mapping.

    ID minting: ``assignment_id`` is seller-issued (created via the
    seller's API on buyer request).
    """

    assignment_id: str = Field(description="Seller-issued assignment identifier.")
    creative_id: str
    line_id: str = Field(description="Seller-issued line the creative runs on.")
    rotation_mode: RotationMode = RotationMode.EVEN
    sov: float | None = Field(
        default=None, ge=0, le=1, description="Share of voice (0-1) for weighted rotation."
    )
    effective_start_date: date | None = None
    effective_end_date: date | None = None
    status: str | None = Field(
        default=None,
        description="Free-form assignment status; the typed vocabulary lands with "
        "the EP-1.4 state-machine bead.",
    )
    ext: dict[str, Any] | None = None


__all__ = [
    "AdProfile",
    "Assignment",
    "ContentPolicy",
    "Creative",
    "CreativeApproval",
    "CreativeAsset",
    "CreativeManifest",
    "ReviewStatus",
    "RotationMode",
]
