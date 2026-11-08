"""Avails surface: ``POST /products/avails`` (availability + pricing query).

An avails query is a capability, not a persisted object — it is a protocol
message, not a primitive (RECONCILIATION.md G9 / plan §4.4). The surface
shipped in the seller agent v2.1.0 and is documented on its public API
reference, so the canonical contract preserves the served wire dialect
byte-for-byte: OpenDirect 2.1 spec-lowercase names for spec-defined fields
(``productid``/``startdate``/``enddate``) and camelCase for the extension
fields, exactly as both agents already exchange them.

Dialect convergence (v0.5.0): alongside the legacy simplified profile,
this module now carries the PUBLISHED OpenDirect 2.1 wire shapes,
transcribed from the normative attribute tables of OpenDirect v2.1 final
(July 8, 2024; https://github.com/InteractiveAdvertisingBureau/OpenDirect
— the IAB publishes no machine-readable schemas, so the attribute tables
are the source of truth):

- :class:`ProductAvailsSearch` — the spec REQUEST: multi-product
  ``productids`` array plus required ``accountid``/``advertiserbrandid``.
- :class:`Avails` — the spec per-product RESPONSE record: required
  ``productid``/``accountid``/``price``/``startdate``/``enddate`` with
  optional ``availability`` and ``availsstatus``.
- :class:`AvailsStatus` / :class:`ProductTargeting` — the spec
  availability-grouping sub-objects (status Available / Partially
  Available / Unavailable, enumerated reasons).
- :class:`AvailsCollection` — the response envelope: per the spec's
  Collection Objects table, ``POST /products/avails`` responses wrap the
  records in an object whose array property is named ``avails``.

Interop rules (both directions ship in the reference agents):

1. Servers accept BOTH request dialects, discriminated by ``productids``
   (array, spec) vs ``productid`` (scalar, legacy) —
   :func:`parse_avails_request`. The response dialect follows the request
   dialect, so v2.1.0–v2.2.1 payload round-trips are unchanged.
2. The emitted spec request contains ONLY spec-defined top-level fields.
   The legacy extension fields travel in spec slots: requested volume and
   budget as ProductTargeting Investment entries
   (``target=requestedimpressions|budget``,
   ``datasource=iab-agentic-primitives``), and the legacy targeting dict
   as the spec's AdCOM Segment ``targeting`` array
   (``{"name": <dimension>, "value": <value>}``).
3. :func:`avails_from_simplified` derives the spec ``availsstatus``
   semantics from the honest-availability numbers: Available when the
   full requested volume is available, Partially Available (reason
   ``Booked``) when capacity caps it, Unavailable (reason ``Booked``)
   when nothing is available.

Known spec ambiguities (recorded, not resolved in our favor): the spec's
``Avails.availability`` description references a ``quantity`` property
that ProductAvailsSearch does not define; its own examples use PascalCase
field names and an ``availsstatus`` ARRAY while the normative tables use
all-lowercase names and a single object. The normative tables govern
here.

Settled policy decisions encoded here:

1. ``availableImpressions`` is REQUIRED. A product with no capacity cap
   (no ``maximum_impressions``) reports the requested volume as available;
   the field is never omitted.
2. ``deliveryConfidence`` is OPTIONAL and is OMITTED ENTIRELY when the
   seller has no delivery-forecast data source. Conformant emitters never
   fabricate a value and never pad with ``null``; readers tolerate an
   explicit ``null`` from pre-contract emitters (seller <= v2.1.0).
3. ``guaranteedImpressions`` is present ONLY for PG-capable products
   (PG = Programmatic Guaranteed in ``supported_deal_types``); it is
   omitted otherwise.

Money dialect (flagged): ``budget``/``estimatedCpm``/``totalCost`` are
floats, NOT the shared :class:`~iab_agentic_primitives.primitives.Money`
micros type (FD-11). This is a deliberate, documented exception: the
surface is live on the OpenDirect 2.1 float dialect and existing payloads
must round-trip identically. Migrating avails money fields to ``Money``
is a breaking change reserved for the next major version.

OpenDirect = the IAB direct-buying API standard; CPM = cost per mille
(cost per thousand impressions).
"""

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import ConfigDict, Field, model_validator

from ..primitives import WireModel

#: ``datasource`` used for ProductTargeting entries this library mints to
#: carry the legacy extension fields inside spec slots (interop rule 2).
EXTENSION_DATASOURCE = "iab-agentic-primitives"

#: ``target`` names for the minted Investment entries (request side) and
#: the availability description entry (response side).
TARGET_REQUESTED_IMPRESSIONS = "requestedimpressions"
TARGET_BUDGET = "budget"
TARGET_IMPRESSIONS = "impressions"


class AvailsWireModel(WireModel):
    """Base for avails messages: aliased wire names, either spelling in."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)


class AvailsRequest(AvailsWireModel):
    """Request body for ``POST /products/avails``.

    Spec-named fields use the OpenDirect 2.1 all-lowercase wire names;
    the extension fields (``requestedImpressions``/``budget``/
    ``targeting``) keep their camelCase names. When neither
    ``requestedImpressions`` nor ``budget`` is sent, the seller falls back
    to the product's minimum impressions.
    """

    product_id: str = Field(alias="productid", description="Product to check.")
    start_date: datetime = Field(alias="startdate", description="Flight start (ISO-8601).")
    end_date: datetime = Field(
        alias="enddate",
        description="Flight end (ISO-8601); must be after startdate.",
    )
    requested_impressions: int | None = Field(
        default=None,
        alias="requestedImpressions",
        ge=0,
        description="Requested volume; when omitted the seller derives it "
        "from budget at the product CPM, else the product minimum.",
    )
    budget: float | None = Field(
        default=None,
        description="Budget in currency units (OpenDirect 2.1 float "
        "dialect — see the module docstring for the FD-11 exception).",
    )
    targeting: dict[str, Any] | None = Field(
        default=None,
        description="Requested targeting slices; sellers without per-slice "
        "availability data accept but do not filter on it.",
    )

    @model_validator(mode="after")
    def _end_after_start(self) -> "AvailsRequest":
        start, end = self.start_date, self.end_date
        # Normalize mixed naive/aware datetimes (treat naive as UTC) so the
        # comparison never raises.
        if (start.tzinfo is None) != (end.tzinfo is None):
            if start.tzinfo is None:
                start = start.replace(tzinfo=UTC)
            if end.tzinfo is None:
                end = end.replace(tzinfo=UTC)
        if end <= start:
            raise ValueError("enddate must be after startdate")
        return self

    def to_spec(
        self,
        *,
        account_id: str,
        advertiser_brand_id: str,
        currency: str | None = None,
    ) -> "ProductAvailsSearch":
        """Bridge to the published dialect (interop rule 2).

        Produces a spec-shaped :class:`ProductAvailsSearch` whose top
        level contains ONLY spec fields: the extension fields travel as
        minted Investment ProductTargeting entries and the AdCOM
        Segment ``targeting`` array. ``accountid`` and
        ``advertiserbrandid`` are spec-required, so the caller must
        supply them.
        """
        return _legacy_request_to_spec(
            self,
            account_id=account_id,
            advertiser_brand_id=advertiser_brand_id,
            currency=currency,
        )


class AvailsResponse(AvailsWireModel):
    """Response body for ``POST /products/avails``.

    Honest-availability policy: every number is derived from catalog
    data — nothing is fabricated. Optional fields with no value are
    OMITTED from the wire, not sent as ``null`` (readers tolerate ``null``
    from pre-contract emitters).
    """

    product_id: str = Field(alias="productid", description="Echo of the product.")
    available_impressions: int = Field(
        alias="availableImpressions",
        ge=0,
        description="REQUIRED (policy 1). Products without a capacity cap "
        "report the requested volume as available.",
    )
    guaranteed_impressions: int | None = Field(
        default=None,
        alias="guaranteedImpressions",
        ge=0,
        description="Present ONLY for PG-capable products (policy 3); omitted otherwise.",
    )
    estimated_cpm: float = Field(
        alias="estimatedCpm",
        description="CPM the availability is priced at (base CPM, falling "
        "back to floor CPM). OpenDirect 2.1 float dialect (FD-11 exception).",
    )
    total_cost: float = Field(
        alias="totalCost",
        description="availableImpressions / 1000 * estimatedCpm, rounded "
        "to 2 decimals. OpenDirect 2.1 float dialect (FD-11 exception).",
    )
    delivery_confidence: float | None = Field(
        default=None,
        alias="deliveryConfidence",
        ge=0,
        le=100,
        description="Forecast confidence percentage. OPTIONAL — OMITTED "
        "entirely when the seller has no forecast data source (policy 2); "
        "never fabricated.",
    )
    available_targeting: list[str] | None = Field(
        default=None,
        alias="availableTargeting",
        description="Targeting dimensions the product supports; omitted "
        "when the product declares none.",
    )


# ---------------------------------------------------------------------------
# OpenDirect 2.1 spec shapes (normative attribute tables)
# ---------------------------------------------------------------------------


class TargetingDimension(str, Enum):
    """Spec ``ProductTargeting.name``: what the entry describes."""

    INVENTORY = "Inventory"
    DELIVERY = "Delivery"
    DISTRIBUTION = "Distribution"
    INVESTMENT = "Investment"
    PROHIBITIONS = "Prohibitions"


class TargetingUnit(str, Enum):
    """Spec ``ProductTargeting.type``: how the entry is quantified."""

    FRAMES = "Frames"
    AUDIENCE = "Audience"
    INVESTMENT = "Investment"
    TOTAL = "Total"


class AvailsStatusValue(str, Enum):
    """Spec ``AvailsStatus.status`` (note the space in the middle value)."""

    AVAILABLE = "Available"
    PARTIALLY_AVAILABLE = "Partially Available"
    UNAVAILABLE = "Unavailable"


class AvailsStatusReason(str, Enum):
    """Spec ``AvailsStatus.reason``: why inventory is not fully available."""

    BOOKED = "Booked"
    OPTIONED = "Optioned"
    EXCLUDED = "Excluded"
    OUT_OF_CHARGE = "OutOfCharge"
    PROHIBITED = "Prohibited"
    MANUAL_TRADE_ONLY = "Manual Trade Only"
    INVALID_PERIOD_LENGTH = "InvalidPeriodLength"
    INVALID_FRAME_ID = "InvalidFrameID"
    INVALID_BUDGET = "InvalidBudget"
    INVALID_PRICE = "InvalidPrice"
    CLIENT_DUPLICATION = "ClientDuplication"
    LOCATION_DUPLICATION = "LocationDuplication"
    LOCATION_JUXTA = "LocationJuxta"


class ProductTargeting(AvailsWireModel):
    """Spec ``Object: ProductTargeting`` — dimensional targeting/metrics.

    All-lowercase wire names per the normative table; the six starred
    attributes are required.
    """

    name: TargetingDimension = Field(
        description="What is described: Inventory, Delivery, Distribution, "
        "Investment, or Prohibitions."
    )
    type: TargetingUnit = Field(
        description="How it is quantified: Frames, Audience, Investment, or Total."
    )
    datasource: str = Field(
        max_length=255,
        description="Data source that defines the target vocabulary "
        "(third-party schemas welcome by design).",
    )
    target: str = Field(max_length=255, description="The targeted metric within datasource.")
    target_values: list[str] = Field(
        alias="targetvalues",
        description="One or more values for the target (strings on the wire).",
    )
    selectable: bool = Field(
        description="Whether a buyer may select from targetvalues or the values are fixed."
    )
    count: float | None = Field(default=None, description="Count of targetvalues.")
    minimum: float | None = Field(
        default=None, description="Minimum number of selectable targetvalues."
    )
    maximum: float | None = Field(
        default=None, description="Maximum number of selectable targetvalues."
    )
    increment: float | None = Field(
        default=None, description="Permitted increment between target values."
    )
    default: str | float | None = Field(
        default=None,
        description="Default targetvalue(s) when the buyer selects none.",
    )


class AvailsStatus(AvailsWireModel):
    """Spec ``Object: AvailsStatus`` — availability grouping for a product."""

    status: AvailsStatusValue = Field(description="Available, Partially Available, or Unavailable.")
    reason: AvailsStatusReason | None = Field(
        default=None,
        description="Spec-enumerated reason when Partially Available or Unavailable.",
    )
    comment: str | None = Field(default=None, description="Free-text availability comment.")
    context: list[ProductTargeting] | None = Field(
        default=None,
        description="ProductTargeting entries describing the context of a "
        "Partially Available or Unavailable status.",
    )
    product_targeting: list[ProductTargeting] = Field(
        alias="producttargeting",
        description="ProductTargeting entries describing the inventory at "
        "this status (spec-required).",
    )


class ProductAvailsSearch(AvailsWireModel):
    """Spec REQUEST body for ``POST /products/avails``.

    The published multi-product form: ``productids`` is an array, and
    ``accountid``/``advertiserbrandid`` are required. Use
    :meth:`to_simplified` to bridge to the legacy single-product queries
    (one per product id), recovering any minted Investment extension
    entries (requested volume / budget) and the Segment-array targeting.
    """

    product_ids: list[str] = Field(
        alias="productids",
        min_length=1,
        description="Products to get availability + pricing for (spec-required, non-empty).",
    )
    targeting: list[dict[str, Any]] | None = Field(
        default=None,
        description='AdCOM Segment object array ({"name": <dimension>, "value": <value>}).',
    )
    product_targeting: list[ProductTargeting] | None = Field(
        default=None,
        alias="producttargeting",
        description="ProductTargeting entries to target for the availability request.",
    )
    account_id: str = Field(
        alias="accountid",
        max_length=36,
        description="Account identifying the buyer, advertiser, and other "
        "stakeholders (spec-required).",
    )
    currency: str | None = Field(default=None, max_length=3, description="ISO-4217 currency code.")
    advertiser_brand_id: str = Field(
        alias="advertiserbrandid",
        max_length=36,
        description="Brand being advertised (spec-required).",
    )
    availability_fields: list[ProductTargeting] | None = Field(
        default=None,
        alias="availabilityfields",
        description="ProductTargeting metrics availability is returned as.",
    )
    grouping: list[ProductTargeting] | None = Field(
        default=None,
        description="ProductTargeting metrics the availability output is grouped by.",
    )
    start_date: datetime = Field(
        alias="startdate", description="Desired delivery start (ISO-8601)."
    )
    end_date: datetime = Field(
        alias="enddate",
        description="Desired delivery end (ISO-8601); must be after startdate.",
    )

    @model_validator(mode="after")
    def _end_after_start(self) -> "ProductAvailsSearch":
        if _normalized_end_not_after_start(self.start_date, self.end_date):
            raise ValueError("enddate must be after startdate")
        return self

    def to_simplified(self) -> list[AvailsRequest]:
        """Bridge to the legacy dialect: one single-product query per id.

        Recovers the extension fields this library mints on
        :meth:`AvailsRequest.to_spec`: Investment ProductTargeting entries
        (``requestedimpressions``/``budget``) and the Segment-array
        targeting (regrouped into the legacy dict). Foreign
        ProductTargeting entries are ignored — sellers that understand
        them can read ``product_targeting`` directly.
        """
        requested_impressions: int | None = None
        budget: float | None = None
        for entry in self.product_targeting or []:
            value = entry.target_values[0] if entry.target_values else None
            if value is None:
                continue
            if entry.target == TARGET_REQUESTED_IMPRESSIONS:
                requested_impressions = int(float(value))
            elif entry.target == TARGET_BUDGET:
                budget = float(value)

        targeting: dict[str, Any] | None = None
        if self.targeting:
            grouped: dict[str, list[str]] = {}
            for segment in self.targeting:
                name = segment.get("name")
                value = segment.get("value")
                if name is None or value is None:
                    continue
                grouped.setdefault(str(name), []).append(str(value))
            targeting = grouped or None

        return [
            AvailsRequest(
                product_id=product_id,
                start_date=self.start_date,
                end_date=self.end_date,
                requested_impressions=requested_impressions,
                budget=budget,
                targeting=targeting,
            )
            for product_id in self.product_ids
        ]


class Avails(AvailsWireModel):
    """Spec per-product RESPONSE record for ``POST /products/avails``.

    ``price`` stays a float per the OpenDirect 2.1 decimal dialect (the
    FD-11 exception documented in the module docstring).
    """

    product_id: str = Field(
        alias="productid",
        max_length=36,
        description="Product the availability + pricing is for (spec-required).",
    )
    account_id: str = Field(
        alias="accountid",
        max_length=36,
        description="Echo of the requesting account (spec-required).",
    )
    availability: int | None = Field(
        default=None,
        ge=0,
        description="Quantity available for booking in the date range.",
    )
    avails_status: AvailsStatus | None = Field(
        default=None,
        alias="availsstatus",
        description="Availability grouping (Available / Partially Available / Unavailable).",
    )
    currency: str | None = Field(default=None, max_length=3, description="ISO-4217 currency code.")
    price: float = Field(
        description="The product's price (spec-required; OpenDirect 2.1 "
        "float dialect, FD-11 exception)."
    )
    start_date: datetime = Field(
        alias="startdate",
        description="Echo of the requested delivery start (spec-required).",
    )
    end_date: datetime = Field(
        alias="enddate",
        description="Echo of the requested delivery end (spec-required).",
    )

    def to_simplified(self) -> AvailsResponse:
        """Bridge a spec record to the legacy simplified response.

        Field mapping (inverse of :func:`avails_from_simplified`):
        ``availableImpressions`` <- ``availability``, ``estimatedCpm`` <-
        ``price``, ``totalCost`` = availability / 1000 * price rounded to
        2 decimals. Fields with no spec home (``guaranteedImpressions``,
        ``deliveryConfidence``, ``availableTargeting``) stay unset —
        never fabricated. ``availability`` is optional on the spec table,
        but the legacy profile requires it: a record without it raises
        ``ValueError`` rather than inventing a volume.
        """
        if self.availability is None:
            raise ValueError(
                "availability is required to derive the simplified "
                "profile; refusing to fabricate a volume"
            )
        return AvailsResponse(
            product_id=self.product_id,
            available_impressions=self.availability,
            estimated_cpm=self.price,
            total_cost=round(self.availability / 1000 * self.price, 2),
        )


class AvailsCollection(AvailsWireModel):
    """Spec response envelope: the ``avails`` collection object.

    Per the spec's Collection Objects table the ``POST /products/avails``
    response must be an object whose array property is named ``avails``
    (one record per requested product; empty when nothing matches).
    """

    avails: list[Avails] = Field(description="One Avails record per product in the request.")


# ---------------------------------------------------------------------------
# Dialect bridge helpers
# ---------------------------------------------------------------------------


def _normalized_end_not_after_start(start: datetime, end: datetime) -> bool:
    """True when end <= start after normalizing mixed naive/aware inputs."""
    if (start.tzinfo is None) != (end.tzinfo is None):
        if start.tzinfo is None:
            start = start.replace(tzinfo=UTC)
        if end.tzinfo is None:
            end = end.replace(tzinfo=UTC)
    return end <= start


def _legacy_request_to_spec(
    request: AvailsRequest,
    *,
    account_id: str,
    advertiser_brand_id: str,
    currency: str | None = None,
) -> ProductAvailsSearch:
    """Build the spec-shaped search for a legacy single-product query."""
    product_targeting: list[ProductTargeting] = []
    if request.requested_impressions is not None:
        product_targeting.append(
            ProductTargeting(
                name=TargetingDimension.INVESTMENT,
                type=TargetingUnit.AUDIENCE,
                datasource=EXTENSION_DATASOURCE,
                target=TARGET_REQUESTED_IMPRESSIONS,
                target_values=[str(request.requested_impressions)],
                selectable=False,
            )
        )
    if request.budget is not None:
        product_targeting.append(
            ProductTargeting(
                name=TargetingDimension.INVESTMENT,
                type=TargetingUnit.INVESTMENT,
                datasource=EXTENSION_DATASOURCE,
                target=TARGET_BUDGET,
                target_values=[str(request.budget)],
                selectable=False,
            )
        )

    targeting: list[dict[str, Any]] | None = None
    if request.targeting:
        targeting = []
        for name in sorted(request.targeting):
            values = request.targeting[name]
            if not isinstance(values, list):
                values = [values]
            targeting.extend({"name": name, "value": str(value)} for value in values)
        targeting = targeting or None

    return ProductAvailsSearch(
        product_ids=[request.product_id],
        account_id=account_id,
        advertiser_brand_id=advertiser_brand_id,
        currency=currency,
        start_date=request.start_date,
        end_date=request.end_date,
        product_targeting=product_targeting or None,
        targeting=targeting,
    )


def parse_avails_request(
    payload: dict[str, Any],
) -> AvailsRequest | ProductAvailsSearch:
    """Parse either request dialect (interop rule 1).

    ``productids`` (spec array form) wins over ``productid`` (legacy
    scalar form) when both are present.
    """
    if "productids" in payload:
        return ProductAvailsSearch.model_validate(payload)
    return AvailsRequest.model_validate(payload)


def parse_avails_response(
    payload: dict[str, Any],
) -> AvailsResponse | AvailsCollection:
    """Parse either response dialect: spec envelope or legacy object."""
    if "avails" in payload:
        return AvailsCollection.model_validate(payload)
    return AvailsResponse.model_validate(payload)


def avails_from_simplified(
    response: AvailsResponse,
    *,
    account_id: str,
    start_date: datetime,
    end_date: datetime,
    currency: str | None = None,
    requested_impressions: int | None = None,
    datasource: str = EXTENSION_DATASOURCE,
) -> Avails:
    """Derive the spec ``Avails`` record from a legacy simplified response.

    Field mapping: ``price`` <- ``estimatedCpm`` (the CPM the availability
    is priced at), ``availability`` <- ``availableImpressions``, and the
    dates/account echo the request per the spec tables. ``availsstatus``
    encodes the honest-availability outcome (interop rule 3):

    - Available — the full requested volume (or the reported volume when
      no volume was requested) is available.
    - Partially Available, reason ``Booked`` — capacity caps availability
      below the requested volume.
    - Unavailable, reason ``Booked`` — nothing is available.

    The spec-required ``producttargeting`` array describes the available
    inventory as an Inventory/Audience impressions entry.
    """
    available = response.available_impressions
    if available <= 0:
        status = AvailsStatusValue.UNAVAILABLE
        reason: AvailsStatusReason | None = AvailsStatusReason.BOOKED
    elif requested_impressions is not None and available < requested_impressions:
        status = AvailsStatusValue.PARTIALLY_AVAILABLE
        reason = AvailsStatusReason.BOOKED
    else:
        status = AvailsStatusValue.AVAILABLE
        reason = None

    avails_status = AvailsStatus(
        status=status,
        reason=reason,
        product_targeting=[
            ProductTargeting(
                name=TargetingDimension.INVENTORY,
                type=TargetingUnit.AUDIENCE,
                datasource=datasource,
                target=TARGET_IMPRESSIONS,
                target_values=[str(available)],
                selectable=False,
                count=available,
            )
        ],
    )
    return Avails(
        product_id=response.product_id,
        account_id=account_id,
        availability=available,
        avails_status=avails_status,
        currency=currency,
        price=response.estimated_cpm,
        start_date=start_date,
        end_date=end_date,
    )


__all__ = [
    "Avails",
    "AvailsCollection",
    "AvailsRequest",
    "AvailsResponse",
    "AvailsStatus",
    "AvailsStatusReason",
    "AvailsStatusValue",
    "AvailsWireModel",
    "EXTENSION_DATASOURCE",
    "ProductAvailsSearch",
    "ProductTargeting",
    "TARGET_BUDGET",
    "TARGET_IMPRESSIONS",
    "TARGET_REQUESTED_IMPRESSIONS",
    "TargetingDimension",
    "TargetingUnit",
    "avails_from_simplified",
    "parse_avails_request",
    "parse_avails_response",
]
