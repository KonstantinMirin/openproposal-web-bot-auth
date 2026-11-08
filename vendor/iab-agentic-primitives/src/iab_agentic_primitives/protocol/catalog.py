"""Canonical catalog surface: list and detail over ``GET /products``.

Two endpoints, both read-only:

- ``GET /products`` — paginated list; response is
  :class:`ProductListResponse`. Query parameters are the fields of
  :class:`ProductListRequest`.
- ``GET /products/{product_id}`` — detail; response is the
  :class:`~iab_agentic_primitives.primitives.Product` primitive itself
  (no wrapper).

There is explicitly NO ``POST /products/search`` (remediation plan §7
amendment 3). The buyer's OpenDirect-style client posted search filters to
``/products/search`` (buyer ``clients/opendirect_client.py:100``); the
seller never served that route, so every call 405'd. Canonical decision:
the seller returns the full filterable product record in the list
response, and the buyer filters CLIENT-SIDE on the returned fields —
``ad_formats``, ``delivery_type``, ``pricing_model``, ``pricing_type``,
``base_price``, ``available_impressions``, and the three IAB (Interactive
Advertising Bureau) taxonomy targeting blocks. Rich free-text discovery
remains the media-kit search surface, not the catalog.

OpenDirect = the IAB direct-buying API standard.
"""

from pydantic import Field

from ..primitives import Product, WireModel


class ProductListRequest(WireModel):
    """Query parameters for ``GET /products`` (pagination only).

    Deliberately carries no filter fields: filtering is client-side over
    the returned :class:`~iab_agentic_primitives.primitives.Product`
    records (see module docstring). This replaces both the seller's
    unpaginated ``GET /products`` and the buyer's OpenDirect
    ``$skip``/``$top`` query convention.
    """

    limit: int = Field(default=50, ge=1, le=500, description="Maximum products to return.")
    offset: int = Field(default=0, ge=0, description="Zero-based index of the first product.")


class ProductListResponse(WireModel):
    """Response envelope for ``GET /products``."""

    products: list[Product] = Field(default_factory=list)
    total_count: int = Field(
        ge=0, description="Total products in the catalog, ignoring pagination."
    )
    limit: int = Field(ge=1, description="Echo of the applied limit.")
    offset: int = Field(ge=0, description="Echo of the applied offset.")


__all__ = ["ProductListRequest", "ProductListResponse"]
