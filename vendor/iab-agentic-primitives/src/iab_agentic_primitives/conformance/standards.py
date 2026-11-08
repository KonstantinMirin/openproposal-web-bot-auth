"""Registry of claimed standards -> what this kit ACTUALLY checks (EP-6.1 §5).

Honesty contract: every standard the shared library claims alignment with
appears here, mapped either to the concrete check kinds the runner
executes, or to an explicit ``unverified`` marker stating exactly what has
not been verified. The gap report always prints this registry, so there
are no silent coverage claims — "we model a field named after the
standard" is NOT the same as "we verified conformance against the
published standard", and this file keeps the two separate.

Statuses:

- ``implemented`` — the runner executes real checks for this claim today.
  These are the contract's own flagged decisions (FD = flagged decision),
  which ARE fully checkable from this repo's spec artifacts.
- ``unverified`` — the claim references an external published standard and
  NO fidelity check against that publication exists yet. The ``missing``
  field says what a future bead must add. External-spec details are never
  fabricated here.

Acronyms: IAB = Interactive Advertising Bureau; AAMP = the IAB Tech Lab
agent discovery and trust registry; A2A = Agent-to-Agent protocol;
AdCOM = Advertising Common Object Model; OpenRTB = Open Real-Time
Bidding; GPP = Global Privacy Platform; TCF = Transparency & Consent
Framework; JSON-RPC = JSON (JavaScript Object Notation) Remote Procedure
Call.
"""

from __future__ import annotations

from .report import StandardEntry

#: Check kinds the runner executes for the contract's own guarantees.
SELF_CONFORMANCE_CHECKS = ["validate", "roundtrip", "schema", "schema_sync"]
MONEY_CHECKS = ["expected_invalid(money-float)"]
FORWARD_COMPAT_CHECKS = ["must_ignore"]
STATE_CHECKS = ["state_sequence", "state_spec_sync"]

STANDARDS: tuple[StandardEntry, ...] = (
    # ------------------------------------------------------------------
    # Internal contract guarantees — implemented, executable today.
    # ------------------------------------------------------------------
    StandardEntry(
        id="contract-self-conformance",
        name="IAB agentic-primitives shared contract (this spec)",
        version="0.1",
        status="implemented",
        checks=SELF_CONFORMANCE_CHECKS,
    ),
    StandardEntry(
        id="fd11-money-integer-micros",
        name="FD-11 Money as integer micros (float rejected on the wire)",
        version="0.1",
        status="implemented",
        checks=MONEY_CHECKS,
    ),
    StandardEntry(
        id="fd13-forward-compat",
        name="FD-13 must-ignore unknown fields + x_ extension prefix",
        version="0.1",
        status="implemented",
        checks=FORWARD_COMPAT_CHECKS,
    ),
    StandardEntry(
        id="state-lifecycles",
        name="Canonical Deal/Order/ChangeRequest lifecycle machines (EP-1.4)",
        version="0.1",
        status="implemented",
        checks=STATE_CHECKS,
    ),
    # ------------------------------------------------------------------
    # External standards — claimed as influences by the contract, but NOT
    # verified against their publications. Explicitly UNVERIFIED.
    # ------------------------------------------------------------------
    StandardEntry(
        id="opendirect-2.1",
        name="IAB OpenDirect",
        version="2.1",
        status="unverified",
        missing=(
            "The avails surface now carries the published wire shapes "
            "transcribed from the OpenDirect 2.1 normative attribute "
            "tables (ProductAvailsSearch / Avails / AvailsStatus / "
            "ProductTargeting and the 'avails' collection envelope), with "
            "golden vectors, alongside the legacy simplified profile. "
            "Still missing: validation against a hash-pinned copy of the "
            "publication itself (the transcription is authored here), and "
            "any fidelity check for the remaining surfaces — the "
            "Order/Line/Product object tables, the required endpoint "
            "surface (URI Summary Table), and URI versioning."
        ),
    ),
    StandardEntry(
        id="iab-deals-api-1.0",
        name="IAB Deals API",
        version="1.0",
        status="unverified",
        missing=(
            "No vectors derived from the published Deals API v1.0 "
            "examples/schemas. Internal vectors cover our reconciled "
            "quote->book envelopes only."
        ),
    ),
    StandardEntry(
        id="aamp",
        name="IAB Tech Lab AAMP agent discovery and trust registry",
        version="",
        status="unverified",
        missing=(
            "No check against the AAMP registry specification. Agent card "
            "and trust-verification vectors cover the reconciled internal "
            "shape only; trust_status semantics are asserted by our own "
            "spec, not against AAMP publications."
        ),
    ),
    StandardEntry(
        id="a2a-jsonrpc",
        name="A2A protocol / JSON-RPC 2.0 envelope",
        version="",
        status="unverified",
        missing=(
            "No conformance run against the published A2A specification or "
            "test suite. Internal vectors cover the reconciled "
            "message/send envelope subset (camelCase aliases, -32601 for "
            "retired methods) as defined by this contract."
        ),
    ),
    StandardEntry(
        id="adcom-openrtb-supply-chain",
        name="AdCOM / OpenRTB supply chain",
        version="",
        status="unverified",
        missing=(
            "SupplyChain (schain) is now modeled (EP-10.3: SupplyChain / "
            "SupplyChainNode with OpenRTB asi/sid/hp/rid field names) and "
            "round-trip/schema checked, but NO fidelity check against the "
            "AdCOM/OpenRTB publications exists: complete/hp 0-1 semantics "
            "and node ordering are asserted by our own spec only."
        ),
    ),
    StandardEntry(
        id="sellers-json-ads-txt",
        name="sellers.json / ads.txt",
        version="",
        status="unverified",
        missing=(
            "A sellers.json entry is now modeled (EP-10.3: SellersJsonEntry "
            "with seller_type PUBLISHER/INTERMEDIARY/BOTH + is_confidential) "
            "and round-trip/schema checked, but no ads.txt/sellers.json file "
            "parsing or cross-file crawl/validation exists."
        ),
    ),
    StandardEntry(
        id="gpp",
        name="Global Privacy Platform (GPP)",
        version="",
        status="unverified",
        missing=(
            "gpp_string / gpp_section_ids are carried as opaque values on "
            "the EP-10.4 ConsentContext (alongside us_privacy); no GPP "
            "string decoding or section validation exists."
        ),
    ),
    StandardEntry(
        id="tcf",
        name="Transparency & Consent Framework (TCF)",
        version="",
        status="unverified",
        missing=(
            "tcf_string / gdpr_applies are carried opaque on the EP-10.4 "
            "ConsentContext; no TC string decoding or vendor-list checks "
            "exist."
        ),
    ),
)


def standards_entries() -> list[StandardEntry]:
    """The registry as a fresh list (safe for callers to extend/mutate)."""
    return [entry.model_copy(deep=True) for entry in STANDARDS]


__all__ = [
    "FORWARD_COMPAT_CHECKS",
    "MONEY_CHECKS",
    "SELF_CONFORMANCE_CHECKS",
    "STANDARDS",
    "STATE_CHECKS",
    "standards_entries",
]
