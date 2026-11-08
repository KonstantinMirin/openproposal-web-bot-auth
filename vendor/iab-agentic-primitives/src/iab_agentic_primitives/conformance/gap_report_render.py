"""Render ``gap_report.json`` as the human-facing STANDARDS_GAP_REPORT.md.

EP-6.2 deliverable. The conformance runner (EP-6.1) emits a machine-readable
``gap_report.json``; this module turns that same data into a durable,
honest, Markdown gap report — the "where are we missing an IAB
(Interactive Advertising Bureau) standard?" document the owner asked for.

Design contract (matches the kit's UNVERIFIED policy):

- The report is a pure function of ``gap_report.json`` plus a static
  remediation table below. No external-spec details are invented: where the
  kit cannot verify against a published external spec, the report says so and
  cites exactly what a future bead must obtain.
- The rendered Markdown is DETERMINISTIC — it deliberately omits the volatile
  ``generated_at`` timestamp so a drift-guard test can assert the checked-in
  file byte-matches a fresh render.

Per-standard status is derived, not stored:

- ``CONFORMANT`` — an ``implemented`` registry entry whose mapped checks ran
  with at least one pass and zero failures.
- ``PARTIAL`` — an ``implemented`` entry with a failing mapped check, or whose
  mapped checks never actually executed (all skipped / absent).
- ``UNVERIFIED`` — a registry entry that references an external published
  standard with no fidelity check against that publication yet.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

#: The single highest-priority gap, called out in the executive summary.
#: Field-level fidelity for the core commercial booking surface (Orders /
#: Lines / Products) is the most consequential unverified claim.
HIGHEST_PRIORITY_GAP_ID = "opendirect-2.1"

#: Concrete "to close this gap" remediation notes, keyed by standard id.
#: These describe the WORK required, never fabricated spec contents.
REMEDIATION: dict[str, str] = {
    "opendirect-2.1": (
        "Obtain the published IAB OpenDirect 2.1 field specification "
        "(Order / Line / Product JSON schemas and canonical example payloads) "
        "and add field-level golden vectors derived from those examples; "
        "assert our reconciled Order/Line/Product shapes and the "
        "OpenDirect-cased LineStatus vocabulary round-trip against them."
    ),
    "iab-deals-api-1.0": (
        "Obtain the published IAB Deals API v1.0 schemas and example payloads "
        "and add vectors derived from them; assert our reconciled quote->book "
        "envelopes validate against the published request/response shapes."
    ),
    "aamp": (
        "Obtain the IAB Tech Lab AAMP (agent discovery and trust registry) "
        "specification and add vectors that validate agent-card and "
        "trust-verification payloads against its published schema and "
        "trust_status vocabulary, rather than against our own reconciled shape."
    ),
    "a2a-jsonrpc": (
        "Run the published A2A (Agent-to-Agent) / JSON-RPC 2.0 conformance "
        "suite, or derive vectors from its message/send examples, and assert "
        "our envelope subset (camelCase aliases, -32601 for retired methods) "
        "conforms to the publication rather than to this contract alone."
    ),
    "adcom-openrtb-supply-chain": (
        "Model the SupplyChain (schain) object per AdCOM (Advertising Common "
        "Object Model) / OpenRTB (Open Real-Time Bidding) and add vectors that "
        "validate schain nodes, the `complete` flag, and AdCOM enum integers "
        "against the published specifications."
    ),
    "sellers-json-ads-txt": (
        "Model sellers.json and ads.txt records and add parser/validation "
        "checks against the published IAB Tech Lab formats (record grammar, "
        "seller_id/domain relationships, and the DIRECT/RESELLER distinction)."
    ),
    "gpp": (
        "Integrate a GPP (Global Privacy Platform) string decoder and add "
        "vectors that decode gpp_string / gpp_section_ids and validate section "
        "structure against the GPP specification, replacing the FD-10 "
        "(flagged decision) opaque placeholder."
    ),
    "tcf": (
        "Integrate a TCF (Transparency & Consent Framework) TC-string decoder "
        "and add vectors that decode tcf_string and validate it against a "
        "pinned GVL (Global Vendor List), replacing the FD-10 opaque "
        "placeholder."
    ),
}


def _base_kind(check_name: str) -> str:
    """Strip a parametrized suffix: ``expected_invalid(money-float)`` -> ``expected_invalid``."""
    return check_name.split("(", 1)[0]


def _counts_by_kind(report: dict[str, Any]) -> dict[str, Counter[str]]:
    """Aggregate executed check statuses per base check kind."""
    counts: dict[str, Counter[str]] = {}
    for record in report.get("checks", []):
        counts.setdefault(record["check"], Counter())[record["status"]] += 1
    return counts


def _standard_status(entry: dict[str, Any], counts: dict[str, Counter[str]]) -> str:
    """Derive CONFORMANT / PARTIAL / UNVERIFIED for one registry entry."""
    if entry["status"] == "unverified":
        return "UNVERIFIED"
    total: Counter[str] = Counter()
    for mapped in entry.get("checks", []):
        total.update(counts.get(_base_kind(mapped), Counter()))
    if total["fail"]:
        return "PARTIAL"
    if total["pass"]:
        return "CONFORMANT"
    return "PARTIAL"  # mapped checks never executed — cannot claim conformance


def _checks_detail(entry: dict[str, Any], counts: dict[str, Counter[str]]) -> str:
    """Human summary of which mapped checks passed (with skip/fail annotations)."""
    parts: list[str] = []
    for mapped in entry.get("checks", []):
        c = counts.get(_base_kind(mapped), Counter())
        bits = [f"{c[s]} {s}" for s in ("pass", "fail", "skip") if c[s]]
        summary = ", ".join(bits) if bits else "not executed"
        parts.append(f"`{mapped}` ({summary})")
    return "; ".join(parts) if parts else "—"


def render_markdown(report: dict[str, Any]) -> str:
    """Render ``gap_report.json`` (as a parsed dict) into the Markdown report."""
    counts = _counts_by_kind(report)
    summary = report.get("summary", {})
    standards = report.get("standards", [])
    version = report.get("library_version", "unknown")

    statuses = {s["id"]: _standard_status(s, counts) for s in standards}
    conformant = [s for s in standards if statuses[s["id"]] == "CONFORMANT"]
    partial = [s for s in standards if statuses[s["id"]] == "PARTIAL"]
    unverified = [s for s in standards if statuses[s["id"]] == "UNVERIFIED"]

    lines: list[str] = []
    lines.append("# IAB Agentic Primitives — Standards Gap Report")
    lines.append("")
    lines.append(
        "> Generated from `gap_report.json` by "
        "`python -m iab_agentic_primitives.conformance --render-md "
        "STANDARDS_GAP_REPORT.md`. **Do not edit by hand** — a drift-guard "
        "test asserts this file matches a fresh render."
    )
    lines.append("")
    lines.append(
        "IAB = Interactive Advertising Bureau. This report answers a single "
        "question honestly: for each standard the shared contract claims "
        "alignment with, have we actually *verified* it, and if not, exactly "
        'what is missing and how to close the gap. "We model a field named '
        'after a standard" is never treated as "we verified conformance '
        'against the published standard".'
    )
    lines.append("")

    # ---- Executive summary --------------------------------------------------
    lines.append("## Executive summary")
    lines.append("")
    lines.append(f"- **{len(standards)} standards tracked** (library version `{version}`).")
    lines.append(
        f"- **{len(conformant)} fully self-conformant** — the contract's own "
        "guarantees (primitives, protocol, state, events, money, idempotency, "
        "forward-compat), verified by executed checks against our spec "
        "artifacts."
    )
    lines.append(
        f"- **{len(partial)} partial** — an implemented claim whose mapped "
        "checks failed or did not execute."
    )
    lines.append(
        f"- **{len(unverified)} unverified (pending external spec)** — claims "
        "that reference a published external standard with no fidelity check "
        "against that publication yet."
    )
    lines.append("")
    lines.append(
        "Conformance run: **{checks} checks**, {passed} passed, {failed} "
        "failed, {skipped} skipped across {vectors} vectors / {targets} "
        "targets. Self-conformance verdict: **{verdict}**.".format(
            verdict="CONFORMANT" if summary.get("conformant") else "NOT CONFORMANT",
            checks=summary.get("checks", 0),
            passed=summary.get("passed", 0),
            failed=summary.get("failed", 0),
            skipped=summary.get("skipped", 0),
            vectors=summary.get("vectors", 0),
            targets=summary.get("targets", 0),
        )
    )
    lines.append("")
    top = next((s for s in standards if s["id"] == HIGHEST_PRIORITY_GAP_ID), None)
    if top is not None:
        lines.append(
            f"**Highest-priority gap: {top['name']} {top.get('version', '')}".strip()
            + "** — field-level fidelity for the core commercial booking "
            "surface (Orders / Lines / Products) is the most consequential "
            "unverified claim. " + REMEDIATION.get(top["id"], "")
        )
        lines.append("")

    # ---- Self vs external framing ------------------------------------------
    lines.append("## What is verified vs. what is not")
    lines.append("")
    lines.append(
        "Our **self-conformance is strong**: every wire primitive, protocol "
        "message, state machine, and event round-trips through the shared "
        "models; FD-11 (flagged decision) integer-micros money rejects "
        "float-typed money on the wire; FD-13 must-ignore forward-compat is "
        "executable; and the canonical Deal / Order / ChangeRequest lifecycle "
        "machines replay identically through their Python and JSON exports."
    )
    lines.append("")
    lines.append(
        "What is **not** verified is external-spec *fidelity*. The contract "
        "borrows names and shapes from published IAB and IAB Tech Lab "
        "standards, but this kit does not yet validate our payloads against "
        "those publications' own schemas and examples. Those claims are listed "
        "below as UNVERIFIED, each with a concrete note on how to close it. No "
        "external-spec detail is fabricated into a vector."
    )
    lines.append("")

    # ---- Per-standard detail ------------------------------------------------
    lines.append("## Standards")
    lines.append("")

    def emit(entry: dict[str, Any]) -> None:
        status = statuses[entry["id"]]
        title = f"{entry['name']} {entry.get('version', '')}".strip()
        lines.append(f"#### {title}")
        lines.append("")
        lines.append(f"- **Status:** {status}")
        lines.append(f"- **Registry id:** `{entry['id']}`")
        if status in ("CONFORMANT", "PARTIAL"):
            lines.append(f"- **Checks:** {_checks_detail(entry, counts)}")
        if entry.get("missing"):
            lines.append(f"- **Unverified / missing:** {entry['missing']}")
        if status == "UNVERIFIED":
            note = REMEDIATION.get(
                entry["id"],
                "Obtain the published specification and add fidelity vectors "
                "derived from its schemas/examples.",
            )
            lines.append(f"- **To close this gap:** {note}")
        lines.append("")

    lines.append("### Self-conformant (verified against our spec artifacts)")
    lines.append("")
    for entry in conformant:
        emit(entry)
    if partial:
        lines.append("### Partial")
        lines.append("")
        for entry in partial:
            emit(entry)
    lines.append("### Unverified — pending external published spec")
    lines.append("")
    for entry in unverified:
        emit(entry)

    return "\n".join(lines).rstrip() + "\n"


__all__ = [
    "HIGHEST_PRIORITY_GAP_ID",
    "REMEDIATION",
    "render_markdown",
]
