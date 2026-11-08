# iab-agentic-primitives

> ⚠️ **PRE-RELEASE.** This library is a versioned pre-release under active
> development as part of the buyer/seller agent remediation. Tagged releases
> are published on
> [GitHub](https://github.com/IABTechLab/iab-agentic-primitives/releases);
> pin an exact tag when depending on it. APIs, schemas, and package layout
> may still change between releases until a 1.0 IAB Tech Lab
> standardization.

Shared contract library for IAB Tech Lab agentic advertising: the single
source of truth for every cross-agent primitive, wire message, state
machine, and event type shared by the
[buyer-agent](https://github.com/IABTechLab/buyer-agent) and
[seller-agent](https://github.com/IABTechLab/seller-agent).

## Spec vs. implementation

**The spec is the normative artifact; this package is its reference
implementation.**

- **`spec/`** holds the language-neutral standard: OpenAPI documents,
  JSON-Schema definitions, and golden fixtures (conformance vectors).
  Third parties implementing the standard in any language conform to the
  *spec*, not to this package.
- **`src/iab_agentic_primitives/`** is the Python reference implementation
  of that spec, consumed by the two agent repos. It is verified against the
  spec fixtures in CI (continuous integration) like any other
  implementation.

The Web Bot Auth vectors are the one exception: they live in the package, in
`src/iab_agentic_primitives/web_bot_auth/vectors/`, beside the adapter
protocol they are graded with (`conformance/PROTOCOL.md`). The module is
self-contained so it can be lifted into another repository, and an installed
wheel carries everything its conformance CLI reads. Regenerate them with
`python -m iab_agentic_primitives.web_bot_auth.conformance --regenerate`, the
same flag as the package's own conformance CLI.

## Package layout

| Module | Role |
|---|---|
| `iab_agentic_primitives.primitives` | Wire primitives both agents exchange (Product, Quote, Deal, Order, Line, Proposal, Negotiation, MediaKit, ...) |
| `iab_agentic_primitives.protocol` | Protocol messages: Deals API v1.0, A2A JSON-RPC, OpenDirect 2.1, Agent Card |
| `iab_agentic_primitives.state` | Canonical lifecycle state machines (one state vocabulary per exchanged primitive) |
| `iab_agentic_primitives.events` | Shared event types crossing the buyer/seller boundary |
| `iab_agentic_primitives.conformance` | Schema validators, golden vectors, standards checklist |
| `iab_agentic_primitives.web_bot_auth` | The OpenProposal § 2.8 Web Bot Auth profile: signed requests and responses, the signed key directory, verification, conformance vectors, and an interop harness. Needs the `wba` extra; see [WEB_BOT_AUTH.md](WEB_BOT_AUTH.md) |

The subpackages are scaffolded but intentionally empty of domain models:
primitive and protocol definitions land in subsequent work items.

## Versioning policy

This library follows semantic versioning (semver):

- **A breaking schema change is a major version bump.** Any change that
  breaks a golden fixture or alters the wire shape of an exchanged
  primitive, protocol message, state enum, or event type is breaking.
- Both agent repos **pin a compatible version range** and upgrade
  deliberately; a breaking contract change is therefore an explicit,
  opt-in event on both sides rather than silent drift.
- A schema change that breaks a conformance vector fails CI in *both*
  repos on the next dependency bump.

## Development

Requires Python >= 3.11 and [uv](https://docs.astral.sh/uv/).

```bash
uv run pytest        # tests
uv run ruff check .  # lint
make quality         # Web Bot Auth gates
```

The only runtime dependency is `pydantic>=2`.

## Background

This repo implements EP-1 of the IAB buyer/seller agent remediation. Design
rationale, target architecture, and the full primitive placement map live in
the remediation plan: **IAB_Agents_Remediation_Plan_20260713** (see §2
design principles, §3.1 system context, and §7 amendments — in particular
amendment 1, which establishes the spec-is-normative rule this repo follows).
