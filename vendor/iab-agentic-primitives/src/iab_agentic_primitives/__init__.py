"""iab-agentic-primitives: shared contract library for IAB agentic advertising.

This package is the single source of truth for every cross-agent primitive,
wire message, state machine, and event type shared by the IAB Tech Lab
buyer-agent and seller-agent. The normative artifact is the language-neutral
spec under ``spec/`` (OpenAPI + JSON-Schema + golden fixtures); this Python
package is its reference implementation, verified against the spec fixtures
in continuous integration like any other implementation.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("iab-agentic-primitives")
except PackageNotFoundError:  # pragma: no cover - package not installed (raw checkout)
    __version__ = "0.0.0+unknown"
