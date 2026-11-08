"""Builders for the normative JSON (JavaScript Object Notation) Schema artifacts.

The checked-in files under ``spec/jsonschema/events/`` are generated from
these builders by ``spec/jsonschema/events/generate.py``; a test asserts the
checked-in artifacts match the models, so schema and implementation cannot
drift silently.
"""

from typing import Any

from .models import Event, EventType

SPEC_BASE_URI = "https://github.com/atc964/iab-agentic-primitives/spec/jsonschema/events"


def build_event_schema() -> dict[str, Any]:
    """Return the JSON Schema for the canonical :class:`Event` envelope."""
    schema = Event.model_json_schema()
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"{SPEC_BASE_URI}/event.schema.json",
        **schema,
    }


def build_event_type_values() -> dict[str, Any]:
    """Return the canonical :class:`EventType` value list as a JSON document."""
    return {
        "$id": f"{SPEC_BASE_URI}/event_type.values.json",
        "title": "EventType",
        "description": (
            "Canonical dot-namespaced event-type values shared by the buyer "
            "and seller agents. See EVENTS_RECONCILIATION.md for the mapping "
            "from the legacy per-repo vocabularies."
        ),
        "values": [member.value for member in EventType],
    }
