"""The YAML loader applies the YAML 1.2 core schema and the § 4.1.1 validity rules."""

import pytest

from protocol.documents import InvalidDocument, loads_yaml


def test_core_schema_values() -> None:
    doc = loads_yaml(
        "b: &b {x: 1}\nm: {<<: *b, y: 2}\nt: 2026-11-10T00:00:00Z\nd: 2026-11-10\n"
        "u: 1_000\nbin: 0b11\nhex: 0x18\ne: 24.00\nno: no\nyes: True\nn: ~\n"
    )
    assert doc["m"] == {"<<": {"x": 1}, "y": 2}  # `<<` is an ordinary key
    assert doc["t"] == "2026-11-10T00:00:00Z" and doc["d"] == "2026-11-10"  # no timestamps
    assert doc["u"] == "1_000" and doc["bin"] == "0b11"  # not core-schema integers
    assert doc["hex"] == 24 and doc["e"] == 24.0  # § 4.1.1: 24.00, 24, and 0x18 are one value
    assert doc["no"] == "no" and doc["yes"] is True and doc["n"] is None


@pytest.mark.parametrize(
    "text",
    [
        "a: !!str 5\n",  # an explicit tag
        "availability: .inf\n",  # even under a path the binding record removes
        "a: .nan\n",
        "a: 1\na: 2\n",
        "1: a\n",
        "a: 1\n---\nb: 2\n",
        "a: &x [*x]\n",
        "a: 0.1000000000000000055511151231257827\n",  # RFC 8785 does not reproduce it
        "a: [",  # not YAML
        'a: "x',
        "3",  # YAML, but not a mapping
        "- a",
        "",
    ],
)
def test_documents_with_no_json_form_are_invalid(text: str) -> None:
    with pytest.raises(InvalidDocument):
        loads_yaml(text)
