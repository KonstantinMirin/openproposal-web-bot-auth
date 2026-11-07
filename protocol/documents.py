"""Reading OpenProposal documents carried as YAML, as § 4.1.1 requires.

§ 4.1.1: "A document carried as YAML is a single YAML document, converted to
JSON under the YAML 1.2 core schema: aliases expand, and `<<` is an ordinary
key. A non-string mapping key, `.inf`, `.nan`, a recursive alias, an explicit
tag, or a second document in the stream has no JSON form and makes the document
invalid for this section, and so do duplicate object keys in its JSON form."

PyYAML parses; this module only replaces its YAML 1.1 type resolution with the
core schema's (null, bool, int, float, str; no timestamps, merges, `1_000`, or
`0b11`) and refuses what has no JSON form. Each test reads the whole document,
before any path is removed.
"""

from __future__ import annotations

import re
from decimal import Decimal
from pathlib import Path

import yaml

from .values import JsonObject

#: The YAML 1.2 core schema's implicit tags (YAML 1.2.2 § 10.3.2).
_CORE = (
    ("tag:yaml.org,2002:null", r"^(?:null|Null|NULL|~|)$", ["n", "N", "~", ""]),
    ("tag:yaml.org,2002:bool", r"^(?:true|True|TRUE|false|False|FALSE)$", list("tTfF")),
    ("tag:yaml.org,2002:int", r"^(?:[-+]?[0-9]+|0o[0-7]+|0x[0-9a-fA-F]+)$", list("-+0123456789")),
    (
        "tag:yaml.org,2002:float",
        (
            r"^(?:[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?"
            r"|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$"
        ),
        list("-+0123456789."),
    ),
)
#: The largest integer RFC 8785 serializes exactly (an IEEE 754 double).
_EXACT = 2**53


class InvalidDocument(ValueError):
    """The document has no JSON form under § 4.1.1."""

    @classmethod
    def at(cls, mark: yaml.Mark, subject: str, reason: str) -> InvalidDocument:
        """`subject`, at the line `mark` points to, fails for `reason`."""
        return cls(f"{subject} at line {mark.line + 1} {reason}")

    @classmethod
    def recursive_alias(cls) -> InvalidDocument:
        return cls("a recursive alias has no JSON form")

    @classmethod
    def not_a_mapping(cls, document: object) -> InvalidDocument:
        return cls(f"the document is a {type(document).__name__}, not a mapping")


class CoreSchemaLoader(yaml.SafeLoader):
    pass


CoreSchemaLoader.yaml_implicit_resolvers = {}
for _tag, _pattern, _first in _CORE:
    CoreSchemaLoader.add_implicit_resolver(_tag, re.compile(_pattern), _first)


def _int(_loader: CoreSchemaLoader, node: yaml.ScalarNode) -> int:
    text = node.value
    value = int(text, 0) if text[:2] in ("0o", "0x") else int(text, 10)
    if abs(value) > _EXACT:
        raise InvalidDocument.at(node.start_mark, text, "does not survive RFC 8785")
    return value


def _float(_loader: CoreSchemaLoader, node: yaml.ScalarNode) -> float:
    if node.value.lstrip("+-").lower() in (".inf", ".nan"):
        raise InvalidDocument.at(node.start_mark, node.value, "has no JSON form")
    value = float(node.value)
    # § 4.1.1: a Number the serialization does not reproduce makes the document invalid.
    if Decimal(node.value) != Decimal(repr(value)):
        raise InvalidDocument.at(node.start_mark, node.value, "does not survive RFC 8785")
    return value


def _mapping(loader: CoreSchemaLoader, node: yaml.MappingNode) -> dict[str, object]:
    out: dict[str, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if not isinstance(key, str):
            raise InvalidDocument.at(key_node.start_mark, f"key {key!r}", "is not a string")
        if key in out:
            raise InvalidDocument.at(key_node.start_mark, f"key {key!r}", "is a duplicate")
        out[key] = loader.construct_object(value_node, deep=True)
    return out


CoreSchemaLoader.add_constructor("tag:yaml.org,2002:int", _int)
CoreSchemaLoader.add_constructor("tag:yaml.org,2002:float", _float)
CoreSchemaLoader.add_constructor("tag:yaml.org,2002:map", _mapping)


def _acyclic(value: object, path: tuple[int, ...] = ()) -> None:
    if isinstance(value, dict | list):
        if id(value) in path:
            raise InvalidDocument.recursive_alias()
        for child in value.values() if isinstance(value, dict) else value:
            _acyclic(child, (*path, id(value)))


def _load(text: str) -> object:
    """The one document `text` holds, after refusing explicit tags."""
    for event in yaml.parse(text, Loader=CoreSchemaLoader):
        tag = getattr(event, "tag", None)
        if tag is not None:
            raise InvalidDocument.at(event.start_mark, f"explicit tag {tag}", "has no JSON form")
    # Refuses a second document. Not unsafe: CoreSchemaLoader subclasses yaml.SafeLoader.
    return yaml.load(text, Loader=CoreSchemaLoader)  # noqa: S506


def loads_yaml(text: str) -> JsonObject:
    """One YAML document that is a mapping, as JSON values.

    Raises `InvalidDocument` when the text isn't YAML, when the document has no
    JSON form, and when it isn't a mapping.
    """
    try:
        document = _load(text)
    except yaml.YAMLError as e:
        raise InvalidDocument(str(e)) from e
    _acyclic(document)
    if not isinstance(document, dict):
        raise InvalidDocument.not_a_mapping(document)
    return document


def load_yaml(path: str | Path) -> JsonObject:
    return loads_yaml(Path(path).read_text(encoding="utf-8"))
