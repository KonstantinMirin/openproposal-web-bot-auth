"""A party's own identity: the origin it answers as, and the legal name it trades under.

An agent takes its own party from its settings, never from its records, so a
deployment under another origin issues and checks proposals in that origin's
name.
"""

from __future__ import annotations

from persistence.values import Origin
from protocol.values import Value


class OwnParty(Value):
    """This agent's own identity, as its settings configure it."""

    origin: Origin
    legal_name: str
