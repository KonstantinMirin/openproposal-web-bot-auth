"""Directory evidence is kept per fetch: rows merge only when bytes and signatures are identical."""

import sqlite3

from iab_agentic_primitives.web_bot_auth import VerifiedDirectory

from shared.evidence import DIRECTORIES_SCHEMA, save_directory

BODY = b'{"keys": []}'
URL = "https://buyer.wba-demo.noetis.dev/.well-known/http-message-signatures-directory"


def _fetch(signature: str, fetched_at: float, body: bytes = BODY) -> VerifiedDirectory:
    headers = (
        ("content-type", "application/http-message-signatures-directory+json"),
        ("signature", signature),
    )
    return VerifiedDirectory(
        {}, 0, url=URL, status=200, headers=headers, body=body, fetched_at=fetched_at
    )


def _rows(*fetches: VerifiedDirectory) -> int:
    db = sqlite3.connect(":memory:")
    db.executescript(DIRECTORIES_SCHEMA)
    for fetch in fetches:
        save_directory(db, fetch)
    return db.execute("SELECT COUNT(*) FROM directories").fetchone()[0]


def test_same_body_fetched_again_is_a_new_row():
    assert _rows(_fetch("key1=:AAAA:", 1000.0), _fetch("key1=:AAAA:", 8000.0)) == 2


def test_same_body_with_other_signatures_is_a_new_row():
    assert _rows(_fetch("key1=:AAAA:", 1000.0), _fetch("key1=:BBBB:", 1000.0)) == 2


def test_one_fetch_verified_twice_is_one_row():
    fetch = _fetch("key1=:AAAA:", 1000.0)
    assert _rows(fetch, _fetch("key1=:AAAA:", 1000.0)) == 1


def test_the_exact_body_bytes_are_kept():
    db = sqlite3.connect(":memory:")
    db.executescript(DIRECTORIES_SCHEMA)
    body = b'{"keys":[]}\n'  # bytes, not a re-serialization
    digest = save_directory(db, _fetch("key1=:AAAA:", 1.0, body))
    assert (
        db.execute("SELECT body FROM directories WHERE digest = ?", (digest,)).fetchone()[0] == body
    )
