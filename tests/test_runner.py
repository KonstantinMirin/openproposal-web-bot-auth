"""The live runner publishes public data only, and keeps a short history."""

import json

import pytest

from runner.live import (
    HISTORY,
    Config,
    NotPublic,
    assert_public,
    public_headers,
    publish,
    updated_history,
)


def test_public_headers_withhold_credentials_and_proxy_fields():
    shown = public_headers([
        ("Signature-Input", 'sig1=("@method");tag="web-bot-auth"'),
        ("Authorization", "Bearer secret-token-value"),
        ("X-Operator-Key", "operator-secret"),
        ("X-Forwarded-For", "203.0.113.7"),
        ("Content-Digest", "sha-256=:abc=:"),
    ])
    assert shown["lines"] == [["signature-input", 'sig1=("@method");tag="web-bot-auth"'],
                              ["content-digest", "sha-256=:abc=:"]]
    assert shown["withheld"] == ["authorization", "x-forwarded-for", "x-operator-key"]


def test_a_report_with_a_secret_is_refused():
    with pytest.raises(NotPublic):
        assert_public({"note": "token is secret-token-value"}, ["secret-token-value"])


def test_a_report_with_a_private_jwk_is_refused():
    with pytest.raises(NotPublic):
        assert_public({"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "pub", "d": "priv"}]}, [])
    assert_public({"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "pub"}]}, [])


def test_history_keeps_the_newest_runs():
    runs = []
    for n in range(HISTORY + 5):
        runs = updated_history(runs, {"started_at": f"run-{n}", "ok": n % 2 == 0,
                                      "steps": [{"id": "x", "ok": n % 2 == 0}]})
    assert len(runs) == HISTORY
    assert runs[0]["started_at"] == f"run-{HISTORY + 4}"
    assert runs[0]["failed"] == []
    assert runs[1]["failed"] == ["x"]


def test_publish_writes_a_bare_failure_instead_of_a_secret(tmp_path):
    config = Config({"OUT_DIR": str(tmp_path), "OPERATOR_KEY": "operator-secret-value"})
    publish(config, {"started_at": "2026-11-07T00:00:00Z", "ok": True, "steps": [],
                     "leak": "operator-secret-value"})
    latest = (tmp_path / "latest-run.json").read_text()
    assert "operator-secret-value" not in latest
    assert json.loads(latest)["ok"] is False
    assert json.loads((tmp_path / "history.json").read_text())["runs"][0]["ok"] is False
