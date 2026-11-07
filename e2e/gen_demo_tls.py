#!/usr/bin/env python3
"""Mint the e2e stack's throwaway TLS material and demo secrets into e2e/generated/.

- `ca.pem`: a demo CA, valid for 30 days. Its key is discarded once the leaf is signed.
- `front.pem` and `front.key`: one leaf for `*.wba-demo.noetis.dev` and
  `wba-demo.noetis.dev`, which the TLS front serves (and the Caddy front of
  deploy/localhost/).
- `bundle.pem`: the public roots (certifi) followed by the demo CA. Every
  container points `SSL_CERT_FILE` at it, because that variable replaces the
  default trust file instead of adding to it.
- `demo.env`: the bearer token the seller issues the bearer buyer, and the
  operator key every agent's own controls require, both random per run.

Nothing here is a real secret, and e2e/generated/ is gitignored.
"""

from __future__ import annotations

import datetime as dt
import secrets
from pathlib import Path

import certifi
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OUT = Path(__file__).resolve().parent / "generated"
WILDCARD = "*.wba-demo.noetis.dev"
APEX = "wba-demo.noetis.dev"


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def main() -> None:
    OUT.mkdir(exist_ok=True)
    now = dt.datetime.now(dt.UTC) - dt.timedelta(hours=1)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (
        x509.CertificateBuilder()
        .subject_name(_name("wba-demo throwaway CA"))
        .issuer_name(_name("wba-demo throwaway CA"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                     content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(_name(WILDCARD))
        .issuer_name(ca.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(WILDCARD), x509.DNSName(APEX)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                       critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    pem = serialization.Encoding.PEM
    ca_pem = ca.public_bytes(pem)
    (OUT / "ca.pem").write_bytes(ca_pem)
    (OUT / "front.pem").write_bytes(leaf.public_bytes(pem) + ca_pem)
    (OUT / "front.key").write_bytes(leaf_key.private_bytes(
        pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (OUT / "bundle.pem").write_bytes(Path(certifi.where()).read_bytes() + b"\n" + ca_pem)
    (OUT / "demo.env").write_text(f"DEMO_BEARER_TOKEN={secrets.token_urlsafe(32)}\n"
                                  f"OPERATOR_KEY={secrets.token_urlsafe(32)}\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
