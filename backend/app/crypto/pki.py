"""Air-gapped offline Certificate Authority issuing ML-DSA-signed recipient certificates.

Certificates are canonical-JSON documents binding a recipient identity to the
public keys of their token. (OpenSSL >= 3.5 / EJBCA can emit the equivalent
X.509 certificates with ML-DSA OIDs in production.)
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from . import keystore, pqc
from .symmetric import canonical, sha3

CA_LABEL = "offline-root-ca"
CA_NAME = "CN=SIH Offline Root CA (ML-DSA-65),O=Air-Gapped PKI"


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def ca_certificate() -> dict:
    s = keystore.system_session(CA_LABEL)
    pub = keystore.public_keys(CA_LABEL)
    body = {"subject": CA_NAME, "issuer": CA_NAME, "serial": "00",
            "sig_alg": pub["sig_alg"], "sig_pk": pub["sig_pk"], "is_ca": True}
    return {"body": body, "fingerprint": sha3(canonical(body)), "signature": keystore.b64e(s.sign(canonical(body)))}


def issue(subject: dict, token_label: str, days: int = 365) -> dict:
    pub = keystore.public_keys(token_label)
    now = _now()
    body = {
        "serial": os.urandom(8).hex(),
        "issuer": CA_NAME,
        "subject": subject,
        "token": token_label,
        "kem_alg": pub["kem_alg"], "kem_pk": pub["kem_pk"],
        "sig_alg": pub["sig_alg"], "sig_pk": pub["sig_pk"],
        "not_before": now.isoformat(),
        "not_after": (now + timedelta(days=days)).isoformat(),
        "key_usage": ["keyEncipherment(ML-KEM)", "digitalSignature(ML-DSA)"],
    }
    sig = keystore.system_session(CA_LABEL).sign(canonical(body))
    return {"body": body, "fingerprint": sha3(canonical(body)), "signature": keystore.b64e(sig)}


def verify(cert: dict, at: str | None = None) -> dict:
    """Verify a certificate against the offline root, valid at time `at` (ISO-8601 UTC, default now)."""
    ca_pk = keystore.b64d(keystore.public_keys(CA_LABEL)["sig_pk"])
    sig_ok = pqc.verify(ca_pk, canonical(cert["body"]), keystore.b64d(cert["signature"]))
    try:
        when = datetime.fromisoformat(at) if at else _now()
        in_validity = (datetime.fromisoformat(cert["body"]["not_before"]) <= when
                       <= datetime.fromisoformat(cert["body"]["not_after"]))
    except (TypeError, ValueError):
        in_validity = False
    return {"signature_valid": sig_ok, "within_validity": in_validity,
            "issuer": cert["body"]["issuer"], "serial": cert["body"]["serial"],
            "valid": sig_ok and in_validity}
