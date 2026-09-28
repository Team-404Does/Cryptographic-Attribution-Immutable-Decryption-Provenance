"""Software HSM simulating a PKCS#11 token.

Each token holds an ML-KEM decapsulation key and an ML-DSA signing key,
encrypted at rest under a key derived from the user PIN (scrypt). Callers
never receive private key material: they log in to obtain a session and ask
the session to *decapsulate* or *sign*, exactly like C_Decrypt / C_Sign on a
real token (YubiKey, smart card, TPM or HSM in production).
"""
from __future__ import annotations

import base64
import json
import os
import re
import threading
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .. import config
from . import pqc
from .symmetric import aes_decrypt, aes_encrypt, hkdf

_lock = threading.Lock()
b64e = lambda b: base64.b64encode(b).decode()  # noqa: E731
b64d = base64.b64decode


class TokenError(Exception):
    pass


class TokenLocked(TokenError):
    pass


def _path(label: str):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", label):
        raise TokenError("invalid token label")
    return config.TOKENS_DIR / f"{label}.token.json"


def _pin_key(pin: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(pin.encode())


def system_pin(label: str) -> str:
    """PIN for service tokens (CA, ledger nodes, forensics), derived from the installation secret."""
    return hkdf(config.master_secret(), b"system-pin:" + label.encode()).hex()


def create_token(label: str, pin: str) -> dict:
    """Generate key pairs *inside* the token and return only the public keys."""
    path = _path(label)
    if path.exists():
        raise TokenError(f"token {label} already exists")
    kem_pk, kem_sk = pqc.kem_keygen()
    sig_pk, sig_sk = pqc.sig_keygen()
    salt = os.urandom(16)
    k = _pin_key(pin, salt)
    blob = {
        "label": label,
        "kem_alg": pqc.KEM_ALG, "sig_alg": pqc.SIG_ALG,
        "kem_pk": b64e(kem_pk), "sig_pk": b64e(sig_pk),
        "salt": b64e(salt),
        "kem_sk": b64e(aes_encrypt(k, kem_sk, label.encode() + b"|kem")),
        "sig_sk": b64e(aes_encrypt(k, sig_sk, label.encode() + b"|sig")),
        "failed_attempts": 0,
    }
    config.ensure_dirs()
    path.write_text(json.dumps(blob, indent=1))
    path.chmod(0o600)
    return public_keys(label)


def _load(label: str) -> dict:
    path = _path(label)
    if not path.exists():
        raise TokenError(f"token {label} not found")
    return json.loads(path.read_text())


def public_keys(label: str) -> dict:
    t = _load(label)
    return {"label": label, "kem_alg": t["kem_alg"], "kem_pk": t["kem_pk"],
            "sig_alg": t["sig_alg"], "sig_pk": t["sig_pk"]}


def exists(label: str) -> bool:
    return _path(label).exists()


@dataclass
class Session:
    label: str
    _kem_sk: bytes
    _sig_sk: bytes

    def decapsulate(self, kem_ct: bytes) -> bytes:
        return pqc.kem_decaps(self._kem_sk, kem_ct)

    def sign(self, msg: bytes) -> bytes:
        return pqc.sign(self._sig_sk, msg)

    def __repr__(self) -> str:  # never leak key material into logs
        return f"<TokenSession {self.label}>"


def _lock_seconds(failures: int) -> int:
    """Temporary lockout with exponential back-off once MAX_PIN_ATTEMPTS is reached:
    5 min, 10 min, 20 min ... capped at 24 h. Temporary (not permanent) so an
    unauthenticated caller can delay but never brick a token; officers can unlock early."""
    over = failures - config.MAX_PIN_ATTEMPTS
    return 0 if over < 0 else min(300 * (2 ** over), 86400)


def _save(label: str, t: dict) -> None:
    _path(label).write_text(json.dumps(t, indent=1))


def login(label: str, pin: str) -> Session:
    # Reserve the attempt (count it as failed) *before* the expensive scrypt, outside the lock:
    # concurrent guesses cannot exceed the limit and cannot stall other tokens.
    with _lock:
        t = _load(label)
        until = t.get("locked_until", 0)
        if until > time.time():
            mins = max(1, round((until - time.time()) / 60))
            raise TokenLocked(f"token {label} is locked for {mins} more minute(s) after repeated wrong PINs")
        t["failed_attempts"] += 1
        _save(label, t)
    k = _pin_key(pin, b64d(t["salt"]))
    try:
        kem_sk = aes_decrypt(k, b64d(t["kem_sk"]), label.encode() + b"|kem")
        sig_sk = aes_decrypt(k, b64d(t["sig_sk"]), label.encode() + b"|sig")
    except Exception:
        with _lock:
            t = _load(label)
            secs = _lock_seconds(t["failed_attempts"])
            if secs:
                t["locked_until"] = time.time() + secs
                _save(label, t)
                raise TokenLocked(f"incorrect PIN - token locked for {secs // 60} minute(s)") from None
            left = config.MAX_PIN_ATTEMPTS - t["failed_attempts"]
        raise TokenError(f"incorrect PIN ({left} attempts left before lockout)") from None
    with _lock:
        t = _load(label)
        t["failed_attempts"], t["locked_until"] = 0, 0
        _save(label, t)
    return Session(label, kem_sk, sig_sk)


def reset_attempts(label: str) -> None:
    """Administrative unlock after a PIN lockout (requires a security officer upstream)."""
    with _lock:
        t = _load(label)
        t["failed_attempts"], t["locked_until"] = 0, 0
        _save(label, t)


def lock_state(label: str) -> dict:
    t = _load(label)
    until = t.get("locked_until", 0)
    return {"failed_attempts": t["failed_attempts"], "locked": until > time.time(),
            "locked_until": until if until > time.time() else None}


def failed_attempts(label: str) -> int:
    return _load(label)["failed_attempts"]


_system_sessions: dict[str, Session] = {}


def system_session(label: str) -> Session:
    """Log in to (creating on first use) a service token."""
    if label not in _system_sessions:
        if not exists(label):
            create_token(label, system_pin(label))
        _system_sessions[label] = login(label, system_pin(label))
    return _system_sessions[label]


def reset_sessions() -> None:
    _system_sessions.clear()
