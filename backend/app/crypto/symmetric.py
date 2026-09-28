"""Symmetric primitives: AES-256-GCM, HKDF-SHA3, SHA3/SHAKE hashing, canonical JSON."""
from __future__ import annotations

import hashlib
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

NONCE = 12


def aes_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Returns nonce || ciphertext || tag."""
    nonce = os.urandom(NONCE)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(blob[:NONCE], blob[NONCE:], aad)


def hkdf(ikm: bytes, info: bytes, length: int = 32, salt: bytes | None = None) -> bytes:
    return HKDF(algorithm=hashes.SHA3_256(), length=length, salt=salt, info=info).derive(ikm)


def sha3(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def shake(data: bytes, n: int = 32) -> bytes:
    return hashlib.shake_256(data).digest(n)


def canonical(obj) -> bytes:
    """Deterministic JSON encoding used for everything that gets hashed or signed."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
