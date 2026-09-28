"""Keyed watermark payload framing with Reed-Solomon error correction.

Frame layout before whitening (16 bytes = 128 bits):
    wm_id (6 bytes) | check (2 bytes, HMAC-SHA3 of wm_id under the embedding key) | RS parity (8 bytes)

The encoded bits are then XOR-whitened with a keystream derived from the
embedding key. Without the installation's embedding key nobody can produce a
frame that decodes - so knowing a watermark ID (e.g. from the ledger) is not
enough to forge a mark that frames its recipient. The RS code corrects up to
4 corrupted bytes; the keyed check rejects spurious and forged decodes.
"""
from __future__ import annotations

import hashlib
import hmac

import numpy as np
from reedsolo import ReedSolomonError, RSCodec

WM_ID_BYTES = 6
CHECK_BYTES = 2
RS_PARITY = 8
FRAME_BYTES = WM_ID_BYTES + CHECK_BYTES + RS_PARITY
FRAME_BITS = FRAME_BYTES * 8

_rs = RSCodec(RS_PARITY)


def _check(key: bytes, wm_id: bytes) -> bytes:
    return hmac.new(key, b"wm-check|" + wm_id, hashlib.sha3_256).digest()[:CHECK_BYTES]


def _whitening(key: bytes) -> np.ndarray:
    stream = hashlib.shake_256(b"wm-whiten|" + key).digest(FRAME_BYTES)
    return np.unpackbits(np.frombuffer(stream, dtype=np.uint8))


def encode(wm_id: bytes, key: bytes) -> np.ndarray:
    """Return the whitened frame as an array of FRAME_BITS bits (0/1)."""
    if len(wm_id) != WM_ID_BYTES:
        raise ValueError(f"wm_id must be {WM_ID_BYTES} bytes")
    frame = bytes(_rs.encode(wm_id + _check(key, wm_id)))
    return np.unpackbits(np.frombuffer(frame, dtype=np.uint8)) ^ _whitening(key)


def decode(bits: np.ndarray, key: bytes) -> tuple[bytes | None, int]:
    """Decode FRAME_BITS whitened bits. Returns (wm_id or None, corrected byte count)."""
    plain = np.asarray(bits, dtype=np.uint8)[:FRAME_BITS] ^ _whitening(key)
    raw = np.packbits(plain).tobytes()
    try:
        msg, _, errata = _rs.decode(raw)
    except ReedSolomonError:
        return None, -1
    msg = bytes(msg)
    wm_id, chk = msg[:WM_ID_BYTES], msg[WM_ID_BYTES:]
    if not hmac.compare_digest(chk, _check(key, wm_id)):
        return None, -1
    return wm_id, len(errata)
