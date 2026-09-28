"""Recipient side: offline decryption session -> unique forensic copy -> signed ledger event."""
from __future__ import annotations

import json
import os
import platform
import secrets
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from .. import config, db
from ..crypto import keystore, pqc
from ..crypto.symmetric import aes_decrypt, canonical, hkdf, sha3, shake
from ..ledger import chain
from ..watermark import payload, pdf_wm
from . import documents, identity

RECORD_VERSION = 1


class SessionError(ValueError):
    pass


def watermark_key() -> bytes:
    return hkdf(config.master_secret(), b"watermark-embedding-key-v1")


def device_fingerprint() -> str:
    mid = ""
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        if os.path.exists(p):
            mid = Path(p).read_text().strip()
            break
    return sha3(f"{mid}|{socket.gethostname()}|{platform.system()}|{platform.machine()}".encode())[:32]


def derive_watermark_id(recipient_id: str, document_hash: str, nonce: bytes, timestamp: str) -> bytes:
    """Watermark Seed = HKDF(recipient_ID || document_hash || session_nonce || timestamp)."""
    ikm = b"||".join([recipient_id.encode(), bytes.fromhex(document_hash), nonce, timestamp.encode()])
    seed = hkdf(ikm, b"session-watermark-seed", salt=watermark_key())
    return seed[: payload.WM_ID_BYTES]


def copies_dir() -> Path:
    d = config.BLOBS_DIR / "copies"
    d.mkdir(parents=True, exist_ok=True)
    return d


def decrypt(doc_id: str, recipient_id: str, pin: str) -> dict:
    trace, t0 = [], time.perf_counter()

    def step(name: str, **detail):
        trace.append({"step": name, "ms": round((time.perf_counter() - t0) * 1000, 1), **detail})

    doc = documents.get(doc_id)
    rcp = identity.get(recipient_id)
    if not doc or not rcp:
        raise SessionError("unknown document or recipient")
    active, why = identity.is_active(rcp)
    if not active:
        raise SessionError(f"decryption refused: {why}")
    wrap = db.row("SELECT * FROM key_wraps WHERE doc_id=? AND recipient_id=?", doc_id, recipient_id)
    if not wrap:
        raise SessionError("recipient has no key wrap for this document (access not granted)")

    # 1. local authentication against the recipient's token
    tok = keystore.login(rcp["token_label"], pin)
    step("token-login", token=rcp["token_label"], method="PIN + device-bound software token")

    # 2. ML-KEM decapsulation -> KEK -> AES content key
    cek = documents.unwrap(tok, wrap["kem_ct"], wrap["wrapped_cek"], doc_id, recipient_id)
    step("ml-kem-decapsulate", alg=pqc.KEM_ALG)

    # 3. AES-256-GCM decryption + integrity check against the registered hash
    plain = aes_decrypt(cek, Path(documents.blob_path(doc_id)).read_bytes(), doc_id.encode())
    if sha3(plain) != doc["sha3"]:
        raise SessionError("document hash mismatch")
    step("aes-256-gcm-decrypt", bytes=len(plain), sha3=doc["sha3"][:16] + "...")

    # 4. session watermark derivation (unique per decryption event)
    for _ in range(8):
        nonce = os.urandom(16)
        ts = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        wm_id = derive_watermark_id(recipient_id, doc["sha3"], nonce, ts)
        if not db.row("SELECT 1 FROM sessions WHERE wm_id=?", wm_id.hex()):
            break
    else:
        raise SessionError("could not allocate a unique watermark id")
    step("hkdf-watermark-seed", watermark_id=wm_id.hex())

    # 5. watermark injection (raster spread-spectrum + homoglyph text layer, RS-coded)
    copy = pdf_wm.watermark_pdf(plain, wm_id, watermark_key())
    step("watermark-embed", channels=["raster-spread-spectrum", "homoglyph-text"],
         ecc=f"Reed-Solomon RS({payload.FRAME_BYTES},{payload.FRAME_BYTES - payload.RS_PARITY})")

    # 6. decryption record, hashed with SHA3-256 and signed with the recipient's ML-DSA key
    session_id = f"ses-{os.urandom(5).hex()}"
    record = {
        "version": RECORD_VERSION,
        "session_id": session_id,
        "recipient_id": recipient_id,
        "recipient_cert_fingerprint": rcp["cert"]["fingerprint"],
        "document_id": doc_id,
        "document_hash": doc["sha3"],
        "copy_hash": sha3(copy),
        "watermark_id": wm_id.hex(),
        "session_nonce": nonce.hex(),
        "timestamp": ts,
        "device_fingerprint": device_fingerprint(),
        "algorithms": {"kem": pqc.KEM_ALG, "sig": pqc.SIG_ALG, "aead": "AES-256-GCM",
                       "kdf": "HKDF-SHA3-256", "hash": "SHA3-256"},
    }
    record_hash = sha3(canonical(record))
    signature = tok.sign(bytes.fromhex(record_hash))
    step("ml-dsa-sign", alg=pqc.SIG_ALG, record_hash=record_hash[:16] + "...",
         shake256=shake(canonical(record), 16).hex())

    # 7. ledger commit (k-of-n endorsed block)
    event = {"type": "decryption", "record": record, "record_hash": record_hash,
             "signature": keystore.b64e(signature), "sig_alg": pqc.SIG_ALG}
    blk = chain.append([event])
    step("ledger-commit", block=blk["index"], block_hash=blk["block_hash"][:16] + "...",
         endorsements=len(blk["endorsements"]))

    # 8. deliver the watermarked copy. Only its hash is retained (in the signed record);
    #    demo mode additionally keeps the file for the robustness lab / leak simulator.
    if config.DEMO_MODE:
        (copies_dir() / f"{session_id}.pdf").write_bytes(copy)
    download = _issue_download(copy, f"{doc['title']} - {session_id}.pdf")
    with db.tx() as conn:
        conn.execute("INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?)",
                     (session_id, wm_id.hex(), doc_id, recipient_id, json.dumps(record), record_hash,
                      keystore.b64e(signature), blk["index"], ts))
    step("deliver", filename=f"{doc['title']}.pdf")
    return {"session_id": session_id, "watermark_id": wm_id.hex(), "block_index": blk["index"],
            "record": record, "trace": trace, "download_url": f"/api/downloads/{download}",
            "download_expires_in": config.DOWNLOAD_TTL}


# One-time download handles for freshly decrypted copies (kept in memory only)
_downloads: dict[str, tuple[bytes, str, float]] = {}
_dl_lock = threading.Lock()


def _issue_download(data: bytes, filename: str) -> str:
    token = secrets.token_urlsafe(24)
    with _dl_lock:
        now = time.time()
        for t in [t for t, v in _downloads.items() if v[2] < now]:
            del _downloads[t]
        _downloads[token] = (data, filename, now + config.DOWNLOAD_TTL)
    return token


def take_download(token: str) -> tuple[bytes, str]:
    with _dl_lock:
        v = _downloads.pop(token, None)
    if not v or v[2] < time.time():
        raise SessionError("download link expired or already used - decrypt again for a new copy")
    return v[0], v[1]


def copy_path(session_id: str) -> Path:
    p = copies_dir() / f"{session_id}.pdf"
    if not config.DEMO_MODE or not p.exists():
        raise SessionError("recipient copies are only retained in demo mode")
    return p


def list_all() -> list[dict]:
    return db.rows("""SELECT s.id, s.wm_id, s.doc_id, s.recipient_id, s.block_index, s.created_at,
                        r.name AS recipient_name, d.title AS doc_title
                        FROM sessions s JOIN recipients r ON r.id=s.recipient_id
                        JOIN documents d ON d.id=s.doc_id ORDER BY s.created_at DESC""")


def get(session_id: str) -> dict | None:
    s = db.row("SELECT * FROM sessions WHERE id=?", session_id)
    if s:
        s["record"] = json.loads(s["record"])
    return s


def by_watermark(wm_hex: str) -> dict | None:
    s = db.row("SELECT * FROM sessions WHERE wm_id=?", wm_hex)
    if s:
        s["record"] = json.loads(s["record"])
    return s
