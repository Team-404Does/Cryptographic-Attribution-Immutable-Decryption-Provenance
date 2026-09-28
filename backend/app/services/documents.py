"""Sender side: AES-256-GCM document encryption + per-recipient ML-KEM key wrapping."""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

import pymupdf

from .. import auth, config, db
from ..crypto import keystore, pqc
from ..crypto.symmetric import aes_decrypt, aes_encrypt, hkdf, sha3
from ..ledger import chain
from ..watermark import pdf_wm
from . import identity

# The custodian token keeps an escrowed wrap of every content key so that
# access can be granted to new recipients later without the sender re-uploading.
CUSTODIAN = "document-custodian"


class DocumentError(ValueError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _wrap(cek: bytes, kem_pk: bytes, doc_id: str, holder: str) -> tuple[str, str]:
    kem_ct, ss = pqc.kem_encaps(kem_pk)
    context = f"cek-wrap|{doc_id}|{holder}".encode()
    kek = hkdf(ss, context)
    return keystore.b64e(kem_ct), keystore.b64e(aes_encrypt(kek, cek, context))


def unwrap(session: keystore.Session, kem_ct: str, wrapped: str, doc_id: str, holder: str) -> bytes:
    ss = session.decapsulate(keystore.b64d(kem_ct))
    context = f"cek-wrap|{doc_id}|{holder}".encode()
    return aes_decrypt(hkdf(ss, context), keystore.b64d(wrapped), context)


def _recipient(rid: str) -> dict:
    r = identity.get(rid)
    if not r:
        raise DocumentError(f"unknown recipient {rid}")
    ok, why = identity.is_active(r)
    if not ok:
        raise DocumentError(f"cannot grant {rid}: {why}")
    return r


def _grant_event(actor: auth.Operator, doc_id: str, r: dict) -> dict:
    return auth.sign_action(actor, "grant", {"document_id": doc_id, "recipient_id": r["id"],
                                             "employee_id": r["employee_id"],
                                             "cert_fingerprint": r["cert"]["fingerprint"]})


def upload(actor: auth.Operator, title: str, filename: str, pdf: bytes, recipient_ids: list[str]) -> dict:
    if pdf[:5] != b"%PDF-":
        raise DocumentError("file is not a PDF")
    try:
        d = pymupdf.open(stream=pdf, filetype="pdf")
    except Exception:
        raise DocumentError("file is not a readable PDF") from None
    with d:
        if d.needs_pass:
            raise DocumentError("password-protected PDFs are not supported; remove the password first")
        pages = d.page_count
        if pages == 0:
            raise DocumentError("PDF has no pages")
        try:
            pdf_wm.check_render_size(d, config.MAX_PDF_PAGES, config.MAX_IMAGE_PIXELS)
        except pdf_wm.PdfTooLarge as e:
            raise DocumentError(str(e)) from None
    recipients = [_recipient(rid) for rid in dict.fromkeys(recipient_ids)]  # validate before writing
    doc_id = f"doc-{os.urandom(4).hex()}"
    cek = os.urandom(32)
    blob = config.BLOBS_DIR / f"{doc_id}.enc"
    blob.write_bytes(aes_encrypt(cek, pdf, doc_id.encode()))
    keystore.system_session(CUSTODIAN)  # provisions the custodian token on first use
    custodian = keystore.public_keys(CUSTODIAN)
    c_ct, c_wrap = _wrap(cek, keystore.b64d(custodian["kem_pk"]), doc_id, CUSTODIAN)
    with db.tx() as conn:
        conn.execute("INSERT INTO documents VALUES (?,?,?,?,?,?,?,?,?)",
                     (doc_id, (title.strip() or filename)[:200], filename[:200], sha3(pdf), len(pdf), pages,
                      blob.name, _now(), actor.id))  # store filename only - portable across hosts
        conn.execute("INSERT INTO key_wraps VALUES (?,?,?,?,?,?)", (doc_id, CUSTODIAN, c_ct, c_wrap, _now(), actor.id))
    for r in recipients:
        _grant_with_cek(actor, doc_id, r, cek)
    # one block: the signed registration plus every initial grant (Merkle tree over all of them)
    reg = auth.sign_action(actor, "document-registration", {"document_id": doc_id, "sha3": sha3(pdf),
                                                             "pages": pages, "title": (title.strip() or filename)[:200]})
    chain.append([reg] + [_grant_event(actor, doc_id, r) for r in recipients])
    return get(doc_id)


def _grant_with_cek(actor: auth.Operator, doc_id: str, r: dict, cek: bytes) -> None:
    kem_ct, wrapped = _wrap(cek, keystore.b64d(r["cert"]["body"]["kem_pk"]), doc_id, r["id"])
    with db.tx() as conn:
        conn.execute("INSERT OR REPLACE INTO key_wraps VALUES (?,?,?,?,?,?)",
                     (doc_id, r["id"], kem_ct, wrapped, _now(), actor.id))


def grant(actor: auth.Operator, doc_id: str, rid: str) -> dict:
    w = db.row("SELECT * FROM key_wraps WHERE doc_id=? AND recipient_id=?", doc_id, CUSTODIAN)
    if not w:
        raise DocumentError("unknown document")
    if db.row("SELECT 1 FROM key_wraps WHERE doc_id=? AND recipient_id=?", doc_id, rid):
        raise DocumentError("recipient already has access")
    r = _recipient(rid)
    cek = unwrap(keystore.system_session(CUSTODIAN), w["kem_ct"], w["wrapped_cek"], doc_id, CUSTODIAN)
    _grant_with_cek(actor, doc_id, r, cek)
    chain.append([_grant_event(actor, doc_id, r)])
    return get(doc_id)


def revoke_access(actor: auth.Operator, doc_id: str, rid: str) -> dict:
    with db.tx() as conn:
        n = conn.execute("DELETE FROM key_wraps WHERE doc_id=? AND recipient_id=? AND recipient_id<>?",
                         (doc_id, rid, CUSTODIAN)).rowcount
    if not n:
        raise DocumentError("recipient has no access to this document")
    chain.append([auth.sign_action(actor, "access-revocation", {"document_id": doc_id, "recipient_id": rid})])
    return get(doc_id)


def get(doc_id: str) -> dict | None:
    d = db.row("SELECT * FROM documents WHERE id=?", doc_id)
    if not d:
        return None
    d.pop("blob_path")
    o = db.row("SELECT name FROM operators WHERE id=?", d["created_by"])
    d["created_by_name"] = o["name"] if o else None
    d["recipients"] = [r["recipient_id"] for r in db.rows(
        "SELECT recipient_id FROM key_wraps WHERE doc_id=? AND recipient_id<>?", doc_id, CUSTODIAN)]
    d["sessions"] = db.row("SELECT COUNT(*) n FROM sessions WHERE doc_id=?", doc_id)["n"]
    return d


def directory() -> list[dict]:
    """Public listing for the secure viewer: titles and which identities may open them."""
    return [{"id": d["id"], "title": d["title"], "pages": d["pages"], "recipients": d["recipients"]}
            for d in list_all()]


def list_all() -> list[dict]:
    return [get(r["id"]) for r in db.rows("SELECT id FROM documents ORDER BY created_at DESC")]


def blob_path(doc_id: str) -> str:
    d = db.row("SELECT blob_path FROM documents WHERE id=?", doc_id)
    if not d:
        raise DocumentError("unknown document")
    stored = d["blob_path"]
    p = Path(stored)
    # Trust the stored path only when it is an absolute path inside THIS
    # runtime's blobs dir; anything else (old absolute paths from other hosts,
    # rooted paths, bare names) resolves to the runtime blobs dir by name.
    if p.is_absolute() and p.parent == config.BLOBS_DIR:
        return stored
    return str(config.BLOBS_DIR / p.name)
