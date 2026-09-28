"""Reference pages for informed registration: the original (unwatermarked) page renders of every
sealed document, decrypted through the custodian token and kept only in memory."""
from __future__ import annotations

import threading
from collections import OrderedDict
from pathlib import Path

import pymupdf

from .. import db
from ..crypto import keystore
from ..crypto.symmetric import aes_decrypt
from ..watermark import pdf_wm, registration
from . import documents

MAX_CACHED_DOCS = 16
MAX_DOCS_SCANNED = 200

_cache: OrderedDict[str, list[registration.PageRef]] = OrderedDict()
_lock = threading.Lock()


def _build(doc_id: str) -> list[registration.PageRef]:
    w = db.row("SELECT * FROM key_wraps WHERE doc_id=? AND recipient_id=?", doc_id, documents.CUSTODIAN)
    if not w:
        return []
    cek = documents.unwrap(keystore.system_session(documents.CUSTODIAN), w["kem_ct"], w["wrapped_cek"],
                           doc_id, documents.CUSTODIAN)
    pdf = aes_decrypt(cek, Path(documents.blob_path(doc_id)).read_bytes(), doc_id.encode())
    with pymupdf.open(stream=pdf, filetype="pdf") as d:
        return [registration.make_ref(doc_id, i, pdf_wm._render(p)) for i, p in enumerate(d)]


def pages(doc_id: str) -> list[registration.PageRef]:
    with _lock:
        if doc_id in _cache:
            _cache.move_to_end(doc_id)
            return _cache[doc_id]
    refs = _build(doc_id)
    with _lock:
        _cache[doc_id] = refs
        while len(_cache) > MAX_CACHED_DOCS:
            _cache.popitem(last=False)
    return refs


def all_pages() -> list[registration.PageRef]:
    ids = [r["id"] for r in db.rows("SELECT id FROM documents ORDER BY created_at DESC LIMIT ?", MAX_DOCS_SCANNED)]
    return [p for i in ids for p in pages(i)]


def clear() -> None:
    with _lock:
        _cache.clear()
