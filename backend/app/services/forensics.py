"""Leak detection -> watermark extraction -> ledger lookup -> signature verification -> evidence."""
from __future__ import annotations

import io
import json
import os
from collections import Counter
from datetime import datetime, timezone

from PIL import Image, UnidentifiedImageError

from .. import auth, config, db
from ..crypto import keystore, pki, pqc
from ..crypto.symmetric import canonical, sha3
from ..ledger import chain
from ..watermark import pdf_wm
from . import identity, references, reports, sessions

FORENSICS_LABEL = "forensic-examiner"


class ForensicsError(ValueError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


Image.MAX_IMAGE_PIXELS = config.MAX_IMAGE_PIXELS


def extract_channels(filename: str, data: bytes) -> tuple[str, list[pdf_wm.ChannelResult]]:
    key = sessions.watermark_key()
    if data[:5] == b"%PDF-":
        try:
            return "pdf", pdf_wm.extract_pdf(data, key, max_pages=config.MAX_PDF_PAGES, max_pixels=config.MAX_IMAGE_PIXELS,
                                             refs_fn=references.all_pages)
        except pdf_wm.PdfTooLarge as e:
            raise ForensicsError(str(e)) from None
        except Exception:
            raise ForensicsError("PDF could not be parsed") from None
    try:
        img = Image.open(io.BytesIO(data))
        if img.width * img.height > config.MAX_IMAGE_PIXELS:   # check before decoding pixels
            raise ForensicsError(f"image exceeds {config.MAX_IMAGE_PIXELS:,} pixels")
        img.load()
        return "image", [pdf_wm.extract_image(img, key, f"image ({img.width}x{img.height})", references.all_pages)]
    except Image.DecompressionBombError:
        raise ForensicsError(f"image exceeds {config.MAX_IMAGE_PIXELS:,} pixels") from None
    except (UnidentifiedImageError, OSError):
        pass
    try:
        return "text", [pdf_wm.extract_text(data.decode("utf-8"), key, "plain text")]
    except UnicodeDecodeError:
        raise ForensicsError("unsupported file: expected a PDF, image, or UTF-8 text") from None


def _find_event(wm_hex: str) -> tuple[dict, int] | None:
    """Resolve the watermark to its ledger event. The sessions table is only an index;
    the ledger is the source of truth, so fall back to a scan if the index is missing."""
    s = db.row("SELECT block_index FROM sessions WHERE wm_id=?", wm_hex)
    pred = lambda e: e.get("type") == "decryption" and e["record"].get("watermark_id") == wm_hex  # noqa: E731
    if s and s["block_index"] is not None:
        hit = chain.locate_event(s["block_index"], pred)
        if hit:
            return hit
    for b in chain.blocks(limit=100000):
        for i, e in enumerate(b["events"]):
            if pred(e):
                return b, i
    return None


def _identity_history(recipient_id: str, cert_fp: str) -> tuple[dict, dict | None]:
    """Officer-signed enrolment and (if any) revocation of this identity, taken from verified
    ledger events rather than mutable database columns."""
    enrollment: dict = {"found": False, "signature_ok": False, "cert_matches": False}
    revocation = None
    for b in chain.blocks(limit=100000):
        for e in b["events"]:
            p = e.get("body", {}).get("payload", {})
            if p.get("recipient_id") != recipient_id or e.get("type") not in ("enrollment", "revocation"):
                continue
            v = auth.verify_action(e)
            if not v["valid"]:
                continue   # unsigned / mis-signed events are ignored (and break the chain audit)
            if e["type"] == "enrollment" and not enrollment["found"]:
                enrollment = {"found": True, "block_index": b["index"], "at": e["body"]["at"],
                              "approved_by": v["operator_name"], "approved_by_id": v["operator_id"],
                              "approved_by_role": v["operator_role"], "signature_ok": True,
                              "cert_matches": p.get("cert_fingerprint") == cert_fp}
            elif e["type"] == "revocation" and revocation is None:
                revocation = {"block_index": b["index"], "at": e["body"]["at"], "reason": p.get("reason"),
                              "revoked_by": v["operator_name"]}
    return enrollment, revocation


def analyze(examiner: auth.Operator, filename: str, data: bytes) -> dict:
    kind, channels = extract_channels(filename, data)
    votes = Counter(c.wm_id for c in channels if c.wm_id)
    wm_hex = votes.most_common(1)[0][0] if votes else None
    report: dict = {
        "report_id": f"rpt-{os.urandom(5).hex()}",
        "generated_at": _now(),
        "evidence": {"filename": filename, "type": kind, "size": len(data), "sha3": sha3(data)},
        "extraction": {"channels": [c.__dict__ for c in channels], "watermark_id": wm_hex,
                       "agreeing_channels": votes.get(wm_hex, 0) if wm_hex else 0,
                       "conflicting_ids": [k for k in votes if k != wm_hex]},
        "system": {"pqc": pqc.info()},
        "examiner": {"operator_id": examiner.id, "name": examiner.name,
                     "cert_fingerprint": examiner.cert_fingerprint},
    }

    if not wm_hex:
        report["verdict"] = "NO_WATERMARK"
        report["summary"] = "No recoverable forensic watermark was found in the submitted evidence."
        return _finalise(report, examiner)

    hit = _find_event(wm_hex)
    if not hit:
        report["verdict"] = "UNKNOWN_WATERMARK"
        report["summary"] = (f"Watermark {wm_hex} was recovered but has no ledger record: the copy was not "
                             "produced by this system's decryption pipeline, or the ledger was altered.")
        report["ledger"] = chain.verify_chain() | {"blocks": None}
        return _finalise(report, examiner)

    blk, ev_idx = hit
    event = blk["events"][ev_idx]
    record = event["record"]
    rcp = identity.get(record.get("recipient_id", ""))

    checks: dict = {}
    checks["record_hash_ok"] = sha3(canonical(record)) == event["record_hash"]
    subject: dict = {}
    enrollment: dict = {"found": False, "signature_ok": False, "cert_matches": False}
    revocation = None
    if rcp:
        cert = rcp["cert"]
        # identity comes from the CA-signed certificate, never from mutable database columns
        subject = cert["body"]["subject"]
        enrollment, revocation = _identity_history(rcp["id"], cert["fingerprint"])
        # certificate must have been valid when the decryption happened
        checks["certificate"] = pki.verify(cert, at=record.get("timestamp"))
        checks["cert_fingerprint_matches_record"] = cert["fingerprint"] == record.get("recipient_cert_fingerprint")
        sig_pk = keystore.b64d(cert["body"]["sig_pk"])
        checks["ml_dsa_signature_ok"] = pqc.verify(sig_pk, bytes.fromhex(event["record_hash"]),
                                                   keystore.b64d(event["signature"]))
    else:
        checks["certificate"] = {"valid": False, "error": "recipient not in identity registry"}
        checks["cert_fingerprint_matches_record"] = False
        checks["ml_dsa_signature_ok"] = False
    chain_audit = chain.verify_chain()
    block_check = next((b for b in chain_audit["blocks"] if b["index"] == blk["index"]), {})
    checks["block_integrity_ok"] = bool(block_check.get("ok"))
    checks["chain_integrity_ok"] = chain_audit["valid"]
    proof = chain.inclusion_proof(blk, ev_idx)
    checks["merkle_inclusion_ok"] = proof["verified"] and block_check.get("merkle_root_ok", False)
    checks["enrollment_ok"] = enrollment["found"] and enrollment["signature_ok"] and enrollment["cert_matches"]

    namesakes = identity.same_name(subject.get("name", ""), rcp["id"]) if rcp else []
    report["attribution"] = {
        "recipient_id": record.get("recipient_id"),
        "employee_id": subject.get("employee_id"),
        "recipient_name": subject.get("name"),
        "department": subject.get("department"),
        "clearance": subject.get("clearance"),
        "cert_serial": rcp["cert"]["body"]["serial"] if rcp else None,
        "identity_status": ("revoked" if revocation else "active") if rcp else "unknown",
        "revoked_at": revocation["at"] if revocation else None,
        "session_id": record.get("session_id"),
        "document_id": record.get("document_id"),
        "document_hash": record.get("document_hash"),
        "decrypted_at": record.get("timestamp"),
        "device_fingerprint": record.get("device_fingerprint"),
        "session_nonce": record.get("session_nonce"),
    }
    report["verification"] = checks
    report["enrollment"] = enrollment
    report["warnings"] = [
        f"Another identity shares the name '{subject.get('name')}': {n['id']} (employee {n['employee_id']}, "
        f"{n['status']}). Attribution is to employee {subject.get('employee_id')} only." for n in namesakes]
    if revocation:
        report["warnings"].append(f"Identity was revoked at {revocation['at']} by {revocation['revoked_by']} "
                                  f"({revocation['reason']}).")
    raster_ids = {c.wm_id for c in channels if c.wm_id and c.channel.startswith("raster")}
    if report["extraction"]["conflicting_ids"]:
        report["warnings"].append("Channels disagree: other watermark IDs were also recovered "
                                  f"({', '.join(report['extraction']['conflicting_ids'])}). The evidence may be a "
                                  "composite of several copies or an attempted forgery.")
    if not raster_ids:
        report["warnings"].append("Only the homoglyph text channel carried the mark. Text evidence is weaker than "
                                  "the raster channel; corroborate before acting.")
    report["ledger"] = {
        "block_index": blk["index"], "block_hash": blk["block_hash"], "header": blk["header"],
        "endorsements": [e["node"] for e in blk["endorsements"]],
        "quorum": f"{config.LEDGER_QUORUM}-of-{len(config.LEDGER_NODES)}",
        "inclusion_proof": proof,
        "chain_length": chain_audit["length"], "chain_head": chain_audit["head_hash"],
        "first_invalid_block": chain_audit["first_invalid_block"],
        "node_health": chain_audit["node_health"],
    }
    report["event"] = event

    crypto_ok = (checks["record_hash_ok"] and checks["ml_dsa_signature_ok"]
                 and checks["certificate"]["valid"] and checks["cert_fingerprint_matches_record"])
    strong_evidence = bool(raster_ids) and not report["extraction"]["conflicting_ids"]
    if (crypto_ok and checks["enrollment_ok"] and checks["block_integrity_ok"] and checks["merkle_inclusion_ok"]
            and checks["chain_integrity_ok"] and strong_evidence):
        report["verdict"] = "ATTRIBUTED"
        report["summary"] = (f"Leak attributed to {subject['name']} (employee {subject['employee_id']}, "
                             f"{record['recipient_id']}), decryption session {record['session_id']} at "
                             f"{record['timestamp']}. Signature, certificate, officer-approved enrolment, Merkle "
                             "inclusion and full-chain integrity verified.")
    elif crypto_ok and checks["block_integrity_ok"]:
        report["verdict"] = "ATTRIBUTED_WITH_WARNINGS"
        problems = []
        if not strong_evidence:
            problems.append("the watermark evidence is text-only or conflicting")
        if not checks["enrollment_ok"]:
            problems.append("the identity's enrolment record is missing or does not verify")
        if not checks["chain_integrity_ok"]:
            problems.append(f"the ledger audit failed (first invalid block: {chain_audit['first_invalid_block']})")
        report["summary"] = ("The decryption record is cryptographically valid, but " + " and ".join(problems) + ".")
    else:
        report["verdict"] = "EVIDENCE_COMPROMISED"
        report["summary"] = ("The ledger record for this watermark fails verification - it has been altered after "
                             "commitment. The attribution cannot be relied on and the tampering itself is evidence.")
    return _finalise(report, examiner)


def _finalise(report: dict, examiner: auth.Operator) -> dict:
    """Dual signature: the installation's forensic service key and the examiner's personal token."""
    tok = keystore.system_session(FORENSICS_LABEL)
    body_hash = sha3(canonical(report))
    digest = bytes.fromhex(body_hash)
    report["report_signature"] = {
        "signer": FORENSICS_LABEL, "alg": pqc.SIG_ALG, "report_sha3": body_hash,
        "signature": keystore.b64e(tok.sign(digest)),
        "signer_pk_sha3": sha3(keystore.b64d(keystore.public_keys(FORENSICS_LABEL)["sig_pk"])),
        "examiner_id": examiner.id,
        "examiner_signature": keystore.b64e(examiner.token.sign(digest)),
    }
    pdf_path = config.REPORTS_DIR / f"{report['report_id']}.pdf"
    pdf_path.write_bytes(reports.render_pdf(report))
    (config.REPORTS_DIR / f"{report['report_id']}.json").write_text(json.dumps(report, indent=2))
    with db.tx() as conn:
        conn.execute("INSERT INTO reports VALUES (?,?,?,?,?,?,?)",
                     (report["report_id"], report["generated_at"], report["verdict"],
                      report["extraction"]["watermark_id"], json.dumps(report), str(pdf_path), examiner.id))
    return report


def verify_report(report: dict) -> dict:
    """Independently re-verify an exported JSON evidence report's signature."""
    sig = report.get("report_signature")
    if not sig:
        return {"valid": False, "error": "no report_signature"}
    body = {k: v for k, v in report.items() if k != "report_signature"}
    body_hash = sha3(canonical(body))
    try:
        digest = bytes.fromhex(body_hash)
        pk = keystore.b64d(keystore.public_keys(FORENSICS_LABEL)["sig_pk"])
        service_ok = body_hash == sig.get("report_sha3") and pqc.verify(pk, digest, keystore.b64d(sig["signature"]))
        o = db.row("SELECT cert FROM operators WHERE id=?", sig.get("examiner_id", ""))
        examiner_ok = False
        if o:
            cert = json.loads(o["cert"])
            examiner_ok = (pki.verify(cert, at=report.get("generated_at"))["valid"]
                           and cert["body"]["subject"].get("role") == "examiner"
                           and pqc.verify(keystore.b64d(cert["body"]["sig_pk"]), digest,
                                          keystore.b64d(sig.get("examiner_signature", ""))))
    except (KeyError, ValueError, TypeError):
        return {"valid": False, "error": "malformed report signature"}
    return {"valid": service_ok and examiner_ok, "service_signature_ok": service_ok,
            "examiner_signature_ok": examiner_ok, "report_sha3": body_hash}


def list_reports() -> list[dict]:
    return db.rows("""SELECT r.id, r.created_at, r.verdict, r.wm_id, o.name AS examiner FROM reports r
                      LEFT JOIN operators o ON o.id = r.created_by ORDER BY r.created_at DESC""")


def get_report(rid: str) -> dict | None:
    r = db.row("SELECT * FROM reports WHERE id=?", rid)
    return json.loads(r["report"]) if r else None


def report_pdf(rid: str) -> str | None:
    r = db.row("SELECT pdf_path FROM reports WHERE id=?", rid)
    return r["pdf_path"] if r else None
