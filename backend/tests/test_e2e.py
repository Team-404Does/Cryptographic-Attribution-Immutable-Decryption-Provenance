"""End-to-end: encrypt -> per-session decrypt -> leak -> attribute -> tamper detection."""
import io

import pymupdf
from PIL import Image


def decrypt(client, doc_id, rid, pin):
    r = client.post("/api/sessions/decrypt", json={"doc_id": doc_id, "recipient_id": rid, "pin": pin})
    assert r.status_code == 200, r.text
    return r.json()


def fetch_copy(client, session):
    r = client.get(session["download_url"])
    assert r.status_code == 200 and r.content[:5] == b"%PDF-"
    return r.content


def screenshot(pdf_bytes, dpi=96, quality=70):
    page = pymupdf.open(stream=pdf_bytes, filetype="pdf")[0]
    pix = page.get_pixmap(dpi=dpi)
    img = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=quality)
    return buf.getvalue()


def analyze(client, examiner, name, data, ctype):
    r = client.post("/api/forensics/analyze", files={"file": (name, data, ctype)}, headers=examiner)
    assert r.status_code == 200, r.text
    return r.json()


def test_full_attribution_flow(client, seeded, examiner):
    doc_id = seeded["document"]
    asha, rahul = seeded["recipients"][:2]

    s1 = decrypt(client, doc_id, asha, "1111")
    s2 = decrypt(client, doc_id, asha, "1111")       # same recipient, new session
    s3 = decrypt(client, doc_id, rahul, "2222")
    assert len({s1["watermark_id"], s2["watermark_id"], s3["watermark_id"]}) == 3

    copy = fetch_copy(client, s2)
    assert client.get(s2["download_url"]).status_code == 400, "download links are single-use"

    rep = analyze(client, examiner, "leak.jpg", screenshot(copy), "image/jpeg")
    assert rep["verdict"] == "ATTRIBUTED", rep["summary"]
    assert rep["attribution"]["session_id"] == s2["session_id"]      # exact session, not just recipient
    assert rep["attribution"]["employee_id"] == "EMP-1001"
    assert rep["enrollment"]["approved_by"] == "Priya Nair" and rep["verification"]["enrollment_ok"]
    assert all(rep["verification"][k] for k in ("record_hash_ok", "ml_dsa_signature_ok", "merkle_inclusion_ok",
                                                "chain_integrity_ok"))

    # exported report verifies (service + examiner signatures); a modified one does not
    v = client.post("/api/reports/verify", json=rep).json()
    assert v["valid"] and v["examiner_signature_ok"]
    assert not client.post("/api/reports/verify", json=rep | {"verdict": "NO_WATERMARK"}).json()["valid"]
    assert client.get(f"/api/reports/{rep['report_id']}/pdf", headers=examiner).content[:5] == b"%PDF-"

    rep = analyze(client, examiner, "leak.pdf", copy, "application/pdf")
    assert rep["verdict"] == "ATTRIBUTED" and rep["extraction"]["agreeing_channels"] == 3

    text = "".join(p.get_text() for p in pymupdf.open(stream=copy, filetype="pdf"))
    rep = analyze(client, examiner, "leak.txt", text[300:1100].encode(), "text/plain")
    assert rep["attribution"]["session_id"] == s2["session_id"]
    assert rep["verdict"] == "ATTRIBUTED_WITH_WARNINGS"      # text-only evidence is flagged as weaker


def test_cropped_rotated_screenshot_is_attributed(client, seeded, examiner):
    """Informed registration: a partial, rotated capture is mapped back onto the source page."""
    s = decrypt(client, seeded["document"], seeded["recipients"][0], "1111")
    page = pymupdf.open(stream=fetch_copy(client, s), filetype="pdf")[0]
    pix = page.get_pixmap(dpi=110)
    img = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
    img = img.rotate(5, expand=True, fillcolor=(60, 60, 60)).crop((80, 120, img.width - 40, int(img.height * 0.6)))
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=80)
    rep = analyze(client, examiner, "photo.jpg", buf.getvalue(), "image/jpeg")
    assert rep["verdict"] == "ATTRIBUTED", rep["summary"]
    assert rep["attribution"]["session_id"] == s["session_id"]
    assert rep["extraction"]["channels"][0]["channel"] == "raster-registered"


def test_unmarked_document_is_not_attributed(client, examiner):
    from app.services.sample import build
    assert analyze(client, examiner, "orig.pdf", build(), "application/pdf")["verdict"] == "NO_WATERMARK"


def test_wrong_pin_and_no_access(client, seeded, officer):
    doc_id = seeded["document"]
    r = client.post("/api/sessions/decrypt", json={"doc_id": doc_id, "recipient_id": seeded["recipients"][0], "pin": "9999"})
    assert r.status_code == 401
    other = client.post("/api/recipients", headers=officer,
                        json={"employee_id": "EMP-2000", "name": "Outsider", "pin": "4444"}).json()["id"]
    r = client.post("/api/sessions/decrypt", json={"doc_id": doc_id, "recipient_id": other, "pin": "4444"})
    assert r.status_code == 400 and "access" in r.json()["detail"]


def test_ledger_tamper_detected(client, seeded, examiner, auditor, officer):
    s = decrypt(client, seeded["document"], seeded["recipients"][2], "3333")
    copy = fetch_copy(client, s)
    assert client.get("/api/ledger/verify", headers=auditor).json()["valid"]
    assert client.post("/api/demo/tamper", json={"block_index": s["block_index"]}, headers=auditor).status_code == 403
    client.post("/api/demo/tamper", json={"block_index": s["block_index"]}, headers=officer)
    client.post("/api/demo/tamper", json={"block_index": s["block_index"] - 1}, headers=officer)
    audit = client.get("/api/ledger/verify", headers=auditor).json()
    assert not audit["valid"] and audit["first_invalid_block"] == s["block_index"] - 1
    assert analyze(client, examiner, "leak.pdf", copy, "application/pdf")["verdict"] == "EVIDENCE_COMPROMISED"
    client.post("/api/demo/repair", headers=officer)     # restores *both* tampered blocks
    assert client.get("/api/ledger/verify", headers=auditor).json()["valid"]


def test_robustness_suite(client, seeded, examiner):
    s = decrypt(client, seeded["document"], seeded["recipients"][1], "2222")
    res = client.post(f"/api/sessions/{s['session_id']}/robustness", headers=examiner).json()
    by = {r["transform"]: r["success"] for r in res["results"]}
    assert by["Screenshot @ 96 dpi + JPEG q75"] and by["Print-scan simulation"] and by["Copy/paste one paragraph"]
    for t in ("Screenshot inside PDF viewer (chrome + grey canvas)", "Crop: centre 50 % of the page", "Rotate 8° + crop",
              "Phone photo (perspective + blur + noise + JPEG)"):
        assert by[t], t
    assert not by["Retyped / homoglyphs normalised"]   # documented limitation
