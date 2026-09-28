"""Access control, identity integrity and anti-framing checks."""
import pymupdf

from app import config, db
from test_e2e import analyze, decrypt, fetch_copy


def test_privileged_endpoints_require_login(client, seeded):
    body = {"employee_id": "EMP-9", "name": "Asha Verma", "pin": "1234"}
    assert client.post("/api/recipients", json=body).status_code == 401
    assert client.post(f"/api/documents/{seeded['document']}/grant", json={"recipient_id": "x"}).status_code == 401
    assert client.get("/api/ledger/blocks").status_code == 401
    assert client.post("/api/forensics/analyze", files={"file": ("a.txt", b"x", "text/plain")}).status_code == 401
    assert client.post("/api/recipients", json=body, headers={"Authorization": "Bearer forged"}).status_code == 401


def test_roles_are_enforced(client, examiner, auditor):
    body = {"employee_id": "EMP-9", "name": "Mallory", "pin": "1234"}
    assert client.post("/api/recipients", json=body, headers=examiner).status_code == 403
    assert client.post("/api/recipients", json=body, headers=auditor).status_code == 403
    assert client.post("/api/forensics/analyze", headers=auditor,
                       files={"file": ("a.txt", b"x", "text/plain")}).status_code == 403
    assert client.post("/api/operators", json={"name": "x", "role": "examiner", "pin": "1234"},
                       headers=examiner).status_code == 403


def test_bootstrap_only_once(client, seeded):
    assert client.post("/api/auth/bootstrap", json={"name": "Eve", "pin": "1234"}).status_code == 400


def test_duplicate_employee_rejected_until_revoked(client, officer, seeded):
    dup = {"employee_id": "emp-1001", "name": "Asha Verma", "pin": "5555"}
    r = client.post("/api/recipients", json=dup, headers=officer)
    assert r.status_code == 400 and "already has an active identity" in r.json()["detail"]


def test_revoked_identity_cannot_decrypt_or_be_granted(client, officer, seeded):
    rid = client.post("/api/recipients", headers=officer,
                      json={"employee_id": "EMP-3000", "name": "Temp Contractor", "pin": "7777"}).json()["id"]
    doc = seeded["document"]
    assert client.post(f"/api/documents/{doc}/grant", json={"recipient_id": rid}, headers=officer).status_code == 200
    decrypt(client, doc, rid, "7777")
    assert client.post(f"/api/recipients/{rid}/revoke", json={"reason": "contract ended"}, headers=officer).status_code == 200
    r = client.post("/api/sessions/decrypt", json={"doc_id": doc, "recipient_id": rid, "pin": "7777"})
    assert r.status_code == 400 and "revoked" in r.json()["detail"]
    # re-enrolment of the same employee is allowed only after revocation
    r = client.post("/api/recipients", headers=officer,
                    json={"employee_id": "EMP-3000", "name": "Temp Contractor", "pin": "7778"})
    assert r.status_code == 200


def test_namesake_is_flagged_not_blamed(client, officer, examiner, seeded):
    """A second identity with the same display name must not be confused with the real one."""
    fake = client.post("/api/recipients", headers=officer,
                       json={"employee_id": "EMP-6666", "name": "asha  VERMA", "pin": "6666"}).json()["id"]
    s = decrypt(client, seeded["document"], seeded["recipients"][0], "1111")
    rep = analyze(client, examiner, "leak.pdf", fetch_copy(client, s), "application/pdf")
    assert rep["attribution"]["employee_id"] == "EMP-1001"
    assert any(fake in w for w in rep["warnings"])


def test_database_name_edit_does_not_change_attribution(client, examiner, seeded):
    """An insider renaming a recipient row cannot redirect blame: identity comes from the CA-signed cert."""
    s = decrypt(client, seeded["document"], seeded["recipients"][1], "2222")
    with db.tx() as conn:
        conn.execute("UPDATE recipients SET name='Scapegoat', employee_id='EMP-0000' WHERE id=?",
                     (seeded["recipients"][1],))
    rep = analyze(client, examiner, "leak.pdf", fetch_copy(client, s), "application/pdf")
    assert rep["attribution"]["recipient_name"] == "Rahul Mehta"
    assert rep["attribution"]["employee_id"] == "EMP-1002"
    with db.tx() as conn:
        conn.execute("UPDATE recipients SET name='Rahul Mehta', employee_id='EMP-1002' WHERE id=?",
                     (seeded["recipients"][1],))


def test_admin_actions_are_signed_on_ledger(client, auditor):
    types = [e.get("type") for b in client.get("/api/ledger/blocks?limit=500", headers=auditor).json()
             for e in b["events"]]
    for t in ("operator-enrollment", "enrollment", "document-registration", "grant", "revocation"):
        assert t in types, t


def test_demo_endpoints_disabled_outside_demo_mode(client, auditor):
    config.DEMO_MODE = False
    try:
        assert client.post("/api/demo/reset").status_code == 404
        assert client.post("/api/demo/tamper", json={"block_index": 1}, headers=auditor).status_code == 404
        assert client.get("/api/robustness/transforms").status_code == 404
    finally:
        config.DEMO_MODE = True


def test_oversized_pdf_rejected(client, officer):
    doc = pymupdf.open()
    for _ in range(config.MAX_PDF_PAGES + 1):
        doc.new_page()
    r = client.post("/api/documents", headers=officer, files={"file": ("big.pdf", doc.tobytes(), "application/pdf")})
    assert r.status_code == 400 and "pages" in r.json()["detail"]


def test_forged_text_mark_cannot_frame_a_recipient(client, examiner, auditor, seeded):
    """Knowing a watermark ID (visible to any operator) is not enough to forge evidence."""
    from app.watermark import text_wm
    wm = client.get("/api/sessions", headers=auditor).json()[0]["wm_id"]
    fake, _ = text_wm.embed("The committee recommends a secure procurement process. " * 30,
                            bytes.fromhex(wm), b"guessed-key-guessed-key-guessed!")
    rep = analyze(client, examiner, "paste.txt", fake.encode(), "text/plain")
    assert rep["verdict"] == "NO_WATERMARK"


def test_cross_origin_and_foreign_host_refused(client, officer):
    r = client.post("/api/demo/reset", headers={**officer, "Origin": "https://evil.example"})
    assert r.status_code == 403
    r = client.post("/api/auth/login", json={"operator_id": "x", "pin": "1"}, headers={"Origin": "null"})
    assert r.status_code == 403
    assert client.get("/api/status", headers={"Host": "attacker.example"}).status_code == 400
    assert client.post("/api/demo/reset").status_code == 401          # reset needs an officer


def test_pin_lockout_is_temporary_and_officer_can_unlock(client, officer):
    from app.crypto import keystore
    op = client.post("/api/operators", headers=officer, json={"name": "Temp Auditor", "role": "auditor", "pin": "4321"}).json()
    for _ in range(config.MAX_PIN_ATTEMPTS - 1):
        assert client.post("/api/auth/login", json={"operator_id": op["id"], "pin": "0000"}).status_code == 401
    assert client.post("/api/auth/login", json={"operator_id": op["id"], "pin": "0000"}).status_code == 423
    assert client.post("/api/auth/login", json={"operator_id": op["id"], "pin": "4321"}).status_code == 423
    st = keystore.lock_state(op["id"])
    assert st["locked"] and st["locked_until"] is not None             # timed, not permanent
    assert client.post(f"/api/operators/{op['id']}/unlock", headers=officer).status_code == 200
    assert client.post("/api/auth/login", json={"operator_id": op["id"], "pin": "4321"}).status_code == 200


def test_bootstrap_needs_setup_code():
    from app import auth
    import pytest
    with pytest.raises(auth.AuthError):
        auth.bootstrap("Eve", "1234", "WRONG-CODE")


def test_huge_page_pdf_rejected(client, officer, examiner):
    doc = pymupdf.open()
    doc.new_page(width=8000, height=8000)
    data = doc.tobytes()
    r = client.post("/api/documents", headers=officer, files={"file": ("big.pdf", data, "application/pdf")})
    assert r.status_code == 400 and "too large" in r.json()["detail"]
    r = client.post("/api/forensics/analyze", headers=examiner, files={"file": ("big.pdf", data, "application/pdf")})
    assert r.status_code == 400 and "too large" in r.json()["detail"]
