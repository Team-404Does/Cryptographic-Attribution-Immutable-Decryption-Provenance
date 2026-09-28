"""Recipient lifecycle: officer-approved enrolment, revocation and PIN unlock.

Each step is signed by the acting security officer and committed to the ledger.
An employee id can have at most one active identity; re-enrolling someone
requires revoking their current certificate first.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone

from .. import auth, db
from ..crypto import keystore, pki
from ..ledger import chain

EMPLOYEE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{1,31}")
CLEARANCES = ("CONFIDENTIAL", "SECRET", "TOP SECRET")


class ProvisioningError(ValueError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _norm(name: str) -> str:
    return " ".join(name.lower().split())


def create_recipient(actor: auth.Operator, employee_id: str, name: str, department: str,
                     clearance: str, pin: str) -> dict:
    name, employee_id = " ".join(name.split()), employee_id.strip().upper()
    if not name:
        raise ProvisioningError("name is required")
    if not EMPLOYEE_RE.fullmatch(employee_id):
        raise ProvisioningError("employee ID must be 2-32 letters, digits or dashes")
    if clearance not in CLEARANCES:
        raise ProvisioningError(f"clearance must be one of {', '.join(CLEARANCES)}")
    if not auth.PIN_RE.fullmatch(pin):
        raise ProvisioningError("PIN must be 4-12 digits")
    clash = db.row("SELECT id, name FROM recipients WHERE employee_id=? AND status='active'", employee_id)
    if clash:
        raise ProvisioningError(f"employee {employee_id} already has an active identity ({clash['id']}, "
                                f"{clash['name']}); revoke it before re-enrolling")
    rid = f"rcp-{os.urandom(4).hex()}"
    keystore.create_token(rid, pin)
    subject = {"recipient_id": rid, "employee_id": employee_id, "name": name,
               "department": department.strip(), "clearance": clearance}
    cert = pki.issue(subject, rid)
    with db.tx() as conn:
        conn.execute("""INSERT INTO recipients (id, employee_id, name, department, clearance, token_label, cert,
                        created_at, enrolled_by) VALUES (?,?,?,?,?,?,?,?,?)""",
                     (rid, employee_id, name, department.strip(), clearance, rid, json.dumps(cert), _now(), actor.id))
    chain.append([auth.sign_action(actor, "enrollment", subject | {
        "cert_fingerprint": cert["fingerprint"], "cert_serial": cert["body"]["serial"]})])
    return get(rid)


def revoke(actor: auth.Operator, rid: str, reason: str) -> dict:
    r = get(rid)
    if not r:
        raise ProvisioningError("unknown recipient")
    if r["status"] != "active":
        raise ProvisioningError("identity is already revoked")
    reason = reason.strip() or "unspecified"
    with db.tx() as conn:
        conn.execute("UPDATE recipients SET status='revoked', revoked_at=?, revoked_by=?, revoked_reason=? WHERE id=?",
                     (_now(), actor.id, reason, rid))
    chain.append([auth.sign_action(actor, "revocation", {
        "recipient_id": rid, "employee_id": r["employee_id"], "cert_serial": r["cert"]["body"]["serial"],
        "cert_fingerprint": r["cert"]["fingerprint"], "reason": reason})])
    return get(rid)


def unlock(actor: auth.Operator, rid: str) -> dict:
    r = get(rid)
    if not r:
        raise ProvisioningError("unknown recipient")
    keystore.reset_attempts(r["token_label"])
    chain.append([auth.sign_action(actor, "token-unlock", {"recipient_id": rid, "employee_id": r["employee_id"]})])
    return get(rid)


def get(rid: str) -> dict | None:
    r = db.row("SELECT * FROM recipients WHERE id=?", rid)
    if not r:
        return None
    r["cert"] = json.loads(r["cert"])
    return r


def is_active(r: dict) -> tuple[bool, str]:
    if r["status"] != "active":
        return False, f"identity revoked ({r.get('revoked_reason') or 'no reason'})"
    st = pki.verify(r["cert"])
    if not st["valid"]:
        return False, "certificate invalid or expired"
    return True, ""


def same_name(name: str, exclude: str) -> list[dict]:
    """Other identities sharing a display name - surfaced in reports to prevent mis-attribution."""
    out = []
    for r in db.rows("SELECT id, employee_id, name, department, status FROM recipients WHERE id<>?", exclude):
        if _norm(r["name"]) == _norm(name):
            out.append(r)
    return out


def list_all() -> list[dict]:
    out = []
    for r in db.rows("""SELECT r.*, o.name AS enrolled_by_name FROM recipients r
                        LEFT JOIN operators o ON o.id = r.enrolled_by ORDER BY r.created_at"""):
        cert = json.loads(r.pop("cert"))
        r["cert_fingerprint"] = cert["fingerprint"]
        r["cert_serial"] = cert["body"]["serial"]
        r["cert_not_after"] = cert["body"]["not_after"]
        r["sessions"] = db.row("SELECT COUNT(*) n FROM sessions WHERE recipient_id=?", r["id"])["n"]
        r["failed_pin_attempts"] = keystore.failed_attempts(r["token_label"])
        r["duplicate_name"] = bool(same_name(r["name"], r["id"]))
        out.append(r)
    return out


def directory() -> list[dict]:
    """Minimal public listing used by the secure viewer's identity picker."""
    return db.rows("SELECT id, employee_id, name, department FROM recipients WHERE status='active' ORDER BY name")
