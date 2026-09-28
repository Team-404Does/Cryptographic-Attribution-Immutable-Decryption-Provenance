"""Operator identities, role-based access and signed administrative actions.

Operators (security officers, forensic examiners, auditors) hold their own
PIN-protected ML-DSA tokens with CA-issued certificates. Logging in unlocks the
token for the session; every privileged action (enrolment, grant, revocation,
document registration...) is signed by the acting operator's token and
committed to the ledger, so each administrative decision is attributable and
tamper-evident exactly like a decryption.
"""
from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import Depends, Header, HTTPException

from . import config, db
from .crypto import keystore, pki, pqc
from .crypto.symmetric import canonical

ROLES = {
    "security-officer": "Enrols identities, registers documents, grants and revokes access",
    "examiner": "Runs leak forensics and issues evidence reports",
    "auditor": "Reads and verifies the audit ledger",
}
PIN_RE = re.compile(r"\d{4,12}")


class AuthError(ValueError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Operator:
    id: str
    name: str
    role: str
    cert_fingerprint: str
    token: keystore.Session
    expires: float

    def public(self) -> dict:
        return {"id": self.id, "name": self.name, "role": self.role, "cert_fingerprint": self.cert_fingerprint}


_sessions: dict[str, Operator] = {}
_lock = threading.Lock()


# ---------------------------------------------------------------- signed actions
def sign_action(op: Operator, action: str, payload: dict) -> dict:
    body = {"action": action, "payload": payload, "operator_id": op.id, "operator_role": op.role,
            "operator_cert_fingerprint": op.cert_fingerprint, "at": datetime.now(timezone.utc).isoformat()}
    return {"type": action, "body": body, "sig_alg": pqc.SIG_ALG,
            "signature": keystore.b64e(op.token.sign(canonical(body)))}


# which operator role may sign which administrative action
ACTION_ROLES = {
    "operator-enrollment": {"security-officer"}, "operator-unlock": {"security-officer"},
    "enrollment": {"security-officer"}, "revocation": {"security-officer"}, "token-unlock": {"security-officer"},
    "document-registration": {"security-officer"}, "grant": {"security-officer"},
    "access-revocation": {"security-officer"},
}


def verify_action(event: dict) -> dict:
    """Check an administrative ledger event: signature by the operator's CA-issued certificate
    (valid at signing time), event type bound into the signed body, and signer role authorised."""
    body = event.get("body", {})
    o = db.row("SELECT * FROM operators WHERE id=?", body.get("operator_id", ""))
    if not o:
        return {"valid": False, "error": "operator unknown"}
    cert = json.loads(o["cert"])
    cert_status = pki.verify(cert, at=body.get("at"))
    bound = cert["fingerprint"] == body.get("operator_cert_fingerprint")
    try:
        sig_ok = pqc.verify(keystore.b64d(cert["body"]["sig_pk"]), canonical(body), keystore.b64d(event["signature"]))
    except (KeyError, ValueError, TypeError):
        sig_ok = False
    role = cert["body"]["subject"].get("role")
    type_ok = event.get("type") == body.get("action")
    role_ok = role in ACTION_ROLES.get(body.get("action"), set())
    return {"valid": sig_ok and bound and cert_status["valid"] and type_ok and role_ok,
            "signature_ok": sig_ok, "cert_bound": bound, "cert_valid": cert_status["valid"],
            "type_bound": type_ok, "role_authorised": role_ok,
            "operator_id": o["id"], "operator_name": cert["body"]["subject"]["name"], "operator_role": role}


# ---------------------------------------------------------------- operators
def _create(name: str, role: str, pin: str, created_by: str | None) -> tuple[str, dict]:
    name = name.strip()
    if not name:
        raise AuthError("name is required")
    if role not in ROLES:
        raise AuthError(f"role must be one of {', '.join(ROLES)}")
    if not PIN_RE.fullmatch(pin):
        raise AuthError("PIN must be 4-12 digits")
    oid = f"opr-{os.urandom(4).hex()}"
    keystore.create_token(oid, pin)
    cert = pki.issue({"operator_id": oid, "name": name, "role": role}, oid)
    with db.tx() as conn:
        conn.execute("INSERT INTO operators VALUES (?,?,?,?,?,?,?)",
                     (oid, name, role, oid, json.dumps(cert), _now(), created_by))
    return oid, cert


def bootstrap_required() -> bool:
    return db.row("SELECT COUNT(*) n FROM operators")["n"] == 0


def _setup_code_path():
    return config.DATA_DIR / "setup-code.txt"


def ensure_setup_code() -> str | None:
    """While uninitialised, a one-time setup code (printed to the server console and stored
    in the 0600 data directory) must be presented to bootstrap - so another local process or
    web page cannot race the legitimate administrator to become the first security officer."""
    p = _setup_code_path()
    if not bootstrap_required():
        p.unlink(missing_ok=True)
        return None
    if not p.exists():
        p.write_text("-".join(secrets.token_hex(2).upper() for _ in range(3)))
        p.chmod(0o600)
    return p.read_text().strip()


def bootstrap(name: str, pin: str, setup_code: str | None = None, _trusted: bool = False) -> dict:
    """First-run ceremony: create the initial security officer. Only possible on an empty installation."""
    from .ledger import chain
    with _lock:
        if not bootstrap_required():
            raise AuthError("installation already initialised")
        expected = ensure_setup_code() or ""
        if not _trusted and not hmac.compare_digest((setup_code or "").strip().upper(), expected):
            raise AuthError(f"invalid setup code - see the server console or {_setup_code_path()}")
        oid, cert = _create(name, "security-officer", pin, None)
    op = _open(oid, pin)
    chain.append([sign_action(op, "operator-enrollment", {
        "operator_id": oid, "name": name, "role": "security-officer", "cert_fingerprint": cert["fingerprint"],
        "cert_serial": cert["body"]["serial"], "bootstrap": True})])
    _setup_code_path().unlink(missing_ok=True)
    return op.public()


def create_operator(actor: Operator, name: str, role: str, pin: str) -> dict:
    from .ledger import chain
    oid, cert = _create(name, role, pin, actor.id)
    chain.append([sign_action(actor, "operator-enrollment", {
        "operator_id": oid, "name": name.strip(), "role": role, "cert_fingerprint": cert["fingerprint"],
        "cert_serial": cert["body"]["serial"]})])
    return {"id": oid, "name": name.strip(), "role": role, "cert_fingerprint": cert["fingerprint"]}


def unlock_operator(actor: Operator, oid: str) -> dict:
    from .ledger import chain
    o = db.row("SELECT * FROM operators WHERE id=?", oid)
    if not o:
        raise AuthError("unknown operator")
    keystore.reset_attempts(o["token_label"])
    chain.append([sign_action(actor, "operator-unlock", {"operator_id": oid, "name": o["name"]})])
    return {"id": oid, **keystore.lock_state(o["token_label"])}


def list_operators() -> list[dict]:
    out = db.rows("SELECT id, name, role, created_at, created_by FROM operators ORDER BY created_at")
    for o in out:
        o.update(keystore.lock_state(o["id"]))
    return out


# ---------------------------------------------------------------- sessions
def _open(oid: str, pin: str) -> Operator:
    o = db.row("SELECT * FROM operators WHERE id=?", oid)
    if not o:
        raise keystore.TokenError("unknown operator")
    tok = keystore.login(o["token_label"], pin)
    cert = json.loads(o["cert"])
    return Operator(o["id"], o["name"], o["role"], cert["fingerprint"], tok,
                    time.time() + config.OPERATOR_SESSION_TTL)


def login(oid: str, pin: str) -> tuple[str, Operator]:
    op = _open(oid, pin)
    token = secrets.token_urlsafe(32)
    with _lock:
        _purge()
        _sessions[token] = op
    return token, op


def logout(token: str) -> None:
    with _lock:
        _sessions.pop(token, None)


def _purge() -> None:
    now = time.time()
    for t in [t for t, o in _sessions.items() if o.expires < now]:
        del _sessions[t]


def reset() -> None:
    with _lock:
        _sessions.clear()


def current(authorization: str | None = Header(default=None)) -> Operator:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "operator login required")
    token = authorization[7:]
    with _lock:
        op = _sessions.get(token)
        if not op or op.expires < time.time():
            _sessions.pop(token, None)
            raise HTTPException(401, "session expired - please log in again")
        op.expires = time.time() + config.OPERATOR_SESSION_TTL  # sliding idle timeout
    return op


def require(*roles: str):
    """FastAPI dependency: an authenticated operator holding one of `roles`."""
    def dep(op: Operator = Depends(current)) -> Operator:
        if roles and op.role not in roles:
            raise HTTPException(403, f"requires role: {' or '.join(roles)}")
        return op
    return dep
