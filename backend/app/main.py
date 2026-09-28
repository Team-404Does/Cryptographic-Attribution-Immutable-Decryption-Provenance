"""FastAPI local backend. Binds to 127.0.0.1 only - the desktop UI is the sole client.

Access model
    public            status, CA certificate, operator/viewer directories, report verification
    recipient (PIN)   decrypt a document they were granted; fetch the one-time copy
    security-officer  enrol / revoke identities, create operators, register documents, grant access
    examiner          leak forensics, evidence reports
    auditor           ledger inspection and verification (also open to the other operators)
    demo mode only    seed / reset / tamper simulation, retained copies, robustness lab
"""
from __future__ import annotations

import re
import shutil
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import auth, config, db
from .auth import Operator, require
from .crypto import keystore, pki, pqc
from .ledger import chain
from .services import documents, forensics, identity, references, robustness, sample, sessions

MAX_UPLOAD = 50 * 1024 * 1024
OFFICER = Depends(require("security-officer"))
EXAMINER = Depends(require("examiner"))
ANY_OPERATOR = Depends(require())


def startup() -> None:
    config.ensure_dirs()
    db.connect()
    chain.ensure_genesis()
    code = auth.ensure_setup_code()
    if code:
        print(f"\n  ** Installation not initialised. One-time setup code: {code}\n"
              f"     (also stored in {config.DATA_DIR / 'setup-code.txt'})\n", flush=True)


@asynccontextmanager
async def lifespan(_: FastAPI):
    startup()
    yield
    db.close()


app = FastAPI(title="PQC Leak Attribution System", version="2.0.0", lifespan=lifespan)
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


@app.middleware("http")
async def origin_guard(request: Request, call_next):
    """Refuse cross-site state changes. Browsers always send Origin on cross-origin POSTs
    (including 'no-cors' simple requests), so a malicious page cannot drive this API."""
    origin = request.headers.get("origin")
    if request.method not in SAFE_METHODS and origin and origin not in config.ALLOWED_ORIGINS:
        return JSONResponse(status_code=403, content={"detail": f"cross-origin request from {origin} refused"})
    return await call_next(request)


app.add_middleware(TrustedHostMiddleware, allowed_hosts=config.ALLOWED_HOSTS)
if config.DEV_MODE:
    app.add_middleware(CORSMiddleware, allow_origins=config.ALLOWED_ORIGINS, allow_methods=["*"],
                       allow_headers=["*"])


@app.exception_handler(ValueError)
async def value_error(_: Request, exc: ValueError):
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(keystore.TokenError)
async def token_error(_: Request, exc: keystore.TokenError):
    return JSONResponse(status_code=423 if isinstance(exc, keystore.TokenLocked) else 401,
                        content={"detail": str(exc)})


def demo_only() -> None:
    if not config.DEMO_MODE:
        raise HTTPException(404, "demo features are disabled (start the server with SIH_DEMO=1)")


async def _read(f: UploadFile) -> bytes:
    data = await f.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, "file too large")
    return data


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9 ._-]", "_", name)[:120] or "document.pdf"


# ---------------------------------------------------------------- system
@app.get("/api/status")
def status():
    audit = chain.verify_chain()
    return {
        "pqc": pqc.info(),
        "ca": pki.ca_certificate()["body"]["subject"],
        "demo_mode": config.DEMO_MODE,
        "bootstrap_required": auth.bootstrap_required(),
        "counts": {t: db.row(f"SELECT COUNT(*) n FROM {t}")["n"]
                   for t in ("recipients", "operators", "documents", "sessions", "blocks", "reports")},
        "ledger": {"valid": audit["valid"], "length": audit["length"], "head": audit["head_hash"],
                   "first_invalid_block": audit["first_invalid_block"], "nodes": audit["node_health"]["nodes"],
                   "quorum": f"{config.LEDGER_QUORUM}-of-{len(config.LEDGER_NODES)}"},
        "network": "offline (loopback only)",
    }


@app.get("/api/pki/ca")
def ca():
    return pki.ca_certificate()


# ---------------------------------------------------------------- operator auth
class BootstrapIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    pin: str
    setup_code: str = Field(default="", max_length=32)


class LoginIn(BaseModel):
    operator_id: str
    pin: str


def _session_payload(token: str, op: Operator) -> dict:
    return {"token": token, "operator": op.public(), "expires_in": config.OPERATOR_SESSION_TTL}


@app.get("/api/auth/operators")
def operator_directory():
    return [{"id": o["id"], "name": o["name"], "role": o["role"]} for o in auth.list_operators()]


@app.post("/api/auth/bootstrap")
def bootstrap(body: BootstrapIn):
    op = auth.bootstrap(body.name, body.pin, body.setup_code)
    token, sess = auth.login(op["id"], body.pin)
    return _session_payload(token, sess)


@app.post("/api/auth/login")
def login(body: LoginIn):
    token, op = auth.login(body.operator_id, body.pin)
    return _session_payload(token, op)


@app.post("/api/auth/logout")
def logout(authorization: str | None = Header(default=None)):
    if authorization and authorization.startswith("Bearer "):
        auth.logout(authorization[7:])
    return {"ok": True}


@app.get("/api/auth/me")
def me(op: Operator = ANY_OPERATOR):
    return op.public()


class OperatorIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    role: str
    pin: str


@app.get("/api/operators")
def operators(_: Operator = OFFICER):
    return auth.list_operators()


@app.post("/api/operators")
def create_operator(body: OperatorIn, op: Operator = OFFICER):
    return auth.create_operator(op, body.name, body.role, body.pin)


@app.post("/api/operators/{oid}/unlock")
def unlock_operator(oid: str, op: Operator = OFFICER):
    return auth.unlock_operator(op, oid)


# ---------------------------------------------------------------- recipients
class RecipientIn(BaseModel):
    employee_id: str = Field(min_length=2, max_length=32)
    name: str = Field(min_length=1, max_length=80)
    department: str = Field(default="", max_length=80)
    clearance: str = Field(default="SECRET", max_length=40)
    pin: str


class ReasonIn(BaseModel):
    reason: str = Field(default="", max_length=200)


@app.get("/api/recipients")
def recipients(_: Operator = ANY_OPERATOR):
    return identity.list_all()


@app.post("/api/recipients")
def create_recipient(body: RecipientIn, op: Operator = OFFICER):
    return identity.create_recipient(op, body.employee_id, body.name, body.department, body.clearance, body.pin)


@app.get("/api/recipients/{rid}")
def recipient(rid: str, _: Operator = ANY_OPERATOR):
    r = identity.get(rid)
    if not r:
        raise HTTPException(404, "not found")
    return r | {"cert_status": pki.verify(r["cert"])}


@app.post("/api/recipients/{rid}/revoke")
def revoke_recipient(rid: str, body: ReasonIn, op: Operator = OFFICER):
    return identity.revoke(op, rid, body.reason)


@app.post("/api/recipients/{rid}/unlock")
def unlock_recipient(rid: str, op: Operator = OFFICER):
    return identity.unlock(op, rid)


# ---------------------------------------------------------------- documents
@app.get("/api/documents")
def list_documents(_: Operator = ANY_OPERATOR):
    return documents.list_all()


@app.post("/api/documents")
async def upload_document(file: UploadFile = File(...), title: str = Form(""), recipients: str = Form(""),
                          op: Operator = OFFICER):
    ids = [r for r in recipients.split(",") if r]
    return documents.upload(op, title, file.filename or "document.pdf", await _read(file), ids)


class GrantIn(BaseModel):
    recipient_id: str


@app.post("/api/documents/{doc_id}/grant")
def grant(doc_id: str, body: GrantIn, op: Operator = OFFICER):
    return documents.grant(op, doc_id, body.recipient_id)


@app.post("/api/documents/{doc_id}/revoke")
def revoke_access(doc_id: str, body: GrantIn, op: Operator = OFFICER):
    return documents.revoke_access(op, doc_id, body.recipient_id)


# ---------------------------------------------------------------- secure viewer (recipient side)
@app.get("/api/viewer/directory")
def viewer_directory():
    return {"documents": documents.directory(), "recipients": identity.directory()}


class DecryptIn(BaseModel):
    doc_id: str
    recipient_id: str
    pin: str


@app.post("/api/sessions/decrypt")
def decrypt(body: DecryptIn):
    return sessions.decrypt(body.doc_id, body.recipient_id, body.pin)


@app.get("/api/downloads/{token}")
def download(token: str):
    data, name = sessions.take_download(token)
    return Response(data, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{_safe_name(name)}"',
                             "Cache-Control": "no-store"})


@app.get("/api/sessions")
def list_sessions(_: Operator = ANY_OPERATOR):
    return sessions.list_all()


# ---------------------------------------------------------------- ledger
@app.get("/api/ledger/blocks")
def ledger_blocks(limit: int = 100, offset: int = 0, _: Operator = ANY_OPERATOR):
    return chain.blocks(min(max(limit, 1), 500), max(offset, 0))


@app.get("/api/ledger/verify")
def ledger_verify(_: Operator = ANY_OPERATOR):
    return chain.verify_chain()


# ---------------------------------------------------------------- forensics & reports
@app.post("/api/forensics/analyze")
async def analyze(file: UploadFile = File(...), op: Operator = EXAMINER):
    return forensics.analyze(op, _safe_name(file.filename or "evidence"), await _read(file))


@app.get("/api/reports")
def list_reports(_: Operator = EXAMINER):
    return forensics.list_reports()


@app.get("/api/reports/{rid}")
def get_report(rid: str, _: Operator = EXAMINER):
    r = forensics.get_report(rid)
    if not r:
        raise HTTPException(404, "not found")
    return r


@app.get("/api/reports/{rid}/pdf")
def report_pdf(rid: str, _: Operator = EXAMINER):
    p = forensics.report_pdf(rid)
    if not p or not Path(p).exists():
        raise HTTPException(404, "not found")
    return FileResponse(p, media_type="application/pdf", filename=f"{_safe_name(rid)}.pdf")


@app.post("/api/reports/verify")
def verify_report(report: dict):
    return forensics.verify_report(report)


# ---------------------------------------------------------------- demo-mode only
@app.get("/api/robustness/transforms", dependencies=[Depends(demo_only)])
def transforms():
    return [{"id": i, "name": n} for i, (n, _) in enumerate(robustness.TRANSFORMS)]


@app.get("/api/sessions/{sid}/leak", dependencies=[Depends(demo_only)])
def simulate_leak(sid: str, transform: int = 1, page: int = 0, _: Operator = EXAMINER):
    return Response(robustness.simulate_leak(sid, transform, page), media_type="image/jpeg",
                    headers={"Content-Disposition": f'inline; filename="leak-{_safe_name(sid)}.jpg"'})


@app.get("/api/sessions/{sid}/copy", dependencies=[Depends(demo_only)])
def session_copy(sid: str, _: Operator = EXAMINER):
    if not sessions.get(sid):
        raise HTTPException(404, "not found")
    return FileResponse(sessions.copy_path(sid), media_type="application/pdf", filename=f"{_safe_name(sid)}.pdf")


@app.post("/api/sessions/{sid}/robustness", dependencies=[Depends(demo_only)])
def run_robustness(sid: str, _: Operator = EXAMINER):
    return robustness.run(sid)


class TamperIn(BaseModel):
    block_index: int


@app.post("/api/demo/tamper", dependencies=[Depends(demo_only)])
def tamper(body: TamperIn, _: Operator = OFFICER):
    return chain.simulate_tamper(body.block_index)


@app.post("/api/demo/repair", dependencies=[Depends(demo_only)])
def repair(_: Operator = OFFICER):
    return chain.repair_tamper()


DEMO_OPERATORS = [("Priya Nair", "security-officer", "9000"),
                  ("Arjun Rao", "examiner", "9100"),
                  ("Meera Das", "auditor", "9200")]
DEMO_RECIPIENTS = [("EMP-1001", "Asha Verma", "Procurement", "SECRET", "1111"),
                   ("EMP-1002", "Rahul Mehta", "Legal", "SECRET", "2222"),
                   ("EMP-1003", "Kavya Iyer", "IT Security", "TOP SECRET", "3333")]


@app.post("/api/demo/seed", dependencies=[Depends(demo_only)])
def seed():
    if not auth.bootstrap_required():
        raise HTTPException(409, "installation already initialised - reset the demo first")
    name, _, pin = DEMO_OPERATORS[0]
    officer = auth.bootstrap(name, pin, _trusted=True)   # demo seed replaces the setup ceremony
    _, op = auth.login(officer["id"], pin)
    for n, role, p in DEMO_OPERATORS[1:]:
        auth.create_operator(op, n, role, p)
    ids = [identity.create_recipient(op, *r)["id"] for r in DEMO_RECIPIENTS]
    doc = documents.upload(op, "Programme Memorandum PM-2026-17", "classified_memo.pdf", sample.build(), ids)
    return {"document": doc["id"], "recipients": ids,
            "operators": {n: {"role": r, "pin": p} for n, r, p in DEMO_OPERATORS},
            "recipient_pins": {n: p for _, n, _, _, p in DEMO_RECIPIENTS}}


@app.post("/api/demo/reset", dependencies=[Depends(demo_only)])
def reset(_: Operator = OFFICER):
    db.close()
    keystore.reset_sessions()
    auth.reset()
    for sub in ("tokens", "blobs", "reports", "nodes"):
        shutil.rmtree(config.DATA_DIR / sub, ignore_errors=True)
    for f in ("sih.db", "sih.db-wal", "sih.db-shm", "master.key"):
        (config.DATA_DIR / f).unlink(missing_ok=True)
    config.reset_caches()
    references.clear()
    startup()
    return {"reset": True}


# Serve the built UI (Electron loads it from here) when present
_dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if _dist.exists():
    app.mount("/", StaticFiles(directory=_dist, html=True), name="ui")
