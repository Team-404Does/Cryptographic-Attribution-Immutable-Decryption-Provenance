# START HERE

Onboarding for humans and AI agents. Read this first, then `ARCHITECTURE.md` for the design. `README.md` is the user-facing overview. The original brief is `SIH_Full_Technical_Stack_and_Architecture.docx`.

## What this project is, in one paragraph
This is an offline document-leak attribution system for Smart India Hackathon (SIH). Security officers seal PDFs, encrypted with AES-256-GCM and with a key wrapped per recipient using ML-KEM-768. Each time a recipient decrypts one, they get a copy with a **unique invisible watermark for that session**. The decryption record is **signed with ML-DSA-65** and committed to a **2-of-3-endorsed Merkle hash-chain ledger**. Examiners upload a leaked PDF, screenshot, photo or text excerpt, and the system names the **exact recipient and session**, verifies the whole chain of evidence, and outputs a dual-signed JSON and PDF report. The backend is Python/FastAPI (`backend/`) and the UI is React + Tailwind + Electron (`frontend/`).

---

## 1. Prerequisites
- Python 3.10+ (a virtualenv lives at `.venv/`)
- Node 16+ (Vite is pinned to 4.x because this machine runs Node 16.10)
- No network is needed at runtime

## 2. Setup and run

```bash
./run.sh setup     # create .venv, pip install -r requirements.txt, npm install, build frontend/dist
./run.sh demo      # backend + built UI at http://127.0.0.1:8765 with demo helpers (SIH_DEMO=1)
./run.sh backend   # production mode (no demo helpers; first run prints a one-time setup code)
./run.sh desktop   # Electron app, which spawns the backend itself (DEMO=1 ./run.sh desktop for demo)
./run.sh dev       # uvicorn --reload + Vite dev server on :5173 (SIH_DEMO=1 SIH_DEV=1)
./run.sh test      # pytest backend/tests (expect: 26 passed)
```

Manual equivalents:
```bash
cd backend && SIH_DEMO=1 ../.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8765
cd frontend && npm run build          # the backend serves frontend/dist at /
.venv/bin/python -m pytest backend/tests -q
```

## 3. Demo credentials
These exist after **Load demo environment** on the first-run screen, or `POST /api/demo/seed` on a fresh install in demo mode.

| Name | Role | PIN |
|---|---|---|
| Priya Nair | security-officer | 9000 |
| Arjun Rao | examiner | 9100 |
| Meera Das | auditor | 9200 |
| Asha Verma (EMP-1001) | recipient | 1111 |
| Rahul Mehta (EMP-1002) | recipient | 2222 |
| Kavya Iyer (EMP-1003) | recipient | 3333 |

**Recipient flow:** open `#/viewer`, pick a document, pick an identity, enter the PIN, then download the copy (single-use link).
**Attribution flow:** sign in as the examiner and go to **Leak analysis**. Drop in the copy or a screenshot of it, or use the leak simulator.

## 4. Repository map

```
backend/app/
  main.py            FastAPI routes, middleware (TrustedHost, Origin guard), demo endpoints, static UI mount
  config.py          env vars, limits, data paths, master secret
  auth.py            operators, bearer sessions, require(role), signed admin actions, bootstrap/setup code
  db.py              SQLite schema v2, single locked connection, SchemaMismatch
  crypto/  pqc.py (ML-KEM/ML-DSA, liboqs or pure-python) · symmetric.py (AES-GCM, HKDF, SHA3, canonical JSON)
           keystore.py (PIN software HSM, lockout) · pki.py (offline CA, certificates)
  watermark/ payload.py (keyed RS frame) · image_wm.py (raster) · text_wm.py (homoglyphs)
             pdf_wm.py (PDF embed/extract) · registration.py (ORB + homography)
  ledger/  chain.py (blocks, quorum, audit, node health, tamper demo) · merkle.py
  services/ identity · documents · sessions (decrypt) · forensics · reports (PDF) · references (original pages)
            robustness (adversarial suite + leak simulator) · sample (demo PDF)
backend/tests/       conftest (temp data dir, demo on, role fixtures) · test_e2e · test_security · test_units
frontend/src/        App.jsx (router/shell) · api.js · components/ (ui kit, ReportView, events) · pages/
frontend/electron/main.cjs   Electron shell (spawns backend, air-gap request filter, SIH_SMOKE)
scripts/make_sample_pdf.py   writes samples/classified_memo.pdf
backend/data/        runtime state (gitignored). Deleting it resets everything
```

## 5. Invariants: do not break these
1. **Everything signed is hashed via `crypto.symmetric.canonical()`.** Never sign `json.dumps` output directly, and never change `canonical()`: old signatures would stop verifying.
2. **The ledger is the source of truth.** The `sessions` table is only an index. Forensics must resolve identity from the ledger event plus the **CA-signed certificate subject**, never from mutable database columns like `recipients.name`.
3. **Every privileged state change must be a signed ledger event** (`auth.sign_action` then `chain.append`). If you add a new action type, add it to `auth.ACTION_ROLES`, `frontend/src/components/events.jsx` and the tests.
4. **Watermark frames are keyed.** Always pass `sessions.watermark_key()` to `payload`, `image_wm`, `text_wm` and `pdf_wm`. Changing `payload.py`, the layout constants in `image_wm.py` (`CANON_W`, `CELL`, `BLOCK`) or the HKDF labels invalidates every copy issued so far.
5. **Private keys never leave `keystore.Session`.** Use `session.decapsulate()` or `session.sign()`, and don't add getters for raw keys.
6. **New endpoints need an explicit access level:** `Depends(require(...))`, `demo_only`, or deliberately public. State-changing requests must stay behind the Origin guard (all non-GET requests are, automatically).
7. **The API stays loopback-only.** Don't widen `ALLOWED_HOSTS` or CORS by default.
8. **Schema changes:** bump `db.SCHEMA_VERSION`. Old data dirs then fail fast with `SchemaMismatch` (there are no migrations; demo data is disposable).
9. **Tests must stay green:** `./run.sh test`. Add a regression test in `test_security.py` for every security fix.

## 6. Common tasks: where to change things

| Task | Touch |
|---|---|
| New API endpoint | `main.py` (route + access), a service in `services/`, a test |
| New ledger event type | service code → `auth.sign_action`; `auth.ACTION_ROLES`; `events.jsx` (label, icon, `describe`) |
| Change the verdict logic | `services/forensics.py:analyze` (plus `ReportView.jsx` and `reports.py` if you add fields) |
| New leak transformation for the lab | `services/robustness.py:TRANSFORMS` |
| Tune watermark strength or robustness | `image_wm.py` (`AMPLITUDE`, residual filter); re-run the robustness suite |
| New UI page | `frontend/src/pages/X.jsx` plus a `NAV` entry in `App.jsx` (roles, demo flag) |
| Styling / theme | CSS variables in `frontend/src/index.css`, colours in `tailwind.config.cjs` |
| Swap in native liboqs | `pip install liboqs-python` (needs the liboqs C library). `crypto/pqc.py` picks it up automatically |

## 7. Verifying your change
```bash
./run.sh test                                              # 26 backend tests
cd frontend && npm run build                               # UI compiles
curl -s 127.0.0.1:8765/api/status                          # server up (when running)
SIH_DEMO=1 SIH_SMOKE=/tmp/shot.png npx electron .          # (in frontend/) Electron smoke test, stop the server first
```
The robustness suite (examiner, Robustness lab, or `POST /api/sessions/{id}/robustness`) should report **25/28**. The three expected failures are: the tiny 18% downscaled crop, a text excerpt under capacity, and retyped text.

## 8. Gotchas
- **Wiping the data dir changes the master key**, so all old watermarks and tokens become unreadable. That's intended.
- **Demo reset requires a security officer login.** On a fresh install, seeding works only while `bootstrap_required` is true.
- **Test client host:** tests use host `testserver`, which is allowed via `SIH_ALLOWED_HOSTS` in `tests/conftest.py`. Requests through a real browser must use `127.0.0.1` or `localhost`.
- **Pure-Python PQC is slow-ish** (tens of ms per operation). Ledger audits memoise signature checks, so don't remove `_verify_cached`.
- **Node 16:** don't upgrade Vite past 4.x, and don't add packages that need Node 18 at build time.
- **`pkill -f uvicorn`-style commands can kill your own shell** in some agent harnesses. Stop servers by their task or PID instead.
- **Evidence PDFs are downloaded through authenticated fetches** (`api.download`). Plain `<a href>` links won't carry the Bearer token.
