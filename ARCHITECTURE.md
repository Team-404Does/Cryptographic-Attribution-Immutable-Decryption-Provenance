# Architecture

This is an offline, post-quantum **document-leak attribution system**. It's the working prototype of `SIH_Full_Technical_Stack_and_Architecture.docx`.

What it does:
- It seals a PDF so that only enrolled recipients can open it.
- Every time a recipient opens it, they get a copy that looks identical but carries a unique invisible watermark for that session.
- Each decryption record is signed with the recipient's post-quantum key and committed to a tamper-evident ledger.
- From a leaked PDF, screenshot, photo or text excerpt, it recovers the **exact recipient and decryption session**, verifies the whole chain of evidence, and issues a signed report.

Everything runs on one machine. The API binds to `127.0.0.1` only, and the Electron shell blocks every non-loopback request. There is no cloud, public blockchain or network dependency.

---

## 1. System overview

```
┌──────────────────────── Electron shell (frontend/electron/main.cjs) ────────────────────────┐
│  spawns backend · blocks non-loopback requests · loads http://127.0.0.1:8765                  │
│  ┌──────────────── React 18 + Tailwind UI (frontend/src) ────────────────┐                   │
│  │ Operator console (login, role-based)      │ Recipient Secure Viewer (PIN) │               │
│  └───────────────────────────────┬───────────────────────────────────────┘                   │
└──────────────────────────────────┼───────────────────────────────────────────────────────────┘
                                   │ JSON / multipart over loopback, Bearer token for operators
┌──────────────────────────────────▼──────── FastAPI (backend/app/main.py) ───────────────────┐
│ TrustedHost + Origin guard · role dependencies (auth.py) · exception→HTTP mapping            │
├──────────────┬──────────────┬──────────────┬───────────────┬──────────────┬─────────────────┤
│ identity.py  │ documents.py │ sessions.py  │ forensics.py  │ reports.py   │ robustness.py   │
│ enrol/revoke │ seal/grant   │ decrypt+mark │ attribute     │ PDF render   │ adversarial lab │
├──────────────┴──────┬───────┴──────┬───────┴───────┬───────┴──────────────┴─────────────────┤
│ crypto/             │ watermark/   │ ledger/        │ references.py (original pages, in RAM) │
│ pqc  symmetric      │ payload      │ chain  merkle  │                                        │
│ keystore  pki       │ image_wm     │                │                                        │
│                     │ text_wm      │                │                                        │
│                     │ pdf_wm       │                │                                        │
│                     │ registration │                │                                        │
├─────────────────────┴──────────────┴───────────────┴────────────────────────────────────────┤
│ backend/data/: sih.db (SQLite) · tokens/*.token.json · blobs/*.enc · reports/ · nodes/*.head  │
│                master.key (0600) · setup-code.txt (first run only)                            │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Technology map (spec → implementation)

| Spec layer | Implementation | Where |
|---|---|---|
| Desktop UI | React 18, Tailwind 3, Vite 4, lucide-react, bundled Inter/JetBrains Mono fonts, Electron 31 | `frontend/` |
| Backend / API | Python 3.10+, FastAPI, uvicorn | `backend/app/main.py` |
| Document encryption | AES-256-GCM. A random 256-bit content key (CEK); the doc id is the AAD | `crypto/symmetric.py`, `services/documents.py` |
| PQC KEM | **ML-KEM-768** (FIPS 203) wraps the CEK per recipient: `KEK = HKDF(ss, "cek-wrap\|doc\|holder")` | `crypto/pqc.py` |
| PQC signatures | **ML-DSA-65** (FIPS 204) signs records, admin actions, ledger endorsements, certificates and reports | `crypto/pqc.py` |
| PQC backend | liboqs (`oqs`) if importable, otherwise the pure-Python `kyber-py` / `dilithium-py` | `crypto/pqc.py` |
| KDF / hashing | HKDF-SHA3-256, SHA3-256, SHAKE-256, canonical JSON for everything that gets signed | `crypto/symmetric.py` |
| Key storage | Software HSM with PKCS#11 semantics: keys generated inside, scrypt(PIN)-encrypted, exposes only `decapsulate()` / `sign()` | `crypto/keystore.py` |
| Offline PKI | Air-gapped root CA (ML-DSA) issuing JSON certificates that bind identity to token public keys | `crypto/pki.py` |
| Watermark | Keyed spread-spectrum raster + homoglyph text, framed with Reed-Solomon RS(16,8) | `watermark/` |
| Geometric recovery | ORB features + RANSAC homography onto the original page (OpenCV) | `watermark/registration.py` |
| PDF handling | PyMuPDF (render, rebuild, text layer, Story-based report PDF) | `watermark/pdf_wm.py`, `services/reports.py` |
| Ledger | Append-only hash chain with Merkle-rooted blocks, **2-of-3 ML-DSA node endorsements**, per-node signed head files | `ledger/` |
| Database | SQLite, WAL mode, one process-wide connection behind an RLock | `db.py` |
| Tests | pytest: 26 tests covering e2e, security regressions and units | `backend/tests/` |

---

## 3. Actors and access model

| Actor | Authenticates with | Can do |
|---|---|---|
| **Security officer** (operator) | Operator token + PIN → Bearer session | Enrol/revoke recipients, create/unlock operators, seal documents, grant/revoke access, demo reset/tamper |
| **Forensic examiner** (operator) | same | Leak analysis, evidence reports, leak simulator and robustness lab (demo mode only) |
| **Auditor** (operator) | same | Read and verify the ledger. All operators can read recipients, documents, the decryption log and the ledger |
| **Recipient** | Own token + PIN, per request (no session) | Decrypt documents they hold a key wrap for, from the Secure Viewer |
| Public (no auth) | — | `/api/status`, `/api/pki/ca`, operator and viewer directories, `/api/reports/verify` |

- **Operator sessions** (`auth.py`): the token id comes from `secrets.token_urlsafe(32)` and is kept only in memory. The unlocked keystore `Session` is held server-side, and the idle timeout slides to 30 minutes. `require(*roles)` is the FastAPI dependency that enforces roles.
- **Bootstrap:** the first security officer needs a one-time **setup code**, printed to the console and stored in `data/setup-code.txt`. Demo seeding skips this with `_trusted=True`.

---

## 4. Core flows

### 4.1 Enrolment (security officer)
`identity.create_recipient`:
1. Validate the input. Only one **active** identity may exist per `employee_id`; a partial unique index enforces this too.
2. `keystore.create_token`: generate ML-KEM and ML-DSA key pairs inside the token.
3. `pki.issue`: the CA signs `{subject, kem_pk, sig_pk, validity}`.
4. Insert the recipients row.
5. `chain.append([auth.sign_action(officer, "enrollment", …)])`.

Revocation and token unlock follow the same pattern: a signed action committed to the ledger.

### 4.2 Sealing (security officer)
`documents.upload`:
1. Validate the PDF: magic bytes, no password, 1–100 pages, render size under `MAX_IMAGE_PIXELS`.
2. Generate a random CEK and write `blobs/<doc>.enc = AES-GCM(CEK, pdf, aad=doc_id)`.
3. Wrap the CEK for the **custodian** system token (escrow, so later grants are possible) and for each selected recipient using their certificate's ML-KEM key.
4. Commit **one block** holding a `document-registration` event plus one `grant` event per recipient, all officer-signed.

### 4.3 Decryption session (recipient, `sessions.decrypt`)
```
login(token, PIN) → decapsulate(kem_ct) → KEK → CEK → AES-GCM decrypt → check SHA3 == registered hash
  → nonce(16B), timestamp(µs) → wm_id = HKDF(recipient ‖ doc_hash ‖ nonce ‖ ts, salt=watermark_key)[:6]
  → pdf_wm.watermark_pdf(plain, wm_id, key)            # raster burn-in + homoglyph text layer
  → record{session, recipient, cert_fp, doc, doc_hash, copy_hash, wm_id, nonce, ts, device_fp, algs}
  → record_hash = SHA3(canonical(record)); signature = token.sign(record_hash)   # ML-DSA-65
  → chain.append([{type:"decryption", record, record_hash, signature}])
  → one-time download token (in memory, 10 min). The copy file is kept only in demo mode.
```
Decryption is refused if the identity is revoked, the certificate is invalid, or there is no key wrap. The steps and timings come back in `trace` for the UI.

### 4.4 Attribution (examiner, `forensics.analyze`)
```
evidence ─┬─ PDF   → per page: embedded raster (or render) → extract_image ; text layer → text channel
          ├─ image → extract_image
          └─ text  → text channel
extract_image: blind full-page decode ──fail──► registration against reference pages
               (references.all_pages: originals decrypted via custodian, cached in RAM)
votes → majority wm_id → find ledger event (sessions table is only an index; falls back to a ledger scan)
verify: record hash · recipient ML-DSA signature · certificate (valid at decryption time) · cert bound to
        record · officer-signed enrolment (role-checked) · block integrity · Merkle inclusion proof ·
        full chain audit + node consensus
identity (name, employee id, clearance) comes from the CA-signed certificate; revocation from the ledger
verdict → report JSON signed twice (forensic service key + examiner's own token) → PDF rendering
```

**Verdicts** (`forensics.py`):

| Verdict | Meaning |
|---|---|
| `ATTRIBUTED` | Every check passed, and the raster channel found the mark with no conflicting IDs |
| `ATTRIBUTED_WITH_WARNINGS` | The record is cryptographically valid, but the evidence is text-only or conflicting, the enrolment check failed, or the wider chain audit failed |
| `EVIDENCE_COMPROMISED` | The ledger record for this watermark no longer verifies: it was tampered with |
| `UNKNOWN_WATERMARK` | A valid keyed mark was found but no ledger record exists for it |
| `NO_WATERMARK` | Nothing could be decoded |

Warnings are added when another identity shares the display name, when the identity was revoked, and when channels disagree.

---

## 5. Watermarking in detail (`backend/app/watermark/`)

**Frame (`payload.py`)**
- Layout: `wm_id(6B) ‖ HMAC-SHA3(key, wm_id)[:2] ‖ RS parity(8B)` = 16 bytes = 128 bits.
- The bits are XOR-whitened with `SHAKE(key)`, so a valid frame can't be forged without the installation's embedding key, `hkdf(master, "watermark-embedding-key-v1")`.
- RS corrects up to 4 byte errors.

**Raster channel (`image_wm.py`)**
- The page is resized to a canonical width of **1240 px** (A4 at 150 dpi) and divided into 16×16-pixel cells.
- Each cell carries one frame bit, modulated onto a keyed ±1 pseudo-random pattern made of 4×4 chips, at an amplitude of **±3 grey levels** (PSNR ≈ 37 dB).
- A keyed permutation scatters the bits, giving about 30 repetitions per bit.
- Decoding: a high-pass residual, clipped to ±12, is correlated with the pattern. The correlations are summed per bit, then the signs go to RS decoding.
- `valid` masks restrict decoding to the cells the evidence actually covers.

**Text channel (`text_wm.py`)**
- Each eligible Latin letter carries one frame bit: 0 is the original letter, 1 is a visually identical Cyrillic or Greek homoglyph.
- The frame repeats back to back through the text. The decoder tries all 128 phases and takes a majority vote. It needs at least 128 eligible characters.
- Retyping the text, or normalising confusable characters, destroys it.

**PDF (`pdf_wm.py`)**
- Each output page is the 150 dpi render with the raster mark burned in.
- On top sits an invisible text layer (render mode 3, Noto Sans) that keeps the page searchable and carries the homoglyph channel.

**Registration (`registration.py`)**
- Match ORB features (about 6k on the reference, about 8k on the evidence), apply the Lowe ratio test at 0.78, fit a RANSAC homography (3 px), then refine it on the inliers.
- Warp the evidence onto the page grid, erode the coverage mask, and decode only the covered cells.
- Recovers crops down to about 25% of the page, rotations, perspective photos and screenshots that include the viewer's chrome.

---

## 6. Ledger (`backend/app/ledger/`)

Each block is stored like this:
- `header = {version, index, prev_hash, timestamp, merkle_root, event_count}`
- `block_hash = SHA3(canonical(header))`
- `merkle_root` covers `leaf = SHA3(0x00 ‖ canonical(event))` for every event in the block

**Rules:**
- **Quorum:** a block is admitted only when at least `LEDGER_QUORUM=2` of the nodes (`legal`, `it-security`, `compliance`) produce valid ML-DSA endorsements.
- **Node views:** after each append, every node signs its own head file, `nodes/<node>.head.json`. `node_health()` cross-checks these against the shared chain: *in-sync*, *stale* or *DIVERGED*.
- **Audit:** `verify_chain()` recomputes each block's Merkle root, header hash, previous link and quorum. Signature checks go through `_verify_cached` (an lru_cache on pk, msg and sig), so repeated audits are cheap, and tampering always misses the cache.

**Event types:** `genesis`, `operator-enrollment`, `operator-unlock`, `enrollment`, `revocation`, `token-unlock`, `document-registration`, `grant`, `access-revocation`, `decryption`.

**Signed admin actions:** these events have the shape `{type, body:{action, payload, operator_id, operator_role, operator_cert_fingerprint, at}, signature}`. `auth.verify_action` checks four things:
- the signature against the operator's certificate,
- that the certificate was valid at signing time,
- that `type == body.action`,
- that the signer's role may perform that action (`ACTION_ROLES`).

Demo helpers `simulate_tamper` and `repair_tamper` edit `blocks.events` directly, as an insider would, and keep per-block backups in `nodes/tamper_backup.json`.

---

## 7. Data model (`db.py`, `SCHEMA_VERSION = 2`)

| Table | Key columns |
|---|---|
| `operators` | id `opr-…`, name, role, token_label, cert (JSON), created_by |
| `recipients` | id `rcp-…`, employee_id (unique among active), name, department, clearance, cert, enrolled_by, status, revoked_* |
| `documents` | id `doc-…`, title, sha3, pages, blob_path, created_by |
| `key_wraps` | (doc_id, recipient_id or `document-custodian`), kem_ct, wrapped_cek, granted_by |
| `sessions` | id `ses-…`, wm_id (unique), doc_id, recipient_id, record, record_hash, signature, block_index. **This is an index only**; the ledger is the source of truth |
| `blocks` | idx, header, block_hash, events (JSON), endorsements (JSON) |
| `reports` | id `rpt-…`, verdict, wm_id, report (JSON), pdf_path, created_by |

A database created by an older schema version raises `SchemaMismatch` at startup. To recover, delete `backend/data/` (or reset the demo).

**System tokens** (created on first use, PIN = `hkdf(master, "system-pin:"+label)`):
- `offline-root-ca`
- `document-custodian`
- `forensic-examiner`, the service key for reports
- `ledger-node-{legal,it-security,compliance}`

---

## 8. Security controls

| Threat | Control |
|---|---|
| Unauthorised enrolment or grants | Officer role required; every action signed and on the ledger |
| Duplicate or impersonated identity | One active identity per employee id; reports use the CA-signed certificate subject, not database columns; namesake warnings |
| Framing with a known watermark ID | Keyed frame (HMAC check + whitening); text-only evidence can't reach `ATTRIBUTED` |
| Insider edits the ledger | Merkle, header and link checks, 2-of-3 endorsements, node head cross-check; attribution becomes `EVIDENCE_COMPROMISED` |
| CSRF / DNS rebinding against localhost | `TrustedHostMiddleware` (`SIH_ALLOWED_HOSTS`); Origin guard refuses cross-origin POST, PUT and DELETE; CORS only with `SIH_DEV=1` |
| PIN brute force / lockout DoS | Attempt reserved before scrypt; after 5 failures a **temporary** lockout (5 min, doubling, capped at 24 h); officer unlock |
| First-run takeover | Bootstrap needs the one-time setup code |
| Resource exhaustion | 50 MB upload cap; PDFs ≤ 100 pages with a render-size check; images ≤ 60 MP, checked before decode |
| Copy exfiltration from the server | Single-use in-memory download links (10 min); copies are retained only in demo mode |
| Header injection | `_safe_name()` sanitises download filenames |

**Known limitations** (by design, or not yet built):
- `master.key` is a plain 0600 file, standing in for an HSM, so root on the host defeats everything.
- The text channel can be stripped.
- Tiny, heavily downscaled fragments can't be decoded.
- Recipient copies are 150 dpi raster pages, not the original vectors.
- The ledger runs on a single host; production would use Hyperledger Fabric with RAFT or PBFT.

---

## 9. Frontend (`frontend/src/`)

| File | Role |
|---|---|
| `App.jsx` | Hash router (`#/page`), theme (`data-theme`, remembered in localStorage), role-filtered sidebar, top bar, user menu. `#/viewer` is the standalone recipient surface |
| `api.js` | Fetch wrapper: adds the Bearer token (sessionStorage), clears the session on 401, `download()`/`saveBlob()` for authenticated files, `ROLE_LABEL` |
| `components/ui.jsx` | Design-system primitives: Button, Badge, Card, Stat, Modal, Drawer, Confirm, Table, Tabs, Hash (copyable), KV, CheckRow, Alert, toasts, `useLoad`/`useAction` hooks |
| `components/events.jsx` | Ledger event metadata (label, icon, tone) and `describe()` for human-readable activity lines |
| `components/ReportView.jsx` | Verdict banner, pipeline stages, attribution card, chain-of-evidence checklist, channels table, signatures |
| `pages/*` | Login (bootstrap, demo seed, sign-in), Dashboard, Recipients, Operators, Documents, Sessions, Ledger, Forensics, Reports, Robustness, Viewer |

**Styling:** design tokens are CSS variables (RGB triplets) in `index.css` for light and dark, exposed as Tailwind colours (`bg`, `surface`, `inset`, `line`, `fg`, `muted`, `subtle`, `accent`, `ok`, `bad`, `warn`, `info`). Runtime tone classes (`text-${tone}`, `bg-${tone}/10`) are safelisted in `tailwind.config.cjs`.

**CSP** (`index.html`): `default-src 'self'`, and `connect-src` allows the loopback API, plus `font-src data:` for the bundled fonts.

---

## 10. API reference (`backend/app/main.py`)

Role key: 🔓 public · 🔑 recipient PIN · 👤 any operator · 🛡 security officer · 🔍 examiner · 🧪 demo mode only.

| Method & path | Access | Purpose |
|---|---|---|
| GET `/api/status` | 🔓 | Counts, ledger health, PQC backend, `demo_mode`, `bootstrap_required` |
| GET `/api/pki/ca` | 🔓 | Root CA certificate |
| GET `/api/auth/operators` | 🔓 | Operator directory (id, name, role) for the login picker |
| POST `/api/auth/bootstrap` | 🔓 + setup code | Create the first security officer |
| POST `/api/auth/login` · `/logout` · GET `/me` | 🔓 / 👤 | Operator session |
| GET/POST `/api/operators`, POST `/api/operators/{id}/unlock` | 🛡 | Manage operators |
| GET `/api/recipients`, GET `/api/recipients/{id}` | 👤 | List / detail (with certificate status) |
| POST `/api/recipients`, `/{id}/revoke`, `/{id}/unlock` | 🛡 | Enrol / revoke / unlock |
| GET `/api/documents` | 👤 | Documents with access lists |
| POST `/api/documents` (multipart), `/{id}/grant`, `/{id}/revoke` | 🛡 | Seal / grant / revoke access |
| GET `/api/viewer/directory` | 🔓 | Documents and active recipients for the viewer |
| POST `/api/sessions/decrypt` | 🔑 | Run a decryption session → trace + `download_url` |
| GET `/api/downloads/{token}` | single-use token | Fetch the watermarked copy |
| GET `/api/sessions` | 👤 | Decryption log |
| GET `/api/ledger/blocks`, `/api/ledger/verify` | 👤 | Blocks / full audit |
| POST `/api/forensics/analyze` (multipart) | 🔍 | Attribute evidence |
| GET `/api/reports`, `/{id}`, `/{id}/pdf` | 🔍 | Evidence reports |
| POST `/api/reports/verify` | 🔓 | Re-verify an exported JSON report |
| GET `/api/robustness/transforms`, `/api/sessions/{id}/leak`, `/api/sessions/{id}/copy`; POST `/api/sessions/{id}/robustness` | 🧪 🔍 | Leak simulator / robustness lab |
| POST `/api/demo/seed` | 🧪 (fresh install only) | Provision the demo environment |
| POST `/api/demo/reset`, `/tamper`, `/repair` | 🧪 🛡 | Wipe / simulate insider edit / restore |

Interactive OpenAPI docs are served at `/docs`.

---

## 11. Configuration (`backend/app/config.py`, environment variables)

| Variable | Default | Effect |
|---|---|---|
| `SIH_DATA_DIR` | `backend/data` | All state (DB, tokens, blobs, reports, node heads, master key) |
| `SIH_DEMO` | off | Enables demo endpoints, copy retention, leak simulator and robustness lab |
| `SIH_DEV` | off | Enables CORS for the Vite dev server on :5173 |
| `SIH_ALLOWED_HOSTS` | `127.0.0.1,localhost` | Host header allow-list (tests add `testserver`) |
| `SIH_PORT` | `8765` | Port used to build the allowed origins (uvicorn's port is set in `run.sh`) |
| `SIH_PYTHON` | `.venv/bin/python` | Python interpreter Electron uses to spawn the backend |
| `SIH_UI_URL` | `http://127.0.0.1:8765/` | URL Electron loads (`electron:dev` points it at Vite) |
| `SIH_SMOKE` | — | Electron smoke test: hidden window, save a PNG capture, quit |

Tunables in `config.py`: `LEDGER_NODES`, `LEDGER_QUORUM`, `MAX_PIN_ATTEMPTS`, `OPERATOR_SESSION_TTL`, `DOWNLOAD_TTL`, `MAX_PDF_PAGES`, `MAX_IMAGE_PIXELS`.
