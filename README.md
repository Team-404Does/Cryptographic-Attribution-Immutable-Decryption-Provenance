# Cryptographic Attribution and Immutable Decryption Provenance for Multi-Recipient Encrypted Document Distribution

> **Smart India Hackathon 2026 · PS ID 26237** · Offline, post-quantum document-leak attribution

This is an offline, post-quantum document-leak attribution system. It is the working prototype of *SIH_Full_Technical_Stack_and_Architecture.docx*.

Every decryption of a protected PDF produces a copy that looks the same as the original but carries a unique forensic watermark for that session. The system signs the decryption record with the recipient's **ML-DSA** key and commits it to a tamper-evident ledger. The ledger is endorsed by several nodes and uses Merkle trees and a hash chain.

Suppose a screenshot, recompressed image, print-scan or pasted excerpt leaks. The forensic engine recovers the watermark and resolves the **exact recipient and decryption session**. It verifies the whole chain of evidence and issues a signed PDF and JSON report.

No cloud KMS, public blockchain or network is involved. The backend listens on `127.0.0.1` only, and the Electron shell blocks every non-loopback request.

> **New here (human or agent)?** Read [`START.md`](START.md) first, then [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Quick start

```bash
./run.sh setup      # python venv + pip deps, npm install + UI build   (Windows: run.bat setup)
./run.sh demo       # demo mode on http://127.0.0.1:8765 (seed/reset/tamper, leak simulator, robustness lab)
./run.sh backend    # production mode: no demo helpers, first run needs the console setup code
./run.sh desktop    # Electron app (DEMO=1 ./run.sh desktop for demo mode)
./run.sh dev        # backend with --reload + Vite dev server on :5173
./run.sh test       # pytest suite (26 tests incl. security regressions)
```

Works on Linux/macOS (Git Bash) with `run.sh` and on Windows with `run.bat` (same commands).
Once a demo server is running, `scripts/e2e_check.py` (stdlib only) exercises the full chain:
operator logins → recipient decrypt → leak simulation → forensic attribution → report re-verification.

**Demo mode.** On first launch, click **Load demo environment**. It creates:

| Who | Role | PIN |
|---|---|---|
| Priya Nair | Security officer: enrols people, seals documents, grants access | 9000 |
| Arjun Rao | Forensic examiner: leak analysis, evidence reports | 9100 |
| Meera Das | Auditor: ledger inspection | 9200 |
| Asha Verma / Rahul Mehta / Kavya Iyer | Recipients (EMP-1001/2/3), used in the **Secure Viewer** | 1111 / 2222 / 3333 |

**Production mode.** There's no demo data. The server prints a one-time **setup code** at start-up (also saved in `backend/data/setup-code.txt`). Enter it to create the first security officer.

## Access model & security controls

- **Operators log in** with their own PIN-protected ML-DSA token and get a bearer session with a 30-minute idle timeout. Roles are enforced on every endpoint:
  - Security officer: enrol and revoke identities, create operators, seal documents, grant and revoke access.
  - Examiner: forensics and reports.
  - Auditor: the ledger. All operators can read the ledger and the decryption log.
- **Recipients** only use the Secure Viewer. Decrypting needs their PIN, a key wrap for that document, an active identity, and a valid certificate.
- **Every administrative action is signed and on the ledger.** Enrolment, revocation, grants, document registration, operator creation and unlocks are signed by the acting officer's token. Forensics checks that the identity's enrolment was signed by an authorised officer.
- **Identities can't be duplicated or faked.** Each employee ID can have only one *active* identity, and re-enrolment requires revocation first. Reports take identity from the **CA-signed certificate**, not editable database fields. If another identity shares a display name, the report shows a warning.
- **Watermarks are keyed.** Frames are whitened and HMAC-checked with the installation's embedding key, so knowing a watermark ID from the ledger isn't enough to forge evidence against someone. Text-only or conflicting evidence yields ATTRIBUTED_WITH_WARNINGS, not ATTRIBUTED.
- **Copies are delivered once.** Each decrypted copy is served through a single-use download link that expires after 10 minutes. Only its hash is kept, except in demo mode.
- **Browser hardening.** A Host allow-list blocks DNS rebinding. Cross-origin state-changing requests are refused (CSRF). CORS is only enabled in `dev` mode.
- **PIN brute force.** Five wrong PINs trigger a temporary, exponentially growing lockout. It can't be used to brick a token permanently, and an officer can unlock early. Attempts are reserved before scrypt runs, so parallel guessing is still capped.
- **Resource limits.** Uploads are capped at 50 MB. PDFs are limited to 100 pages and a maximum rendered page size. Images are limited to 60 MP.
- **Demo helpers.** Seed, reset, tamper, the leak simulator, retained copies and the robustness lab are disabled unless `SIH_DEMO=1`. Reset and tamper also require a security officer.

## Architecture

```
React + Electron (offline UI) ──► FastAPI (127.0.0.1:8765)
                                     │
      ┌──────────────┬───────────────┼────────────────┬──────────────────┐
  AES-256-GCM     ML-KEM-768      ML-DSA-65      Offline CA + PKCS#11-style token
      └──────────────┴───────┬───────┴────────────────┘
                             ▼
     Watermark engine: HKDF seed → RS(16,8) → spread-spectrum raster + homoglyph text
                             ▼
     Visually identical recipient copy ──► LEAK ──► extraction + ECC recovery
                             ▼
     Merkle / hash-chain ledger (2-of-3 endorsed) ──► signed evidence report (PDF/JSON)
```

| Spec layer | Implementation | Code |
|---|---|---|
| Frontend / desktop | React 18 + Tailwind + Electron (air-gap request filter) | `frontend/` |
| Backend / API | Python + FastAPI | `backend/app/main.py` |
| Document encryption | AES-256-GCM, random 256-bit content key, doc-id as AAD | `crypto/symmetric.py`, `services/documents.py` |
| PQC KEM | ML-KEM-768: content key wrapped per recipient via HKDF-derived KEK | `crypto/pqc.py` |
| PQC signatures | ML-DSA-65 over SHA3-256 of each decryption record | `crypto/pqc.py`, `services/sessions.py` |
| Key derivation | `HKDF-SHA3(recipient_id ‖ doc_hash ‖ nonce ‖ timestamp)` → 48-bit watermark ID | `services/sessions.py` |
| Hashing | SHA3-256 (records, blocks, Merkle), SHAKE-256 (frame check, record digest) | |
| Watermark: raster | Keyed spread-spectrum ±1 chips in 16×16 cells on a canonical grid, repeated ~30× per bit across the page | `watermark/image_wm.py` |
| Watermark: text | Homoglyph substitution (Latin → Cyrillic/Greek look-alikes) in the searchable text layer | `watermark/text_wm.py` |
| Error correction | Reed-Solomon RS(16,8): fixes 4 byte errors, plus a SHAKE check field against false positives | `watermark/payload.py` |
| PDF handling | PyMuPDF: render, burn in the mark, rebuild the invisible text layer | `watermark/pdf_wm.py` |
| Offline PKI | Air-gapped root CA issuing ML-DSA-signed certificates that bind identity to token keys | `crypto/pki.py` |
| Secure key storage | Software HSM with a PKCS#11-style interface: keys are generated inside the token, scrypt-PIN encrypted, lock out after 5 wrong PINs, and are exposed only as `decapsulate` / `sign` | `crypto/keystore.py` |
| Ledger | Append-only hash chain with Merkle roots and inclusion proofs. Each block needs **2-of-3 ML-DSA endorsements** (legal / IT security / compliance). Every node keeps a signed head view for divergence alarms | `ledger/` |
| Database | SQLite (identities, documents, key wraps, session index, blocks, reports) | `db.py` |
| Forensics | Multi-channel blind extraction → consensus → ledger lookup (the ledger is the source of truth, not the session table) → full verification | `services/forensics.py` |
| Reporting | ML-DSA-signed canonical JSON evidence plus a rendered PDF; `POST /api/reports/verify` re-checks exported reports | `services/reports.py` |
| Testing | pytest end-to-end and unit tests, plus the adversarial transformation harness | `backend/tests/`, `services/robustness.py` |

**PQC backend.** When liboqs (`oqs`, from Open Quantum Safe) is importable, the system uses it. Otherwise it falls back to the pure-Python FIPS 203/204 reference implementations (`kyber-py`, `dilithium-py`). Both produce standard-size keys, ciphertexts and signatures, so the prototype runs on any air-gapped machine without a native build.

### Differentiators implemented (Tier 3)
- **Threshold attribution**: a block enters the ledger only after a k-of-n ML-DSA endorsement quorum.
- **Adversarial robustness suite**: screenshots at 96/72 dpi, JPEG down to q25, 0.5×–1.5× scaling, blur, noise, greyscale, contrast, median denoise, print-scan and photo-of-screen models, and text excerpts.
- **Self-auditing ledger health**: each node's signed head is cross-checked against the shared chain.
- **Verifiable, legal-grade evidence**: a signed JSON package with a Merkle inclusion proof and chain audit, plus a PDF rendering.

### Known limitations / production path
- **Informed registration.** When blind extraction fails, forensics matches ORB features of the evidence against the original pages (decrypted in memory by the custodian token). It then fits a RANSAC homography and decodes only the covered cells. This recovers crops down to about 25% of the page, rotations, perspective phone photos and screenshots that include the PDF viewer's chrome. Very small, heavily downscaled fragments still carry too little signal.
- Retyping removes the homoglyph channel. The planned mitigation is canary facts: session-specific plausible wording.
- The pages of a recipient copy are 150 dpi raster images with an invisible text layer on top, so they are not the original vector content.
- Production path: replace the software token with a YubiKey, TPM, HSM or smart card. Replace the single-host ledger with Hyperledger Fabric using RAFT or PBFT ordering, and the JSON certificates with X.509 ML-DSA certificates from OpenSSL 3.5 or EJBCA.

## API summary
`GET /api/status` · `POST /api/recipients` · `POST /api/documents` (multipart) · `POST /api/documents/{id}/grant` · `POST /api/sessions/decrypt` · `GET /api/sessions/{id}/copy` · `GET /api/sessions/{id}/leak?transform=N` · `POST /api/sessions/{id}/robustness` · `GET /api/ledger/blocks` · `GET /api/ledger/verify` · `POST /api/forensics/analyze` (multipart) · `GET /api/reports/{id}[/pdf]` · `POST /api/reports/verify` · `POST /api/demo/{seed,reset,tamper,repair}`. Interactive docs are at `/docs`.
