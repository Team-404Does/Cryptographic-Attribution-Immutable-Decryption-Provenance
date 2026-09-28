"""Evidence report rendering (PDF). The signed JSON report is the canonical artifact;
the PDF is a human-readable rendering that embeds the report hash and signature."""
from __future__ import annotations

import html
import io

import pymupdf

CSS = """
* { font-family: sans-serif; }
body { font-size: 9.5pt; color: #1b2330; }
h1 { font-size: 17pt; margin: 0 0 2pt 0; }
h2 { font-size: 11.5pt; margin: 12pt 0 4pt 0; color: #23406e; border-bottom: 0.5pt solid #9aa9c2; }
.sub { color: #5a6578; font-size: 9pt; }
.verdict { font-size: 13pt; font-weight: bold; padding: 6pt; margin-top: 8pt; }
.ok { color: #0f6b3a; } .bad { color: #a4161a; } .warn { color: #8a5a00; }
table { border-collapse: collapse; width: 100%; }
td { padding: 2.5pt 4pt; vertical-align: top; border-bottom: 0.3pt solid #d5dbe5; }
td.k { width: 34%; color: #4a5568; }
.mono { font-family: monospace; font-size: 7.5pt; }
"""

_VERDICT_CLASS = {"ATTRIBUTED": "ok", "ATTRIBUTED_WITH_WARNINGS": "warn"}


def _e(v) -> str:
    return html.escape(str(v))


def _table(rows: list[tuple[str, object]], mono: bool = False) -> str:
    cls = ' class="mono"' if mono else ""
    body = "".join(f'<tr><td class="k">{_e(k)}</td><td{cls}>{_e(v)}</td></tr>' for k, v in rows)
    return f"<table>{body}</table>"


def _mark(v: bool) -> str:
    return "PASS" if v else "FAIL"


def _html(r: dict) -> str:
    v = r["verdict"]
    parts = [
        "<h1>Forensic Attribution &amp; Evidence Report</h1>",
        f'<p class="sub">Report {_e(r["report_id"])} &middot; generated {_e(r["generated_at"])} &middot; '
        "Offline PQC Leak Attribution System</p>",
        f'<p class="verdict {_VERDICT_CLASS.get(v, "bad")}">Verdict: {_e(v)}</p>',
        f"<p>{_e(r['summary'])}</p>",
        "".join(f'<p class="warn">Warning: {_e(w)}</p>' for w in r.get("warnings", [])),
        _table([("Examiner", f'{r["examiner"]["name"]} ({r["examiner"]["operator_id"]})')]) if r.get("examiner") else "",
        "<h2>1. Evidence item</h2>",
        _table([("File", r["evidence"]["filename"]), ("Type", r["evidence"]["type"]),
                ("Size (bytes)", r["evidence"]["size"]), ("SHA3-256", r["evidence"]["sha3"])]),
        "<h2>2. Watermark extraction</h2>",
        _table([(f'{c["channel"]} - {c["location"]}',
                 f'{c["wm_id"] or "not recovered"}  ' + ", ".join(f"{k}={val}" for k, val in c["detail"].items()))
                for c in r["extraction"]["channels"]]),
        _table([("Recovered watermark ID", r["extraction"]["watermark_id"] or "-"),
                ("Agreeing channels", r["extraction"]["agreeing_channels"])]),
    ]
    if "attribution" in r:
        a, c, lg = r["attribution"], r["verification"], r["ledger"]
        parts += [
            "<h2>3. Attribution</h2>",
            _table([("Recipient", f'{a["recipient_name"]} ({a["recipient_id"]})'),
                    ("Employee ID / certificate", f'{a.get("employee_id")} / serial {a.get("cert_serial")}'),
                    ("Identity status", a.get("identity_status")),
                    ("Department / clearance", f'{a["department"]} / {a["clearance"]}'),
                    ("Decryption session", a["session_id"]), ("Decrypted at (UTC)", a["decrypted_at"]),
                    ("Document", f'{a["document_id"]}  sha3={a["document_hash"]}'),
                    ("Device fingerprint", a["device_fingerprint"]), ("Session nonce", a["session_nonce"])]),
            "<h2>4. Cryptographic verification</h2>",
            _table([("Record hash (SHA3-256) recomputed", _mark(c["record_hash_ok"])),
                    ("Recipient ML-DSA signature over record", _mark(c["ml_dsa_signature_ok"])),
                    ("Recipient certificate (offline CA)", _mark(c["certificate"].get("valid", False))),
                    ("Certificate bound to record", _mark(c["cert_fingerprint_matches_record"])),
                    ("Officer-signed enrolment of this identity", _mark(c.get("enrollment_ok", False))),
                    ("Ledger block integrity", _mark(c["block_integrity_ok"])),
                    ("Merkle inclusion proof", _mark(c["merkle_inclusion_ok"])),
                    ("Full chain integrity + node consensus", _mark(c["chain_integrity_ok"]))]),
            _table([("Enrolment approved by", f'{r["enrollment"].get("approved_by")} '
                                              f'({r["enrollment"].get("approved_by_role")}) at {r["enrollment"].get("at")}, '
                                              f'block {r["enrollment"].get("block_index")}')])
            if r.get("enrollment", {}).get("found") else "",
            "<h2>5. Ledger provenance</h2>",
            _table([("Block", lg["block_index"]), ("Block hash", lg["block_hash"]),
                    ("Previous hash", lg["header"]["prev_hash"]), ("Merkle root", lg["header"]["merkle_root"]),
                    ("Endorsed by", ", ".join(lg["endorsements"]) + f' (quorum {lg["quorum"]})'),
                    ("Chain length / head", f'{lg["chain_length"]} / {lg["chain_head"]}')], mono=True),
            "<h2>6. Signed decryption record</h2>",
            _table([(k, val if not isinstance(val, dict) else ", ".join(f"{x}={y}" for x, y in val.items()))
                    for k, val in r["event"]["record"].items()], mono=True),
            _table([("Record signature (" + r["event"]["sig_alg"] + ", truncated)",
                     r["event"]["signature"][:160] + "...")], mono=True),
        ]
    s = r["report_signature"]
    parts += [
        "<h2>Report signature</h2>",
        _table([("Signer", f'{s["signer"]} + examiner {s.get("examiner_id")}'), ("Algorithm", s["alg"]),
                ("Report SHA3-256", s["report_sha3"]),
                ("Signer key SHA3-256", s["signer_pk_sha3"]), ("Signature (truncated)", s["signature"][:160] + "...")],
               mono=True),
        '<p class="sub">The accompanying JSON report is the canonical signed artifact; verify it with '
        "POST /api/reports/verify on any installation holding the examiner public key.</p>",
    ]
    return "".join(parts)


def render_pdf(report: dict) -> bytes:
    story = pymupdf.Story(html=_html(report), user_css=CSS)
    buf = io.BytesIO()
    writer = pymupdf.DocumentWriter(buf)
    page_rect = pymupdf.paper_rect("a4")
    where = page_rect + (40, 40, -40, -40)
    more = True
    while more:
        dev = writer.begin_page(page_rect)
        more, _ = story.place(where)
        story.draw(dev)
        writer.end_page()
    writer.close()
    return buf.getvalue()
