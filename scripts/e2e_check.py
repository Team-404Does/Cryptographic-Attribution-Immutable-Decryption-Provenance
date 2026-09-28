"""End-to-end sanity check against a running demo server (127.0.0.1:8765).

Flow: officer login -> pick document -> recipient decrypt -> leak transform ->
examiner login -> forensic analysis -> verdict + identity + report verify.
Stdlib only (urllib), so it runs anywhere the backend runs.
"""
import json
import sys
import urllib.request
import uuid

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8765"


def call(method, path, body=None, token=None, raw=False):
    req = urllib.request.Request(BASE + path, method=method)
    req.add_header("Origin", BASE)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    data = None
    if body is not None:
        if raw:
            req.add_header("Content-Type", body[0])
            data = body[1]
        else:
            req.add_header("Content-Type", "application/json")
            data = json.dumps(body).encode()
    try:
        with urllib.request.urlopen(req, data) as r:
            payload = r.read()
            ctype = r.headers.get("Content-Type", "")
            if ctype.startswith("application/json") or payload[:1] in (b"{", b"["):
                return json.loads(payload)
            return payload  # binary (leak artifact, PDF)
    except urllib.error.HTTPError as e:
        print(f"  ! {method} {path} -> HTTP {e.code}: {e.read().decode()[:200]}")
        raise


print("== 1. operator logins ==")
ops = call("GET", "/api/auth/operators")
tok = {}
for o in ops:
    pin = {"Priya Nair": "9000", "Arjun Rao": "9100", "Meera Das": "9200"}[o["name"]]
    s = call("POST", "/api/auth/login", {"operator_id": o["id"], "pin": pin})
    tok[o["role"]] = s["token"]
    print(f"  {o['name']:12s} {o['role']:16s} ok")

print("== 2. documents + recipients ==")
docs = call("GET", "/api/documents", token=tok["security-officer"])
rcps = call("GET", "/api/recipients", token=tok["security-officer"])
active = [r for r in rcps if r.get("status") == "active"]
pins = {"EMP-1001": "1111", "EMP-1002": "2222", "EMP-1003": "3333"}
doc, rcp = None, None
for d0 in docs:
    for r0 in active:
        if r0["id"] in (d0.get("recipients") or []):
            doc, rcp = d0, r0
            break
    if doc:
        break
if not doc:
    doc, rcp = docs[0], active[0]
    print(f"  no existing grant - officer grants access to demonstrate the flow")
    call("POST", f"/api/documents/{doc['id']}/grant", {"recipient_id": rcp["id"]},
         token=tok["security-officer"])
print(f"  doc: {doc['title']} ({doc['id']}) recipients={doc.get('recipients')}")
print(f"  recipient: {rcp['name']} ({rcp['id']})")

print("== 3. recipient decrypts (new session) ==")
d = call("POST", "/api/sessions/decrypt",
         {"doc_id": doc["id"], "recipient_id": rcp["id"], "pin": pins.get(rcp["employee_id"], "1111")})
sid = d["session_id"]
wm = d["watermark_id"]
print(f"  session {sid} wm_id={wm} block={d.get('block_index')}")
print(f"  trace: {[t.get('step', t.get('name', '?')) for t in d.get('trace', [])][:6]}")

print("== 4. leak simulation (JPEG photo-of-screen) ==")
leak = call("GET", f"/api/sessions/{sid}/leak?transform=9", token=tok["examiner"])
assert isinstance(leak, bytes) and leak[:2] == b"\xff\xd8", f"unexpected leak artifact: {type(leak)}"
print(f"  leak artifact: {len(leak)} bytes (JPEG)")
open("evidence.jpg", "wb").write(leak)

print("== 5. examiner forensic analysis ==")
boundary = uuid.uuid4().hex
part = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
        f"filename=\"evidence.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n").encode() + leak + f"\r\n--{boundary}--\r\n".encode()
rep = call("POST", "/api/forensics/analyze",
           ("multipart/form-data; boundary=" + boundary, part), token=tok["examiner"], raw=True)
print(f"  verdict: {rep['verdict']}")
att = rep.get("attribution", {})
print(f"  attributed to: {att.get('recipient_name', '?')} (employee {att.get('employee_id', '?')}, "
      f"{att.get('clearance', '?')}, {att.get('identity_status', '?')})")
print(f"  session: {att.get('session_id', '?')}  decrypted_at: {att.get('decrypted_at', '?')}")
print(f"  device_fp: {att.get('device_fingerprint', '?')}")

print("== 6. exported report re-verification ==")
rid = rep.get("report_id") or rep.get("id")
r = call("GET", f"/api/reports/{rid}", token=tok["examiner"])
pkg = r.get("report", r)
v = call("POST", "/api/reports/verify", pkg)
print(f"  verify_report: {v}")

print("\nE2E RESULT: PASS" if rep["verdict"].startswith("ATTRIBUTED") else "\nE2E RESULT: CHECK VERDICT")
