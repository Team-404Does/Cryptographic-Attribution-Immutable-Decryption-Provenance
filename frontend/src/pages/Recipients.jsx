import React, { useMemo, useState } from "react";
import { AlertTriangle, BadgeCheck, LockOpen, Search, ShieldX, UserPlus, Users } from "lucide-react";
import { api, when } from "../api.js";
import {
  Alert, Badge, Button, Card, Drawer, Empty, ErrorBox, Field, Hash, KV, Modal, PageHeader, Spinner, Table, Tabs,
  useAction, useLoad,
} from "../components/ui.jsx";

const CLEAR_TONE = { CONFIDENTIAL: "info", SECRET: "accent", "TOP SECRET": "warn" };
const EMPTY = { employee_id: "", name: "", department: "", clearance: "SECRET", pin: "", confirm: "" };

function EnrolModal({ open, onClose, onDone, existing }) {
  const [f, setF] = useState(EMPTY);
  const act = useAction();
  const namesake = existing.find((r) => f.name.trim() && r.name.toLowerCase().replace(/\s+/g, " ") === f.name.trim().toLowerCase().replace(/\s+/g, " "));
  const submit = (e) => {
    e.preventDefault();
    if (f.pin !== f.confirm) return act.setError("PINs do not match");
    act.run(async () => {
      const { confirm, ...body } = f;
      const r = await api.post("/api/recipients", body);
      setF(EMPTY);
      onDone(r);
    }, { success: (r) => `${r.name} enrolled · certificate #${r.cert.body.serial}` });
  };
  return (
    <Modal open={open} onClose={onClose} title="Enrol recipient" width="max-w-xl"
      subtitle="Key pairs are generated inside the new token. Your officer signature on the enrolment is committed to the ledger."
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" busy={act.busy} onClick={submit} icon={UserPlus}>Generate keys & issue certificate</Button></>}>
      <form onSubmit={submit} className="grid gap-4 sm:grid-cols-2">
        <Field label="Employee ID" hint="Unique; one active identity per employee"><input className="input font-mono uppercase" value={f.employee_id} onChange={(e) => setF({ ...f, employee_id: e.target.value })} required /></Field>
        <Field label="Full name"><input className="input" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} required /></Field>
        <Field label="Department"><input className="input" value={f.department} onChange={(e) => setF({ ...f, department: e.target.value })} /></Field>
        <Field label="Clearance">
          <select className="input" value={f.clearance} onChange={(e) => setF({ ...f, clearance: e.target.value })}>
            {["CONFIDENTIAL", "SECRET", "TOP SECRET"].map((c) => <option key={c}>{c}</option>)}
          </select>
        </Field>
        <Field label="Token PIN" hint="4–12 digits, chosen by the recipient"><input className="input" type="password" inputMode="numeric" value={f.pin} onChange={(e) => setF({ ...f, pin: e.target.value })} required /></Field>
        <Field label="Confirm PIN"><input className="input" type="password" inputMode="numeric" value={f.confirm} onChange={(e) => setF({ ...f, confirm: e.target.value })} required /></Field>
        {namesake && (
          <div className="sm:col-span-2">
            <Alert tone="warn" title="Another identity already uses this name">
              {namesake.name} · {namesake.employee_id} ({namesake.status}). Reports identify people by employee ID and certificate, so both will be listed if a leak is attributed to either.
            </Alert>
          </div>
        )}
        <div className="sm:col-span-2"><ErrorBox error={act.error} /></div>
        <button type="submit" hidden />
      </form>
    </Modal>
  );
}

function Detail({ id, onClose, canManage, onChanged }) {
  const d = useLoad(() => api.get(`/api/recipients/${id}`), [id]);
  const [reason, setReason] = useState("");
  const [revoking, setRevoking] = useState(false);
  const act = useAction();
  const r = d.data;
  const revoke = () => act.run(async () => { await api.post(`/api/recipients/${id}/revoke`, { reason }); setRevoking(false); d.reload(); onChanged(); }, { success: "Identity revoked and recorded on the ledger" });
  const unlock = () => act.run(async () => { await api.post(`/api/recipients/${id}/unlock`); d.reload(); onChanged(); }, { success: "Token unlocked" });

  return (
    <Drawer open onClose={onClose} title={r ? r.name : "Recipient"} subtitle={r && <span className="font-mono">{r.id} · {r.employee_id}</span>}
      actions={r && canManage && r.status === "active" && <Button size="sm" variant="danger" icon={ShieldX} onClick={() => setRevoking(true)}>Revoke</Button>}>
      {!r ? <Spinner /> : (
        <div className="space-y-6">
          <div className="flex flex-wrap gap-2">
            {r.status === "active" ? <Badge tone="ok" dot>Active</Badge> : <Badge tone="bad" dot>Revoked</Badge>}
            <Badge tone={CLEAR_TONE[r.clearance]}>{r.clearance}</Badge>
            {r.cert_status.valid ? <Badge tone="ok"><BadgeCheck className="h-3 w-3" /> Certificate valid</Badge> : <Badge tone="bad">Certificate invalid</Badge>}
          </div>
          {r.status !== "active" && <Alert tone="bad" title={`Revoked ${when(r.revoked_at)}`}>{r.revoked_reason}. This identity can no longer decrypt or be granted access. Past sessions remain attributable.</Alert>}
          <section>
            <div className="eyebrow mb-3">Identity</div>
            <KV cols={2} rows={[["Employee ID", <span className="font-mono">{r.employee_id}</span>], ["Department", r.department || "—"],
              ["Enrolled", when(r.created_at)], ["Enrolled by", <span className="font-mono">{r.enrolled_by}</span>]]} />
          </section>
          <section>
            <div className="eyebrow mb-3">X.509-style certificate (ML-DSA-65, offline root)</div>
            <KV rows={[["Serial", <span className="font-mono">{r.cert.body.serial}</span>], ["Issuer", r.cert.body.issuer],
              ["Validity", `${when(r.cert.body.not_before)} → ${when(r.cert.body.not_after)}`],
              ["Fingerprint (SHA3-256)", <Hash value={r.cert.fingerprint} full />],
              [`${r.cert.body.kem_alg} encapsulation key`, <span className="font-mono text-[12px] text-muted">{Math.round(r.cert.body.kem_pk.length * 0.75)} bytes · <Hash value={r.cert.body.kem_pk} n={40} /></span>],
              [`${r.cert.body.sig_alg} verification key`, <span className="font-mono text-[12px] text-muted">{Math.round(r.cert.body.sig_pk.length * 0.75)} bytes · <Hash value={r.cert.body.sig_pk} n={40} /></span>],
              ["CA signature", <Hash value={r.cert.signature} n={40} />]]} />
          </section>
          {canManage && (
            <section>
              <div className="eyebrow mb-3">Token</div>
              <div className="flex items-center justify-between rounded-lg border border-line p-3">
                <div className="text-[13px] text-muted">Wrong PIN entries trigger a temporary lockout. Unlocking is signed and logged.</div>
                <Button size="sm" icon={LockOpen} busy={act.busy} onClick={unlock}>Unlock token</Button>
              </div>
            </section>
          )}
          <ErrorBox error={act.error} />
        </div>
      )}
      <Modal open={revoking} onClose={() => setRevoking(false)} title="Revoke identity" width="max-w-md"
        subtitle="Revocation is permanent and recorded on the ledger with your signature."
        footer={<><Button onClick={() => setRevoking(false)}>Cancel</Button><Button variant="danger" busy={act.busy} onClick={revoke}>Revoke identity</Button></>}>
        <Field label="Reason"><input className="input" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. left the organisation" /></Field>
      </Modal>
    </Drawer>
  );
}

export default function Recipients({ session }) {
  const list = useLoad(() => api.get("/api/recipients"));
  const [q, setQ] = useState("");
  const [tab, setTab] = useState("active");
  const [open, setOpen] = useState(null);
  const [enrol, setEnrol] = useState(false);
  const canManage = session.operator.role === "security-officer";
  const all = list.data || [];
  const rows = useMemo(() => all.filter((r) => (tab === "all" || r.status === tab) &&
    `${r.name} ${r.employee_id} ${r.department} ${r.id}`.toLowerCase().includes(q.toLowerCase())), [all, q, tab]);

  return (
    <>
      <PageHeader eyebrow="Identity & access" title="Recipients"
        subtitle="People who can decrypt sealed documents. A security officer enrols each one. They get their own ML-KEM and ML-DSA keys, certified by the offline root CA."
        actions={canManage && <Button variant="primary" icon={UserPlus} onClick={() => setEnrol(true)}>Enrol recipient</Button>} />
      <Card pad={false}>
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-3">
          <Tabs value={tab} onChange={setTab} items={[["active", "Active", all.filter((r) => r.status === "active").length],
            ["revoked", "Revoked", all.filter((r) => r.status === "revoked").length], ["all", "All", all.length]]} />
          <div className="relative w-72">
            <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-subtle" />
            <input className="input pl-9" placeholder="Search name, employee ID…" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
        </div>
        <ErrorBox error={list.error} className="m-4" />
        {list.loading && !list.data ? <div className="p-5"><Spinner /></div> : rows.length === 0 ? (
          <Empty icon={Users} title={all.length ? "No matching recipients" : "No recipients yet"}>
            {canManage && !all.length ? "Enrol the first recipient to start distributing documents." : null}
          </Empty>
        ) : (
          <Table head={["Recipient", "Employee ID", "Clearance", "Certificate", "Sessions", "Status"]}>
            {rows.map((r) => (
              <tr key={r.id} className="cursor-pointer transition hover:bg-inset" onClick={() => setOpen(r.id)}>
                <td className="td">
                  <div className="flex items-center gap-3">
                    <span className="flex h-8 w-8 items-center justify-center rounded-full bg-accent/10 text-[11.5px] font-semibold text-accent">{r.name.split(" ").map((p) => p[0]).slice(0, 2).join("")}</span>
                    <div>
                      <div className="flex items-center gap-1.5 font-medium">{r.name}{r.duplicate_name && <AlertTriangle className="h-3.5 w-3.5 text-warn" title="Name shared with another identity" />}</div>
                      <div className="text-[12px] text-subtle">{r.department || "—"}</div>
                    </div>
                  </div>
                </td>
                <td className="td font-mono text-[12.5px]">{r.employee_id}</td>
                <td className="td"><Badge tone={CLEAR_TONE[r.clearance]}>{r.clearance}</Badge></td>
                <td className="td"><div className="font-mono text-[12px]">#{r.cert_serial}</div><div className="text-[11.5px] text-subtle">expires {when(r.cert_not_after)}</div></td>
                <td className="td tabular-nums">{r.sessions}</td>
                <td className="td">
                  {r.status === "active" ? <Badge tone="ok" dot>Active</Badge> : <Badge tone="bad" dot>Revoked</Badge>}
                  {r.failed_pin_attempts > 0 && <Badge tone="warn" className="ml-1.5">{r.failed_pin_attempts} bad PIN</Badge>}
                </td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
      <EnrolModal open={enrol} onClose={() => setEnrol(false)} existing={all} onDone={() => { setEnrol(false); list.reload(); }} />
      {open && <Detail id={open} onClose={() => setOpen(null)} canManage={canManage} onChanged={list.reload} />}
    </>
  );
}
