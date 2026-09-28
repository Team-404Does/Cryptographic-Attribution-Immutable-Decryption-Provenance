import React, { useState } from "react";
import { LockOpen, UserCog, UserPlus } from "lucide-react";
import { api, ROLE_LABEL, when } from "../api.js";
import { Badge, Button, Card, Empty, ErrorBox, Field, Modal, PageHeader, Spinner, Table, useAction, useLoad } from "../components/ui.jsx";

const ROLE_DESC = {
  "security-officer": "Enrols identities, seals documents, grants and revokes access",
  examiner: "Runs leak forensics and signs evidence reports",
  auditor: "Inspects and verifies the audit ledger",
};

export default function Operators({ session }) {
  const list = useLoad(() => api.get("/api/operators"));
  const [open, setOpen] = useState(false);
  const [f, setF] = useState({ name: "", role: "examiner", pin: "" });
  const act = useAction();
  const names = Object.fromEntries((list.data || []).map((o) => [o.id, o.name]));

  const create = (e) => {
    e?.preventDefault();
    act.run(async () => {
      const r = await api.post("/api/operators", f);
      setOpen(false);
      setF({ name: "", role: "examiner", pin: "" });
      list.reload();
      return r;
    }, { success: (r) => `${r.name} added as ${ROLE_LABEL[r.role]}` });
  };
  const unlock = (id) => act.run(async () => { await api.post(`/api/operators/${id}/unlock`); list.reload(); }, { success: "Operator token unlocked" });

  return (
    <>
      <PageHeader eyebrow="Identity & access" title="Operators"
        subtitle="Staff who run the system. Each operator has a personal ML-DSA token, and their privileged actions are signed and recorded on the ledger."
        actions={<Button variant="primary" icon={UserPlus} onClick={() => setOpen(true)}>Add operator</Button>} />
      <div className="mb-6 grid gap-4 md:grid-cols-3">
        {Object.entries(ROLE_DESC).map(([r, d]) => (
          <div key={r} className="card p-4">
            <div className="flex items-center justify-between">
              <span className="text-[13px] font-semibold">{ROLE_LABEL[r]}</span>
              <Badge tone="accent">{(list.data || []).filter((o) => o.role === r).length}</Badge>
            </div>
            <p className="mt-1 text-[12.5px] text-subtle">{d}</p>
          </div>
        ))}
      </div>
      <Card pad={false}>
        <ErrorBox error={list.error || act.error} className="m-4" />
        {list.loading && !list.data ? <div className="p-5"><Spinner /></div> : !list.data?.length ? <Empty icon={UserCog} title="No operators" /> : (
          <Table head={["Operator", "Role", "Added", "Added by", "Token", ""]}>
            {list.data.map((o) => (
              <tr key={o.id}>
                <td className="td"><div className="font-medium">{o.name}{o.id === session.operator.id && <span className="ml-2 text-[12px] text-subtle">(you)</span>}</div><div className="font-mono text-[11.5px] text-subtle">{o.id}</div></td>
                <td className="td"><Badge tone={o.role === "security-officer" ? "accent" : o.role === "examiner" ? "info" : "mute"}>{ROLE_LABEL[o.role]}</Badge></td>
                <td className="td text-muted">{when(o.created_at)}</td>
                <td className="td text-muted">{o.created_by ? names[o.created_by] || o.created_by : <span className="italic">installation ceremony</span>}</td>
                <td className="td">{o.locked ? <Badge tone="bad" dot>Locked</Badge> : o.failed_attempts ? <Badge tone="warn">{o.failed_attempts} bad PIN</Badge> : <Badge tone="ok" dot>OK</Badge>}</td>
                <td className="td text-right">{(o.locked || o.failed_attempts > 0) && <Button size="sm" icon={LockOpen} onClick={() => unlock(o.id)}>Unlock</Button>}</td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
      <Modal open={open} onClose={() => setOpen(false)} title="Add operator" subtitle="A token is generated and certified by the offline CA. The enrolment is signed by you."
        footer={<><Button onClick={() => setOpen(false)}>Cancel</Button><Button variant="primary" busy={act.busy} onClick={create}>Create operator</Button></>}>
        <form onSubmit={create} className="space-y-4">
          <Field label="Full name"><input className="input" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} required /></Field>
          <Field label="Role">
            <div className="space-y-1.5">
              {Object.entries(ROLE_DESC).map(([r, d]) => (
                <label key={r} className={`flex cursor-pointer gap-3 rounded-lg border p-3 ${f.role === r ? "border-accent bg-accent/5" : "border-line hover:bg-inset"}`}>
                  <input type="radio" name="role" className="mt-0.5 accent-[rgb(var(--accent))]" checked={f.role === r} onChange={() => setF({ ...f, role: r })} />
                  <span><span className="block text-[13px] font-medium">{ROLE_LABEL[r]}</span><span className="block text-[12px] text-subtle">{d}</span></span>
                </label>
              ))}
            </div>
          </Field>
          <Field label="Initial token PIN" hint="4–12 digits"><input className="input" type="password" inputMode="numeric" value={f.pin} onChange={(e) => setF({ ...f, pin: e.target.value })} required /></Field>
          <ErrorBox error={act.error} />
          <button type="submit" hidden />
        </form>
      </Modal>
    </>
  );
}
